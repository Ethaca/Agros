import { z } from "zod";

/**
 * The hand-off between `argos ci prepare` (runs customer code, holds NO write credential) and `argos ci publish`
 * (holds the write token, never runs customer code). publish trusts nothing in the artifact: every rule here is
 * re-checked on its side before a byte reaches git or GitHub.
 */

export const ARTIFACT_SCHEMA = "argos-ci-artifact/v1";
/** Every branch Argos pushes starts with this; CI never runs prepare/publish for such a branch (recursion guard). */
export const ARGOS_BRANCH_PREFIX = "argos/";
/** Commit trailers publish writes on every Argos commit. */
export const TRAILER_RESULT = "Argos-Result";
export const TRAILER_SOURCE = "Argos-Source";
/** Hidden marker publish appends to the PR body; identifies the PR as Argos's own for this branch. */
export const prMarker = (branch: string): string => `<!-- argos-ci:v1 branch=${branch} -->`;
export const MARKER_PREFIX = "<!-- argos-ci";

/** Names of credentials that must never reach the step that runs customer code. */
export const WRITE_CREDENTIALS = [
  "GITHUB_TOKEN",
  "GH_TOKEN",
  "GH_ENTERPRISE_TOKEN",
  "GITHUB_ENTERPRISE_TOKEN",
  "ACTIONS_RUNTIME_TOKEN",
  "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
  "ACTIONS_ID_TOKEN_REQUEST_URL",
] as const;

export const reportBranch = (base: string): string => `${ARGOS_BRANCH_PREFIX}report-${base.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "head"}`;

const RelPath = z
  .string()
  .min(1)
  .max(300)
  .refine((p) => !p.startsWith("/") && !p.includes("\\") && !p.split("/").some((s) => s === ".." || s === "." || s === ""), "must be a plain relative path");

export const Artifact = z.strictObject({
  schema: z.literal(ARTIFACT_SCHEMA),
  /** verified: ran, nothing left unverified · partial: ran, some scope unverified · failed: preparation failed · unsupported: stack/config not supported · skipped: nothing to publish */
  status: z.enum(["verified", "partial", "failed", "unsupported", "skipped"]),
  /** Why nothing is published (status skipped). */
  skip: z.string().optional(),
  headSha: z.string().regex(/^[0-9a-f]{40}$/),
  base: z.string().min(1).max(200).regex(/^[A-Za-z0-9._\/-]+$/).refine((b) => !b.includes("..") && !b.startsWith("/") && !b.endsWith("/") && !b.endsWith(".lock"), "invalid branch name"),
  branch: z.string().max(220).regex(/^argos\/[A-Za-z0-9._-]+$/),
  title: z.string().min(1).max(200),
  /** PR body, relative to the artifact dir. */
  body: z.literal("body.md"),
  /** Files to commit: `from` (inside the artifact's files/ dir) -> `to` (repository path). */
  files: z.array(z.strictObject({ from: RelPath, to: RelPath })).max(20),
  /** Verified code fix as a git diff, relative to the artifact dir, or null. */
  patch: z.literal("fix.patch").nullable(),
  patchFiles: z.array(z.string()).default([]),
  /** Names (never values) of credentials prepare found in its environment and dropped before running anything. */
  credentialsDropped: z.array(z.string()).default([]),
  counts: z.record(z.string(), z.number()).optional(),
});
export type Artifact = z.infer<typeof Artifact>;

/** Repository paths publish may write as files (the config draft and the report directory). */
export function allowedFileTarget(to: string): boolean {
  return /^(?:[A-Za-z0-9._-]+\/)*argos\.config\.yaml$/.test(to) || /^\.argos\/[A-Za-z0-9._-]+\.(?:md|json)$/.test(to);
}

/**
 * Paths a code fix must never touch: CI definitions, Argos's own config/expectations/report, tests, migrations and
 * seed data. A "fix" that edits any of these could make the check pass without fixing anything.
 */
export function forbiddenPatchPath(p: string): string | undefined {
  const lower = p.toLowerCase();
  if (lower.startsWith(".github/") || lower.includes("/.github/")) return "touches .github (CI definitions)";
  if (lower.startsWith(".git/") || lower.includes("/.git/")) return "touches .git";
  if (/(^|\/)argos[^/]*\.(ya?ml|json)$/.test(lower) || lower.startsWith(".argos/")) return "touches the Argos config/expectations/report";
  if (/(^|\/)(test|tests|__tests__|spec|e2e|src\/test)\//.test(lower) || /\.(test|spec)\.[a-z0-9]+$/.test(lower) || /(?:Test|Tests|IT)\.(?:java|kt)$/.test(p)) return "touches a test";
  if (/(^|\/)(migrations?|db\/migration|db\/changelog)\//.test(lower) || /\.sql$/.test(lower)) return "touches a migration/schema/seed";
  return undefined;
}

/** Paths a git diff touches (both sides of renames/copies), plus structural problems publish refuses. */
export function patchPaths(patch: string): { paths: string[]; problems: string[] } {
  const paths = new Set<string>();
  const problems: string[] = [];
  const unq = (s: string) => s.replace(/^"|"$/g, "");
  for (const line of patch.split("\n")) {
    let m: RegExpExecArray | null;
    if ((m = /^diff --git (\S+|"[^"]+") (\S+|"[^"]+")$/.exec(line))) {
      paths.add(unq(m[1]!).replace(/^a\//, ""));
      paths.add(unq(m[2]!).replace(/^b\//, ""));
    } else if ((m = /^(?:---|\+\+\+) (.+)$/.exec(line)) && m[1] !== "/dev/null") {
      paths.add(unq(m[1]!).replace(/^[ab]\//, "").replace(/\t.*$/, ""));
    } else if ((m = /^(?:rename|copy) (?:from|to) (.+)$/.exec(line))) {
      paths.add(unq(m[1]!));
    } else if (/^GIT binary patch/.test(line) || /^Binary files /.test(line)) problems.push("binary patch");
    else if (/^(?:new file mode|new mode|old mode|deleted file mode) (?:120000|160000)/.test(line)) problems.push("symlink or submodule change");
  }
  for (const p of paths) {
    if (p.startsWith("/") || p.split("/").includes("..")) problems.push(`unsafe path ${p}`);
  }
  return { paths: [...paths], problems };
}

const SECRET_PATTERNS: { name: string; re: RegExp }[] = [
  { name: "JWT", re: /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  // Seed markers are only ever shown as their first 6 characters; a full one means the masking was bypassed.
  { name: "full Argos marker", re: /ARGOS_[A-Za-z0-9_-]*_[0-9a-f]{6,8}(?![0-9A-Za-z])/g },
  { name: "GitHub token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/g },
  { name: "private key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
  { name: "AWS access key", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: "Bearer credential", re: /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}/g },
];

/** What looks like a secret or a full canary in the text (names of the patterns, not the values). */
export function findSecrets(text: string): string[] {
  return SECRET_PATTERNS.filter((p) => new RegExp(p.re.source).test(text)).map((p) => p.name);
}

/** Replace anything that looks like a secret; used by prepare on text that came from customer code (logs, errors). */
export function scrubSecrets(text: string): string {
  let out = text;
  for (const p of SECRET_PATTERNS) out = out.replace(p.re, (m) => (p.name === "full Argos marker" ? `${m.slice(0, 6)}…` : `[redacted ${p.name}]`));
  // Nobody but publish writes the hidden PR marker.
  return out.split(MARKER_PREFIX).join("<!-- (removed)");
}
