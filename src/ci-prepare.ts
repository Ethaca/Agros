import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import {
  ARGOS_BRANCH_PREFIX,
  ARTIFACT_SCHEMA,
  forbiddenPatchPath,
  reportBranch,
  scrubSecrets,
  TRAILER_RESULT,
  WRITE_CREDENTIALS,
  type Artifact,
} from "./ci-artifact.js";
import { loadConfig, type Config } from "./config.js";
import { runFix, type FixReport } from "./fix/index.js";
import { applyEdits, type Edit } from "./fix/rules.js";
import { InitError, runInit, type InitResult } from "./init/index.js";
import { ciBase } from "./pr.js";
import { CI_TEXT } from "./ci-text.js";
import { LIMITS, loadScan, renderReport, type LoadedScan } from "./report.js";
import type { Isolation } from "./runner.js";
import type { ReportLang } from "./types.js";

/**
 * `argos ci prepare`: the half of CI that runs customer code (build, app, LLM). It holds no Git/PR write credential
 * (they are dropped from the environment before anything runs) and its only output is an artifact directory that
 * `argos ci publish` validates and turns into a branch + PR.
 *
 *   no argos.config.yaml -> runInit (Spring or Node) -> runFix (scan + re-verify fixes under the SAME config)
 *   -> artifact: pr.json, body.md, files/ (config draft, plain report, evidence), fix.patch (verified fixes only)
 *
 * Every failure on the way still yields an artifact: a report PR that says what was not verified and why.
 */

export class PrepareError extends Error {}

export interface PrepareOptions {
  /** The application directory inside the checked-out repository. */
  dir: string;
  artifactDir: string;
  /** Scratch space for init/scan output. Default: a new temp dir. */
  workDir?: string;
  /** Default container: the customer's code is untrusted. */
  isolation?: Isolation;
  timeoutMs?: number;
  /** Branch the report PR targets. Default: ciBase() in GitHub Actions, else the checked-out branch. */
  base?: string;
  llmData?: "none" | "files";
  /** Report/PR language. Default: the existing config's `report.lang`, else "en". */
  lang?: ReportLang;
  /** Environment to read CI variables from and to strip write credentials from. Default: process.env (mutated). */
  env?: NodeJS.ProcessEnv;
  quiet?: boolean;
  log?: (line: string) => void;
}

/** Injected so tests can stand in for the parts that need Docker. */
export interface PrepareDeps {
  runInit: typeof runInit;
  runFix: typeof runFix;
}

export interface PrepareResult {
  artifact: Artifact;
  artifactDir: string;
  body: string;
  report?: string;
}

interface StageError {
  stage: "init" | "config" | "scan" | "fix-guard";
  message: string;
}

const git = (cwd: string, args: string[]): string => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
const tryGit = (cwd: string, args: string[]): string | undefined => {
  try {
    return git(cwd, args);
  } catch {
    return undefined;
  }
};
const sha256 = (t: string | Buffer): string => createHash("sha256").update(t).digest("hex");
/** First line of an error (RunnerError appends the app's log tail, which is customer output). */
const firstLine = (e: unknown): string => scrubSecrets(String((e as Error)?.message ?? e).split("\n")[0]!.slice(0, 500));
const cell = (s: string): string => s.replace(/\|/g, "\\|").replace(/\n/g, " ");

/** Remove write credentials from the environment before any customer code can run. Returns the names dropped. */
export function dropWriteCredentials(env: NodeJS.ProcessEnv = process.env): string[] {
  const dropped: string[] = [];
  for (const k of WRITE_CREDENTIALS) {
    if (env[k] !== undefined) {
      delete env[k];
      dropped.push(k);
    }
  }
  return dropped;
}

/** Fields that decide what is expected and what is tested. A fix may not change any of them. */
export function policySnapshot(cfg: Config): Record<string, string> {
  const c = cfg as Record<string, unknown>;
  const fields = ["mode", "checks", "personas", "resources", "auth", "seed", "db", "provenance"];
  return Object.fromEntries(fields.map((f) => [f, JSON.stringify(c[f] ?? null)]));
}

/** Hash of every tracked change in the checkout: scan and fix work on temp copies and must leave it as it was. */
function trackedState(root: string): string {
  return sha256(tryGit(root, ["diff", "HEAD", "--binary", "--no-ext-diff", "--no-textconv"]) ?? "");
}

/** Unified diff (repo-relative paths) of the verified edits; the checkout is restored afterwards. */
function makePatch(root: string, srcDir: string, edits: Edit[]): string {
  const files = [...new Set(edits.map((e) => join(srcDir, e.file)))];
  if (tryGit(root, ["diff", "--quiet", "HEAD", "--", ...files]) === undefined) throw new PrepareError("the files the fix edits have local changes");
  const original = new Map(files.map((f) => [f, readFileSync(f)]));
  try {
    applyEdits(srcDir, edits);
    return git(root, ["-c", "core.quotepath=false", "diff", "--no-color", "--no-ext-diff", "--no-textconv", "HEAD", "--", ...files]) + "\n";
  } finally {
    for (const [f, text] of original) writeFileSync(f, text);
  }
}

export async function runPrepare(opts: PrepareOptions, deps: PrepareDeps = { runInit, runFix }): Promise<PrepareResult> {
  const log = opts.log ?? ((l: string) => console.log(l));
  const env = opts.env ?? process.env;
  const credentialsDropped = dropWriteCredentials(env);
  if (credentialsDropped.length) log(`dropped from the environment before running anything: ${credentialsDropped.join(", ")}`);

  if (!existsSync(opts.dir)) throw new PrepareError(`${opts.dir} does not exist`);
  // realpath: git reports the top level with symlinks resolved (macOS /var -> /private/var)
  const dir = realpathSync(resolve(opts.dir));
  const root = tryGit(dir, ["rev-parse", "--show-toplevel"]);
  if (!root) throw new PrepareError(`${opts.dir} is not inside a git repository`);
  const headSha = git(root, ["rev-parse", "HEAD"]);
  const current = git(root, ["rev-parse", "--abbrev-ref", "HEAD"]);
  const base = opts.base ?? ciBase(env) ?? (current !== "HEAD" ? current : undefined);
  if (!base) throw new PrepareError("cannot tell which branch the report PR should target (detached HEAD): pass --base <branch>");
  const branch = reportBranch(base);
  const short = headSha.slice(0, 7);

  const artifactDir = resolve(opts.artifactDir);
  if (existsSync(artifactDir) && readdirSync(artifactDir).length && !existsSync(join(artifactDir, "pr.json"))) {
    throw new PrepareError(`${artifactDir} is not empty and is not an Argos artifact: refusing to overwrite it`);
  }
  rmSync(artifactDir, { recursive: true, force: true });
  mkdirSync(join(artifactDir, "files"), { recursive: true });

  const write = (a: Omit<Artifact, "schema" | "headSha" | "base" | "branch" | "body" | "credentialsDropped">, body: string): PrepareResult => {
    const artifact: Artifact = { schema: ARTIFACT_SCHEMA, headSha, base, branch, body: "body.md", credentialsDropped, ...a };
    const clean = scrubSecrets(body);
    writeFileSync(join(artifactDir, "body.md"), clean);
    writeFileSync(join(artifactDir, "pr.json"), JSON.stringify(artifact, null, 2) + "\n");
    log(`wrote ${artifactDir} (status ${artifact.status}${artifact.skip ? `: ${artifact.skip}` : ""})`);
    return { artifact, artifactDir, body: clean };
  };

  // ---- recursion guard: never run on Argos's own branches or commits
  const names = [env.GITHUB_HEAD_REF, env.GITHUB_REF_TYPE === "branch" ? env.GITHUB_REF_NAME : undefined, current];
  const own = names.find((n) => !!n && n.startsWith(ARGOS_BRANCH_PREFIX));
  const headMsg = tryGit(root, ["log", "-1", "--format=%B"]) ?? "";
  const skip = own ? `${own} is an Argos branch` : new RegExp(`^${TRAILER_RESULT}:`, "m").test(headMsg) ? `HEAD ${short} is an Argos commit` : undefined;
  if (skip) {
    log(`skipped: ${skip} (no result is produced for Argos's own output)`);
    return write({ status: "skipped", skip, title: "argos: skipped", files: [], patch: null, patchFiles: [] }, `Argos: ${skip}.\n`);
  }

  const work = resolve(opts.workDir ?? mkdtempSync(join(tmpdir(), "argos-prepare-")));
  mkdirSync(work, { recursive: true });
  const isolation = opts.isolation ?? "container";
  const errors: StageError[] = [];
  const configPath = join(dir, "argos.config.yaml");
  const configRel = relative(root, configPath);
  let existingLang: ReportLang | undefined;
  try {
    if (existsSync(configPath)) existingLang = loadConfig(configPath).report.lang;
  } catch {
    /* reported below */
  }
  const lang: ReportLang = opts.lang ?? existingLang ?? "en";
  const T = CI_TEXT[lang];
  const stack = detectStack(dir, T);

  // ---- 1. config: an existing one is used as is (it may hold rules a person confirmed); otherwise draft one
  let init: (InitResult & { configWritten?: boolean; adapter?: string }) | undefined;
  let configSource: "existing" | "generated" | "none" = existsSync(configPath) ? "existing" : "none";
  let unsupported = false;
  if (configSource === "none") {
    log(`[prepare 1/3] no argos.config.yaml: drafting one (${stack})`);
    try {
      init = await deps.runInit({ dir, out: configPath, reportDir: join(work, "init"), isolation, llmData: opts.llmData ?? "none", verify: false, log: opts.quiet ? () => {} : log });
      if (init.configWritten === false || !existsSync(configPath)) {
        unsupported = true;
        errors.push({ stage: "init", message: T.initNoConfig });
      } else configSource = "generated";
    } catch (e) {
      unsupported = e instanceof InitError;
      errors.push({ stage: "init", message: firstLine(e) });
    }
  } else log("[prepare 1/3] using the existing argos.config.yaml (not regenerated)");

  // ---- 2. scan + fix under a frozen policy
  let cfg: Config | undefined;
  let fix: FixReport | undefined;
  let scan: LoadedScan | undefined;
  let patch: string | undefined;
  let patchFiles: string[] = [];
  const refused: string[] = [];
  if (configSource !== "none") {
    try {
      cfg = loadConfig(configPath);
    } catch (e) {
      errors.push({ stage: "config", message: T.configUnreadable(firstLine(e)) });
    }
  }
  if (cfg) {
    log(`[prepare 2/3] scan + verify fixes (${isolation})`);
    const policyBefore = policySnapshot(cfg);
    const textBefore = sha256(readFileSync(configPath));
    const treeBefore = trackedState(root);
    try {
      fix = await deps.runFix({ configPath, outDir: work, apply: false, timeoutMs: opts.timeoutMs, isolation, quiet: opts.quiet, log: opts.quiet ? () => {} : log });
      scan = loadScan({ scanDir: join(work, "before"), fixPath: join(work, "fix.json") });
    } catch (e) {
      errors.push({ stage: "scan", message: firstLine(e) });
    }
    if (fix?.adopted) {
      // The fix must not have made the check pass by changing what is expected or what is tested.
      let after: Record<string, string> | undefined;
      try {
        after = policySnapshot(loadConfig(configPath));
      } catch {
        refused.push(T.guardUnreadable);
      }
      if (after) for (const k of Object.keys(policyBefore)) if (policyBefore[k] !== after[k]) refused.push(T.guardField(k));
      if (sha256(readFileSync(configPath)) !== textBefore) refused.push(T.guardText);
      if (trackedState(root) !== treeBefore) refused.push(T.guardTree);
      const srcDir = resolve(dirname(configPath), cfg.target.cwd);
      const edits = fix.proposals.filter((p) => p.status === "adopted").flatMap((p) => p.edits);
      for (const e of edits) {
        const rel = relative(root, join(srcDir, e.file));
        const why = forbiddenPatchPath(rel);
        if (why || rel.startsWith("..")) refused.push(T.guardPath(rel, why ?? T.outsideRepo));
      }
      if (!refused.length) {
        try {
          patch = makePatch(root, srcDir, edits);
          patchFiles = [...new Set(edits.map((e) => relative(root, join(srcDir, e.file))))];
        } catch (e) {
          refused.push(firstLine(e));
        }
      }
      if (refused.length) {
        errors.push({ stage: "fix-guard", message: T.guardSummary(refused.join("; ")) });
        if (scan) scan = { ...scan, fix: undefined };
      }
    }
  }

  // ---- 3. artifact
  log("[prepare 3/3] report + artifact");
  const status: Artifact["status"] = unsupported
    ? "unsupported"
    : !scan || errors.some((e) => e.stage !== "fix-guard")
      ? "failed"
      : (scan.meta.unverified?.length ?? 0) > 0 || scan.findings.some((f) => f.verdict === "SKIPPED") || untestedRoutes(init).length > 0
        ? "partial"
        : "verified";
  const ctx: ReportCtx = { lang, status, stack, short, base, configSource, configRel, init, cfg, scan, fix: refused.length ? undefined : fix, refused, errors, patchFiles };
  const report = scrubSecrets(renderPlainReport(ctx));
  const files: Artifact["files"] = [];
  const addFile = (name: string, to: string, content: string | Buffer) => {
    writeFileSync(join(artifactDir, "files", name), typeof content === "string" ? scrubSecrets(content) : content);
    files.push({ from: `files/${name}`, to });
  };
  if (configSource === "generated") addFile("argos.config.yaml", configRel, readFileSync(configPath, "utf8"));
  addFile("report.md", ".argos/report.md", report);
  if (scan) addFile("evidence.md", ".argos/evidence.md", renderReport(scan, { lang }));
  if (init?.reportPath && existsSync(init.reportPath)) addFile("init-report.md", ".argos/init-report.md", readFileSync(init.reportPath, "utf8"));
  const counts = scan ? { ...scan.meta.results.counts } : undefined;
  addFile("result.json", ".argos/result.json", JSON.stringify({ status, source: headSha, base, config: configSource, counts: counts ?? null, fix: patchFiles.length ? { files: patchFiles } : null, errors: errors.map((e) => ({ stage: e.stage, message: e.message })) }, null, 2) + "\n");
  if (patch) writeFileSync(join(artifactDir, "fix.patch"), patch);

  const adopted = patch ? (fix?.proposals.filter((p) => p.status === "adopted").length ?? 0) : 0;
  const title = adopted ? T.titleFix(adopted, short) : T.titleReport(configSource === "generated", short);
  return { ...write({ status, title, files, patch: patch ? "fix.patch" : null, patchFiles, ...(counts ? { counts } : {}) }, renderPrBody(ctx)), report };
}

type Text = (typeof CI_TEXT)[ReportLang];

function detectStack(dir: string, T: Text): string {
  const has = (f: string) => existsSync(join(dir, f));
  if (["pom.xml", "build.gradle", "build.gradle.kts"].some(has)) {
    const build = ["pom.xml", "build.gradle", "build.gradle.kts"].filter(has).map((f) => readFileSync(join(dir, f), "utf8")).join("\n");
    return /spring-boot|org\.springframework\.boot/.test(build) ? T.stackSpring : T.stackJvmOther;
  }
  if (has("package.json")) return T.stackNode;
  return T.stackUnknown;
}

// ---------------------------------------------------------------------------------------------------------------
// Plain-language report and PR body. Facts come from the scan files and the init result; nothing here is inferred.

interface ReportCtx {
  lang: ReportLang;
  status: Artifact["status"];
  stack: string;
  short: string;
  base: string;
  configSource: "existing" | "generated" | "none";
  configRel: string;
  init?: InitResult & { configWritten?: boolean; adapter?: string };
  cfg?: Config;
  scan?: LoadedScan;
  fix?: FixReport;
  refused: string[];
  errors: StageError[];
  patchFiles: string[];
}

function untestedRoutes(init: ReportCtx["init"]): { route: string; reason: string }[] {
  const u = (init?.draft as { untested?: unknown } | undefined)?.untested;
  return Array.isArray(u) ? u.filter((x): x is { route: string; reason: string } => !!x && typeof x.route === "string") : [];
}
function initUnsupported(init: ReportCtx["init"]): string[] {
  const v = (init?.draft as Record<string, unknown> | undefined)?.unsupported;
  return Array.isArray(v) ? v.map((x) => (typeof x === "string" ? x : typeof x === "object" && x && "item" in x ? String((x as { item: unknown }).item) : JSON.stringify(x))) : [];
}
function needsHuman(init: ReportCtx["init"]): { topic: string; message: string }[] {
  const v = (init?.draft as { needsHuman?: unknown } | undefined)?.needsHuman;
  return Array.isArray(v) ? v.map((n: { topic?: string; message?: string }) => ({ topic: String(n.topic ?? ""), message: String(n.message ?? "") })) : [];
}
function staticHints(init: ReportCtx["init"]): string[] {
  const v = (init?.draft as { likelyFindings?: unknown } | undefined)?.likelyFindings;
  return Array.isArray(v) ? v.map((f: { route?: string; what?: string }) => `${f.route ?? ""}: ${f.what ?? ""}`) : [];
}

function impact(T: Text, f: LoadedScan["findings"][number]): string {
  switch (f.check) {
    case "bola":
      return T.impact.bola(f.persona, f.resourceId);
    case "unauth":
      return T.impact.unauth(f.resourceId);
    case "sqli":
      return T.impact.sqli(f.resourceId);
    case "secrets":
      return T.impact.secrets(f.resourceId, f.column ?? f.env ?? T.impact.sensitiveField);
  }
}

function coverage(ctx: ReportCtx): { route: string; state: string; ran: boolean; reason: string }[] {
  const C = CI_TEXT[ctx.lang].cov;
  const rows: { route: string; state: string; ran: boolean; reason: string }[] = [];
  const unverified = new Map((ctx.scan?.meta.unverified ?? []).map((u) => [u.scope, u.reason]));
  const runLevel = unverified.get("run");
  for (const r of ctx.cfg?.resources ?? []) {
    if (!ctx.scan) {
      rows.push({ route: r.route, state: C.ranNot, ran: false, reason: ctx.errors.find((e) => e.stage === "scan")?.message ?? C.scanNotRun });
      continue;
    }
    const cells = ctx.scan.matrix.cells.filter((c) => c.resource === r.id);
    const why = unverified.get(`resources.${r.id}`) ?? runLevel;
    if (!cells.length) rows.push({ route: r.route, state: C.notSent, ran: false, reason: why ?? C.noRequest });
    else if (cells.every((c) => c.verdict === "SKIPPED")) rows.push({ route: r.route, state: C.ranNot, ran: false, reason: why ?? cells[0]!.evidence.note ?? C.allSkipped });
    else rows.push({ route: r.route, state: C.ran, ran: true, reason: why ? C.partly(why) : "" });
  }
  for (const u of untestedRoutes(ctx.init)) rows.push({ route: u.route, state: C.notInConfig, ran: false, reason: u.reason });
  return rows;
}

const unverifiedItems = (ctx: ReportCtx): { scope: string; reason: string }[] => [
  ...ctx.errors.filter((e) => e.stage !== "fix-guard").map((e) => ({ scope: e.stage, reason: e.message })),
  ...(ctx.scan?.meta.unverified ?? []),
  ...initUnsupported(ctx.init).map((u) => ({ scope: CI_TEXT[ctx.lang].report.unsupportedScope, reason: u })),
];

function renderPlainReport(ctx: ReportCtx): string {
  const T = CI_TEXT[ctx.lang];
  const P = T.report;
  const L: string[] = [];
  const { scan } = ctx;
  const red = scan?.findings.filter((f) => f.verdict === "VULNERABLE") ?? [];
  const yellow = scan?.findings.filter((f) => f.verdict === "SUSPECTED") ?? [];
  L.push(P.title(ctx.short), "", T.status[ctx.status], "");
  L.push(`| ${P.item} | ${P.value} |`, "|---|---|");
  L.push(`| ${P.stack} | ${ctx.stack} |`);
  L.push(`| ${P.config} | ${ctx.configSource === "generated" ? P.configGenerated(ctx.configRel) : ctx.configSource === "existing" ? P.configExisting(ctx.configRel) : P.configNone} |`);
  if (scan) {
    L.push(`| ${P.isolation} | ${scan.meta.isolation}${scan.meta.image ? ` (\`${scan.meta.image}\`)` : ""} |`);
    L.push(`| ${P.result} | ${P.counts(scan.meta.results.counts)} |`);
  }
  L.push(`| ${P.baseBranch} | \`${cell(ctx.base)}\` |`, "");

  L.push(`## ${P.problems}`, "");
  if (!scan) L.push(P.noScan, "");
  else if (!red.length && !yellow.length) L.push(P.nothingFound, "");
  else {
    for (const f of red) L.push(`- 🔴 ${impact(T, f)}`, `  - ${P.evidence}: \`${cell([f.proof.request, f.proof.status ? `[${f.proof.status}]` : "", f.proof.marker ? `marker ${f.proof.marker}…` : ""].filter(Boolean).join(" "))}\``);
    for (const f of yellow) L.push(`- 🟡 ${P.suspected}: ${cell(f.detail)} (\`${cell(f.proof.request)}\`)`);
    L.push("");
  }

  L.push(`## ${P.fixHead}`, "");
  if (ctx.refused.length) L.push(P.refused, "", ...ctx.refused.map((r) => `- ${cell(r)}`), "");
  else if (ctx.fix?.adopted && ctx.patchFiles.length) {
    L.push(P.fixIncluded(ctx.fix.proposals.filter((p) => p.status === "adopted").length, ctx.patchFiles.map((f) => `\`${f}\``).join(", ")));
    L.push(P.reverified(ctx.fix.before.VULNERABLE, String(ctx.fix.after?.VULNERABLE ?? "?"), ctx.fix.before.SUSPECTED, String(ctx.fix.after?.SUSPECTED ?? "?")), "");
  } else if (ctx.fix?.proposals.length) L.push(P.fixNoneVerified, "");
  else L.push(scan ? P.fixNothing : P.fixNotTried, "");

  const cov = coverage(ctx);
  L.push(`## ${P.coverage(cov.length, cov.filter((r) => r.ran).length)}`, "");
  if (!cov.length) L.push(P.noApis, "");
  else {
    L.push(P.covHeader, "|---|---|---|");
    for (const r of cov) L.push(`| \`${cell(r.route)}\` | ${r.state} | ${cell(r.reason)} |`);
    L.push("");
  }

  const unconfirmed = scan?.meta.unconfirmed ?? Object.entries(ctx.cfg?.provenance ?? {}).filter(([, v]) => v === "ai-draft").map(([k]) => k);
  const human = needsHuman(ctx.init);
  const hints = staticHints(ctx.init);
  L.push(`## ${P.unconfirmedHead}`, "");
  if (!unconfirmed.length && !human.length && !hints.length) L.push(P.none, "");
  else {
    if (unconfirmed.length) {
      L.push(P.unconfirmedIntro(unconfirmed.length), "");
      for (const k of unconfirmed.slice(0, 20)) L.push(`- \`${cell(k)}\``);
      if (unconfirmed.length > 20) L.push(P.more(unconfirmed.length - 20));
      L.push("");
    }
    if (human.length) L.push(P.human, "", ...human.map((n) => `- ${cell(n.topic)}: ${cell(n.message)}`), "");
    if (hints.length) L.push(P.hints, "", ...hints.map((h) => `- ${cell(h)}`), "");
  }

  const envIssues = unverifiedItems(ctx);
  L.push(`## ${P.envHead}`, "");
  if (!envIssues.length) L.push(P.none, "");
  else {
    L.push(P.envIntro, "", P.scopeHeader, "|---|---|");
    for (const u of envIssues) L.push(`| \`${cell(u.scope)}\` | ${cell(u.reason)} |`);
    L.push("");
  }

  L.push(`## ${P.todoHead}`, "");
  if (ctx.configSource === "generated") L.push(P.todoConfirm(ctx.configRel));
  if (red.length) L.push(P.todoFix(red.length, ctx.patchFiles.length > 0));
  if (envIssues.length) L.push(P.todoEnv);
  L.push(P.todoDetail, "");
  L.push(`## ${P.limitsHead}`, "", LIMITS[ctx.lang], "");
  return L.join("\n") + "\n";
}

function renderPrBody(ctx: ReportCtx): string {
  const T = CI_TEXT[ctx.lang];
  const B = T.body;
  const L: string[] = [];
  const red = ctx.scan?.findings.filter((f) => f.verdict === "VULNERABLE") ?? [];
  const cov = coverage(ctx);
  const unverified = unverifiedItems(ctx).map((u) => `${u.scope}: ${u.reason}`);
  L.push(B.title(ctx.short), "", T.status[ctx.status], "");
  if (ctx.scan) L.push(B.line(ctx.scan.meta.results.counts, ctx.scan.meta.isolation, cov.length, cov.filter((r) => r.ran).length), "");
  for (const f of red.slice(0, 5)) L.push(`- 🔴 ${impact(T, f)}`);
  if (red.length > 5) L.push(B.moreRed(red.length - 5));
  if (red.length) L.push("");
  if (ctx.patchFiles.length && ctx.fix) L.push(B.fixIncluded(ctx.fix.before.VULNERABLE, String(ctx.fix.after?.VULNERABLE ?? "?")), "");
  else if (ctx.refused.length) L.push(B.fixRefused, "");
  else L.push(B.noFix, "");
  if (unverified.length) {
    L.push(B.unverified(unverified.length), "");
    for (const u of unverified.slice(0, 8)) L.push(`- ${cell(u)}`);
    if (unverified.length > 8) L.push(B.moreItems(unverified.length - 8));
    L.push("");
  }
  if (ctx.configSource === "generated") L.push(B.draft(ctx.configRel), "");
  L.push(B.fullReport, "", `> ${LIMITS[ctx.lang].replace(/\*\*/g, "")}`);
  return L.join("\n") + "\n";
}
