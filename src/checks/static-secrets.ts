import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import type { Config } from "../config.js";
import type { Finding } from "../types.js";

/**
 * secrets (c): hardcoded secrets in the target's source. Static and heuristic, so findings are SUSPECTED
 * (🟡), never red. The value is never printed in full: first 4 chars + length, and not the source line.
 */

interface Pattern {
  kind: string;
  re: RegExp;
  /** Which capture group is the secret value (0 = whole match). */
  group: number;
  accept?: (value: string) => boolean;
}

const PLACEHOLDER = /^(?:process\.env|\$\{|<|your[_-]|change[_-]?me|example|x{3,}|\*{3,}|test|dummy|placeholder|todo)/i;
const looksReal = (v: string): boolean => !PLACEHOLDER.test(v) && (/\d/.test(v) || v.length >= 16);

export const PATTERNS: Pattern[] = [
  { kind: "API key (sk-...)", re: /\bsk-[A-Za-z0-9_-]{20,}/g, group: 0 },
  { kind: "AWS access key id", re: /\bAKIA[0-9A-Z]{16}\b/g, group: 0 },
  { kind: "private key block", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g, group: 0 },
  {
    kind: "hardcoded credential assignment",
    re: /\b[\w.-]*(?:secret|token|passw(?:or)?d|api[_-]?key)[\w-]*["']?\s*[:=]\s*(["'])([^"'\s]{8,})\1/gi,
    group: 2,
    accept: looksReal,
  },
];

const TEXT_FILE = /(?:\.(?:[cm]?js|[jt]sx?|py|rb|json|ya?ml|toml|properties)|(?:^|\/)\.env(?:\.[\w-]+)?)$/i;
const SKIP_DIRS = new Set(["node_modules", ".git", "out", ".omc", "dist", "build", "coverage"]);
const SKIP_FILES = new Set(["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "composer.lock"]);
const ENV_TEMPLATE = /\.env\.(?:example|sample|template)$/i;
const DEFAULT_EXCLUDES = [/(^|\/)seed[^/]*/i, /\.(?:test|spec)\./i, /(^|\/)(?:fixtures?|examples?|__tests__|tests?)(\/|$)/i, /(^|\/)argos[^/]*\.ya?ml$/i];
const MAX_FILE_BYTES = 1_000_000;

export const maskSecret = (v: string): string => (v.startsWith("-----") ? "-----BEGIN… (private key block)" : `${v.slice(0, 4)}… (${v.length} chars)`);

function files(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      const st = statSync(p);
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(name)) walk(p);
      } else if (st.size <= MAX_FILE_BYTES && !SKIP_FILES.has(name) && !ENV_TEMPLATE.test(name) && TEXT_FILE.test(relative(root, p))) out.push(p);
    }
  };
  walk(root);
  return out.sort();
}

export interface StaticScanResult {
  findings: Finding[];
  scannedFiles: number;
}

export function staticSecrets(cfg: Config, srcDir: string): Finding[] {
  const extra = cfg.secrets.staticExclude;
  const candidates = files(srcDir)
    .map((abs) => ({ abs, rel: relative(srcDir, abs).split("\\").join("/") }))
    .filter(({ rel }) => !DEFAULT_EXCLUDES.some((re) => re.test(rel)) && !extra.some((x) => rel.includes(x)));

  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const { abs, rel } of candidates) {
    const text = readFileSync(abs, "utf8");
    for (const pat of PATTERNS) {
      for (const m of text.matchAll(pat.re)) {
        const value = m[pat.group] ?? m[0];
        if (pat.accept && !pat.accept(value)) continue;
        const line = text.slice(0, m.index).split("\n").length;
        const key = `${rel}:${line}:${pat.kind}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({
          check: "secrets",
          resourceId: "(source)",
          persona: "(static)",
          verdict: "SUSPECTED",
          proof: { request: `${rel}:${line}`, note: maskSecret(value) },
          detail: `possible hardcoded secret (${pat.kind}) at ${rel}:${line}: ${maskSecret(value)}`,
        });
      }
    }
  }
  if (!out.length) {
    out.push({
      check: "secrets",
      resourceId: "(source)",
      persona: "(static)",
      verdict: candidates.length ? "OK" : "SKIPPED",
      proof: { request: "-" },
      detail: candidates.length
        ? `no hardcoded secret pattern in ${candidates.length} source files`
        : "no source files to scan (everything excluded or none found)",
    });
  }
  return out;
}
