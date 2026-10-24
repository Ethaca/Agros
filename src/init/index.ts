import { existsSync, mkdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { ConfigError, loadConfig, parseConfig } from "../config.js";
import type { Isolation } from "../runner.js";
import { buildDraft, type Draft } from "./draft.js";
import { renderConfig } from "./emit.js";
import { scanRepo, type RepoFacts } from "./facts.js";
import { verifyDraft, type Verification } from "./verify.js";

export class InitError extends Error {}

export interface InitOptions {
  /** Repository (the directory holding package.json). */
  dir: string;
  /** Where to write the config. Default: <dir>/argos.config.yaml */
  out?: string;
  /** Where to write init-report.md and init-egress.json. Default: ./out */
  reportDir?: string;
  /** Default: container (the customer's code is run to verify the draft). */
  isolation?: Isolation;
  llmData?: "files" | "none";
  verify?: boolean;
  force?: boolean;
  start?: string;
  timeoutMs?: number;
  log?: (line: string) => void;
}

export interface InitResult {
  configPath: string;
  reportPath: string;
  egressPath: string;
  draft: Draft;
  facts: RepoFacts;
  verification?: Verification;
  /** Seconds from start to a config whose boot and login were verified (or to the written draft with --no-verify). */
  t1Seconds: number;
  /** Items a person still has to confirm or fill in. */
  k: number;
  /** 0 = config written and verified (or --no-verify); 1 = written but verification failed. (Thrown errors exit 1 too.) */
  exitCode: 0 | 1;
}

export async function runInit(opts: InitOptions): Promise<InitResult> {
  const log = opts.log ?? ((l: string) => console.log(l));
  const t0 = Date.now();
  const dir = resolve(opts.dir);
  if (!existsSync(dir) || !statSync(dir).isDirectory()) throw new InitError(`${opts.dir} is not a directory`);
  const configPath = resolve(opts.out ?? join(dir, "argos.config.yaml"));
  if (existsSync(configPath) && !opts.force) {
    throw new InitError(`${configPath} already exists: it may hold rules a person confirmed. Use --force to overwrite.`);
  }
  const isolation = opts.isolation ?? "container";

  log(`[1/4] scanning ${dir}`);
  const facts = scanRepo(dir);
  log(`[2/4] drafting the config`);
  const draft = buildDraft(facts, { cwd: relative(dirname(configPath), dir) || ".", isolation, llmData: opts.llmData ?? "none", start: opts.start });
  if (draft.blocker) throw new InitError(draft.blocker);
  try {
    parseConfig(draft.config);
  } catch (e) {
    throw new InitError(`internal error: the drafted config does not satisfy the schema: ${(e as Error).message}`);
  }

  mkdirSync(dirname(configPath), { recursive: true });
  writeFileSync(configPath, renderConfig(draft));
  try {
    const reloaded = loadConfig(configPath);
    if (JSON.stringify(reloaded) !== JSON.stringify(parseConfig(draft.config))) throw new ConfigError("the written YAML does not round-trip to the draft");
  } catch (e) {
    throw new InitError(`internal error: the written config is wrong: ${(e as Error).message}`);
  }
  log(`wrote ${configPath}`);

  let verification: Verification | undefined;
  if (opts.verify !== false) {
    log(`[3/4] verifying the draft: start the app (${isolation}), log in as each persona`);
    verification = await verifyDraft(configPath, { isolation, timeoutMs: opts.timeoutMs });
  } else log("[3/4] verification skipped (--no-verify)");

  const t1Seconds = Math.round(((Date.now() - t0) / 1000) * 10) / 10;
  const k = draft.needsHuman.length + draft.unsupported.length;

  log("[4/4] writing the report");
  const reportDir = resolve(opts.reportDir ?? "out");
  mkdirSync(reportDir, { recursive: true });
  const reportPath = join(reportDir, "init-report.md");
  const egressPath = join(reportDir, "init-egress.json");
  writeFileSync(reportPath, renderInitReport({ facts, draft, verification, t1Seconds, k, configPath, isolation }));
  writeFileSync(egressPath, JSON.stringify({ llm: false, sent: [], masked: 0, note: "no source file was sent anywhere: this draft came from static rules only" }, null, 2) + "\n");

  const result: InitResult = { configPath, reportPath, egressPath, draft, facts, verification, t1Seconds, k, exitCode: verification && !verification.ok ? 1 : 0 };
  summarize(result, log);
  return result;
}

function summarize(r: InitResult, log: (l: string) => void): void {
  log("");
  for (const f of r.draft.found) log(`  found: ${f}`);
  if (r.verification) {
    log(r.verification.ok ? `  verified: app starts, ${r.verification.loggedIn.length} personas can read their own data` : `  NOT verified:`);
    if (!r.verification.ok) for (const p of r.verification.problems) log(`    - ${p}`);
    if (r.verification.preview) log(`  preview scan of the draft (rests on unconfirmed rules, not a verdict): 🔴 ${r.verification.preview.VULNERABLE} 🟡 ${r.verification.preview.SUSPECTED} 🟢 ${r.verification.preview.OK} ⚪ ${r.verification.preview.SKIPPED}`);
  }
  for (const u of r.draft.unsupported) log(`  unsupported: ${u}`);
  log(`  T1 ${r.t1Seconds}s · K ${r.k} item(s) for a person to confirm or fill`);
  log(`  config: ${r.configPath}`);
  log(`  report: ${r.reportPath}`);
}

function renderInitReport(o: { facts: RepoFacts; draft: Draft; verification?: Verification; t1Seconds: number; k: number; configPath: string; isolation: Isolation }): string {
  const { draft, verification: v } = o;
  const L: string[] = [];
  L.push("# argos init: 결과", "");
  L.push("| 항목 | 값 |", "|---|---|", `| 설정 파일 | \`${o.configPath.split("/").slice(-2).join("/")}\` |`, `| T1 (설정 초안 + 검증까지) | ${o.t1Seconds}초 |`, `| K (사람이 확인·입력할 항목) | ${o.k} |`, `| 실행 격리(검증) | ${o.isolation} |`, `| LLM 사용 | 아니오 (정적 규칙만, 소스 전송 없음) |`, "");
  L.push("## 검증", "");
  if (!v) L.push("건너뜀(`--no-verify`). 초안이 실제로 뜨고 로그인되는지는 확인되지 않았다.", "");
  else if (v.ok) L.push(`✅ 앱이 기동했고 ${v.loggedIn.length}개 페르소나(${v.loggedIn.join(", ")})가 자기 데이터를 읽었다.`, "");
  else {
    L.push(v.ran ? "❌ 검증 실패" : "⚪ 검증을 실행하지 못함", "");
    for (const p of v.problems) L.push(`- ${p}`);
    L.push("");
  }
  if (v?.preview) L.push(`미리보기 스캔: 🔴 ${v.preview.VULNERABLE} 🟡 ${v.preview.SUSPECTED} 🟢 ${v.preview.OK} ⚪ ${v.preview.SKIPPED}. **이 숫자는 확인되지 않은 규칙을 기준으로 한 것이라 판정이 아니다.**`, "");
  L.push("## 찾은 것", "", ...draft.found.map((f) => `- ${f}`), "");
  L.push(`## 사람이 확인할 것 (${draft.needsHuman.length})`, "");
  if (!draft.needsHuman.length) L.push("없음.", "");
  else {
    L.push("| 주제 | 내용 | 위치 |", "|---|---|---|");
    for (const n of draft.needsHuman) L.push(`| ${n.topic} | ${n.message.replace(/\|/g, "\\|")} | ${n.where ? `\`${n.where}\`` : ""} |`);
    L.push("");
  }
  if (draft.unsupported.length) L.push("## 아직 지원하지 않는 것", "", ...draft.unsupported.map((u) => `- ${u}`), "");
  L.push(`## 시험 범위: 소스의 라우트 ${o.facts.routes.length}개 중 ${draft.config.resources.length}개를 설정에 넣음`, "");
  if (draft.untested.length) {
    L.push("설정에 넣지 않은 경로(시험하지 않음):", "");
    for (const u of draft.untested) L.push(`- \`${u.route}\`: ${u.reason}`);
    L.push("");
  }
  L.push("## 이 초안의 한계", "", "- 기대 규칙(`resources[].expect`)은 코드에서 읽은 것이 아니라 **보수적 기본값**이다. 사람이 확인하기 전까지 `provenance`에서 `ai-draft`로 남고 보고서가 \"미확인\"으로 표시한다.", "- 정적 분석은 라우트가 코드에 `app.get(\"/경로\", …)` 형태로 있을 때만 찾는다. 찾지 못한 경로는 시험되지 않는다.", "");
  return L.join("\n") + "\n";
}
