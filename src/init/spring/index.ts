import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { parse } from "yaml";
import { loadConfig, parseConfig } from "../../config.js";
import type { InitOptions, InitResult } from "../index.js";
import type { Verification } from "../verify.js";
import { buildSpringDraft, type SpringDraft } from "./draft.js";
import { renderSpringConfig } from "./emit.js";
import { scanSpring, type SpringFacts } from "./facts.js";
import { anthropicClient, linkWithLlm, type Egress } from "./llm.js";
import { renderSpringReport } from "./report.js";
import { verifySpringDraft } from "./verify.js";

/** Keep every field a person marked "confirmed" in the previous config (never weakened by a new draft). */
export function preserveConfirmed(next: Record<string, any>, prev: Record<string, any>): string[] {
  const preserved: string[] = [];
  const prov = (prev.provenance ?? {}) as Record<string, string>;
  next.provenance ??= {};
  for (const [key, v] of Object.entries(prov)) {
    if (v !== "confirmed") continue;
    const parts = key.split(".");
    if (parts[0] === "resources" && parts[1]) {
      const prevRes = (prev.resources ?? []).find((r: any) => r.id === parts[1]);
      if (!prevRes) continue;
      const field = parts.slice(2).join(".");
      const nextRes = (next.resources ?? []).find((r: any) => r.id === parts[1]);
      if (!nextRes) next.resources.push(structuredClone(prevRes));
      else if (!field) Object.assign(nextRes, structuredClone(prevRes));
      else if (prevRes[field] === undefined) delete nextRes[field];
      else nextRes[field] = structuredClone(prevRes[field]);
    } else {
      let src: any = prev;
      let dst: any = next;
      for (const k of parts.slice(0, -1)) {
        src = src?.[k];
        dst[k] ??= {};
        dst = dst[k];
      }
      const last = parts.at(-1)!;
      if (src?.[last] === undefined) continue;
      dst[last] = structuredClone(src[last]);
    }
    next.provenance[key] = "confirmed";
    preserved.push(key);
  }
  return preserved;
}

export async function runSpringInit(opts: InitOptions, dir: string, configPath: string, log: (l: string) => void, t0: number): Promise<InitResult> {
  log(`[1/4] scanning ${dir} (Spring Boot)`);
  const facts: SpringFacts = scanSpring(dir)!;
  const llmData = opts.llmData ?? "none";
  const cwd = relative(dirname(configPath), dir) || ".";
  let draft: SpringDraft = buildSpringDraft(facts, { cwd, llmData });

  log("[2/4] drafting the config");
  let egress: Egress = { llm: false, sent: [], masked: 0, note: "no source file was sent anywhere: this draft came from static analysis only" };
  if (draft.uncertain.length) {
    const key = process.env.ANTHROPIC_API_KEY;
    const client = opts.llmClient ?? (key ? anthropicClient(key) : undefined);
    if (llmData !== "files") egress.note += ` (${draft.uncertain.length} uncertain link(s) left for a person: --llm-data none)`;
    else if (!client) egress.note += ` (${draft.uncertain.length} uncertain link(s) left for a person: ANTHROPIC_API_KEY is not set)`;
    else {
      try {
        const r = await linkWithLlm(facts, draft.uncertain, client);
        egress = r.egress;
        if (r.links.length) draft = buildSpringDraft(facts, { cwd, llmData, links: r.links });
      } catch (e) {
        egress.note = `LLM call failed (${(e as Error).message}): the deterministic draft is used`;
      }
    }
  }

  const reportDir = resolve(opts.reportDir ?? "out");
  mkdirSync(reportDir, { recursive: true });
  const reportPath = join(reportDir, "init-report.md");
  const egressPath = join(reportDir, "init-egress.json");
  const finish = (r: Omit<InitResult, "reportPath" | "egressPath" | "t1Seconds" | "k" | "adapter" | "draft" | "facts">, extra: { notVerifiedReason?: string; preserved?: string[] }): InitResult => {
    const t1Seconds = Math.round(((Date.now() - t0) / 1000) * 10) / 10;
    const k = draft.needsHuman.length + draft.unsupported.length;
    writeFileSync(
      reportPath,
      renderSpringReport({ facts, draft, verification: r.verification, notVerifiedReason: extra.notVerifiedReason, configPath: r.configWritten ? r.configPath : undefined, t1Seconds, k, egress, preserved: extra.preserved ?? [] }),
    );
    writeFileSync(egressPath, JSON.stringify(egress, null, 2) + "\n");
    const result: InitResult = { ...r, reportPath, egressPath, t1Seconds, k, adapter: "spring-boot", draft, facts };
    log("");
    for (const f of draft.found) log(`  found: ${f}`);
    for (const u of draft.unsupported) log(`  unsupported: ${u}`);
    for (const f of draft.likelyFindings) log(`  likely finding: ${f.route}: ${f.what}`);
    log(r.verification?.ok ? `  verified: ${r.verification.loggedIn.length} personas used their own data` : `  NOT verified (미검증): ${r.verification?.problems.join("; ") ?? extra.notVerifiedReason ?? ""}`);
    log(`  T1 ${t1Seconds}s · K ${k}`);
    if (r.configWritten) log(`  config: ${r.configPath}`);
    log(`  report: ${reportPath}`);
    return result;
  };

  let blocker = draft.blocker;
  if (!blocker) {
    try {
      parseConfig(draft.config);
    } catch (e) {
      blocker = `the drafted config does not satisfy the schema: ${(e as Error).message}`;
    }
  }
  if (blocker) {
    log(`no config written: ${blocker}`);
    return finish({ configPath, configWritten: false, exitCode: 1 }, { notVerifiedReason: `설정을 만들지 못함: ${blocker}` });
  }

  let preserved: string[] = [];
  if (existsSync(configPath)) {
    try {
      const prev = parse(readFileSync(configPath, "utf8"));
      if (prev && typeof prev === "object") preserved = preserveConfirmed(draft.config, prev as Record<string, any>);
      if (preserved.length) parseConfig(draft.config);
    } catch (e) {
      log(`warning: the existing config could not be merged (${(e as Error).message}); confirmed fields were NOT carried over`);
      preserved = [];
    }
  }

  mkdirSync(dirname(configPath), { recursive: true });
  writeFileSync(configPath, renderSpringConfig(draft));
  const reloaded = loadConfig(configPath);
  if (JSON.stringify(reloaded) !== JSON.stringify(parseConfig(draft.config))) throw new Error("internal error: the written YAML does not round-trip to the draft");
  log(`wrote ${configPath}`);

  let verification: Verification | undefined;
  let notVerifiedReason: string | undefined;
  if (opts.verify === false) notVerifiedReason = "검증을 건너뜀 (--no-verify)";
  else if (facts.unsupported.length) notVerifiedReason = `미지원 구성 ${facts.unsupported.length}건이 있어 실행 검증을 하지 않음 (아래 '미지원' 참고)`;
  else {
    log("[3/4] verifying: isolated build, PostgreSQL, test issuer, log in as each persona");
    verification = await (opts.springVerifier ?? verifySpringDraft)(configPath, { ...(opts.timeoutMs ? { timeoutMs: opts.timeoutMs } : {}) });
  }
  log("[4/4] writing the report");
  return finish({ configPath, configWritten: true, ...(verification ? { verification } : {}), exitCode: verification?.ok || opts.verify === false ? 0 : 1 }, { notVerifiedReason, preserved });
}
