import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { homedir } from "node:os";
import { join } from "node:path";
import { LIMITS, ReportError, loadScan, renderReport, renderSummary, writeReport } from "../src/report.js";
import type { FixReport } from "../src/fix/index.js";

const EX = "examples/out";
const sha = (p: string) => createHash("sha256").update(readFileSync(p, "utf8")).digest("hex");
const scan = () => loadScan({ scanDir: EX });
const KO = { lang: "ko" as const };
const copy = (): string => {
  const d = mkdtempSync(join(tmpdir(), "argos-rep-"));
  cpSync(EX, d, { recursive: true });
  return d;
};

test("report has the evidence header, scope, summary, matrix, per-check results and the limits statement", () => {
  const md = renderReport(scan(), KO);
  for (const h of ["## 증빙 헤더", "## 요약", "## 🔴 취약 항목", "## 접근 매트릭스", "## 점검별 결과", "## 한계"]) assert.ok(md.includes(h), h);
  assert.match(md, /\| 대상 \| vendor-platform \|/);
  assert.match(md, /\| 점검 \| bola, unauth, sqli, secrets \|/);
  assert.match(md, /시험한 범위.*시험하지 않았다/);
  assert.match(md, /`GET \/api\/datasets\?search=`/);
  assert.ok(md.includes(LIMITS.ko), "V3 limits wording is mandatory");
  assert.match(md, /보증하거나 규정 준수를 증명하지 않는다/);
});

test("header hashes match the files recomputed from disk (acceptance criterion 3)", () => {
  const md = renderReport(scan(), KO);
  for (const [label, file] of [["matrix.json", "matrix.json"], ["findings.json", "findings.json"]] as const) {
    const m = new RegExp(`\\| ${label} \\| SHA-256 \`([0-9a-f]{16})…\``).exec(md);
    assert.ok(m, label);
    assert.equal(m![1], sha(join(EX, file)).slice(0, 16), label);
  }
  assert.match(md, /matrix\.json ✅ 일치 · findings\.json ✅ 일치/);
});

test("a file changed after the scan is rejected, not reported", () => {
  const d = copy();
  const f = JSON.parse(readFileSync(join(d, "findings.json"), "utf8"));
  f[0].verdict = "OK";
  writeFileSync(join(d, "findings.json"), JSON.stringify(f, null, 2) + "\n");
  assert.throws(() => loadScan({ scanDir: d }), (e: Error) => e instanceof ReportError && /findings\.json does not match the hash/.test(e.message));
});

test("missing or invalid inputs give clear errors", () => {
  assert.throws(() => loadScan({ scanDir: "/nonexistent-dir" }), /scan-meta\.json not found/);
  const d = copy();
  writeFileSync(join(d, "matrix.json"), "{ nope");
  assert.throws(() => loadScan({ scanDir: d }), /matrix\.json is not valid JSON/);
  const d2 = copy();
  const m = JSON.parse(readFileSync(join(d2, "scan-meta.json"), "utf8"));
  delete m.tool;
  writeFileSync(join(d2, "scan-meta.json"), JSON.stringify(m));
  assert.throws(() => loadScan({ scanDir: d2 }), /scan-meta\.json: tool/);
});

test("the report carries no full marker, secret, canary, or host path", () => {
  const md = renderReport(scan());
  assert.ok(!/ARGOS_SECRET_\d+_[0-9a-f]{6}/.test(md));
  assert.ok(!/ARGOS_ENV_[A-Z0-9_]+_[0-9a-f]{6}/.test(md));
  assert.ok(!/ARGOS_[A-Za-z0-9-]+_v\d_[0-9a-f]{6}/.test(md));
  assert.ok(!md.includes(homedir()));
});

test("isolation is stated: process warns, container names the image", () => {
  const s = scan();
  assert.match(renderReport(s, KO), /process — \*\*격리 없음/);
  const boxed = { ...s, meta: { ...s.meta, isolation: "container" as const, image: "node:25-slim" } };
  const md = renderReport(boxed, KO);
  assert.match(md, /container \(`node:25-slim`: 네트워크 없음, 읽기 전용 루트, 비root\)/);
  assert.ok(!md.includes("이 실행은 격리 없이"));
});

const FIX: FixReport = {
  tried: true, adopted: true, applied: false, reasons: ["x"],
  before: { VULNERABLE: 25, SUSPECTED: 3, OK: 38, SKIPPED: 0 },
  after: { VULNERABLE: 13, SUSPECTED: 0, OK: 45, SKIPPED: 0 },
  proposals: [
    { kind: "select-star", status: "adopted", reasons: [], addresses: [], title: "limit columns", guidance: "g", edits: [{ file: "app.mjs", line: 73, before: "SELECT * FROM vendors", after: "SELECT id, name FROM vendors" }] },
    { kind: "owner-check", status: "rejected", reasons: ["not resolved: bola|export|v1|"], addresses: [], title: "scope export", guidance: "needs auth", edits: [] },
    { kind: "guidance", status: "guidance", reasons: [], addresses: [], title: "sqli on dataset-search", guidance: "bind the parameter", edits: [] },
  ],
};

test("fix section lists adopted patches with the diff, rejections with reasons, guidance", () => {
  const md = renderReport({ ...scan(), fix: FIX }, KO);
  assert.match(md, /## 수정과 재검증/);
  assert.match(md, /✅ 채택: limit columns/);
  assert.match(md, /`SELECT \* FROM vendors`/);
  assert.match(md, /⚠️ 거부: scope export/);
  assert.match(md, /사유: not resolved/);
  assert.match(md, /📝 지침: sqli on dataset-search/);
  assert.match(md, /🔴 25 🟡 3 → 채택한 패치를 모두 적용한 뒤 🔴 13 🟡 0/);
});

test("PR summary is short, lists remaining reds, and keeps the limits statement", () => {
  const md = renderSummary({ ...scan(), fix: FIX }, { reportPath: "report.md", ...KO });
  assert.ok(md.split("\n").length < 40, "bounded length");
  assert.match(md, /검증된 수정 1건/);
  assert.match(md, /남은 🔴 25건/);
  assert.match(md, /… 외 15건/);
  assert.match(md, /수동 조치 필요.*2건/);
  assert.match(md, /보증하거나 규정 준수를 증명하지 않는다/);
});

test("writeReport writes the file", () => {
  const out = join(mkdtempSync(join(tmpdir(), "argos-rep-")), "nested", "report.md");
  const r = writeReport({ scanDir: EX, outPath: out });
  assert.equal(readFileSync(out, "utf8"), r.markdown);
});

test("English is the default; config report.lang (recorded in scan-meta) and --lang choose the language", () => {
  const s = scan();
  assert.equal(s.meta.reportLang, "en", "argos scan records config report.lang (default en)");
  const legacy = { ...s, meta: { ...s.meta, reportLang: undefined } };
  assert.match(renderReport(legacy), /## Evidence header/, "scans from before the option read as English");
  const en = renderReport({ ...s, fix: FIX });
  for (const h of ["## Evidence header", "## Summary", "## 🔴 Vulnerable", "## Access matrix", "## Results by check", "## Fix and re-verification", "## Limits"]) assert.ok(en.includes(h), h);
  assert.ok(en.includes(LIMITS.en));
  assert.match(en, /matrix\.json ✅ match · findings\.json ✅ match/);
  assert.match(en, /✅ adopted: limit columns/);
  assert.doesNotMatch(en, /[가-힣]/, "no Korean left in the English report");
  const summary = renderSummary({ ...s, fix: FIX }, { reportPath: "report.md" });
  assert.match(summary, /\*\*1 verified fix\*\*/);
  assert.match(summary, /\*\*25 🔴 remaining\*\*/);
  assert.doesNotMatch(summary, /[가-힣]/);

  const ko = { ...s, meta: { ...s.meta, reportLang: "ko" as const } };
  assert.match(renderReport(ko), /## 증빙 헤더/, "config report.lang: ko");
  assert.match(renderReport(ko, { lang: "en" }), /## Evidence header/, "--lang overrides the config");
});
