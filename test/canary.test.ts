import { after, test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, statSync, rmSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { issue } from "../src/canary/issue.js";
import { loadRegistry, sha256, writeJson } from "../src/canary/registry.js";
import { derive, keyBytes, token } from "../src/canary/token.js";
import { normalize, normalizedWithOffsets } from "../src/canary/normalize.js";
import { scan } from "../src/canary/scan.js";
import { probe } from "../src/canary/probe.js";
import { mockClient, startMockServer } from "../src/canary/mock-model.js";
import { httpModel } from "../src/canary/model-client.js";
import { adjusted, matchLength, nullProbability } from "../src/canary/stats.js";
import { report, LIMITS } from "../src/canary/report.js";
import { stress } from "../src/canary/stress.js";
import { generateLlmRows, makePrompt, overlapsOriginal } from "../src/canary/llm.js";
import { Registry, Row, type LlmUsage } from "../src/canary/types.js";

const scratch = mkdtempSync(join(tmpdir(), "argos-canary-test-"));
const previousKey = process.env.ARGOS_CANARY_KEY;
const previousApiKey = process.env.ANTHROPIC_API_KEY;
process.env.ARGOS_CANARY_KEY = "0123456789abcdef0123456789abcdef";
delete process.env.ANTHROPIC_API_KEY;
after(() => {
  if (previousKey === undefined) delete process.env.ARGOS_CANARY_KEY; else process.env.ARGOS_CANARY_KEY = previousKey;
  if (previousApiKey === undefined) delete process.env.ANTHROPIC_API_KEY; else process.env.ANTHROPIC_API_KEY = previousApiKey;
  rmSync(scratch, { recursive: true, force: true });
});
const input = resolve("src/canary/fixtures/eval.jsonl");
const out = join(scratch, "issued");
const { registry, registryPath } = await issue({ input, recipients: ["vendorA", "vendorB", "vendorC"], out });
const { registrySha256 } = loadRegistry(registryPath);
const b = registry.recipients.vendorB!;
const copy = readFileSync(join(out, b.copy), "utf8");
const scanText = (text: string) => scan(text, registry, registrySha256);
const probeWith = (client: { complete(prefix: string): Promise<string> }, controls?: number) => probe({ registry, registrySha256, client, model: "test", modelKind: "mock", controls });
const all = [...Object.values(registry.recipients).flatMap((r) => r.canaries), ...registry.controls];

test("issue: deterministic copies, preserved original rows, unique tokens/stems and unissued controls", async () => {
  const second = join(scratch, "second");
  await issue({ input, recipients: ["vendorA", "vendorB", "vendorC"], out: second });
  const originals = readFileSync(input, "utf8").trimEnd().split("\n");
  const questions = new Set<string>();
  for (const [name, info] of Object.entries(registry.recipients)) {
    const bytes = readFileSync(join(out, info.copy));
    assert.deepEqual(bytes, readFileSync(join(second, info.copy)));
    assert.equal(sha256(bytes), info.sha256);
    assert.equal(statSync(join(out, info.copy)).mode & 0o777, 0o600);
    const lines = bytes.toString("utf8").trimEnd().split("\n");
    const ids = new Set(info.canaries.map((c) => c.id));
    assert.deepEqual(lines.filter((l) => !ids.has((JSON.parse(l) as Row).id)), originals);
    for (const c of info.canaries) {
      const row = Row.parse(JSON.parse(lines[c.line! - 1]!));
      const stem = row.question.replace(c.token, "{{MODEL}}");
      assert.ok(!questions.has(stem)); questions.add(stem);
      assert.equal(row.question.slice(0, row.question.indexOf(c.token)), c.prefix);
      assert.equal((bytes.toString().match(new RegExp(c.token, "g")) ?? []).length, 1);
    }
    const otherTokens = Object.entries(registry.recipients).filter(([n]) => n !== name).flatMap(([, r]) => r.canaries).concat(registry.controls);
    assert.ok(otherTokens.every((c) => !bytes.toString().includes(c.token)));
  }
  assert.equal(statSync(out).mode & 0o777, 0o700);
  assert.equal(statSync(registryPath).mode & 0o777, 0o600);
  assert.equal(new Set(all.map((c) => c.token)).size, all.length);
  Registry.parse(registry);
});

test("issue: bad schema, duplicate id, recipient paths/reserved/duplicates, counts and overwrite are rejected", async () => {
  for (const recipients of [["../escape"], ["vendorA", "VENDORA"], ["controls"], ["registry"], []])
    await assert.rejects(issue({ input, recipients, out: join(scratch, "bad") }));
  for (const canaries of [0, -1, 1.2, NaN, 1001]) await assert.rejects(issue({ input, recipients: ["vendorA"], out: join(scratch, "bad"), canaries }));
  await assert.rejects(issue({ input, recipients: ["vendorA"], out }), /already exists/);
  const invalid = join(scratch, "invalid.jsonl");
  writeFileSync(invalid, '{"id":"1","question":"q","choices":["a","b"],"answer":"c"}\n');
  await assert.rejects(issue({ input: invalid, recipients: ["vendorA"], out: join(scratch, "bad") }), /invalid dataset/);
  writeFileSync(invalid, readFileSync(input, "utf8").split("\n")[0]! + "\n" + readFileSync(input, "utf8").split("\n")[0]!);
  await assert.rejects(issue({ input: invalid, recipients: ["vendorA"], out: join(scratch, "bad") }), /duplicate/);
  assert.throws(() => keyBytes("not-a-key"));
  assert.throws(() => keyBytes("ab".repeat(15)));
  assert.notDeepEqual(derive(keyBytes(), "a|b", "c"), derive(keyBytes(), "a", "b|c"));
  assert.notEqual(token(keyBytes(), "d", "v", 0), token(keyBytes(), "d", "v", 0, true));
});

test("registry validates invariants and optionally detects wrong key; readers need no key", () => {
  const original = process.env.ARGOS_CANARY_KEY;
  process.env.ARGOS_CANARY_KEY = "ff".repeat(16);
  assert.throws(() => loadRegistry(registryPath), /does not match/);
  delete process.env.ARGOS_CANARY_KEY;
  assert.equal(loadRegistry(registryPath).registry.datasetId, registry.datasetId);
  process.env.ARGOS_CANARY_KEY = original;
  const invalid = structuredClone(registry);
  invalid.controls[0]!.token = b.canaries[0]!.token;
  assert.throws(() => Registry.parse(invalid));
});

test("scan: whole and partial copies; absence, rewrite and repeated tokens", () => {
  const full = scanText(copy);
  assert.equal(full.verdict, "IDENTIFIED");
  assert.equal(full.recipients[0]!.recipient, "vendorB");
  assert.equal(full.recipients[0]!.matches, 5);
  assert.ok(full.recipients[0]!.evidence.every((e) => !e.warnings.length));
  const line = copy.split("\n")[b.canaries[0]!.line! - 1]!;
  const partial = scanText(line);
  assert.equal(partial.verdict, "IDENTIFIED");
  assert.equal(partial.recipients[0]!.evidence[0]!.leakedLine, 1);
  assert.equal(partial.recipients[0]!.evidence[0]!.sourceLine, b.canaries[0]!.line);
  assert.deepEqual(partial.recipients[0]!.evidence[0]!.warnings, []);
  assert.equal(scanText(readFileSync(input, "utf8")).verdict, "UNIDENTIFIED");
  assert.equal(scanText("Unrelated sample").verdict, "UNIDENTIFIED");
  assert.equal(scanText(copy.replace(/[a-z]{2}-[a-f0-9]{12}/g, "the product")).verdict, "UNIDENTIFIED");
  assert.equal(scanText(`${line}\n${line}`).recipients[0]!.matches, 1);
});

test("scan: normalization, original offsets, line boundaries, mixed sources and context warnings", () => {
  const c = b.canaries[0]!;
  const variant = [...c.token.toUpperCase()].map((s) => /[A-Z0-9]/.test(s) ? String.fromCharCode(s.charCodeAt(0) + 0xfee0) : " ").join("\u200b");
  const result = scanText("xxx " + variant);
  assert.equal(result.verdict, "IDENTIFIED");
  assert.equal(result.recipients[0]!.evidence[0]!.offset, 4);
  assert.deepEqual(result.recipients[0]!.evidence[0]!.warnings, ["CONTEXT_MISMATCH"]);
  assert.equal(scanText(c.token.slice(0, 5) + "\n" + c.token.slice(5)).verdict, "UNIDENTIFIED");
  assert.equal(scanText(copy + registry.recipients.vendorC!.canaries[0]!.token).verdict, "MIXED_SOURCES");
  assert.equal(normalize(variant), normalize(c.token));
  assert.deepEqual(normalizedWithOffsets("x ﬁ Ａ"), { text: "xfia", offsets: [0, 2, 2, 4] });
  assert.notEqual(normalize("а"), normalize("a")); // Cyrillic is explicitly unsupported.
});

test("probe: memorize, clean, controls, boundary conditions and global correction", async () => {
  const memorized = await probeWith(mockClient({ registry, recipient: "vendorB", recall: 1 }));
  assert.equal(memorized.status, "VALID");
  assert.equal(memorized.recipients.find((r) => r.recipient === "vendorB")!.verdict, "SUSPECTED");
  assert.ok(memorized.recipients.filter((r) => r.recipient !== "vendorB").every((r) => r.verdict === "NO_EVIDENCE"));
  const clean = await probeWith(mockClient({ seed: 7 }));
  assert.equal(clean.status, "VALID"); assert.ok(clean.recipients.every((r) => r.verdict === "NO_EVIDENCE"));
  const answers = new Map(all.map((c) => [c.prefix, c.token]));
  const invalid = await probeWith({ complete: async (prefix) => answers.get(prefix)! });
  assert.equal(invalid.status, "INVALID_CONTROLS"); assert.ok(invalid.recipients.every((r) => r.verdict === null));
  for (const matched of [9, 10]) {
    const r = await probeWith({ complete: async (prefix) => {
      const c = b.canaries.find((c) => c.prefix === prefix);
      return c ? normalize(c.token).slice(0, matched) : "";
    } });
    assert.equal(r.recipients.find((r) => r.recipient === "vendorB")!.verdict, matched === 10 ? "SUSPECTED" : "NO_EVIDENCE");
    assert.equal(r.comparisons, 15);
    const row = r.recipients.find((r) => r.recipient === "vendorB")!;
    assert.equal(row.pAdjustedGlobal, adjusted(nullProbability(matched), 15));
  }
  for (const matched of [3, 4]) {
    const r = await probeWith({ complete: async (prefix) => normalize(answers.get(prefix)!).slice(0, registry.controls.some((c) => c.prefix === prefix) ? matched : 14) });
    assert.equal(r.status, matched === 4 ? "INVALID_CONTROLS" : "VALID");
  }
  const incomplete = await probeWith({ complete: async () => { throw new Error("SECRET_RESPONSE"); } });
  assert.equal(incomplete.status, "INCOMPLETE");
  assert.ok(incomplete.recipients.every((r) => r.verdict === null));
  assert.ok(!JSON.stringify(incomplete).includes("SECRET_RESPONSE"));
  await assert.rejects(probeWith(mockClient({}), 0));
  assert.equal(matchLength("QK-abcdef123456", "qk-abcdef123456"), 14);
});

test("HTTP adapter and mock server support clean/memorize without sending tokens", async () => {
  const { server, url } = await startMockServer(mockClient({ registry, recipient: "vendorB", recall: 1 }));
  try {
    const result = await probeWith(httpModel(url));
    assert.equal(result.recipients.find((r) => r.recipient === "vendorB")!.verdict, "SUSPECTED");
    assert.equal((await fetch(url + "/health")).status, 200);
    assert.equal((await fetch(url + "/complete", { method: "POST", body: "bad" })).status, 400);
    assert.throws(() => httpModel("file:///etc/passwd"));
    assert.throws(() => httpModel("https://user:pass@example.com"));
  } finally { server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve())); }
});

test("HTTP adapter rejects invalid/oversized responses and timeout", async () => {
  const server = createServer((req, res) => {
    if (req.url === "/slow/complete") return;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(req.url === "/big/complete" ? "x".repeat(1_048_577) : '{"completion":42}');
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address(); assert.ok(address && typeof address !== "string");
  const url = `http://127.0.0.1:${address.port}`;
  try {
    await assert.rejects(httpModel(url).complete("prefix"));
    await assert.rejects(httpModel(url + "/big").complete("prefix"));
    await assert.rejects(httpModel(url + "/slow", 20).complete("prefix"));
  } finally { server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve())); }
});

test("stress: attacks expose weaknesses, mixed sources detected, results reproducible", () => {
  const result = stress(registryPath, 3, 7);
  assert.deepEqual(result, stress(registryPath, 3, 7));
  for (const id of ["S1", "S4", "S9"]) assert.equal(result.attacks.find((a) => a.id === id)!.rate, 1);
  for (const id of ["S3", "S5", "S7"]) assert.equal(result.attacks.find((a) => a.id === id)!.rate, 0);
  assert.ok(result.attacks.filter((a) => a.executed).every((a) => a.trials === a.identified + a.mixed + a.unidentified + a.misattributed));
  assert.ok(result.attacks.filter((a) => ["S6", "S8"].includes(a.id)).every((a) => !a.executed && a.rate === null));
});

test("report: file hashes, result binding, limits, mock labels and no secret tokens", async () => {
  const scanPath = join(scratch, "scan.json"), probePath = join(scratch, "probe.json"), stressPath = join(scratch, "stress.json");
  writeJson(scanPath, scanText(copy));
  writeJson(probePath, await probeWith(mockClient({ registry, recipient: "vendorB", recall: 1 })));
  writeJson(stressPath, stress(registryPath, 1));
  const path = join(scratch, "report.md");
  const md = report({ registry: registryPath, scan: scanPath, probe: probePath, stress: stressPath, out: path });
  assert.ok(md.includes(LIMITS)); assert.ok(md.includes("MOCK")); assert.ok(md.includes("LLM으로 나간 데이터 범위"));
  assert.ok(md.includes(registrySha256)); assert.ok(md.includes(b.sha256));
  assert.ok(!all.some((c) => md.includes(c.token)));
  assert.ok(!md.includes("오염 없음"));
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.throws(() => report({ registry: registryPath, out: path }));
  const wrongPath = join(scratch, "wrong.json");
  writeJson(wrongPath, { ...scanText(copy), registrySha256: "0".repeat(64) });
  assert.throws(() => report({ registry: registryPath, scan: wrongPath, out: join(scratch, "wrong.md") }), /different registry/);
  const bPath = join(out, b.copy);
  writeFileSync(bPath, copy + " ");
  assert.throws(() => report({ registry: registryPath, out: join(scratch, "tampered.md") }), /hash mismatch/);
  writeFileSync(bPath, copy);
  const missing = join(scratch, "registry-only.json"); writeJson(missing, registry);
  assert.ok(report({ registry: missing, out: join(scratch, "missing.md") }).includes("검증 불가"));
});

const usage = (): LlmUsage => ({ mode: "schema", model: "stub", calls: 0, latencyMs: 0, inputTokens: 0, outputTokens: 0, fallbackReasons: [] });
const rows: Row[] = readFileSync(input, "utf8").trimEnd().split("\n").map((s) => Row.parse(JSON.parse(s)));
const generated = (n: number): Row[] => Array.from({ length: n }, (_, i) => ({ id: String(i), question: `At repair station ${i}, machine {{MODEL}} has a daily capacity of twelve units. If the operator schedules two equal production shifts, how many units are produced during each shift?`, choices: ["6", "12", "24"], answer: "6" }));

test("LLM: schema request excludes original text; samples limited to five; local token insertion", async () => {
  const prompt = makePrompt(rows, 2, "schema", "variant");
  assert.ok(!rows.some((r) => prompt.includes(r.question) || prompt.includes(r.id)));
  assert.equal((JSON.parse(makePrompt(rows, 2, "samples", "v")) as { samples: Row[] }).samples.length, 5);
  const llmOut = join(scratch, "llm");
  let calls = 0;
  const result = await issue({ input, recipients: ["alpha"], canaries: 2, out: llmOut, generate: "llm", llmClient: async (request) => {
    calls++; assert.ok(!all.some((c) => request.includes(c.token))); assert.ok(!request.includes(rows[0]!.question));
    return { text: JSON.stringify(generated(2)), inputTokens: 100, outputTokens: 50 };
  } });
  assert.equal(calls, 1); assert.equal(result.registry.generation, "llm");
  assert.equal(result.registry.llmUsage.inputTokens, 100);
  assert.equal(result.registry.llmUsage.outputTokens, 50);
});

test("LLM: overlap/invalid output retried within cap; none and missing key use templates", async () => {
  assert.ok(overlapsOriginal(rows[0]!.question, rows));
  const log = usage(); let calls = 0;
  const reply = await generateLlmRows({ rows, count: 1, variant: "v", mode: "schema", usage: log, maxCalls: 2, client: async () => {
    calls++; return { text: JSON.stringify([{ ...generated(1)[0]!, question: rows[0]!.question + " {{MODEL}}" }]), inputTokens: 10, outputTokens: 10 };
  } });
  assert.equal(reply, null); assert.equal(calls, 2); assert.equal(log.calls, 2);
  const cap = usage(); cap.calls = 1;
  assert.equal(await generateLlmRows({ rows, count: 1, variant: "v", mode: "schema", usage: cap, maxCalls: 1, client: async () => { throw new Error("should not call"); } }), null);
  const none = usage();
  assert.equal(await generateLlmRows({ rows, count: 1, variant: "v", mode: "none", usage: none, maxCalls: 2, client: async () => { throw new Error("should not call"); } }), null);
  assert.equal(none.calls, 0);
  const missing = await issue({ input, recipients: ["alpha"], out: join(scratch, "no-key"), generate: "llm" });
  assert.equal(missing.registry.generation, "template");
  assert.ok(missing.registry.llmUsage.fallbackReasons.includes("missing ANTHROPIC_API_KEY"));
});

test("CLI: help, errors 2, missing key redaction, scan detection 1, clean scan 0", () => {
  const cli = (args: string[], env = process.env) => spawnSync(process.execPath, ["--import", "tsx", "src/cli.ts", "canary", ...args], { encoding: "utf8", env });
  assert.equal(cli(["--help"]).status, 0);
  assert.equal(cli(["issue", "--help"]).status, 0);
  assert.equal(cli(["issue"]).status, 2);
  assert.equal(cli(["unknown"]).status, 2);
  const env = { ...process.env }; delete env.ARGOS_CANARY_KEY;
  const missing = cli(["issue", "--input", input, "--recipients", "a", "--out", join(scratch, "missing-key")], env);
  assert.equal(missing.status, 2); assert.ok(!missing.stderr.includes(process.env.ARGOS_CANARY_KEY!));
  const found = cli(["scan", join(out, b.copy), "--registry", registryPath]);
  assert.equal(found.status, 1); assert.match(found.stdout, /IDENTIFIED/);
  assert.ok(!all.some((c) => found.stdout.includes(c.token) || found.stderr.includes(c.token)));
  assert.equal(cli(["scan", input, "--registry", registryPath]).status, 0);
  const existing = join(scratch, "existing.json"); writeFileSync(existing, "original"); chmodSync(existing, 0o644);
  assert.equal(cli(["scan", input, "--registry", registryPath, "--json", existing]).status, 2);
  assert.equal(readFileSync(existing, "utf8"), "original");
});
