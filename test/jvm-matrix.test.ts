import { test } from "node:test";
import assert from "node:assert/strict";
import { bola, unauth } from "../src/checks/index.js";
import { fillParams, fillPath } from "../src/http.js";
import { authPrecheck, plan, renderMatrixMarkdown, runMatrixDetailed } from "../src/matrix.js";
import { redact } from "../src/seed.js";
import { mintPersonaTokens } from "../src/tokens.js";
import { Matrix, type MatrixCell } from "../src/types.js";
import { fakeJvm, fakeJvmApp, type Flaws } from "./helpers/fake-jvm.js";
import { cfg as legacyCfg } from "./helpers/fake-app.js";
import { springConfig, springRaw } from "./helpers/spring-config.js";

const find = (cells: MatrixCell[], persona: string, resource: string, target?: string, targetUser?: string) =>
  cells.find((c) => c.persona === persona && c.resource === resource && c.target === target && c.targetUser === targetUser);

async function scan(flaws: Flaws = {}, over: Record<string, unknown> = {}) {
  const cfg = springConfig(over);
  const f = fakeJvm(cfg);
  const srv = await fakeJvmApp(f, cfg, flaws);
  try {
    const manifest = { ...f.manifest, credentials: Object.values(f.tokens) };
    const pre = await authPrecheck(cfg, srv.url, manifest, { tokens: f.tokens });
    const { matrix } = await runMatrixDetailed(cfg, srv.url, manifest, { tokens: f.tokens, db: f.db, skipPersonas: pre.failed, skipAll: pre.skipAll });
    Matrix.parse(matrix);
    return { cfg, f, pre, matrix, findings: [...bola(cfg, matrix), ...unauth(cfg, matrix)] };
  } finally {
    srv.close();
  }
}

test("path params: both :id and {id}, one value per parameter", () => {
  assert.equal(fillPath("/a/{x}/b/:y", 7), "/a/7/b/7");
  assert.equal(fillParams("/api/projects/{projectId}/documents/{documentId}", (n) => (n === "projectId" ? 101 : "d-1")), "/api/projects/101/documents/d-1");
});

test("planning: legacy configs plan exactly as before (no new relations)", () => {
  const ps = plan(legacyCfg());
  assert.ok(ps.every((p) => !p.relation && !p.targetUser));
  assert.equal(ps.length, 3 /* personas */ * 4 /* resources */ + 2 /* cross-org cell for dataset-read */);
});

test("planning: same-org other user, role, and invalid-token personas", () => {
  const ps = plan(springConfig());
  const of = (persona: string, res: string) => ps.filter((p) => p.persona.name === persona && p.resource.id === res);
  // user-scoped documents: own, two same-org others, one per foreign org
  const docs = of("alice-member", "document-read");
  assert.deepEqual(docs.map((p) => [p.target, p.targetUser, p.relation ?? "", p.expected]), [
    ["orgA", "alice-member", "", "allow"],
    ["orgA", "alice-admin", "same-org", "deny"],
    ["orgA", "alice-member2", "same-org", "deny"],
    ["orgB", "bob-admin", "", "deny"],
  ]);
  // admin-only: members get a role cell with expect.member
  assert.deepEqual(of("alice-member", "admin-users").map((p) => [p.target, p.relation, p.expected]), [["orgA", "role", "deny"], ["orgB", undefined, "deny"]]);
  assert.deepEqual(of("alice-admin", "admin-users")[0]!.relation, undefined);
  assert.deepEqual(of("alice-member", "project-create").map((p) => [p.relation, p.expected]), [["role", "deny"]]);
  // invalid tokens: deny everywhere, aimed at their own user's data
  for (const p of ps.filter((x) => x.persona.invalid)) {
    assert.ok(!p.resource.public, "public routes are not planned for broken tokens");
    assert.deepEqual([p.relation, p.expected], ["invalid-token", "deny"]);
  }
  assert.deepEqual(of("forged", "document-read").map((p) => [p.target, p.targetUser]), [["orgA", "alice-member"]]);
});

test("correct app: no red, controls green, writes verified in the DB", async () => {
  const { matrix, findings, pre } = await scan();
  assert.deepEqual(pre.failed, {});
  assert.equal(pre.skipAll, undefined);
  const red = matrix.cells.filter((c) => c.verdict === "VULNERABLE");
  assert.deepEqual(red, []);
  assert.equal(find(matrix.cells, "alice-member", "document-read", "orgA", "alice-member")!.verdict, "OK");
  assert.equal(find(matrix.cells, "alice-member", "document-read", "orgA", "alice-member2")!.verdict, "OK");
  const ownWrite = find(matrix.cells, "alice-member", "document-update", "orgA", "alice-member")!;
  assert.deepEqual([ownWrite.observed, ownWrite.verdict, ownWrite.action], ["allow", "OK", "update"]);
  assert.match(ownWrite.evidence.note!, /DB changed/);
  const otherWrite = find(matrix.cells, "alice-member", "document-update", "orgA", "alice-member2")!;
  assert.deepEqual([otherWrite.observed, otherWrite.verdict], ["deny", "OK"]);
  assert.match(otherWrite.evidence.note!, /DB unchanged/);
  assert.equal(find(matrix.cells, "alice-admin", "project-create")!.verdict, "OK");
  assert.equal(find(matrix.cells, "alice-member", "project-create")!.verdict, "OK"); // 403 + no new row
  assert.ok(findings.every((f) => f.verdict === "OK"), findings.filter((f) => f.verdict !== "OK").map((f) => f.detail).join("\n"));
});

test("missing owner check: same-org reads and writes are red", async () => {
  const { matrix, findings } = await scan({ noOwnerCheck: true });
  const read = find(matrix.cells, "alice-member", "document-read", "orgA", "alice-member2")!;
  assert.deepEqual([read.relation, read.verdict], ["same-org", "VULNERABLE"]);
  const write = find(matrix.cells, "alice-member", "document-update", "orgA", "alice-member2")!;
  assert.deepEqual([write.observed, write.verdict], ["allow", "VULNERABLE"]);
  assert.ok(findings.some((f) => f.check === "bola" && f.verdict === "VULNERABLE" && /in the same org/.test(f.detail)));
  assert.equal(find(matrix.cells, "alice-member", "document-read", "orgB", "bob-admin")!.verdict, "OK", "org check still holds");
});

test("collection route scoped to the caller: same-org list without the colleague's rows is deny/OK, not suspected", async () => {
  const documentList = {
    id: "document-list",
    route: "GET /api/projects/{projectId}/documents",
    owner: { table: "documents", column: "owner_id", scope: "user" },
    pathParams: { projectId: { table: "projects" } },
    expect: { owner: "allow", other: "deny", anonymous: "deny" },
  };
  const over = { resources: [...springRaw().resources, documentList] };
  const ok = await scan({}, over);
  const own = find(ok.matrix.cells, "alice-member", "document-list", "orgA", "alice-member")!;
  assert.deepEqual([own.observed, own.verdict], ["allow", "OK"]);
  const colleague = find(ok.matrix.cells, "alice-member", "document-list", "orgA", "alice-member2")!;
  assert.deepEqual([colleague.relation, colleague.observed, colleague.verdict], ["same-org", "deny", "OK"]);
  assert.deepEqual(ok.matrix.cells.filter((c) => c.resource === "document-list" && c.verdict !== "OK").map((c) => `${c.persona}->${c.targetUser}:${c.verdict}`), []);
  const leaky = await scan({ noOwnerCheck: true }, over);
  assert.equal(find(leaky.matrix.cells, "alice-member", "document-list", "orgA", "alice-member2")!.verdict, "VULNERABLE");
});

test("delete probes: a successful attack's deletion is restored, so later probes and the owner's control still run", async () => {
  const documentDelete = {
    id: "document-delete",
    route: "DELETE /api/projects/{projectId}/documents/{documentId}",
    owner: { table: "documents", column: "owner_id", scope: "user" },
    pathParams: { projectId: { table: "projects" }, documentId: { table: "documents" } },
    safe: true,
    writeVerify: { table: "documents", column: "id" },
    expect: { owner: "allow", other: "deny", anonymous: "deny" },
  };
  const over = { resources: [...springRaw().resources, documentDelete] };
  const leaky = await scan({ noOwnerCheck: true }, over);
  const cells = leaky.matrix.cells.filter((c) => c.resource === "document-delete");
  // alice-member2's document is attacked by two colleagues; both see it, then its owner deletes it.
  assert.equal(find(cells, "alice-member", "document-delete", "orgA", "alice-member2")!.verdict, "VULNERABLE");
  assert.equal(find(cells, "alice-admin", "document-delete", "orgA", "alice-member2")!.verdict, "VULNERABLE");
  const ownerControl = find(cells, "alice-member2", "document-delete", "orgA", "alice-member2")!;
  assert.deepEqual([ownerControl.observed, ownerControl.verdict], ["allow", "OK"]);
  assert.deepEqual(cells.filter((c) => c.verdict === "SKIPPED").map((c) => `${c.persona}->${c.targetUser}: ${c.evidence.note}`), []);
  const ok = await scan({}, over);
  assert.deepEqual(ok.matrix.cells.filter((c) => c.resource === "document-delete" && c.verdict !== "OK").map((c) => `${c.persona}->${c.targetUser}:${c.verdict}`), []);
});

test("missing role check: members reach admin-only API (function level)", async () => {
  const { matrix, findings } = await scan({ noRoleCheck: true });
  const c = find(matrix.cells, "alice-member", "admin-users", "orgA")!;
  assert.deepEqual([c.relation, c.verdict], ["role", "VULNERABLE"]);
  assert.equal(find(matrix.cells, "alice-member", "project-create")!.verdict, "VULNERABLE");
  assert.ok(findings.some((f) => f.check === "bola" && f.resourceId === "admin-users" && /requires role ADMIN/.test(f.detail)));
});

test("missing org check: cross-org project read is red", async () => {
  const { matrix } = await scan({ noOrgCheck: true });
  assert.equal(find(matrix.cells, "bob-member", "project-read", "orgA")!.verdict, "VULNERABLE");
});

test("invalid tokens accepted: unauth is red", async () => {
  const { findings } = await scan({ acceptInvalid: true });
  assert.ok(findings.some((f) => f.check === "unauth" && f.persona === "forged" && f.verdict === "VULNERABLE" && /invalid token \(wrong-signature\)/.test(f.detail)));
});

test("a 2xx write that did not change the DB is not proof (SUSPECTED, never OK)", async () => {
  const { matrix } = await scan({ writeNoop: true });
  const own = find(matrix.cells, "alice-member", "document-update", "orgA", "alice-member")!;
  assert.deepEqual([own.observed, own.verdict], ["allow-empty", "SUSPECTED"]);
});

test("marker not observable in the DTO: SKIPPED, never OK", async () => {
  const { matrix } = await scan({ omitTitle: true });
  const cells = matrix.cells.filter((c) => c.resource === "document-read" && c.observed === "allow-empty");
  assert.ok(cells.length);
  assert.ok(cells.every((c) => c.verdict === "SKIPPED" && /marker not observable/.test(c.evidence.note!)));
});

test("auth precheck failure: the whole run is unverified, nothing concluded", async () => {
  const { matrix, pre, findings } = await scan({ rejectAll: true });
  assert.ok(pre.skipAll);
  assert.ok(Object.keys(pre.failed).length >= 5);
  const tested = matrix.cells.filter((c) => !c.resource.startsWith("health"));
  assert.ok(tested.every((c) => c.verdict === "SKIPPED" && /미검증/.test(c.evidence.note!)));
  assert.ok(!findings.some((f) => f.verdict === "OK" || f.verdict === "VULNERABLE"));
});

test("tokens never reach evidence, even when the app echoes them", async () => {
  const { matrix, f } = await scan({ echoAuth: true, rejectAll: false, acceptInvalid: false });
  const dump = JSON.stringify(matrix) + renderMatrixMarkdown(matrix);
  for (const t of Object.values(f.tokens)) assert.ok(!dump.includes(t), "token leaked");
  for (const m of Object.values(f.manifest.markers).flatMap((x) => Object.values(x))) assert.ok(!dump.includes(m), "full marker leaked");
});

test("redact: credentials, JWT-shaped strings, Bearer values, PEM and JWK members", () => {
  const m = { markers: {}, secrets: [], ids: {}, credentials: ["db-pass-123456"] };
  const jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJlLXZhbHVl";
  const out = redact(`pw=db-pass-123456 tok=${jwt} Authorization: Bearer abcdefghijkl -----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY----- {"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W"}`, m);
  assert.ok(!out.includes("db-pass-123456"));
  assert.ok(!out.includes(jwt));
  assert.ok(!out.includes("abcdefghijkl"));
  assert.ok(!out.includes("MIIE"));
  assert.ok(!out.includes("0vx7agoeb"));
});

test("mintPersonaTokens: sub from the seeded user, roles claim with prefix, extra placeholders, invalid flags", () => {
  const cfg = springConfig({
    auth: { type: "jwt-issuer", audience: "workspace", claims: { subject: "id", roles: { claim: "realm_access.roles", prefix: "ROLE_" }, extra: { org_id: "$orgId", scope: "api" } } },
  });
  const f = fakeJvm(cfg);
  const seen: { claims: Record<string, any>; opts: any }[] = [];
  const tokens = mintPersonaTokens(cfg, { issuer: "http://issuer", mint: (claims, opts) => (seen.push({ claims, opts }), `t${seen.length}`) }, f.manifest);
  assert.equal(Object.keys(tokens).length, 7);
  const admin = seen[0]!;
  assert.equal(admin.claims.sub, f.manifest.users["orgA/alice-admin"]!.id);
  assert.deepEqual(admin.claims.realm_access, { roles: ["ROLE_ADMIN"] });
  assert.equal(admin.claims.org_id, "o-orgA");
  assert.equal(admin.claims.scope, "api");
  const forged = seen[5]!;
  assert.equal(forged.claims.sub, f.manifest.users["orgA/alice-member"]!.id, "invalid persona impersonates a real user");
  assert.equal(forged.opts.wrongKey, true);
  assert.ok(seen[6]!.opts.expiresInSec < -120, "expired beyond clock skew");
});
