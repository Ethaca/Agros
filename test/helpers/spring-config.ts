import { parseConfig, type Config } from "../../src/config.js";

/** Hand-written jvm config for the Spring fixture (test/fixtures/spring/maven-app). */
export const springRaw = (): Record<string, any> => ({
  version: 1,
  target: {
    start: "java -jar app.jar",
    cwd: "../spring/maven-app",
    readyPath: "/healthz",
    isolation: "container",
    runtime: "jvm",
  },
  db: { kind: "postgres", migrations: "flyway" },
  auth: { type: "jwt-issuer", claims: { subject: "id", roles: { claim: "roles" } } },
  personas: [
    { name: "alice-admin", org: "orgA", auth: { type: "jwt" }, roles: ["ADMIN"] },
    { name: "alice-member", org: "orgA", auth: { type: "jwt" }, roles: ["MEMBER"] },
    { name: "alice-member2", org: "orgA", auth: { type: "jwt" }, roles: ["MEMBER"] },
    { name: "bob-admin", org: "orgB", auth: { type: "jwt" }, roles: ["ADMIN"] },
    { name: "bob-member", org: "orgB", auth: { type: "jwt" }, roles: ["MEMBER"] },
    { name: "forged", org: "orgA", user: "alice-member", auth: { type: "jwt" }, roles: ["ADMIN"], invalid: "wrong-signature" },
    { name: "expired", org: "orgA", user: "alice-member", auth: { type: "jwt" }, roles: ["MEMBER"], invalid: "expired" },
    { name: "anonymous", auth: { type: "none" } },
  ],
  resources: [
    { id: "health", route: "GET /healthz", public: true },
    { id: "project-list", route: "GET /api/projects", owner: { table: "projects", column: "org_id" }, expect: { owner: "allow", other: "deny", anonymous: "deny" } },
    { id: "project-read", route: "GET /api/projects/{projectId}", owner: { table: "projects", column: "org_id" }, expect: { owner: "allow", other: "deny", anonymous: "deny" } },
    {
      id: "document-read",
      route: "GET /api/projects/{projectId}/documents/{documentId}",
      owner: { table: "documents", column: "owner_id", scope: "user" },
      pathParams: { projectId: { table: "projects" }, documentId: { table: "documents" } },
      expect: { owner: "allow", other: "deny", anonymous: "deny" },
    },
    {
      id: "document-update",
      route: "PUT /api/projects/{projectId}/documents/{documentId}",
      owner: { table: "documents", column: "owner_id", scope: "user" },
      pathParams: { projectId: { table: "projects" }, documentId: { table: "documents" } },
      safe: true,
      body: { title: "$unique", body: "updated by argos" },
      writeVerify: { table: "documents", column: "title" },
      expect: { owner: "allow", other: "deny", anonymous: "deny" },
    },
    {
      id: "admin-users",
      route: "GET /api/admin/users",
      owner: { table: "app_users", column: "org_id" },
      roles: ["ADMIN"],
      expect: { owner: "allow", other: "deny", anonymous: "deny", member: "deny" },
    },
    {
      id: "project-create",
      route: "POST /api/projects",
      roles: ["ADMIN"],
      safe: true,
      body: { name: "$unique", description: "created by argos" },
      writeVerify: { table: "projects", column: "name", where: { org_id: "$orgId" } },
      expect: { owner: "allow", other: "deny", anonymous: "deny", member: "deny" },
    },
  ],
  checks: ["bola", "unauth", "secrets"],
  secrets: { staticScan: false },
});

export const springConfig = (over: Record<string, unknown> = {}): Config => parseConfig({ ...springRaw(), ...over });

export const FIXTURE_MIGRATION = "test/fixtures/spring/maven-app/src/main/resources/db/migration/V1__init.sql";
