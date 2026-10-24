import { readFileSync } from "node:fs";
import { relative } from "node:path";
import { parseAllDocuments } from "yaml";
import { walkFiles } from "./detect.js";

/**
 * application*.yml / *.properties: only KEY NAMES and the KIND of each dependency leave this module.
 * Values are read locally to classify them (e.g. `jdbc:postgresql:` -> postgres) and are then dropped.
 */

export interface AppConfigFacts {
  files: string[];
  /** Flattened property names (spring.datasource.url, ...). No values. */
  keys: string[];
  datasource?: { kind: "postgres" | "mysql" | "h2" | "other" | "placeholder"; keys: string[] };
  /** More than one datasource configured (e.g. spring.datasource.primary.url + secondary.url). */
  multipleDataSources: boolean;
  jwt: { issuerUri: boolean; jwkSetUri: boolean; publicKeyLocation: boolean };
  serverPortKey: boolean;
  /** Keys whose name looks secret (password, secret, token, key, credential). Names only. */
  secretKeys: string[];
  /** Keys that hold a literal (not a ${placeholder}) secret-looking value: masked before any egress. */
  literalSecretKeys: string[];
  /** `${ENV_NAME}` placeholders referenced from config (names only). */
  envPlaceholders: string[];
  profiles: string[];
}

const SECRET_KEY = /(?:password|passwd|secret|token|api[-_]?key|private[-_]?key|credential)/i;

function flatten(v: unknown, prefix: string, out: Map<string, string>): void {
  if (v && typeof v === "object" && !Array.isArray(v)) {
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) flatten(x, prefix ? `${prefix}.${k}` : k, out);
  } else if (Array.isArray(v)) v.forEach((x, i) => flatten(x, `${prefix}[${i}]`, out));
  else out.set(prefix, v === null || v === undefined ? "" : String(v));
}

export function readAppConfig(root: string): AppConfigFacts {
  const files = walkFiles(root, (n) => /^(?:application|bootstrap)(?:-[\w.-]+)?\.(?:ya?ml|properties)$/.test(n)).filter((f) => /src\/main\/resources\//.test(f));
  const all = new Map<string, string>();
  const profiles: string[] = [];
  for (const f of files) {
    const prof = /^(?:application|bootstrap)-([\w.-]+)\./.exec(f.split("/").pop()!)?.[1];
    if (prof) profiles.push(prof);
    const text = readFileSync(f, "utf8");
    if (f.endsWith(".properties")) {
      for (const line of text.split("\n")) {
        const m = /^\s*([^#!\s][^=:\s]*)\s*[=:]\s*(.*)$/.exec(line);
        if (m) all.set(m[1]!, m[2]!.trim());
      }
    } else {
      try {
        for (const doc of parseAllDocuments(text)) {
          if ("errors" in doc && doc.errors.length) continue;
          flatten(doc.toJS(), "", all);
        }
      } catch {
        /* unreadable YAML: keys stay unknown */
      }
    }
  }
  const keys = [...all.keys()].sort();
  const dsKeys = keys.filter((k) => /(?:^|\.)datasource\./i.test(k));
  const urlKeys = dsKeys.filter((k) => /\.(?:url|jdbc-url|jdbcUrl)$/i.test(k));
  let datasource: AppConfigFacts["datasource"];
  if (dsKeys.length) {
    const url = all.get("spring.datasource.url") ?? (urlKeys[0] ? all.get(urlKeys[0]) : undefined) ?? "";
    const kind = /^jdbc:postgresql:/i.test(url) ? "postgres" : /^jdbc:(?:mysql|mariadb):/i.test(url) ? "mysql" : /^jdbc:h2:/i.test(url) ? "h2" : /\$\{/.test(url) || !url ? "placeholder" : "other";
    datasource = { kind, keys: dsKeys };
  }
  const secretKeys = keys.filter((k) => SECRET_KEY.test(k.split(".").pop() ?? ""));
  const literalSecretKeys = secretKeys.filter((k) => {
    const v = all.get(k) ?? "";
    return v !== "" && !/^\$\{[^}]*\}$/.test(v);
  });
  const envPlaceholders = [...new Set([...all.values()].flatMap((v) => [...v.matchAll(/\$\{([A-Z][A-Z0-9_]*)(?::[^}]*)?\}/g)].map((m) => m[1]!)))].sort();
  return {
    files: files.map((f) => relative(root, f)),
    keys,
    ...(datasource ? { datasource } : {}),
    multipleDataSources: new Set(urlKeys.map((k) => k.replace(/\.(?:url|jdbc-url|jdbcUrl)$/i, ""))).size > 1,
    jwt: {
      issuerUri: keys.some((k) => /resourceserver\.jwt\.issuer-uri$/.test(k)),
      jwkSetUri: keys.some((k) => /resourceserver\.jwt\.jwk-set-uri$/.test(k)),
      publicKeyLocation: keys.some((k) => /resourceserver\.jwt\.public-key-location$/.test(k)),
    },
    serverPortKey: keys.includes("server.port"),
    secretKeys,
    literalSecretKeys,
    envPlaceholders,
    profiles: [...new Set(profiles)].sort(),
  };
}
