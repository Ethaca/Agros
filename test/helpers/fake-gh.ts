import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * A stateful fake `gh` (PATH shim, a node script) that understands `pr list --head --json`, `pr create`, `pr edit`,
 * so publish's create-or-update logic can be tested without GitHub. Every call is appended to calls.txt.
 */
export interface FakeGh {
  /** PATH with the fake gh first. */
  path: string;
  calls(): string[];
  prs(): { number: number; head: string; base: string; title: string; body: string; url: string }[];
}

export function fakeGh(): FakeGh {
  const root = mkdtempSync(join(tmpdir(), "argos-fakegh-"));
  const bin = join(root, "bin");
  mkdirSync(bin);
  const state = join(root, "prs.json");
  const calls = join(root, "calls.txt");
  writeFileSync(state, "[]");
  const script = `#!/usr/bin/env node
const fs = require("fs");
const args = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(calls)}, args.join(" ") + "\\n");
const opt = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
const prs = JSON.parse(fs.readFileSync(${JSON.stringify(state)}, "utf8"));
const save = () => fs.writeFileSync(${JSON.stringify(state)}, JSON.stringify(prs, null, 2));
if (args[0] === "pr" && args[1] === "list") {
  process.stdout.write(JSON.stringify(prs.filter((p) => p.head === opt("--head")).map((p) => ({ number: p.number, url: p.url, body: p.body }))));
} else if (args[0] === "pr" && args[1] === "create") {
  if (prs.some((p) => p.head === opt("--head"))) { console.error("a pull request already exists"); process.exit(1); }
  const number = 41 + prs.length + 1;
  const url = "https://github.com/acme/app/pull/" + number;
  prs.push({ number, head: opt("--head"), base: opt("--base"), title: opt("--title"), body: fs.readFileSync(opt("--body-file"), "utf8"), url });
  save();
  console.log(url);
} else if (args[0] === "pr" && args[1] === "edit") {
  const p = prs.find((x) => String(x.number) === args[2]);
  if (!p) { console.error("no such PR"); process.exit(1); }
  p.title = opt("--title"); p.body = fs.readFileSync(opt("--body-file"), "utf8");
  save();
} else { console.error("fake gh: unsupported " + args.join(" ")); process.exit(2); }
`;
  writeFileSync(join(bin, "gh"), script);
  chmodSync(join(bin, "gh"), 0o755);
  return {
    path: `${bin}:${process.env.PATH}`,
    calls: () => (existsSync(calls) ? readFileSync(calls, "utf8").split("\n").filter(Boolean) : []),
    prs: () => JSON.parse(readFileSync(state, "utf8")),
  };
}
