#!/usr/bin/env node
// Overlay a flawed variant onto a COPY of maven-app or gradle-app.
// Usage: node apply-variant.mjs <appDir> <variant>
// Every file under variants/<variant>/ replaces the file at the same relative path in <appDir>.
import { cpSync, existsSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const variantsDir = join(here, "variants");
const [appArg, variant] = process.argv.slice(2);
const available = readdirSync(variantsDir).filter((d) => statSync(join(variantsDir, d)).isDirectory());

if (!appArg || !variant || !available.includes(variant)) {
  console.error(`usage: node apply-variant.mjs <appDir> <variant>\nvariants: ${available.join(", ")}`);
  process.exit(2);
}

const appDir = resolve(appArg);
if (["maven-app", "gradle-app"].some((name) => appDir === join(here, name))) {
  console.error("refusing to modify the pristine fixture; copy it first (cp -R maven-app /tmp/x)");
  process.exit(2);
}

const walk = (dir) =>
  readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });

const root = join(variantsDir, variant);
for (const src of walk(root)) {
  const rel = relative(root, src);
  const dest = join(appDir, rel);
  if (!existsSync(dest)) {
    console.error(`target file missing (fixture drift?): ${rel}`);
    process.exit(1);
  }
  cpSync(src, dest);
  console.log(`${variant}: replaced ${rel}`);
}
