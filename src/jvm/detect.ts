import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Build tool and JDK detection for a JVM project (static, never runs project code).
 *
 * Build tool:   gradlew present -> gradle (wrapper) · pom.xml -> maven (mvnw -> wrapper) · build.gradle(.kts)/settings.gradle(.kts) -> gradle
 * JDK version:  pom.xml  <maven.compiler.release> | <release> | <java.version> | <maven.compiler.target|source>  (${prop} resolved, "1.8" -> 8)
 *               gradle   JavaLanguageVersion.of(N) | jvmToolchain(N) | sourceCompatibility/targetCompatibility = JavaVersion.VERSION_N / 'N'
 *               then .java-version, .sdkmanrc (java=N...), default 21.
 */

export type BuildTool = "maven" | "gradle";

export interface JvmProject {
  tool: BuildTool | null;
  /** Project wrapper (./mvnw, ./gradlew) present. */
  wrapper: boolean;
  jdk: number;
  /** Where the JDK version came from, e.g. "pom.xml <java.version>" or "default". */
  jdkSource: string;
}

export const DEFAULT_JDK = 21;

const read = (dir: string, f: string): string | null => {
  const p = join(dir, f);
  return existsSync(p) ? readFileSync(p, "utf8") : null;
};

/** "1.8" -> 8, "17" -> 17, "21.0.2" -> 21; anything else -> null. */
export function normalizeJavaVersion(v: string | undefined): number | null {
  if (!v) return null;
  const s = v.trim().replace(/^["']|["']$/g, "");
  const m = /^1\.(\d+)$/.exec(s) ?? /^(\d+)(?:[.\-+].*)?$/.exec(s) ?? /^VERSION_1_(\d+)$/.exec(s) ?? /^VERSION_(\d+)$/.exec(s);
  if (!m) return null;
  const n = Number(m[1]);
  return n >= 8 && n <= 99 ? n : null;
}

function pomJdk(pom: string): { jdk: number; source: string } | null {
  const xml = pom.replace(/<!--[\s\S]*?-->/g, "");
  const props: Record<string, string> = {};
  const propsBlock = /<properties>([\s\S]*?)<\/properties>/.exec(xml)?.[1] ?? "";
  for (const m of propsBlock.matchAll(/<([\w.\-]+)>\s*([^<]*?)\s*<\/\1>/g)) props[m[1]!] = m[2]!;
  const resolve = (v: string | undefined): string | undefined => {
    for (let i = 0; i < 5 && v; i++) {
      const ref = /^\$\{([\w.\-]+)\}$/.exec(v.trim());
      if (!ref) break;
      v = props[ref[1]!];
    }
    return v;
  };
  const candidates: [string, string | undefined][] = [
    ["<maven.compiler.release>", props["maven.compiler.release"]],
    ["compiler plugin <release>", /<artifactId>maven-compiler-plugin<\/artifactId>[\s\S]*?<release>\s*([^<]+?)\s*<\/release>/.exec(xml)?.[1]],
    ["<java.version>", props["java.version"]],
    ["<maven.compiler.target>", props["maven.compiler.target"]],
    ["<maven.compiler.source>", props["maven.compiler.source"]],
  ];
  for (const [what, raw] of candidates) {
    const n = normalizeJavaVersion(resolve(raw));
    if (n) return { jdk: n, source: `pom.xml ${what}` };
  }
  return null;
}

function gradleJdk(src: string, file: string): { jdk: number; source: string } | null {
  const code = src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  const pats: [string, RegExp][] = [
    ["toolchain JavaLanguageVersion.of", /JavaLanguageVersion\.of\(\s*["']?(\d+)["']?\s*\)/],
    ["jvmToolchain", /jvmToolchain\(\s*(\d+)\s*\)/],
    ["sourceCompatibility", /sourceCompatibility\s*=\s*(?:JavaVersion\.)?(VERSION_[\d_]+|["']?[\d.]+["']?)/],
    ["targetCompatibility", /targetCompatibility\s*=\s*(?:JavaVersion\.)?(VERSION_[\d_]+|["']?[\d.]+["']?)/],
  ];
  for (const [what, re] of pats) {
    const n = normalizeJavaVersion(re.exec(code)?.[1]);
    if (n) return { jdk: n, source: `${file} ${what}` };
  }
  return null;
}

export function detectJvmProject(dir: string): JvmProject {
  const has = (f: string) => existsSync(join(dir, f));
  const gradleFiles = ["build.gradle.kts", "build.gradle", "settings.gradle.kts", "settings.gradle"].filter(has);
  let tool: BuildTool | null = null;
  let wrapper = false;
  if (has("gradlew")) [tool, wrapper] = ["gradle", true];
  else if (has("pom.xml")) [tool, wrapper] = ["maven", has("mvnw")];
  else if (gradleFiles.length) tool = "gradle";

  let found: { jdk: number; source: string } | null = null;
  if (tool === "maven") found = pomJdk(read(dir, "pom.xml") ?? "");
  if (tool === "gradle") {
    for (const f of gradleFiles) if ((found = gradleJdk(read(dir, f) ?? "", f))) break;
  }
  if (!found) {
    const jv = normalizeJavaVersion(read(dir, ".java-version") ?? undefined);
    if (jv) found = { jdk: jv, source: ".java-version" };
  }
  if (!found) {
    const sdk = normalizeJavaVersion(/^java=([^\s]+)/m.exec(read(dir, ".sdkmanrc") ?? "")?.[1]);
    if (sdk) found = { jdk: sdk, source: ".sdkmanrc" };
  }
  return { tool, wrapper, jdk: found?.jdk ?? DEFAULT_JDK, jdkSource: found?.source ?? "default" };
}

/** Default build command when target.build is not set. */
export function defaultBuildCommand(p: JvmProject): string | null {
  if (p.tool === "maven") return `${p.wrapper ? "./mvnw" : "mvn"} -B -q -DskipTests package`;
  if (p.tool === "gradle") return `${p.wrapper ? "./gradlew" : "gradle"} --no-daemon -q bootJar`;
  return null;
}

/** Build image: the wrapper only needs a JDK; a bare Maven/Gradle project needs the tool in the image. */
export function defaultBuildImage(p: JvmProject): string {
  if (p.tool === "maven" && !p.wrapper) return `maven:3-eclipse-temurin-${p.jdk}`;
  if (p.tool === "gradle" && !p.wrapper) return `gradle:jdk${p.jdk}`;
  return `eclipse-temurin:${p.jdk}-jdk`;
}

export const defaultAppImage = (p: JvmProject): string => `eclipse-temurin:${p.jdk}-jre`;
