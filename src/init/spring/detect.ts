import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

/**
 * Spring Boot project detection for `argos init` (static: reads build files, never runs Maven/Gradle).
 * Anything it cannot decide is reported (`unsupported` / `notes`) instead of guessed.
 */

export interface Evidence {
  /** What it is, in plain words. */
  item: string;
  /** file:line or file. */
  where: string;
}

export interface SpringProject {
  root: string;
  buildTool: "maven" | "gradle";
  /** Build file of the runnable module (repo-relative). */
  buildFile: string;
  wrapper: boolean;
  /** Runnable module directory relative to root ("." for single-module builds). */
  module: string;
  java?: { version: string; source: string };
  boot?: { version: string; source: string };
  /** supported: Boot 3.x. unverified: Boot 2.x / 4.x+ (compatibility not verified). none: no Spring Boot. */
  bootStatus: "supported" | "unverified" | "none";
  app?: { className: string; file: string; line: number };
  /** Artifact path relative to the module dir. */
  jar: { path: string; source: string };
  /** Build command run in the module's root (wrapper preferred, tests skipped). */
  build: string;
  start: string;
  /** Dependency coordinates (group:artifact) declared in the build files. */
  deps: string[];
  languages: { java: number; kotlin: number };
  unsupported: Evidence[];
  /** Things likely to break the isolated build (dependency hosts outside the build egress allowlist). */
  risks: Evidence[];
  notes: string[];
}

const read = (p: string): string => readFileSync(p, "utf8");
const lineOf = (text: string, index: number): number => text.slice(0, index).split("\n").length;
const SKIP = new Set(["node_modules", ".git", "target", "build", "out", ".gradle", ".idea", ".mvn", "gradle"]);

export function walkFiles(dir: string, pick: (name: string) => boolean, max = 4000): string[] {
  const out: string[] = [];
  const visit = (d: string) => {
    if (out.length >= max) return;
    for (const name of readdirSync(d).sort()) {
      const p = join(d, name);
      const st = statSync(p);
      if (st.isDirectory()) {
        if (!SKIP.has(name) && !name.startsWith(".")) visit(p);
      } else if (st.size <= 1_000_000 && pick(name)) out.push(p);
    }
  };
  if (existsSync(dir)) visit(dir);
  return out;
}

/** Is this directory a Maven/Gradle (JVM) build at all? */
export function isJvmBuild(dir: string): boolean {
  return ["pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"].some((f) => existsSync(join(dir, f)));
}

const stripXmlComments = (s: string): string => s.replace(/<!--[\s\S]*?-->/g, (m) => m.replace(/[^\n]/g, " "));
const stripGradleComments = (s: string): string => s.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " ")).replace(/\/\/[^\n]*/g, "");

function pomProps(pom: string): Record<string, string> {
  const props: Record<string, string> = {};
  const block = /<properties>([\s\S]*?)<\/properties>/.exec(pom)?.[1] ?? "";
  for (const m of block.matchAll(/<([\w.\-]+)>\s*([^<]*?)\s*<\/\1>/g)) props[m[1]!] = m[2]!;
  return props;
}

function resolveProp(v: string | undefined, props: Record<string, string>): string | undefined {
  for (let i = 0; i < 5 && v; i++) {
    const r = /\$\{([\w.\-]+)\}/.exec(v);
    if (!r || props[r[1]!] === undefined) break;
    v = v.replace(r[0], props[r[1]!]!);
  }
  return v;
}

/** Top-level <tag> of the project (outside parent/dependencies/build/profiles). */
function pomTop(pom: string, tag: string): string | undefined {
  const outer = pom.replace(/<(parent|dependencies|dependencyManagement|build|profiles|properties|reporting|modules)>[\s\S]*?<\/\1>/g, "");
  return new RegExp(`<${tag}>\\s*([^<]*?)\\s*</${tag}>`).exec(outer)?.[1];
}

function mavenFacts(dir: string, root: string) {
  const file = join(dir, "pom.xml");
  const raw = read(file);
  const pom = stripXmlComments(raw);
  const rel = relative(root, file);
  const props = pomProps(pom);
  props["project.artifactId"] = pomTop(pom, "artifactId") ?? "";
  props["project.version"] = pomTop(pom, "version") ?? /<parent>[\s\S]*?<version>\s*([^<]+?)\s*<\/version>/.exec(pom)?.[1] ?? "";
  const deps = [...pom.matchAll(/<(?:dependency|plugin)>\s*([\s\S]*?)<\/(?:dependency|plugin)>/g)].map((m) => {
    const g = /<groupId>\s*([^<]+?)\s*<\/groupId>/.exec(m[1]!)?.[1] ?? "";
    const a = /<artifactId>\s*([^<]+?)\s*<\/artifactId>/.exec(m[1]!)?.[1] ?? "";
    return `${g}:${a}`;
  });
  let boot: SpringProject["boot"];
  const parent = /<parent>\s*([\s\S]*?)<\/parent>/.exec(pom);
  if (parent && /<artifactId>\s*spring-boot-starter-parent\s*<\/artifactId>/.test(parent[1]!)) {
    const v = /<version>\s*([^<]+?)\s*<\/version>/.exec(parent[1]!)?.[1];
    if (v) boot = { version: resolveProp(v, props)!, source: `${rel}:${lineOf(raw, parent.index)} (<parent> spring-boot-starter-parent)` };
  }
  if (!boot) {
    const bom = /<artifactId>\s*spring-boot-dependencies\s*<\/artifactId>\s*<version>\s*([^<]+?)\s*<\/version>/.exec(pom);
    if (bom) boot = { version: resolveProp(bom[1], props)!, source: `${rel}:${lineOf(raw, bom.index)} (spring-boot-dependencies BOM)` };
  }
  if (!boot && props["spring-boot.version"]) boot = { version: props["spring-boot.version"], source: `${rel} <spring-boot.version>` };
  let java: SpringProject["java"];
  for (const [what, v] of [
    ["<maven.compiler.release>", props["maven.compiler.release"]],
    ["<java.version>", props["java.version"]],
    ["<maven.compiler.source>", props["maven.compiler.source"]],
    ["compiler plugin <release>", /<artifactId>maven-compiler-plugin<\/artifactId>[\s\S]*?<release>\s*([^<]+?)\s*<\/release>/.exec(pom)?.[1]],
  ] as const) {
    const r = resolveProp(v, props);
    if (r) {
      java = { version: r.replace(/^1\.(\d)$/, "$1"), source: `${rel} ${what}` };
      break;
    }
  }
  const bootPlugin = /<artifactId>\s*spring-boot-maven-plugin\s*<\/artifactId>/.test(pom);
  const finalName = resolveProp(/<build>[\s\S]*?<finalName>\s*([^<]+?)\s*<\/finalName>/.exec(pom)?.[1], props);
  const jarName = finalName ?? `${props["project.artifactId"]}-${props["project.version"]}`;
  const modules = [...(/<modules>([\s\S]*?)<\/modules>/.exec(pom)?.[1] ?? "").matchAll(/<module>\s*([^<]+?)\s*<\/module>/g)].map((m) => m[1]!);
  const packaging = pomTop(pom, "packaging") ?? "jar";
  return { file: rel, deps, boot, java, bootPlugin, jar: { path: `target/${jarName}.jar`, source: finalName ? `${rel} <finalName>` : `${rel} artifactId-version` }, modules, packaging };
}

function gradleFacts(dir: string, root: string) {
  const buildFile = ["build.gradle.kts", "build.gradle"].map((f) => join(dir, f)).find(existsSync);
  const settingsFile = ["settings.gradle.kts", "settings.gradle"].map((f) => join(root, f)).find(existsSync);
  const raw = buildFile ? read(buildFile) : "";
  const g = stripGradleComments(raw);
  const settings = settingsFile ? stripGradleComments(read(settingsFile)) : "";
  const rel = buildFile ? relative(root, buildFile) : relative(root, settingsFile ?? join(dir, "build.gradle"));
  const deps = [...g.matchAll(/\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|annotationProcessor|developmentOnly)\s*\(?\s*(?:platform\()?\s*["']([^"':]+):([^"':]+)(?::[^"']*)?["']/g)].map((m) => `${m[1]}:${m[2]}`);
  const plugins = [...g.matchAll(/\bid\s*\(?\s*["']([\w.\-]+)["']\s*\)?(?:\s*version\s*\(?\s*["']([^"']+)["'])?/g)].map((m) => ({ id: m[1]!, version: m[2], at: m.index }));
  const kotlinPlugin = /\bkotlin\s*\(\s*["']jvm["']\s*\)/.test(g) || plugins.some((p) => p.id === "org.jetbrains.kotlin.jvm");
  let boot: SpringProject["boot"];
  const bp = plugins.find((p) => p.id === "org.springframework.boot");
  if (bp?.version) boot = { version: bp.version, source: `${rel}:${lineOf(raw, bp.at)} (plugin org.springframework.boot)` };
  if (!boot) {
    const cp = /spring-boot-gradle-plugin:([\w.\-]+)/.exec(g) ?? /spring-boot-dependencies:([\w.\-]+)/.exec(g);
    if (cp) boot = { version: cp[1]!, source: `${rel}:${lineOf(raw, cp.index)}` };
  }
  if (!boot) {
    const sp = /id\s*\(?\s*["']org\.springframework\.boot["']\s*\)?\s*version\s*\(?\s*["']([^"']+)["']/.exec(settings);
    if (sp) boot = { version: sp[1]!, source: `${relative(root, settingsFile!)} (pluginManagement)` };
  }
  if (!boot) {
    const toml = join(root, "gradle", "libs.versions.toml");
    if (existsSync(toml)) {
      const t = read(toml);
      const v = /^\s*(?:spring-?boot|springBoot|spring_boot)\s*=\s*["']([^"']+)["']/m.exec(t);
      if (v) boot = { version: v[1]!, source: "gradle/libs.versions.toml" };
    }
  }
  let java: SpringProject["java"];
  const tc = /JavaLanguageVersion\.of\(\s*["']?(\d+)["']?\s*\)/.exec(g);
  if (tc) java = { version: tc[1]!, source: `${rel} java toolchain` };
  else {
    const sc = /sourceCompatibility\s*=\s*(?:JavaVersion\.VERSION_)?["']?([\d_.]+)["']?/.exec(g) ?? /jvmToolchain\(\s*(\d+)\s*\)/.exec(g);
    if (sc) java = { version: sc[1]!.replace(/^1[._](\d)$/, "$1"), source: `${rel} sourceCompatibility` };
  }
  const bootPlugin = !!bp || /apply\s*\(?\s*plugin\s*[:=]\s*["']org\.springframework\.boot["']/.test(g);
  const archiveFileName = /bootJar\s*\{[\s\S]*?archiveFileName(?:\.set\()?\s*=?\s*["']([^"']+)["']/.exec(g)?.[1] ?? /tasks\.(?:named<BootJar>\("bootJar"\)|bootJar)[\s\S]*?archiveFileName(?:\.set\()?\s*=?\s*\(?["']([^"']+)["']/.exec(g)?.[1];
  const projName = /rootProject\.name\s*=\s*["']([^"']+)["']/.exec(settings)?.[1] ?? dir.split("/").pop()!;
  const version = /^\s*version\s*=\s*["']([^"']+)["']/m.exec(g)?.[1];
  const jarName = archiveFileName ?? `${dir === root ? projName : dir.split("/").pop()}${version ? `-${version}` : ""}.jar`;
  const modules = [...settings.matchAll(/\binclude\s*\(?([^)\n]*)\)?/g)].flatMap((m) => [...m[1]!.matchAll(/["']:?([^"']+)["']/g)].map((x) => x[1]!.replace(/:/g, "/")));
  return { file: rel, deps, boot, java, bootPlugin, kotlinPlugin, jar: { path: `build/libs/${jarName}`, source: archiveFileName ? `${rel} bootJar.archiveFileName` : `${rel} project name-version` }, modules };
}

/** `@SpringBootApplication` classes under a module (repo-relative file, line). */
function bootApps(dir: string, root: string): SpringProject["app"][] {
  const src = join(dir, "src", "main");
  if (!existsSync(src)) return [];
  const out: SpringProject["app"][] = [];
  for (const f of walkFiles(src, (n) => /\.(?:java|kt)$/.test(n))) {
    const t = read(f).replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " ")).replace(/\/\/[^\n]*/g, "");
    const m = /@SpringBootApplication\b[\s\S]*?\bclass\s+(\w+)/.exec(t);
    if (m) out.push({ className: m[1]!, file: relative(root, f), line: lineOf(t, m.index) });
  }
  return out;
}

function countLangs(dir: string): { java: number; kotlin: number } {
  const src = join(dir, "src", "main");
  if (!existsSync(src)) return { java: 0, kotlin: 0 };
  const files = walkFiles(src, (n) => /\.(?:java|kt)$/.test(n));
  return { java: files.filter((f) => f.endsWith(".java")).length, kotlin: files.filter((f) => f.endsWith(".kt")).length };
}

export function detectSpring(root: string): SpringProject | undefined {
  if (!isJvmBuild(root)) return undefined;
  const unsupported: Evidence[] = [];
  const notes: string[] = [];
  const maven = existsSync(join(root, "pom.xml"));
  const buildTool: SpringProject["buildTool"] = maven ? "maven" : "gradle";
  const wrapper = maven ? existsSync(join(root, "mvnw")) : existsSync(join(root, "gradlew"));

  // ---- runnable module
  const rootFacts = maven ? mavenFacts(root, root) : gradleFacts(root, root);
  let module = ".";
  const modules = rootFacts.modules.filter((m) => existsSync(join(root, m)));
  if (modules.length) {
    const candidates = modules.filter((m) => {
      const d = join(root, m);
      const f = maven ? (existsSync(join(d, "pom.xml")) ? mavenFacts(d, root) : undefined) : gradleFacts(d, root);
      return !!f && f.bootPlugin && bootApps(d, root).length > 0;
    });
    if (candidates.length === 1) {
      module = candidates[0]!;
      notes.push(`multi-module build (${modules.length} modules): runnable module ${module} (has @SpringBootApplication and the Boot plugin)`);
    } else {
      unsupported.push({
        item: candidates.length
          ? `여러 모듈이 실행 가능해 보임(${candidates.join(", ")}): 어느 앱을 시험할지 정할 수 없음. 복잡한 멀티모듈은 아직 지원하지 않음`
          : `멀티모듈 빌드(${modules.join(", ")})에서 @SpringBootApplication + Boot 플러그인을 가진 모듈을 찾지 못함`,
        where: rootFacts.file,
      });
    }
  }
  const mdir = join(root, module);
  const mf = module === "." ? rootFacts : maven ? mavenFacts(mdir, root) : gradleFacts(mdir, root);
  const deps = [...new Set([...rootFacts.deps, ...mf.deps])];
  const boot = mf.boot ?? rootFacts.boot;
  const java = mf.java ?? rootFacts.java;
  const apps = bootApps(mdir, root);
  const languages = countLangs(mdir);

  // ---- support level
  let bootStatus: SpringProject["bootStatus"] = "none";
  const hasBootDeps = deps.some((d) => d.startsWith("org.springframework.boot:"));
  if (boot) {
    const major = Number(boot.version.split(".")[0]);
    bootStatus = major === 3 ? "supported" : "unverified";
    if (major !== 3) notes.push(`Spring Boot ${boot.version}: 호환성 미검증 (검증된 fixture는 Boot 3.x). 결과를 그대로 신뢰하지 말 것`);
  } else if (hasBootDeps || apps.length) {
    bootStatus = "unverified";
    notes.push("Spring Boot 버전을 빌드 파일에서 찾지 못함 (BOM/플러그인 버전이 외부에 있음?): 호환성 미검증");
  } else {
    unsupported.push({ item: "Spring Boot가 아님 (Boot 플러그인·parent·의존성 없음). Boot 없는 Spring MVC/WAR는 아직 지원하지 않음", where: mf.file });
  }
  if (!apps.length && bootStatus !== "none") unsupported.push({ item: "@SpringBootApplication 클래스를 찾지 못함: 실행 진입점 불명", where: module === "." ? "src/main" : `${module}/src/main` });
  if (apps.length > 1) notes.push(`@SpringBootApplication 클래스가 ${apps.length}개: ${apps.map((a) => a!.className).join(", ")} (첫 번째 기준)`);
  if (maven && "packaging" in mf && mf.packaging === "war") unsupported.push({ item: "WAR 패키징: 실행 가능한 JAR(java -jar) 기준으로만 지원", where: mf.file });

  if (languages.kotlin > 0 && languages.java === 0) unsupported.push({ item: `Kotlin 전용 프로젝트(.kt ${languages.kotlin}개, .java 없음): 정적 분석은 Java만 지원`, where: module === "." ? "src/main" : `${module}/src/main` });
  else if (languages.kotlin > 0) notes.push(`Kotlin 파일 ${languages.kotlin}개는 분석하지 않음 (Java ${languages.java}개만 분석)`);

  const has = (re: RegExp) => deps.find((d) => re.test(d));
  const webflux = has(/:spring-boot-starter-webflux$/);
  if (webflux && !has(/:spring-boot-starter-web$/)) unsupported.push({ item: "WebFlux(리액티브) 앱: Servlet MVC만 지원", where: `${mf.file} (${webflux})` });
  const mybatis = has(/mybatis/i);
  if (mybatis) unsupported.push({ item: "MyBatis 매퍼: SQL이 XML/어노테이션에 있어 소유권 조건을 읽지 못함 (JPA만 지원)", where: `${mf.file} (${mybatis})` });
  const otherDb = has(/(?:mysql|mariadb|h2database|oracle|mssql|sqlserver|hsqldb|derby)/i);
  if (otherDb && !has(/org\.postgresql:postgresql/)) unsupported.push({ item: `PostgreSQL 외 DB 드라이버(${otherDb}): PostgreSQL만 지원`, where: mf.file });
  if (!has(/:spring-boot-starter-oauth2-resource-server$/) && !has(/spring-security-oauth2-resource-server/)) {
    unsupported.push({ item: "OAuth2 Resource Server(JWT) 의존성이 없음: 표준 JWT 인증만 자동 구성 가능", where: mf.file });
  }

  // ---- build egress: the isolated build only reaches Maven Central / Gradle plugin portal
  const risks: Evidence[] = [];
  const OK_HOST = /repo(?:1)?\.maven\.apache\.org|repo\.maven\.org|plugins\.gradle\.org|services\.gradle\.org/;
  for (const f of [rootFacts.file, mf.file, ...["settings.gradle.kts", "settings.gradle"].filter((x) => existsSync(join(root, x)))]) {
    const p = join(root, f);
    if (!existsSync(p)) continue;
    const raw = read(p);
    const text = f.endsWith(".xml") ? stripXmlComments(raw) : stripGradleComments(raw);
    const urls = f.endsWith(".xml")
      ? [...text.matchAll(/<(?:repository|pluginRepository)>[\s\S]*?<url>\s*([^<]+?)\s*<\/url>/g)].map((m) => ({ url: m[1]!, at: m.index }))
      : [...text.matchAll(/maven\s*(?:\(\s*(?:url\s*=\s*)?(?:uri\()?\s*["']([^"']+)["']|\{[^}]*?url\s*(?:=|\()?\s*(?:uri\()?\s*["']([^"']+)["'])/g)].map((m) => ({ url: (m[1] ?? m[2])!, at: m.index }));
    for (const u of urls) if (!OK_HOST.test(u.url)) risks.push({ item: `빌드 의존성 저장소 허용 목록 밖: ${u.url.replace(/\/\/[^@/]*@/, "//")} (격리 빌드에서 내려받지 못해 실패할 수 있음)`, where: `${f}:${lineOf(raw, u.at)}` });
    const foojay = /foojay-resolver/.exec(text);
    if (foojay && !java) risks.push({ item: "빌드 의존성 저장소 허용 목록 밖: foojay toolchain resolver가 있는데 Java 버전을 정하지 못함 (api.foojay.io는 차단됨, 빌드 이미지 JDK와 다르면 실패)", where: `${f}:${lineOf(raw, foojay.index)}` });
    else if (foojay) notes.push(`foojay toolchain resolver 사용: 빌드 이미지 JDK ${java!.version}가 toolchain과 같아 api.foojay.io 다운로드는 필요 없을 것으로 봄 (차단된 호스트)`);
  }

  // ---- artifact, build, start
  const prefix = module === "." ? "" : `${module}/`;
  let jar = { path: mf.jar.path, source: mf.jar.source };
  const outDir = join(mdir, maven ? "target" : "build/libs");
  if (existsSync(outDir)) {
    const jars = readdirSync(outDir).filter((f) => f.endsWith(".jar") && !/-plain\.jar$|-sources\.jar$|-javadoc\.jar$|\.original$/.test(f));
    if (jars.length === 1 && `${maven ? "target" : "build/libs"}/${jars[0]}` !== jar.path) {
      notes.push(`existing build output ${jars[0]} differs from the computed ${jar.path} (computed name used; the build recreates it)`);
    }
  }
  let build: string;
  if (maven) build = `${wrapper ? "./mvnw" : "mvn"} -B -DskipTests package${module === "." ? "" : ` -pl ${module} -am`}`;
  else build = `${wrapper ? "./gradlew" : "gradle"} --no-daemon ${module === "." ? "" : `:${module.replace(/\//g, ":")}:`}bootJar -x test`;
  if (!wrapper) notes.push(`${maven ? "mvnw" : "gradlew"} wrapper가 없음: 빌드 이미지에 ${maven ? "Maven" : "Gradle"}이 있어야 함`);
  jar = { path: `${prefix}${jar.path}`, source: jar.source };
  const start = `java -jar ${jar.path}`;

  return {
    root,
    buildTool,
    buildFile: mf.file,
    wrapper,
    module,
    ...(java ? { java } : {}),
    ...(boot ? { boot } : {}),
    bootStatus,
    ...(apps[0] ? { app: apps[0] } : {}),
    jar,
    build,
    start,
    deps,
    languages,
    unsupported,
    risks,
    notes,
  };
}
