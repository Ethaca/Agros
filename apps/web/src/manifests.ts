import { isExactVersion } from './versions.ts';

/**
 * 레포에서 "무엇을 어떤 버전으로 쓰는가"를 뽑는다. lock 파일만 보면 PHP 같은 런타임 취약점을 놓치므로
 * Dockerfile, 런타임 버전 파일, CI 설정까지 읽는다.
 */
export interface Component {
  /** 'npm:next', 'composer:guzzlehttp/guzzle', 'runtime:php' */
  target: string;
  /** 파일에 적힌 버전 표기 그대로 (줄 안에서 이 문자열을 패치 버전으로 바꿔 PR 을 만든다) */
  spec: string;
  exact: boolean;
  file: string;
  line: number;
  /** 그 줄 원문 */
  text: string;
  /** deps: 패키지 의존성, lock: lock 파일 (텍스트 치환으로 고칠 수 없음), image: 컨테이너, runtime: 런타임 선언, ci: CI 설정 */
  context: 'deps' | 'lock' | 'image' | 'runtime' | 'ci';
}

const RUNTIME_IMAGES: Record<string, string> = { php: 'php', node: 'node', python: 'python' };
const TOOL_NAMES: Record<string, string> = { php: 'php', nodejs: 'node', node: 'node', python: 'python' };
const MAX_COMPONENTS = 4000;

const base = (path: string) => path.slice(path.lastIndexOf('/') + 1);
const dir = (path: string) => path.slice(0, path.lastIndexOf('/') + 1);

export function isManifestPath(path: string): boolean {
  if (/(^|\/)(node_modules|vendor|\.git)\//.test(path)) return false;
  const name = base(path);
  if (/^\.github\/workflows\/[^/]+\.ya?ml$/.test(path)) return true;
  return /^(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|composer\.lock|package\.json|composer\.json|\.nvmrc|\.node-version|\.python-version|\.tool-versions)$/.test(name)
    || /^(Dockerfile(\..+)?|.+\.Dockerfile|(docker-)?compose(\..+)?\.ya?ml)$/i.test(name);
}

/** 읽을 매니페스트 파일. 서브리퀘스트 한도 때문에 얕은 경로부터 max 개만 */
export function selectManifestPaths(paths: string[], max = 20): string[] {
  const rank = (p: string) => p.split('/').length + (p.startsWith('.github/') ? 3 : 0) + (base(p) === 'package.json' || base(p) === 'composer.json' ? 0.5 : 0);
  return paths.filter(isManifestPath).sort((a, b) => rank(a) - rank(b) || a.localeCompare(b)).slice(0, max);
}

const clip = (s: string) => s.trim().slice(0, 200);

export function parseManifest(path: string, content: string): Component[] {
  const name = base(path);
  const lines = content.split('\n');
  const out: Component[] = [];
  const push = (target: string, spec: string, i: number, context: Component['context']) => {
    spec = spec.trim();
    if (!spec || !/\d/.test(spec) || out.length >= MAX_COMPONENTS) return;
    out.push({ target: target.toLowerCase(), spec, exact: isExactVersion(spec), file: path, line: i + 1, text: clip(lines[i]), context });
  };

  if (name === 'package-lock.json') {
    // v1 의 "dependencies" 중첩, v2/v3 의 "packages" 모두 "키": { 다음에 "version" 이 온다
    const skip = new Set(['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies', 'requires', 'engines', 'bin', 'funding', 'packages', '']);
    let key: string | null = null;
    lines.forEach((l, i) => {
      const k = /^\s*"([^"]*)": \{\s*$/.exec(l);
      if (k) { const at = k[1].lastIndexOf('node_modules/'); key = at < 0 ? k[1] : k[1].slice(at + 13); return; }
      const v = /^\s*"version": "([^"]+)"/.exec(l);
      if (v && key && !skip.has(key)) { push(`npm:${key}`, v[1], i, 'lock'); key = null; }
    });
  } else if (name === 'pnpm-lock.yaml') {
    let inPackages = false;
    lines.forEach((l, i) => {
      if (/^\S/.test(l)) inPackages = /^(packages|snapshots):/.test(l);
      const m = inPackages && /^ {2}['"]?\/?((?:@[^/@\s'"]+\/)?[^/@\s'"(]+)[@/](\d[^\s'"():]*)/.exec(l);
      if (m) push(`npm:${m[1]}`, m[2], i, 'lock');
    });
  } else if (name === 'yarn.lock') {
    let pkg: string | null = null;
    lines.forEach((l, i) => {
      const h = /^"?((?:@[^/@\s"]+\/)?[^@\s",]+)@/.exec(l);
      if (h) { pkg = h[1]; return; }
      const v = /^\s+version:? "?([^"\s]+)"?/.exec(l);
      if (v && pkg) { push(`npm:${pkg}`, v[1], i, 'lock'); pkg = null; }
    });
  } else if (name === 'composer.lock') {
    let pkg: { name: string; at: number } | null = null;
    lines.forEach((l, i) => {
      const n = /^\s*"name": "([\w.-]+\/[\w.-]+)"/.exec(l);
      if (n) { pkg = { name: n[1], at: i }; return; }
      const v = /^\s*"version": "v?([^"]+)"/.exec(l);
      if (v && pkg && i - pkg.at <= 3) { push(`composer:${pkg.name}`, v[1], i, 'lock'); pkg = null; }
    });
  } else if (name === 'package.json' || name === 'composer.json') {
    let json: Record<string, any>;
    try { json = JSON.parse(content); } catch { return []; }
    const lineOf = (key: string, value: string) => {
      const i = lines.findIndex((l) => l.includes(`"${key}"`) && l.includes(`"${value}"`));
      return i < 0 ? 0 : i;
    };
    if (name === 'package.json') {
      if (typeof json.engines?.node === 'string') push('runtime:node', json.engines.node, lineOf('node', json.engines.node), 'runtime');
      for (const section of ['dependencies', 'devDependencies']) {
        for (const [pkg, spec] of Object.entries(json[section] ?? {})) {
          if (typeof spec === 'string') push(`npm:${pkg}`, spec, lineOf(pkg, spec), 'deps');
        }
      }
    } else {
      for (const [pkg, spec] of Object.entries({ ...json['require-dev'], ...json.require })) {
        if (typeof spec !== 'string' || pkg.startsWith('ext-')) continue;
        if (pkg === 'php') push('runtime:php', spec, lineOf(pkg, spec), 'runtime');
        else if (pkg.includes('/')) push(`composer:${pkg}`, spec, lineOf(pkg, spec), 'deps');
      }
    }
  } else if (name === '.nvmrc' || name === '.node-version' || name === '.python-version') {
    const i = lines.findIndex((l) => l.trim() && !l.trim().startsWith('#'));
    if (i >= 0) push(name === '.python-version' ? 'runtime:python' : 'runtime:node', lines[i].trim().replace(/^v/, ''), i, 'runtime');
  } else if (name === '.tool-versions') {
    lines.forEach((l, i) => {
      const m = /^\s*(\w+)\s+v?(\d[^\s#]*)/.exec(l);
      if (m && TOOL_NAMES[m[1]]) push(`runtime:${TOOL_NAMES[m[1]]}`, m[2], i, 'runtime');
    });
  } else if (path.startsWith('.github/workflows/')) {
    lines.forEach((l, i) => {
      const m = /\b(php|node|python)-version:\s*\[?\s*["']?([\d.x]+)/.exec(l);
      if (m) push(`runtime:${m[1]}`, m[2], i, 'ci');
    });
  } else {
    // Dockerfile / compose: FROM php:8.3.35-fpm, image: node:20.11.1-alpine
    lines.forEach((l, i) => {
      const m = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)/i.exec(l) ?? /^\s*image:\s*["']?([^\s"']+)/.exec(l);
      if (!m) return;
      const ref = m[1].split('@')[0];
      const colon = ref.lastIndexOf(':');
      if (colon < 0 || ref.includes('$')) return;
      const image = base(ref.slice(0, colon));
      const version = /^\d+(?:\.\d+){0,2}/.exec(ref.slice(colon + 1))?.[0];
      if (RUNTIME_IMAGES[image] && version) push(`runtime:${RUNTIME_IMAGES[image]}`, version, i, 'image');
    });
  }
  return out;
}

/** lock 파일이 있는 디렉터리에서는 package.json/composer.json 의 범위 표기 의존성을 버린다 (lock 이 실제 버전) */
export function buildInventory(files: { path: string; content: string }[]): Component[] {
  const lockDirs = new Map<string, Set<string>>();
  for (const f of files) {
    const eco = /^(package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$/.test(base(f.path)) ? 'npm' : base(f.path) === 'composer.lock' ? 'composer' : null;
    if (eco) lockDirs.set(eco, (lockDirs.get(eco) ?? new Set()).add(dir(f.path)));
  }
  const seen = new Set<string>();
  const all: Component[] = [];
  for (const f of files) {
    for (const c of parseManifest(f.path, f.content)) {
      const eco = c.target.split(':')[0];
      if (c.context === 'deps' && lockDirs.get(eco)?.has(dir(c.file))) continue;
      const key = `${c.target}@${c.spec}@${c.file}`;
      if (seen.has(key)) continue;
      seen.add(key);
      all.push(c);
      if (all.length >= MAX_COMPONENTS) return all;
    }
  }
  return all;
}
