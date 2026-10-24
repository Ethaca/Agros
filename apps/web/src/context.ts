/** 저장소에 실제 존재하는 상대 import만 해석한다. 별칭·동적 import는 추정하지 않는다. */
export function relatedPaths(contents: Map<string, string>, paths: string[], max = 5): string[] {
  if (max <= 0) return [];
  const known = new Set(paths);
  const out = new Set<string>();
  for (const [file, content] of contents) {
    const imports = content.matchAll(/(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)['"](\.{1,2}\/[^'"\n]+)['"]/g);
    for (const match of imports) {
      const target = new URL(match[1], `https://repo.local/${file}`).pathname.slice(1);
      const stem = target.replace(/\.(?:m?js|cjs)$/, '');
      const candidates = [target, ...['.ts', '.tsx', '.js', '.mjs', '.mts', '.cts', '/index.ts', '/index.tsx', '/index.js'].map((ext) => stem + ext)];
      const path = candidates.find((p) => known.has(p));
      if (path && /\.(?:[cm]?[jt]sx?)$/.test(path) && !contents.has(path)) out.add(path);
      if (out.size >= max) return [...out];
    }
  }
  return [...out];
}
