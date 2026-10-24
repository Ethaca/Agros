export interface ChangedFile {
  filename: string;
  status: 'added' | 'modified' | 'removed' | 'renamed' | string;
  patch?: string;
}

export interface DiffLine {
  type: 'add' | 'del' | 'ctx';
  content: string;
  /** new-side line number (add/ctx) */
  newLine?: number;
  /** old-side line number (del/ctx) */
  oldLine?: number;
}

export interface ParsedPatch {
  lines: DiffLine[];
  /** new-side line numbers a GitHub review comment can anchor on (side=RIGHT) */
  commentable: Set<number>;
}

const HUNK = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/;

export function parsePatch(patch: string | undefined): ParsedPatch {
  const lines: DiffLine[] = [];
  const commentable = new Set<number>();
  if (!patch) return { lines, commentable };

  let oldNo = 0;
  let newNo = 0;
  let inHunk = false;
  for (const raw of patch.split('\n')) {
    const hunk = HUNK.exec(raw);
    if (hunk) {
      oldNo = Number(hunk[1]);
      newNo = Number(hunk[2]);
      inHunk = true;
      continue;
    }
    if (!inHunk || raw.startsWith('\\')) continue;
    const marker = raw[0];
    const content = raw.slice(1);
    if (marker === '+') {
      lines.push({ type: 'add', content, newLine: newNo });
      commentable.add(newNo++);
    } else if (marker === '-') {
      lines.push({ type: 'del', content, oldLine: oldNo++ });
    } else if (marker === ' ' || raw === '') {
      lines.push({ type: 'ctx', content, newLine: newNo, oldLine: oldNo++ });
      commentable.add(newNo++);
    }
  }
  return { lines, commentable };
}

/** `git diff` 전체 출력을 파일 단위로 쪼갠다 (CLI / 플레이그라운드 용) */
export function splitUnifiedDiff(diff: string): ChangedFile[] {
  const files: ChangedFile[] = [];
  const chunks = diff.replace(/\r\n/g, '\n').split(/^(?=diff --git )/m);
  for (const chunk of chunks) {
    const lines = chunk.split('\n');
    const plus = lines.find((l) => l.startsWith('+++ '));
    const minus = lines.find((l) => l.startsWith('--- '));
    const header = /^diff --git a\/(.+?) b\/(.+)$/.exec(lines[0] ?? '');
    const firstHunk = lines.findIndex((l) => l.startsWith('@@'));
    if (firstHunk < 0) continue;

    const strip = (l?: string) => l?.slice(4).replace(/^[ab]\//, '').replace(/\t.*$/, '');
    const newPath = strip(plus);
    const oldPath = strip(minus);
    const removed = newPath === '/dev/null';
    const added = oldPath === '/dev/null';
    const filename = (removed ? oldPath : newPath) ?? header?.[2] ?? 'unknown';
    files.push({
      filename,
      status: removed ? 'removed' : added ? 'added' : 'modified',
      patch: lines.slice(firstHunk).join('\n').replace(/\n$/, ''),
    });
  }
  return files;
}

/** 리뷰 가치가 없는 파일(바이너리, lock, 빌드 산출물 등)은 제외 */
const SKIP = /(^|\/)(node_modules|vendor|dist|build|\.next|coverage)\/|\.(lock|png|jpe?g|gif|svg|ico|webp|pdf|zip|gz|woff2?|ttf|eot|mp4|mp3|min\.js|map|snap)$|(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|go\.sum|Cargo\.lock|poetry\.lock|Gemfile\.lock)$/i;
const CODE = /\.(m?[jt]sx?|cjs|py|rb|go|java|kt|kts|scala|php|cs|rs|swift|ex|exs|graphql|gql|ya?ml|json|toml|ini|conf|env|properties|tf|sql|proto)$|(^|\/)(Dockerfile|\.env[\w.-]*)$/i;

export const isScannable = (f: ChangedFile) => !!f.patch && !SKIP.test(f.filename) && CODE.test(f.filename);
