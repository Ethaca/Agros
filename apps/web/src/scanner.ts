import { analyze } from './analyzer.ts';
import { config } from './config.ts';
import { relatedPaths } from './context.ts';
import { decrypt } from './crypto.ts';
import { scans, users } from './db.ts';
import { isScannable, parsePatch, type ParsedPatch } from './diff.ts';
import { GitHub } from './github.ts';
import { buildReviewComments, renderSummaryMarkdown, REPORT_MARKER, shouldFail, statusDescription } from './reporter.ts';

// Workers 무료 플랜의 서브리퀘스트 한도(50)를 넘지 않도록 전체 파일 컨텍스트는 일부만 가져온다
const MAX_CHANGED_CONTEXT = 10;

/** Cloudflare Queue 로 전달되는 메시지 */
export interface ScanJob { userId: number; repo: string; number: number; force?: boolean }

export async function scanPullRequest({ userId, repo, number, force }: ScanJob): Promise<number | null> {
  const user = await users.get(userId);
  if (!user) throw new Error(`user ${userId} 없음`);
  const gh = new GitHub(decrypt(user.token_enc));

  const pr = await gh.getPull(repo, number);
  const sha = pr.head.sha;
  if (!force && await scans.existsForSha(repo, number, sha)) {
    console.log(`[scan] ${repo}#${number}@${sha.slice(0, 7)} 이미 검사됨, 건너뜀`);
    return null;
  }

  const scanId = await scans.create({ user_id: userId, repo_full_name: repo, pr_number: number, pr_title: pr.title, head_sha: sha });
  const detailUrl = `${config.publicUrl}/scans/${scanId}`;
  console.log(`[scan] #${scanId} ${repo}#${number}@${sha.slice(0, 7)} 시작`);

  try {
    await gh.createStatus(repo, sha, 'pending', 'API 보안 검사 중...', detailUrl).catch(() => {});

    const files = await gh.listPullFiles(repo, number);
    const targets = files.filter((f) => isScannable(f) && f.status !== 'removed');

    // LLM 이 라우터/미들웨어 구성을 볼 수 있도록 변경 파일의 전체 내용도 가져온다
    const fileContents = new Map<string, string>();
    await Promise.all(
      targets.slice(0, MAX_CHANGED_CONTEXT).map(async (f) => {
        try { fileContents.set(f.filename, await gh.getFileContent(repo, f.filename, sha)); } catch { /* 큰 파일 등은 diff 만 사용 */ }
      }),
    );

    const relatedContents = new Map<string, string>();
    // 최대 10개 변경 파일 + 5개 직접 import 파일. 모든 파일은 동일한 PR head에서 읽는다.
    if (fileContents.size) {
      const paths = await gh.listTreePaths(repo, sha).catch(() => []);
      const changed = new Set(files.map((f) => f.filename));
      await Promise.all(relatedPaths(fileContents, paths.filter((p) => !changed.has(p))).map(async (path) => {
        try { relatedContents.set(path, await gh.getFileContent(repo, path, sha)); } catch { /* 문맥이 없으면 추정으로 표시 */ }
      }));
    }

    const result = await analyze({ files, fileContents, relatedContents, pr: { repo, title: pr.title, body: pr.body } });
    const summary = renderSummaryMarkdown(result, { detailUrl, sha });

    await gh.upsertIssueComment(repo, number, REPORT_MARKER, summary, user.login);

    const patches = new Map<string, ParsedPatch>(files.map((f) => [f.filename, parsePatch(f.patch)]));
    const comments = buildReviewComments(result, patches);
    if (comments.length) {
      const body = `🔐 Argos 이 \`${sha.slice(0, 7)}\` 에서 ${comments.length}건을 인라인으로 표시했습니다.`;
      await gh.createReview(repo, number, sha, body, comments).catch((err) => console.warn('[scan] 인라인 리뷰 실패:', err.message));
    }

    await gh.createStatus(repo, sha, shouldFail(result) ? 'failure' : 'success', statusDescription(result), detailUrl);
    await scans.finish(scanId, result.risk, JSON.stringify(result));
    console.log(`[scan] #${scanId} 완료: risk=${result.risk}, findings=${result.findings.length}`);
    return scanId;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await scans.fail(scanId, message);
    await gh.createStatus(repo, sha, 'error', '검사 중 오류 발생', detailUrl).catch(() => {});
    throw err;
  }
}
