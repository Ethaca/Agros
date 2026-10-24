import { Buffer } from 'node:buffer';
import { timingSafeEqual } from 'node:crypto';
import { Hono } from 'hono';
import { MAX_ARCHIVE_BYTES, MAX_RESULT_BYTES, RUNTIME_LIMITS, SandboxResult } from '../../../src/sandbox/protocol.js';
import { config } from './config.ts';
import { decrypt, randomToken } from './crypto.ts';
import { sandboxJobs, users, type SandboxJobRow } from './db.ts';
import { GitHub } from './github.ts';

export const SANDBOX_MARKER = '<!-- argos-sandbox -->';
export function workerAuthorized(header: string | undefined, token: string): boolean {
  if (token.length < 32 || !header?.startsWith('Bearer ')) return false;
  const actual = Buffer.from(header.slice(7)), expected = Buffer.from(token);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
export const sandboxAllowed = (repo: string): boolean => config.sandboxEnabled && config.sandboxWorkerToken.length >= 32 && config.sandboxRepos.includes(repo);
const cell = (text: string) => text.replace(/[|`<>\[\]@\r\n]/g, ' ').slice(0, 500);

export function renderSandboxReport(result: SandboxResult, sha: string): string {
  const ko = config.lang === 'ko';
  const lines = [SANDBOX_MARKER, `## ${ko ? 'Docker 실제 실행 검사' : 'Docker runtime verification'}`, '', `Commit: \`${sha.slice(0, 7)}\` · ${result.durationMs}ms · \`${cell(result.image)}\``, '',
    ko ? '준비(SQL 분석·테스트 DB 생성)와 고객 앱 실행을 각각 네트워크 없는 Docker 안에서 수행합니다. GitHub 토큰은 전달하지 않습니다.' : 'Preparation (including SQL and seeding) and app execution use separate network-disabled containers. GitHub tokens are not passed to either container.', ''];
  if (result.status !== 'completed') {
    lines.push(`**${ko ? '검증 미완료' : 'NOT VERIFIED'}: ${result.status}**`, '', cell(result.reason ?? 'Preparation/runtime could not complete.'), '', ko ? '이 결과를 안전 또는 검사 통과로 해석하면 안 됩니다.' : 'This is not a security pass.');
    return lines.join('\n');
  }
  lines.push(ko ? '**정책 기준:** 저장소 설정 또는 자동 초안입니다. 업무상 올바른 권한인지는 별도 검토가 필요합니다.' : '**Policy basis:** repository settings or an automatic draft; intended business permissions still require review.', `Policy: ${result.policy}`, '',
    '| Check | Vulnerable under policy | Suspected | No finding in executed scope | Skipped |', '|---|---:|---:|---:|---:|');
  for (const check of ['bola', 'unauth', 'sqli', 'secrets']) {
    const fs = result.findings.filter((f) => f.check === check);
    const n = (v: string) => fs.filter((f) => f.verdict === v).length;
    lines.push(`| ${check} | ${n('VULNERABLE')} | ${n('SUSPECTED')} | ${n('OK')} | ${n('SKIPPED')} |`);
  }
  lines.push('', ko ? '정상 사용자 자신의 데이터 접근 대조를 통과한 실행입니다.' : 'Authenticated own-data control requests succeeded.', '', `Matrix: ${result.matrix!.cells.length} cells · Routes: ${result.routes.length}`, '');
  for (const f of result.findings.filter((f) => f.verdict !== 'OK').slice(0, 80)) lines.push(`- **${f.verdict} [${f.check}]** ${cell(f.resourceId)} / ${cell(f.persona)}: ${cell(f.detail)} (${f.proof.status ?? 'no status'})`);
  lines.push('', '<details><summary>Executed routes</summary>', '', ...result.routes.map((r) => `- \`${cell(r)}\``), '', '</details>', '', '<details><summary>Access matrix (up to 100 cells)</summary>', '', '| Persona | Resource | Target | Expected | Observed | Verdict | HTTP |', '|---|---|---|---|---|---|---|');
  for (const c of result.matrix!.cells.slice(0, 100)) lines.push(`| ${cell(c.persona)} | ${cell(c.resource)} | ${cell(c.target ?? '-')} | ${c.expected} | ${c.observed} | ${c.verdict} | ${c.evidence.status ?? '-'} |`);
  lines.push('', '</details>', '', '**Not executed / limits**', ...RUNTIME_LIMITS.map((r) => `- ${r}`), ...result.untested.map((r) => `- ${cell(r)}`));
  const report = lines.join('\n');
  return report.length <= 60_000 ? report : report.slice(0, 59_000) + '\n\n</details>\n\nReport truncated. See the Argos dashboard for the full result.';
}

export async function enqueueSandbox(scanId: number, userId: number, repo: string, pr: number, sha: string) {
  if (!sandboxAllowed(repo)) return;
  await sandboxJobs.enqueue(scanId, userId, repo, pr, sha);
  const user = await users.get(userId);
  if (user) await new GitHub(decrypt(user.token_enc)).createStatus(repo, sha, 'pending', 'Docker runtime verification queued', `${config.publicUrl}/scans/${scanId}`, 'argos/sandbox').catch(() => {});
}

const router = new Hono();
router.use('*', async (c, next) => {
  if (!config.sandboxEnabled || !workerAuthorized(c.req.header('authorization'), config.sandboxWorkerToken)) return c.text('unauthorized', 401);
  return next();
});
router.post('/claim', async (c) => {
  const row = await sandboxJobs.claim(config.sandboxRepos, randomToken(32), Date.now());
  if (!row) return c.body(null, 204);
  return c.json({ job: { id: row.id, lease: row.lease, repo: row.repo, pr: row.pr, sha: row.sha }, result: row.result_json ? JSON.parse(row.result_json) : null });
});

async function active(id: string, lease: string | undefined): Promise<SandboxJobRow | null> {
  if (!/^\d+$/.test(id) || !lease || !/^[a-f0-9]{64}$/.test(lease)) return null;
  const row = await sandboxJobs.active(Number(id), lease);
  return row && sandboxAllowed(row.repo) ? row : null;
}
router.get('/:id/source', async (c) => {
  const row = await active(c.req.param('id'), c.req.header('x-argos-lease'));
  if (!row || row.status !== 'running') return c.text('inactive job', 409);
  const user = await users.get(row.user_id);
  if (!user) return c.text('user unavailable', 409);
  try {
    const archive = await new GitHub(decrypt(user.token_enc)).sourceArchive(row.repo, row.sha);
    const reader = archive.body!.getReader();
    const chunks: Uint8Array[] = []; let bytes = 0;
    while (true) {
      const { done, value } = await reader.read(); if (done) break;
      if ((bytes += value.length) > MAX_ARCHIVE_BYTES) { await reader.cancel(); return c.text('snapshot too large', 413); }
      chunks.push(value);
    }
    return new Response(Buffer.concat(chunks), { headers: { 'content-type': 'application/gzip', 'cache-control': 'no-store' } });
  } catch (error) {
    const message = error instanceof Error ? error.message : '';
    console.warn('[sandbox snapshot]', message.replace(/https?:\/\/\S+/g, '[redacted URL]').replace(/(?:token|authorization|secret)\s*[:=]\s*\S+/gi, '[redacted credential]').slice(0, 160) || 'transport failure');
    return c.text('snapshot unavailable', 502);
  }
});
router.post('/:id/complete', async (c) => {
  const row = await active(c.req.param('id'), c.req.header('x-argos-lease'));
  if (!row) return c.text('inactive job', 409);
  const body = await c.req.text();
  if (Buffer.byteLength(body) > MAX_RESULT_BYTES) return c.text('result too large', 413);
  let result: SandboxResult;
  try { result = SandboxResult.parse(JSON.parse(body)); } catch { return c.text('invalid result', 400); }
  const user = await users.get(row.user_id);
  if (!user) return c.text('user unavailable', 409);
  const gh = new GitHub(decrypt(user.token_enc));
  const pr = await gh.getPull(row.repo, row.pr);
  if (pr.head.sha !== row.sha) { await sandboxJobs.finish(row.id, row.lease!, 'superseded'); return c.text('superseded', 409); }
  // Persist before publishing. An expired lease can retry publication without executing again.
  if (!await sandboxJobs.save(row.id, row.lease!, JSON.stringify(result))) return c.text('inactive job', 409);
  await gh.upsertIssueComment(row.repo, row.pr, SANDBOX_MARKER, renderSandboxReport(result, row.sha), user.login);
  const red = result.findings.some((f) => f.verdict === 'VULNERABLE');
  const uncertain = result.findings.some((f) => f.verdict === 'SUSPECTED' || f.verdict === 'SKIPPED');
  const state = result.status !== 'completed' ? 'error' : red || uncertain ? 'failure' : 'success';
  await gh.createStatus(row.repo, row.sha, state, result.status !== 'completed' ? 'Runtime verification incomplete' : red ? 'Runtime policy violations found' : uncertain ? 'Runtime verification needs review' : 'No violations in executed runtime scope', `${config.publicUrl}/scans/${row.scan_id}`, 'argos/sandbox');
  await sandboxJobs.finish(row.id, row.lease!, result.status);
  return c.json({ ok: true });
});

export { router as sandboxRouter };
