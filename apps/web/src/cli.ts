import { existsSync, readFileSync } from 'node:fs';
import { analyze } from './analyzer.ts';
import { bindEnv } from './config.ts';
import { splitUnifiedDiff } from './diff.ts';
import { renderSummaryMarkdown, shouldFail } from './reporter.ts';

// 사용법: npm run scan -- <diff 파일 | -> [--json] [--no-llm] [--intent "변경 목적"]
// POE_API_KEY 등은 환경변수나 .dev.vars 에서 읽는다
for (const f of ['.dev.vars', '.env']) if (existsSync(f)) process.loadEnvFile(f);
bindEnv(process.env);

const args = process.argv.slice(2);
const intentIndex = args.indexOf('--intent');
if (intentIndex !== -1 && (!args[intentIndex + 1] || args[intentIndex + 1].startsWith('--'))) {
  console.error('--intent 뒤에 변경 목적을 입력해 주세요.');
  process.exit(2);
}
const intent = intentIndex === -1 ? undefined : args[intentIndex + 1];
const path = args.find((a, i) => !a.startsWith('--') && !(intentIndex !== -1 && i === intentIndex + 1));
if (!path) {
  console.error('사용법: npm run scan -- <diff 파일 | - (stdin)> [--json] [--no-llm] [--intent "변경 목적"]\n예: git diff main | npm run scan -- -');
  process.exit(2);
}
if (args.includes('--no-llm')) bindEnv({ POE_API_KEY: '' });

const diff = readFileSync(path === '-' ? 0 : path, 'utf8');
const result = await analyze({ files: splitUnifiedDiff(diff), intent });
console.log(args.includes('--json') ? JSON.stringify(result, null, 2) : renderSummaryMarkdown(result));
process.exit(shouldFail(result) ? 1 : 0);
