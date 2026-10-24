import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const varsPath = fileURLToPath(new URL('../.dev.vars', import.meta.url));
const templatePath = fileURLToPath(new URL('../.dev.vars.example', import.meta.url));
const args = process.argv.slice(2);
if (args.length !== 0 && (args.length !== 2 || args[0] !== '--url')) {
  throw new Error('Usage: node scripts/setup-demo.mjs [--url https://your-tunnel.example]');
}
const origin = args[1] ? new URL(args[1]) : undefined;
if (origin && (origin.protocol !== 'https:' || origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash)) {
  throw new Error('--url must be an HTTPS origin without a path, credentials or query');
}

let text = readFileSync(existsSync(varsPath) ? varsPath : templatePath, 'utf8');
function set(name, value) {
  const pattern = new RegExp(`^${name}=.*$`, 'm');
  const line = `${name}=${JSON.stringify(value)}`;
  text = pattern.test(text) ? text.replace(pattern, () => line) : `${text.trimEnd()}\n${line}\n`;
}
for (const name of ['SESSION_SECRET', 'ENCRYPTION_KEY']) {
  const current = text.match(new RegExp(`^${name}=(.*)$`, 'm'))?.[1]?.trim();
  if (!current || current === '""' || current === "''") set(name, randomBytes(32).toString('hex'));
}
if (origin) set('PUBLIC_URL', origin.origin);
set('REPORT_LANG', 'en');
writeFileSync(varsPath, text, { mode: 0o600 });
chmodSync(varsPath, 0o600);
console.log('Local demo settings ready in apps/web/.dev.vars (gitignored, owner-only).');
console.log('Existing credentials and encryption/session keys were preserved.');
console.log('Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET in that file, then restart the dev server.');
if (origin) {
  console.log(`Homepage URL: ${origin.origin}`);
  console.log(`OAuth callback URL: ${origin.origin}/auth/github/callback`);
}
