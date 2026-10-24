import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const varsPath = fileURLToPath(new URL('../.dev.vars', import.meta.url));
const templatePath = fileURLToPath(new URL('../.dev.vars.example', import.meta.url));
const { values } = parseArgs({ options: { url: { type: 'string' }, 'sandbox-repos': { type: 'string' } } });
const origin = values.url ? new URL(values.url) : undefined;
if (origin && (origin.protocol !== 'https:' || origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash)) {
  throw new Error('--url must be an HTTPS origin without a path, credentials or query');
}

let text = readFileSync(existsSync(varsPath) ? varsPath : templatePath, 'utf8');
function set(name, value) {
  const pattern = new RegExp(`^${name}=.*$`, 'm');
  const line = `${name}=${JSON.stringify(value)}`;
  text = pattern.test(text) ? text.replace(pattern, () => line) : `${text.trimEnd()}\n${line}\n`;
}
for (const name of ['SESSION_SECRET', 'ENCRYPTION_KEY', 'SANDBOX_WORKER_TOKEN']) {
  const current = text.match(new RegExp(`^${name}=(.*)$`, 'm'))?.[1]?.trim();
  if (!current || current === '""' || current === "''") set(name, randomBytes(32).toString('hex'));
}
if (origin) set('PUBLIC_URL', origin.origin);
if (!/^REPORT_LANG=\s*["']?(?:en|ko)["']?\s*$/m.test(text)) set('REPORT_LANG', 'en');
if (values['sandbox-repos'] !== undefined) {
  const repos = values['sandbox-repos'].split(',').map((r) => r.trim());
  if (!repos.length || repos.some((r) => !/^[\w.-]+\/[\w.-]+$/.test(r))) throw new Error('--sandbox-repos requires owner/repo names');
  set('SANDBOX_REPOS', repos.join(','));
  set('SANDBOX_ENABLED', 'true');
}
writeFileSync(varsPath, text, { mode: 0o600 });
chmodSync(varsPath, 0o600);
console.log('Local demo settings ready in apps/web/.dev.vars (gitignored, owner-only).');
console.log('Existing credentials and encryption/session keys were preserved.');
console.log('Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET in that file, then restart the dev server.');
if (origin) {
  console.log(`Homepage URL: ${origin.origin}`);
  console.log(`OAuth callback URL: ${origin.origin}/auth/github/callback`);
}
