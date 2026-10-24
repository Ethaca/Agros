import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Do not expose Wrangler's local database explorer through the public tunnel.
const child = spawn(process.execPath, [
  fileURLToPath(new URL('../node_modules/wrangler/bin/wrangler.js', import.meta.url)),
  'dev', '--ip', '127.0.0.1', '--port', '8787',
], {
  cwd: fileURLToPath(new URL('..', import.meta.url)),
  env: { ...process.env, X_LOCAL_EXPLORER: 'false', X_LOCAL_OBSERVABILITY: 'false' },
  stdio: 'inherit',
});
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));
child.on('error', () => { console.error('Failed to start the demo server.'); process.exitCode = 1; });
child.on('exit', (code) => { process.exitCode = code ?? 1; });
