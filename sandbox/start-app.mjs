// Trusted launcher in a read-only image. The app receives only synthetic credentials.
import { copyFileSync, readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
const { entry, env } = JSON.parse(readFileSync('/work/launch.json', 'utf8'));
copyFileSync('/work/target/.argos-test.db', '/tmp/argos-test.db');
const child = spawn(process.execPath, [`/work/target/${entry}`], {
  cwd: '/work/target', stdio: 'inherit',
  env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp', PORT: '3000', ...env },
});
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));
child.on('exit', (code) => { process.exitCode = code ?? 1; });
