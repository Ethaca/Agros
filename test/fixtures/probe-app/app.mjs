// Reports what the sandbox really allows, from the inside. Used by container tests.
import { createServer, connect } from "node:net";
import { createServer as http } from "node:http";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { networkInterfaces } from "node:os";

if (process.env.CRASH) {
  console.error("boot failed: CRASH set");
  process.exit(3);
}

const attempt = (fn) => {
  try {
    return { ok: true, value: fn() };
  } catch (e) {
    return { ok: false, error: e.code ?? String(e.message) };
  }
};

const egress = (host, port) =>
  new Promise((done) => {
    const s = connect({ host, port, timeout: 1500 });
    s.once("connect", () => (s.destroy(), done({ ok: true })));
    s.once("timeout", () => (s.destroy(), done({ ok: false, error: "timeout" })));
    s.once("error", (e) => done({ ok: false, error: e.code ?? e.message }));
  });

http(async (req, res) => {
  if (req.url === "/health") return res.end("ok");
  if (req.url === "/probe") {
    const status = readFileSync("/proc/self/status", "utf8");
    const body = {
      uid: process.getuid(),
      capEff: /CapEff:\s+(\w+)/.exec(status)?.[1],
      noNewPrivs: /NoNewPrivs:\s+(\d)/.exec(status)?.[1],
      interfaces: Object.keys(networkInterfaces()),
      egressIp: await egress("1.1.1.1", 443),
      egressDns: await egress("example.com", 443),
      writeRoot: attempt(() => writeFileSync("/etc/argos-probe", "x")),
      writeUsr: attempt(() => writeFileSync("/usr/argos-probe", "x")),
      writeTmp: attempt(() => writeFileSync("/tmp/argos-probe", "x")),
      writeApp: attempt(() => writeFileSync("/app/argos-probe.txt", "x")),
      hostPathVisible: existsSync("/Users") || existsSync("/private") || existsSync("/var/folders"),
      env: process.env,
      cwd: process.cwd(),
    };
    return res.end(JSON.stringify(body));
  }
  res.statusCode = 404;
  res.end();
}).listen(Number(process.env.PORT), "127.0.0.1");
