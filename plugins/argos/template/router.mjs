// A tiny Express-shaped router on node:http, so the demo runs with no `npm install`.
// Argos CI does not install dependencies of the code under test; this keeps the demo self-contained.
import { createServer } from "node:http";

export function createApp() {
  const routes = [];
  const add = (method) => (path, ...handlers) => routes.push({ method, path, handlers });

  const handle = async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    req.query = Object.fromEntries(url.searchParams);
    req.get = (name) => req.headers[name.toLowerCase()];
    res.status = (code) => ((res.statusCode = code), res);
    res.json = (body) => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(body));
    };

    if (req.method === "POST") {
      let raw = "";
      for await (const chunk of req) {
        raw += chunk;
        if (raw.length > 100_000) return res.status(413).json({ error: "payload too large" });
      }
      try {
        req.body = raw ? JSON.parse(raw) : {};
      } catch {
        return res.status(400).json({ error: "invalid json" });
      }
    }

    for (const r of routes) {
      if (r.method !== req.method) continue;
      const names = [];
      const re = new RegExp("^" + r.path.replace(/:(\w+)/g, (_, n) => (names.push(n), "([^/]+)")) + "$");
      const m = re.exec(url.pathname);
      if (!m) continue;
      req.params = Object.fromEntries(names.map((n, i) => [n, decodeURIComponent(m[i + 1])]));
      let i = 0;
      const next = () => r.handlers[i++](req, res, next);
      try {
        return await next();
      } catch {
        return res.status(500).json({ error: "internal error" });
      }
    }
    res.status(404).json({ error: "not found" });
  };

  return {
    get: add("GET"),
    post: add("POST"),
    listen: (port, host, cb) => createServer(handle).listen(port, host, cb),
  };
}
