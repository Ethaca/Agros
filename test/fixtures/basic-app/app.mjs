import { createServer } from "node:http";
import { writeFileSync } from "node:fs";

if (process.env.CRASH) {
  console.error("boot failed: CRASH set");
  process.exit(3);
}
const delay = Number(process.env.READY_DELAY_MS ?? 0);
const up = Date.now() + delay;

createServer((req, res) => {
  if (req.url === "/health") {
    res.statusCode = Date.now() >= up ? 200 : 503;
    return res.end("ok");
  }
  if (req.url === "/env") return res.end(JSON.stringify(process.env));
  if (req.url === "/write") {
    writeFileSync("written.txt", "x");
    return res.end("written");
  }
  res.statusCode = 404;
  res.end();
}).listen(Number(process.env.PORT), "127.0.0.1", () => console.log("listening", process.env.PORT));
