import { createServer, type Server } from "node:http";
import { createHash } from "node:crypto";
import { z } from "zod";
import type { Registry } from "./types.js";
import type { ModelClient } from "./model-client.js";

export function mockClient(options: { registry?: Registry; recipient?: string; recall?: number; seed?: number }): ModelClient {
  const { registry, recipient, recall = 0.8, seed = 7 } = options;
  if (!Number.isFinite(recall) || recall < 0 || recall > 1) throw new Error("recall must be between 0 and 1");
  if (recipient && !registry?.recipients[recipient]) throw new Error("unknown mock recipient");
  const memorized = registry && recipient ? registry.recipients[recipient]!.canaries : [];
  return { async complete(prefix) {
    const digest = createHash("sha256").update(JSON.stringify([seed, prefix])).digest();
    const item = memorized.find((c) => c.prefix === prefix);
    if (item && digest.readUInt32BE(0) / 2 ** 32 < recall) return item.token;
    // A seeded hex-like completion, with a letter prefix independent of issued tokens.
    return String.fromCharCode(97 + digest[4]! % 26, 97 + digest[5]! % 26) + "-" + digest.subarray(6, 12).toString("hex");
  } };
}
export async function startMockServer(client: ModelClient, port = 0): Promise<{ server: Server; url: string }> {
  const server = createServer(async (req, res) => {
    if (req.method === "GET" && req.url === "/health") { res.writeHead(200).end("ok"); return; }
    if (req.method !== "POST" || req.url !== "/complete") { res.writeHead(404).end(); return; }
    try {
      const chunks: Buffer[] = []; let size = 0;
      for await (const chunk of req) {
        const data = Buffer.from(chunk as Uint8Array); size += data.length;
        if (size > 65_536) { res.writeHead(413).end(); return; }
        chunks.push(data);
      }
      const { prompt } = z.strictObject({ prompt: z.string().max(50_000) }).parse(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ completion: await client.complete(prompt) }));
    } catch { res.writeHead(400).end(); }
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 10_000;
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(port, "127.0.0.1", resolve); });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("mock server has no port");
  return { server, url: `http://127.0.0.1:${address.port}` };
}
