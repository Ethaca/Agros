import { z } from "zod";

export interface ModelClient { complete(prefix: string): Promise<string> }
export async function boundedJson(response: Response, limit = 1_048_576): Promise<unknown> {
  if (!response.ok || !response.body) { await response.body?.cancel(); throw new Error("model request failed"); }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) throw new Error("model response too large");
      chunks.push(value);
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } finally { await reader.cancel(); }
}
export function httpModel(base: string, timeoutMs = 10_000): ModelClient {
  const url = new URL(base);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash)
    throw new Error("model must be an HTTP(S) URL without credentials, query, or fragment");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new Error("timeout must be a positive integer");
  url.pathname = url.pathname.replace(/\/$/, "") + "/complete";
  return {
    async complete(prompt) {
      const response = await fetch(url, {
        method: "POST", redirect: "error", headers: { "content-type": "application/json" },
        body: JSON.stringify({ prompt }), signal: AbortSignal.timeout(timeoutMs),
      });
      return z.object({ completion: z.string().max(100_000) }).parse(await boundedJson(response)).completion;
    },
  };
}
