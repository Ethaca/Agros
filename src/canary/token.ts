import { createHash, createHmac } from "node:crypto";

export function keyBytes(value = process.env.ARGOS_CANARY_KEY): Buffer {
  if (!value || !/^(?:[a-f0-9]{2}){16,}$/i.test(value)) throw new Error("ARGOS_CANARY_KEY must be hex encoding of at least 16 bytes");
  return Buffer.from(value, "hex");
}
export const keyId = (key: Buffer): string => createHash("sha256").update(key).digest("hex").slice(0, 8);
export const derive = (key: Buffer, ...parts: (string | number)[]): Buffer => createHmac("sha256", key).update(JSON.stringify(parts)).digest();
export function token(key: Buffer, dataset: string, recipient: string, index: number, control = false): string {
  const parts = [control ? "control" : "token", dataset, recipient, index];
  const hex = derive(key, ...parts).subarray(0, 6).toString("hex");
  let letters = "";
  for (let counter = 0; letters.length < 2; counter++) {
    for (const byte of derive(key, "letters", ...parts, counter)) {
      if (byte < 234) letters += String.fromCharCode(97 + byte % 26);
      if (letters.length === 2) break;
    }
  }
  return `${letters}-${hex}`;
}
