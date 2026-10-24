import { generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";
import type { IssuerHandle, MintOptions } from "../stack.js";

/**
 * Per-run test JWT issuer keys. Private keys live only in this process (never on disk, never in a container);
 * the sidecar gets the public JWKS only. The "wrong" key shares the kid, so a token signed with it reaches the
 * app's signature check and must fail there (not merely on an unknown kid).
 */

export interface IssuerKeys {
  kid: string;
  privateKey: KeyObject;
  wrongKey: KeyObject;
  jwks: { keys: Record<string, unknown>[] };
}

const b64url = (b: Buffer | string): string => Buffer.from(b).toString("base64url");

export function createIssuerKeys(): IssuerKeys {
  const kid = `argos-${randomBytes(6).toString("hex")}`;
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const { privateKey: wrongKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
  return { kid, privateKey, wrongKey, jwks: { keys: [{ ...jwk, kid, alg: "RS256", use: "sig" }] } };
}

/** Default Spring clock skew is 60s: use expiresInSec <= -120 for a token that must count as expired. */
export function mintJwt(keys: IssuerKeys, iss: string, audience: string | undefined, claims: Record<string, unknown>, opts: MintOptions = {}): string {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + (opts.expiresInSec ?? 300);
  const header = { alg: "RS256", typ: "JWT", kid: keys.kid };
  const payload = { ...claims, iss, iat: Math.min(now, exp - 60), exp, ...(audience ? { aud: audience } : {}) };
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = sign("sha256", Buffer.from(input), opts.wrongKey ? keys.wrongKey : keys.privateKey);
  return `${input}.${b64url(sig)}`;
}

export function issuerHandle(keys: IssuerKeys, issuer: string, audience?: string): IssuerHandle {
  return { issuer, mint: (claims, opts) => mintJwt(keys, issuer, audience, claims, opts) };
}
