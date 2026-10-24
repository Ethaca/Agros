/** Strip run secrets (DB password, any JWT) from text that may end up in errors, logs or reports. */

const JWT_RE = /eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/g;

export function redact(text: string, secrets: readonly string[] = []): string {
  let out = text.replace(JWT_RE, "<redacted-jwt>");
  for (const s of secrets) if (s.length >= 6) out = out.split(s).join("<redacted>");
  return out;
}

export const redactLines = (lines: string[], secrets: readonly string[] = []): string[] => lines.map((l) => redact(l, secrets));
