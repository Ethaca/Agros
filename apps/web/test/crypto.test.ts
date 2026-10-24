import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { test } from 'node:test';

process.env.SESSION_SECRET ||= 'test-session';
process.env.ENCRYPTION_KEY ||= 'test-enc';
const { decrypt, encrypt, signPayload, verifyPayload, verifyWebhookSignature } = await import('../src/crypto.ts');

test('토큰 암복호화 왕복, 변조 감지', () => {
  const enc = encrypt('gho_secret');
  assert.equal(decrypt(enc), 'gho_secret');
  const tampered = Buffer.from(enc, 'base64');
  tampered[tampered.length - 1] ^= 1;
  assert.throws(() => decrypt(tampered.toString('base64')));
});

test('세션 서명: 변조/만료 거부', () => {
  const t = signPayload({ uid: 1, exp: Date.now() + 1000 });
  assert.equal(verifyPayload<{ uid: number; exp: number }>(t)?.uid, 1);
  assert.equal(verifyPayload(t.replace(/^./, 'x')), null);
  assert.equal(verifyPayload(signPayload({ uid: 1, exp: Date.now() - 1 })), null);
});

test('webhook 서명 검증', () => {
  const body = Buffer.from('{"action":"opened"}');
  const sig = 'sha256=' + createHmac('sha256', 's3cret').update(body).digest('hex');
  assert.equal(verifyWebhookSignature('s3cret', body, sig), true);
  assert.equal(verifyWebhookSignature('other', body, sig), false);
  assert.equal(verifyWebhookSignature('s3cret', body, undefined), false);
});
