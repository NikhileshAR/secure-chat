const test = require('node:test');
const assert = require('node:assert/strict');
const { generateIdentity, rotateDeviceIdentity } = require('../src/client/identity');
const { computeRouteTag, encryptPayload, decryptPayload } = require('../src/client/crypto');

test('identity generation and rotation keeps long term identity key while rotating device identity', () => {
  const id1 = generateIdentity({ ttlMs: 1_000 });
  const id2 = rotateDeviceIdentity(id1, { rotateDeviceId: true, ttlMs: 1_000 });

  assert.ok(id1.deviceId);
  assert.ok(id1.identityKeyPair.publicKey.includes('PUBLIC KEY'));
  assert.notEqual(id1.deviceId, id2.deviceId);
  assert.notEqual(id1.deviceKeyPair.publicKey, id2.deviceKeyPair.publicKey);
  assert.equal(id1.identityKeyPair.publicKey, id2.identityKeyPair.publicKey);
});

test('route tags are deterministic for shared secret and hashing is opaque', () => {
  const a = computeRouteTag('shared-secret');
  const b = computeRouteTag('shared-secret');
  const c = computeRouteTag('other-secret');

  assert.equal(a, b);
  assert.notEqual(a, c);
  assert.equal(a.length, 128);
});

test('payload encrypted by sender can be decrypted by recipient only', () => {
  const sender = generateIdentity();
  const recipient = generateIdentity();

  const plaintext = { messageId: '1', content: 'hello', attachments: { type: 'text' } };
  const encrypted = encryptPayload(
    plaintext,
    sender.deviceKeyPair.privateKey,
    recipient.deviceKeyPair.publicKey,
  );

  const decrypted = decryptPayload(
    encrypted,
    recipient.deviceKeyPair.privateKey,
    sender.deviceKeyPair.publicKey,
  );

  assert.deepEqual(decrypted, plaintext);
});
