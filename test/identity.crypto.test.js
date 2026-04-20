const test = require('node:test');
const assert = require('node:assert/strict');
const { generateIdentity, rotateDeviceIdentity, verifyDeviceKeyBinding } = require('../src/client/identity');
const {
  computeRouteTag,
  encryptPayload,
  decryptPayload,
  deriveInitialChainKey,
  deriveMessageKey,
  deriveNextChainKey,
} = require('../src/client/crypto');

test('identity generation and rotation keeps long term identity key while rotating device identity', () => {
  const id1 = generateIdentity({ ttlMs: 1_000 });
  const id2 = rotateDeviceIdentity(id1, { rotateDeviceId: true, ttlMs: 1_000 });

  assert.ok(id1.deviceId);
  assert.ok(id1.identityKeyPair.publicKey.includes('PUBLIC KEY'));
  assert.notEqual(id1.deviceId, id2.deviceId);
  assert.notEqual(id1.deviceKeyPair.publicKey, id2.deviceKeyPair.publicKey);
  assert.equal(id1.identityKeyPair.publicKey, id2.identityKeyPair.publicKey);
  assert.ok(id1.deviceKeySignature);
  assert.ok(verifyDeviceKeyBinding(
    id1.identityKeyPair.publicKey,
    id1.deviceKeyPair.publicKey,
    id1.deviceKeySignature,
  ));
  assert.ok(verifyDeviceKeyBinding(
    id2.identityKeyPair.publicKey,
    id2.deviceKeyPair.publicKey,
    id2.deviceKeySignature,
  ));
});

test('identity-device binding rejects tampered device keys', () => {
  const id = generateIdentity();
  assert.equal(
    verifyDeviceKeyBinding(
      id.identityKeyPair.publicKey,
      `${id.deviceKeyPair.publicKey}\n`,
      id.deviceKeySignature,
    ),
    false,
  );
});

test('route tags are deterministic per shared secret and counter', () => {
  const a = computeRouteTag('shared-secret', 3);
  const b = computeRouteTag('shared-secret', 3);
  const c = computeRouteTag('shared-secret', 4);

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

test('ratchet key derivation evolves message keys per step', () => {
  const startChainKey = deriveInitialChainKey('shared-secret');
  const firstMessageKey = deriveMessageKey(startChainKey);
  const secondChainKey = deriveNextChainKey(startChainKey);
  const secondMessageKey = deriveMessageKey(secondChainKey);

  assert.notDeepEqual(firstMessageKey, secondMessageKey);
  assert.equal(firstMessageKey.length, 32);
});
