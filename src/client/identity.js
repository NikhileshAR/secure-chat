const { generateKeyPairSync, randomUUID, sign, verify, createPrivateKey, createPublicKey } = require('node:crypto');

function createSigningKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

function createDeviceKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  return {
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

function generateIdentity({ ttlMs } = {}) {
  const now = Date.now();
  const identityKeyPair = createSigningKeyPair();
  const deviceKeyPair = createDeviceKeyPair();
  const deviceKeySignature = sign(
    null,
    Buffer.from(deviceKeyPair.publicKey),
    createPrivateKey(identityKeyPair.privateKey),
  ).toString('base64');

  return {
    identityKeyPair,
    deviceKeyPair,
    deviceKeySignature,
    deviceId: randomUUID(),
    createdAt: now,
    expiresAt: ttlMs ? now + ttlMs : undefined,
  };
}

function rotateDeviceIdentity(identity, { rotateDeviceId = true, ttlMs } = {}) {
  const now = Date.now();
  const deviceKeyPair = createDeviceKeyPair();
  const deviceKeySignature = sign(
    null,
    Buffer.from(deviceKeyPair.publicKey),
    createPrivateKey(identity.identityKeyPair.privateKey),
  ).toString('base64');

  return {
    identityKeyPair: identity.identityKeyPair,
    deviceKeyPair,
    deviceKeySignature,
    deviceId: rotateDeviceId ? randomUUID() : identity.deviceId,
    createdAt: now,
    expiresAt: ttlMs ? now + ttlMs : undefined,
  };
}

function verifyDeviceKeyBinding(identityPublicKeyPem, devicePublicKeyPem, deviceKeySignature) {
  if (!identityPublicKeyPem || !devicePublicKeyPem || !deviceKeySignature) {
    return false;
  }

  return verify(
    null,
    Buffer.from(devicePublicKeyPem),
    createPublicKey(identityPublicKeyPem),
    Buffer.from(deviceKeySignature, 'base64'),
  );
}

module.exports = {
  generateIdentity,
  rotateDeviceIdentity,
  verifyDeviceKeyBinding,
};
