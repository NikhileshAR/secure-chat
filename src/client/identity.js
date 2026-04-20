const { generateKeyPairSync, randomUUID } = require('node:crypto');

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
  return {
    identityKeyPair: createSigningKeyPair(),
    deviceKeyPair: createDeviceKeyPair(),
    deviceId: randomUUID(),
    createdAt: now,
    expiresAt: ttlMs ? now + ttlMs : undefined,
  };
}

function rotateDeviceIdentity(identity, { rotateDeviceId = true, ttlMs } = {}) {
  const now = Date.now();
  return {
    identityKeyPair: identity.identityKeyPair,
    deviceKeyPair: createDeviceKeyPair(),
    deviceId: rotateDeviceId ? randomUUID() : identity.deviceId,
    createdAt: now,
    expiresAt: ttlMs ? now + ttlMs : undefined,
  };
}

module.exports = {
  generateIdentity,
  rotateDeviceIdentity,
};
