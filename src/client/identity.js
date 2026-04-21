const {
  createHash,
  generateKeyPairSync,
  randomUUID,
  sign,
  verify,
  createPrivateKey,
  createPublicKey,
} = require('node:crypto');

const IDENTITY_STATES = {
  ACTIVE: 'ACTIVE',
  ROTATING: 'ROTATING',
  REVOKED: 'REVOKED',
};

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

function signDevicePublicKey(identityPrivateKeyPem, devicePublicKeyPem) {
  return sign(
    null,
    Buffer.from(devicePublicKeyPem),
    createPrivateKey(identityPrivateKeyPem),
  ).toString('base64');
}

function createDeviceRegistryEntry(identityPrivateKeyPem, deviceId, devicePublicKey, lastSeen = Date.now()) {
  return {
    devicePublicKey,
    signature: signDevicePublicKey(identityPrivateKeyPem, devicePublicKey),
    lastSeen,
    deviceId,
  };
}

function fingerprintIdentityPublicKey(identityPublicKeyPem) {
  if (!identityPublicKeyPem) {
    throw new Error('identityPublicKeyPem is required for fingerprinting');
  }
  return createHash('sha256').update(Buffer.from(identityPublicKeyPem)).digest('hex');
}

function formatIdentityFingerprint(identityPublicKeyPem, groupSize = 4) {
  const fingerprint = fingerprintIdentityPublicKey(identityPublicKeyPem);
  const groups = [];
  for (let i = 0; i < fingerprint.length; i += groupSize) {
    groups.push(fingerprint.slice(i, i + groupSize));
  }
  return groups.join(':');
}

function getIdentityFingerprintChange(previousIdentityPublicKeyPem, nextIdentityPublicKeyPem) {
  const previousFingerprint = previousIdentityPublicKeyPem
    ? fingerprintIdentityPublicKey(previousIdentityPublicKeyPem)
    : null;
  const nextFingerprint = nextIdentityPublicKeyPem
    ? fingerprintIdentityPublicKey(nextIdentityPublicKeyPem)
    : null;
  return {
    changed: previousFingerprint !== nextFingerprint,
    previousFingerprint,
    nextFingerprint,
    previousDisplay: previousIdentityPublicKeyPem ? formatIdentityFingerprint(previousIdentityPublicKeyPem) : null,
    nextDisplay: nextIdentityPublicKeyPem ? formatIdentityFingerprint(nextIdentityPublicKeyPem) : null,
  };
}

function generateIdentity({ ttlMs } = {}) {
  const now = Date.now();
  const identityKeyPair = createSigningKeyPair();
  const deviceKeyPair = createDeviceKeyPair();
  const deviceId = randomUUID();
  const deviceKeySignature = signDevicePublicKey(identityKeyPair.privateKey, deviceKeyPair.publicKey);

  return {
    identityKeyPair,
    deviceKeyPair,
    deviceKeySignature,
    deviceId,
    createdAt: now,
    expiresAt: ttlMs ? now + ttlMs : undefined,
    state: IDENTITY_STATES.ACTIVE,
    stateChangedAt: now,
    deviceRegistry: {
      [deviceId]: {
        devicePublicKey: deviceKeyPair.publicKey,
        signature: deviceKeySignature,
        lastSeen: now,
      },
    },
  };
}

function linkDevice(identity, { devicePublicKey, deviceId = randomUUID(), lastSeen = Date.now() }) {
  if (!identity?.identityKeyPair?.privateKey) {
    throw new Error('identity private key is required to link device');
  }
  if (!devicePublicKey) {
    throw new Error('devicePublicKey is required to link device');
  }

  const signature = signDevicePublicKey(identity.identityKeyPair.privateKey, devicePublicKey);
  return {
    ...identity,
    deviceRegistry: {
      ...(identity.deviceRegistry || {}),
      [deviceId]: {
        devicePublicKey,
        signature,
        lastSeen,
      },
    },
  };
}

function updateDeviceLastSeen(identity, deviceId, timestamp = Date.now()) {
  if (!identity?.deviceRegistry?.[deviceId]) {
    return identity;
  }
  return {
    ...identity,
    deviceRegistry: {
      ...identity.deviceRegistry,
      [deviceId]: {
        ...identity.deviceRegistry[deviceId],
        lastSeen: timestamp,
      },
    },
  };
}

function rotateDeviceIdentity(identity, { rotateDeviceId = true, ttlMs } = {}) {
  const now = Date.now();
  const deviceKeyPair = createDeviceKeyPair();
  const nextDeviceId = rotateDeviceId ? randomUUID() : identity.deviceId;
  const deviceKeySignature = signDevicePublicKey(
    identity.identityKeyPair.privateKey,
    deviceKeyPair.publicKey,
  );

  return {
    ...identity,
    deviceKeyPair,
    deviceKeySignature,
    deviceId: nextDeviceId,
    createdAt: now,
    expiresAt: ttlMs ? now + ttlMs : undefined,
    state: IDENTITY_STATES.ACTIVE,
    stateChangedAt: now,
    deviceRegistry: {
      ...(identity.deviceRegistry || {}),
      [nextDeviceId]: {
        devicePublicKey: deviceKeyPair.publicKey,
        signature: deviceKeySignature,
        lastSeen: now,
      },
    },
  };
}

function rotateIdentityKeys(identity, { ttlMs } = {}) {
  const now = Date.now();
  const identityKeyPair = createSigningKeyPair();
  const deviceRegistry = {};
  for (const [deviceId, device] of Object.entries(identity.deviceRegistry || {})) {
    deviceRegistry[deviceId] = createDeviceRegistryEntry(
      identityKeyPair.privateKey,
      deviceId,
      device.devicePublicKey,
      device.lastSeen || now,
    );
  }

  return {
    ...identity,
    identityKeyPair,
    deviceKeySignature: signDevicePublicKey(identityKeyPair.privateKey, identity.deviceKeyPair.publicKey),
    createdAt: now,
    expiresAt: ttlMs ? now + ttlMs : identity.expiresAt,
    state: IDENTITY_STATES.ACTIVE,
    stateChangedAt: now,
    deviceRegistry,
  };
}

function beginIdentityRotation(identity) {
  return {
    ...identity,
    state: IDENTITY_STATES.ROTATING,
    stateChangedAt: Date.now(),
  };
}

function revokeIdentity(identity) {
  return {
    ...identity,
    state: IDENTITY_STATES.REVOKED,
    stateChangedAt: Date.now(),
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
  IDENTITY_STATES,
  generateIdentity,
  rotateDeviceIdentity,
  rotateIdentityKeys,
  beginIdentityRotation,
  revokeIdentity,
  linkDevice,
  updateDeviceLastSeen,
  verifyDeviceKeyBinding,
  fingerprintIdentityPublicKey,
  formatIdentityFingerprint,
  getIdentityFingerprintChange,
};
