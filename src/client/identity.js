const {
  createHash,
  generateKeyPairSync,
  randomUUID,
  sign,
  verify,
  createPrivateKey,
  createPublicKey,
  timingSafeEqual,
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

/* ---------- Trust / verification helpers --------------------------------- */

// 256-word list for 12-word verification phrases (8 bits per word, 96 bits
// of entropy drawn from a 256-bit hash – sufficient for out-of-band check).
const VERIFICATION_WORDS = [
  'able','acid','aged','also','area','army','away','back','ball','band',
  'bank','base','bath','bear','beat','been','bell','best','bird','blue',
  'body','bomb','bond','bone','book','born','both','bowl','bulk','burn',
  'busy','call','calm','came','camp','card','care','case','cash','cast',
  'cave','cell','chad','chef','chin','chip','city','clap','clay','clip',
  'club','coal','coat','code','coil','cold','come','cook','cool','cope',
  'cord','core','cork','corn','cost','coup','cove','crew','crop','cure',
  'curl','dark','dart','data','date','dawn','days','dead','deal','dean',
  'dear','deck','deep','deny','desk','dial','dice','diet','dime','dire',
  'dirt','disk','dock','does','dome','done','door','dose','dove','down',
  'draw','drop','drum','dual','dull','dump','dust','each','earn','east',
  'edge','epic','even','exam','face','fact','fail','fair','fall','farm',
  'fast','fate','feed','feel','fell','felt','file','fill','film','find',
  'fire','firm','fish','fist','flag','flat','flew','flip','flow','foam',
  'fold','folk','fond','font','food','foot','ford','fore','fork','form',
  'fort','foul','four','free','from','fuel','full','fund','fuse','gain',
  'game','gang','gate','gave','gaze','gear','gene','gift','give','glad',
  'glow','glue','goal','goes','gold','golf','gone','good','grab','gray',
  'grew','grid','grim','grip','grow','gulf','gust','half','hall','hand',
  'hang','hard','harm','hate','have','hawk','head','heat','heel','help',
  'herb','here','hero','high','hill','hint','hire','hold','hole','home',
  'hook','hope','horn','hour','huge','hull','hunt','hurt','hymn','icon',
  'idea','idle','inch','into','iris','iron','isle','item','jack','jade',
  'jail','java','jazz','join','joke','jolt','jump','june','just','keen',
  'keep','kent','kern','kind','king','knot','lake','lamp','land','lane',
  'last','late','lava','lawn','leaf','lean','left','lend',
];

/**
 * Returns true when two fingerprint hex strings are equal (timing-safe).
 *
 * @param {string} fp1
 * @param {string} fp2
 * @returns {boolean}
 */
function compareFingerprints(fp1, fp2) {
  if (typeof fp1 !== 'string' || typeof fp2 !== 'string') {
    return false;
  }
  if (fp1.length !== fp2.length) {
    return false;
  }
  return timingSafeEqual(Buffer.from(fp1, 'utf8'), Buffer.from(fp2, 'utf8'));
}

/**
 * Generates a deterministic verification string from two identity public keys.
 * Both parties compute the same string by sorting fingerprints so the result
 * is order-independent.
 *
 * Returns:
 *   { numeric: string, words: string[] }
 *
 * numeric – 60-digit decimal string (12 × 5-digit groups) derived from
 *           SHA-256(sorted fingerprints), suitable for display / QR.
 * words   – 12-word phrase for voice verification.
 *
 * @param {string} identityPublicKeyA  PEM-encoded identity public key
 * @param {string} identityPublicKeyB  PEM-encoded identity public key
 * @returns {{ numeric: string, words: string[] }}
 */
function generateVerificationString(identityPublicKeyA, identityPublicKeyB) {
  if (!identityPublicKeyA || !identityPublicKeyB) {
    throw new Error('generateVerificationString requires two identity public keys');
  }

  const fpA = fingerprintIdentityPublicKey(identityPublicKeyA);
  const fpB = fingerprintIdentityPublicKey(identityPublicKeyB);

  // Sort so the result is independent of argument order.
  const sorted = [fpA, fpB].sort();
  const combined = Buffer.from(`${sorted[0]}:${sorted[1]}`);
  const hash = createHash('sha256').update(combined).digest();

  // --- 60-digit numeric string (12 groups of 5 digits) --------------------
  // Convert 256-bit hash to a BigInt and take mod 10^60, then zero-pad.
  const DIGITS = 60n;
  const MODULUS = 10n ** DIGITS;
  let numeric = (BigInt(`0x${hash.toString('hex')}`) % MODULUS).toString();
  numeric = numeric.padStart(Number(DIGITS), '0');

  // --- 12-word phrase (8 bits per word from the first 12 hash bytes) ------
  const words = [];
  for (let i = 0; i < 12; i += 1) {
    words.push(VERIFICATION_WORDS[hash[i]]);
  }

  return { numeric, words };
}

/* ---------- Device key binding ------------------------------------------- */

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
  compareFingerprints,
  generateVerificationString,
};
