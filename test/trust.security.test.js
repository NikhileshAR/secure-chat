const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { TrustStore, TRUST_LEVELS } = require('../src/client/storage/trustStore');
const {
  generateIdentity,
  rotateDeviceIdentity,
  fingerprintIdentityPublicKey,
  generateVerificationString,
  compareFingerprints,
} = require('../src/client/identity');
const { SecureClient } = require('../src/client/client');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'securechat-trust-'));
}

function makeTrustStore(dir) {
  return new TrustStore({ storageDir: dir, deviceSecret: 'test-device-secret' });
}

function makeClient(identity, dir, extraOpts = {}) {
  const client = new SecureClient({
    serverUrl: 'ws://127.0.0.1:1',
    identity,
    sendDelayRangeMs: { min: 0, max: 0 },
    batchingWindowMs: 0,
    parallelRouteTags: 1,
    pullNoiseLevel: 0,
    coverTrafficIntervalRangeMs: { min: 60_000, max: 60_000 },
    rateShaping: { minMessagesPerSecond: 1_000_000, maxMessagesPerSecond: 1_000_000 },
    trustStoreStorageDir: dir,
    deviceSecret: 'test-device-secret',
    ...extraOpts,
  });
  client.sendRaw = () => {};
  return client;
}

// ---------------------------------------------------------------------------
// 1. New identity → becomes UNKNOWN
// ---------------------------------------------------------------------------
test('new identity becomes UNKNOWN in TrustStore', () => {
  const dir = makeDir();
  try {
    const store = makeTrustStore(dir);
    const identity = generateIdentity();
    const fp = fingerprintIdentityPublicKey(identity.identityKeyPair.publicKey);

    assert.equal(store.get(fp), null);

    // Simulate first-seen via client
    const client = makeClient(generateIdentity(), dir);
    client.trustStore = store;
    client.checkAndUpdateTrust(identity.identityKeyPair.publicKey);

    const entry = store.get(fp);
    assert.ok(entry, 'entry should exist');
    assert.equal(entry.level, TRUST_LEVELS.UNKNOWN);
    assert.equal(entry.fingerprint, fp);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 2. Trust identity → becomes TRUSTED
// ---------------------------------------------------------------------------
test('trustIdentity sets level to TRUSTED', () => {
  const dir = makeDir();
  try {
    const client = makeClient(generateIdentity(), dir);
    const peer = generateIdentity();
    const peerKey = peer.identityKeyPair.publicKey;

    client.trustIdentity(peerKey, 'Alice');

    assert.equal(client.getTrustLevel(peerKey), TRUST_LEVELS.TRUSTED);

    const fp = fingerprintIdentityPublicKey(peerKey);
    const entry = client.trustStore.get(fp);
    assert.equal(entry.label, 'Alice');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 3. Verify identity → becomes VERIFIED
// ---------------------------------------------------------------------------
test('verifyIdentity sets level to VERIFIED with timestamp', () => {
  const dir = makeDir();
  try {
    const client = makeClient(generateIdentity(), dir);
    const peer = generateIdentity();
    const peerKey = peer.identityKeyPair.publicKey;

    client.verifyIdentity(peerKey);

    assert.equal(client.getTrustLevel(peerKey), TRUST_LEVELS.VERIFIED);

    const fp = fingerprintIdentityPublicKey(peerKey);
    const entry = client.trustStore.get(fp);
    assert.ok(typeof entry.verifiedAt === 'number', 'verifiedAt should be set');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 4. Verified identity key change → message rejected
// ---------------------------------------------------------------------------
test('VERIFIED identity key change throws hard error', () => {
  const dir = makeDir();
  try {
    const client = makeClient(generateIdentity(), dir);
    const peerA = generateIdentity();
    const peerAKey = peerA.identityKeyPair.publicKey;

    // Mark peerA's key as VERIFIED under peerA's fingerprint slot
    client.verifyIdentity(peerAKey);
    assert.equal(client.getTrustLevel(peerAKey), TRUST_LEVELS.VERIFIED);

    // Generate a genuinely different identity (different key material)
    const peerB = generateIdentity();
    const peerBKey = peerB.identityKeyPair.publicKey;

    // Simulate MITM: store peerB's key in peerA's fingerprint slot
    const fp = fingerprintIdentityPublicKey(peerAKey);
    const existingEntry = client.trustStore.get(fp);
    client.trustStore.set(fp, { ...existingEntry, identityPublicKey: peerBKey });

    // Now checkAndUpdateTrust with peerA's original key sees a mismatch against the stored peerB key
    assert.throws(
      () => client.checkAndUpdateTrust(peerAKey),
      /Security alert.*VERIFIED/,
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 5. Blocked identity → message dropped (decryptChat returns null)
// ---------------------------------------------------------------------------
test('blocked identity message is silently dropped', () => {
  const dir = makeDir();
  try {
    const aliceIdentity = generateIdentity();
    const bobIdentity = generateIdentity();
    const { client: alice } = (() => {
      const c = makeClient(aliceIdentity, dir);
      const sent = [];
      c.sendRaw = (msg) => sent.push(msg);
      return { client: c, sent };
    })();

    const bobDir = makeDir();
    const bob = makeClient(bobIdentity, bobDir);
    bob.sendRaw = () => {};

    // Alice sends a message to Bob
    const sent = [];
    alice.sendRaw = (msg) => sent.push(msg);
    alice.sendChat({
      content: 'hello',
      recipientDeviceId: bobIdentity.deviceId,
      recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
      recipientIdentityPublicKey: bobIdentity.identityKeyPair.publicKey,
    });
    assert.equal(sent.length, 1);
    const envelope = sent[0];

    // Bob blocks Alice before receiving
    bob.blockIdentity(aliceIdentity.identityKeyPair.publicKey);
    assert.equal(bob.getTrustLevel(aliceIdentity.identityKeyPair.publicKey), TRUST_LEVELS.BLOCKED);

    // decryptChat should silently drop and return null
    const result = bob.decryptChat({
      message: envelope,
      senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
      senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
    });
    assert.equal(result, null);

    fs.rmSync(bobDir, { recursive: true, force: true });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 6. TrustStore persists after reload
// ---------------------------------------------------------------------------
test('TrustStore persists entries after reload', () => {
  const dir = makeDir();
  try {
    const store1 = makeTrustStore(dir);
    const identity = generateIdentity();
    const fp = fingerprintIdentityPublicKey(identity.identityKeyPair.publicKey);

    store1.set(fp, {
      identityPublicKey: identity.identityKeyPair.publicKey,
      fingerprint: fp,
      level: TRUST_LEVELS.TRUSTED,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      label: 'Persisted Contact',
      deviceFingerprints: [],
    });

    // Reload with a fresh instance
    const store2 = makeTrustStore(dir);
    store2.loadTrust();
    const entry = store2.get(fp);

    assert.ok(entry, 'entry should survive reload');
    assert.equal(entry.level, TRUST_LEVELS.TRUSTED);
    assert.equal(entry.label, 'Persisted Contact');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 7. Corrupted trust file → safe fallback (empty map)
// ---------------------------------------------------------------------------
test('corrupted trust file returns empty map (fail-closed)', () => {
  const dir = makeDir();
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'securechat.trust.enc'), 'NOT_VALID_JSON\n');

    const store = makeTrustStore(dir);
    const map = store.loadTrust();

    assert.ok(map instanceof Map);
    assert.equal(map.size, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 8. Device fingerprint tracking
// ---------------------------------------------------------------------------
test('device fingerprints are tracked per TrustEntry', () => {
  const dir = makeDir();
  try {
    const client = makeClient(generateIdentity(), dir);
    const peer = generateIdentity();
    const peerKey = peer.identityKeyPair.publicKey;
    const deviceKey1 = peer.deviceKeyPair.publicKey;

    // First message from device 1
    client.checkAndUpdateTrust(peerKey, deviceKey1);

    // Rotate device key (new device)
    const rotated = rotateDeviceIdentity(peer, { rotateDeviceId: true });
    const deviceKey2 = rotated.deviceKeyPair.publicKey;

    // Second message from device 2
    client.checkAndUpdateTrust(peerKey, deviceKey2);

    const fp = fingerprintIdentityPublicKey(peerKey);
    const entry = client.trustStore.get(fp);

    assert.ok(entry.deviceFingerprints.length >= 2, 'both device fingerprints should be tracked');

    const fp1 = client.fingerprintDevicePublicKey(deviceKey1);
    const fp2 = client.fingerprintDevicePublicKey(deviceKey2);
    assert.ok(entry.deviceFingerprints.includes(fp1));
    assert.ok(entry.deviceFingerprints.includes(fp2));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 9. Verification string matches on both sides
// ---------------------------------------------------------------------------
test('verification string is identical regardless of argument order', () => {
  const idA = generateIdentity();
  const idB = generateIdentity();

  const v1 = generateVerificationString(idA.identityKeyPair.publicKey, idB.identityKeyPair.publicKey);
  const v2 = generateVerificationString(idB.identityKeyPair.publicKey, idA.identityKeyPair.publicKey);

  // Must be identical regardless of argument order
  assert.equal(v1.numeric, v2.numeric);
  assert.deepEqual(v1.words, v2.words);

  // Numeric string must be exactly 60 decimal digits
  assert.match(v1.numeric, /^\d{60}$/);

  // Words must be exactly 12 entries from the embedded list
  assert.equal(v1.words.length, 12);
  for (const word of v1.words) {
    assert.ok(typeof word === 'string' && word.length > 0);
  }

  // Different identity pair must produce different string
  const idC = generateIdentity();
  const v3 = generateVerificationString(idA.identityKeyPair.publicKey, idC.identityKeyPair.publicKey);
  assert.notEqual(v1.numeric, v3.numeric);
});

// ---------------------------------------------------------------------------
// compareFingerprints helper
// ---------------------------------------------------------------------------
test('compareFingerprints returns true for identical, false for different', () => {
  const identity = generateIdentity();
  const fp = fingerprintIdentityPublicKey(identity.identityKeyPair.publicKey);

  assert.equal(compareFingerprints(fp, fp), true);
  assert.equal(compareFingerprints(fp, `${fp.slice(0, -1)}0`), false);
  assert.equal(compareFingerprints(fp, null), false);
  assert.equal(compareFingerprints(null, fp), false);
});

// ---------------------------------------------------------------------------
// listTrustedIdentities only returns TRUSTED / VERIFIED
// ---------------------------------------------------------------------------
test('listTrustedIdentities filters by TRUSTED and VERIFIED levels', () => {
  const dir = makeDir();
  try {
    const client = makeClient(generateIdentity(), dir);
    const idA = generateIdentity();
    const idB = generateIdentity();
    const idC = generateIdentity();

    client.trustIdentity(idA.identityKeyPair.publicKey);
    client.verifyIdentity(idB.identityKeyPair.publicKey);
    client.checkAndUpdateTrust(idC.identityKeyPair.publicKey); // UNKNOWN

    const trusted = client.listTrustedIdentities();
    assert.equal(trusted.length, 2);
    const levels = trusted.map((e) => e.level);
    assert.ok(levels.includes(TRUST_LEVELS.TRUSTED));
    assert.ok(levels.includes(TRUST_LEVELS.VERIFIED));
    assert.ok(!levels.includes(TRUST_LEVELS.UNKNOWN));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// unblockIdentity reverts to UNKNOWN
// ---------------------------------------------------------------------------
test('unblockIdentity reverts a BLOCKED identity back to UNKNOWN', () => {
  const dir = makeDir();
  try {
    const client = makeClient(generateIdentity(), dir);
    const peer = generateIdentity();
    const peerKey = peer.identityKeyPair.publicKey;

    client.blockIdentity(peerKey);
    assert.equal(client.getTrustLevel(peerKey), TRUST_LEVELS.BLOCKED);

    client.unblockIdentity(peerKey);
    assert.equal(client.getTrustLevel(peerKey), TRUST_LEVELS.UNKNOWN);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
