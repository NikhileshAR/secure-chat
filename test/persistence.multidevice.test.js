const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { SecureClient } = require('../src/client/client');
const { generateIdentity, linkDevice } = require('../src/client/identity');
const { validateMessage } = require('../src/protocol/schema');

function createClient(identity, options = {}) {
  const client = new SecureClient({
    serverUrl: 'ws://127.0.0.1:1',
    identity,
    sendDelayRangeMs: { min: 0, max: 0 },
    batchingWindowMs: 0,
    parallelRouteTags: 1,
    pullNoiseLevel: 0,
    coverTrafficIntervalRangeMs: { min: 60_000, max: 60_000 },
    rateShaping: { minMessagesPerSecond: 1_000_000, maxMessagesPerSecond: 1_000_000 },
    ...options,
  });
  const sent = [];
  client.sendRaw = (message) => sent.push(message);
  return { client, sent };
}

test('session persistence resumes ratchet state across restart and rejects replay', () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();
  const storageDir = fs.mkdtempSync(path.join(os.tmpdir(), 'securechat-session-'));

  const { client: alice, sent } = createClient(aliceIdentity);
  const { client: bob } = createClient(bobIdentity, {
    sessionStorageDir: storageDir,
    deviceSecret: `secret:${bobIdentity.deviceId}`,
  });

  alice.sendChat({
    content: 'persist-1',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    routeSecret: 'persist-route',
  });

  const first = bob.decryptChat({
    message: sent[0],
    senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
    senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
    routeSecret: 'persist-route',
  });
  assert.equal(first.content, 'persist-1');
  bob.close();

  const { client: bobRestarted } = createClient(bobIdentity, {
    sessionStorageDir: storageDir,
    deviceSecret: `secret:${bobIdentity.deviceId}`,
  });

  const replay = bobRestarted.decryptChat({
    message: sent[0],
    senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
    senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
    routeSecret: 'persist-route',
  });
  assert.equal(replay, null);

  alice.sendChat({
    content: 'persist-2',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    routeSecret: 'persist-route',
  });

  const second = bobRestarted.decryptChat({
    message: sent[1],
    senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
    senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
    routeSecret: 'persist-route',
  });
  assert.equal(second.content, 'persist-2');

  bobRestarted.close();
  fs.rmSync(storageDir, { recursive: true, force: true });
});

test('corrupted session storage is handled safely', () => {
  const identity = generateIdentity();
  const storageDir = fs.mkdtempSync(path.join(os.tmpdir(), 'securechat-corrupt-'));
  const storePath = path.join(storageDir, 'securechat.sessions.enc');
  fs.writeFileSync(storePath, '{"bad":true,"ciphertext":"!!!"}\n', 'utf8');

  const { client } = createClient(identity, {
    sessionStorageDir: storageDir,
    deviceSecret: `secret:${identity.deviceId}`,
  });

  assert.equal(client.sessions.size, 0);
  client.close();
  fs.rmSync(storageDir, { recursive: true, force: true });
});

test('multi-device send emits one encrypted envelope per linked device', () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();
  const extraDevice = generateIdentity().deviceKeyPair.publicKey;
  const bobMulti = linkDevice(bobIdentity, { devicePublicKey: extraDevice, deviceId: 'bob-device-2' });

  const { client: alice, sent } = createClient(aliceIdentity);
  const envelopes = alice.sendChatToIdentityDevices({
    content: 'hello-multi',
    recipientIdentity: bobMulti,
    routeSecretByDevice: {
      default: 'multi-default',
    },
  });

  assert.equal(envelopes.length, 2);
  assert.equal(sent.length, 2);
  const targetIds = new Set(sent.map((message) => message.targetDeviceId));
  assert.equal(targetIds.has(bobIdentity.deviceId), true);
  assert.equal(targetIds.has('bob-device-2'), true);
});

test('schema rejects unsupported protocol versions', () => {
  assert.throws(() => {
    validateMessage({
      type: 'ack',
      protocolVersion: '9.9',
      ackId: 'm-1',
      senderDeviceId: 'd1',
      encryptedPayload: '',
      timestamp: Date.now(),
    }, { allowLegacy: false });
  }, /unsupported protocolVersion/i);
});
