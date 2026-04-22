const test = require('node:test');
const assert = require('node:assert/strict');

const { SecureClient } = require('../src/client/client');
const { generateIdentity } = require('../src/client/identity');
const { encodeMessage, decodeMessage, hashWireMessage } = require('../src/protocol/wire');

function createClient(identity, options = {}) {
  const client = new SecureClient({
    serverUrl: 'ws://127.0.0.1:1',
    identity,
    sendDelayRangeMs: { min: 0, max: 0 },
    batchingWindowMs: 0,
    parallelRouteTags: 2,
    pullNoiseLevel: 0,
    coverTrafficIntervalRangeMs: { min: 60_000, max: 60_000 },
    rateShaping: { minMessagesPerSecond: 1_000_000, maxMessagesPerSecond: 1_000_000 },
    ...options,
  });
  const sent = [];
  client.sendRaw = (message) => sent.push(message);
  return { client, sent };
}

function makeDeterministicChat() {
  return {
    type: 'chat',
    protocolVersion: '1.0',
    messageId: 'msg-1',
    senderDeviceId: 'alice-device',
    targetDeviceId: 'bob-device',
    counter: 0,
    previousCounter: 0,
    dhPublicKey: 'dh-public',
    routeTag: 'route-tag-1',
    encryptedPayload: '{"ciphertext":"x"}',
    timestamp: 1_710_000_000_000,
    signature: 'sig-1',
  };
}

test('same message encodes to identical wire buffer before encryption', () => {
  const message = makeDeterministicChat();
  const first = encodeMessage(message, { strictMode: true });
  const second = encodeMessage(message, { strictMode: true });
  assert.deepEqual(first, second);
});

test('hashWireMessage is stable and replay-safe for deterministic inputs', () => {
  const message = makeDeterministicChat();
  const encoded = encodeMessage(message, { strictMode: true });
  const replayEncoded = encodeMessage(decodeMessage(encoded, { strictMode: true }), { strictMode: true });

  const hashA = hashWireMessage(encoded);
  const hashB = hashWireMessage(replayEncoded);

  assert.equal(hashA, hashB);
  assert.equal(hashA.length, 64);
});

test('out-of-order delivery reaches same final session state', () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();

  const { client: alice, sent } = createClient(aliceIdentity);
  const { client: bobOrdered } = createClient(bobIdentity);
  const { client: bobOutOfOrder } = createClient(bobIdentity);

  alice.sendChat({
    content: 'first',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    recipientIdentityPublicKey: bobIdentity.identityKeyPair.publicKey,
    routeSecret: 'deterministic-route',
  });
  alice.sendChat({
    content: 'second',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    recipientIdentityPublicKey: bobIdentity.identityKeyPair.publicKey,
    routeSecret: 'deterministic-route',
  });

  const commonParams = {
    senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
    senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
    routeSecret: 'deterministic-route',
  };

  const orderedOne = bobOrdered.decryptChat({ message: sent[0], ...commonParams });
  const orderedTwo = bobOrdered.decryptChat({ message: sent[1], ...commonParams });
  const outTwo = bobOutOfOrder.decryptChat({ message: sent[1], ...commonParams });
  const outOne = bobOutOfOrder.decryptChat({ message: sent[0], ...commonParams });

  assert.equal(orderedOne.content, 'first');
  assert.equal(orderedTwo.content, 'second');
  assert.equal(outTwo.content, 'second');
  assert.equal(outOne.content, 'first');

  const orderedSession = bobOrdered.sessions.get(aliceIdentity.deviceId);
  const outSession = bobOutOfOrder.sessions.get(aliceIdentity.deviceId);

  assert.equal(orderedSession.receiveCounter, outSession.receiveCounter);
  assert.equal(orderedSession.skippedMessageKeys.size, outSession.skippedMessageKeys.size);
});

test('same logical inputs preserve routeTag structure (shape, count, length)', () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();

  const { client: senderA } = createClient(aliceIdentity, { parallelRouteTags: 3 });
  const { client: senderB } = createClient(generateIdentity(), { parallelRouteTags: 3 });

  const sessionA = senderA.ensureSession({
    peerDeviceId: bobIdentity.deviceId,
    peerDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    routeSecret: 'route-structure-A',
  });
  const sessionB = senderB.ensureSession({
    peerDeviceId: bobIdentity.deviceId,
    peerDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    routeSecret: 'route-structure-B',
  });

  const tagsA = senderA.computeRouteTagCandidates(sessionA.rootKey, 5, 'send');
  const tagsB = senderB.computeRouteTagCandidates(sessionB.rootKey, 5, 'send');

  assert.equal(tagsA.length, 3);
  assert.equal(tagsB.length, 3);
  assert.equal(new Set(tagsA.map((tag) => tag.length)).size, 1);
  assert.equal(new Set(tagsB.map((tag) => tag.length)).size, 1);
  assert.equal(tagsA[0].length, tagsB[0].length);
});

test('strict wire mode does not normalize control aliases', () => {
  const controlPull = {
    type: 'control',
    action: 'pull',
    protocolVersion: '1.0',
    senderDeviceId: 'device-a',
    timestamp: 1,
    encryptedPayload: '',
    routeTags: [],
  };

  assert.throws(
    () => encodeMessage(controlPull, { strictMode: true }),
    /unknown (message type|field)/i,
  );
  assert.doesNotThrow(() => encodeMessage(controlPull, { strictMode: false }));
});
