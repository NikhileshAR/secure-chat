const test = require('node:test');
const assert = require('node:assert/strict');
const { SecureClient } = require('../src/client/client');
const { generateIdentity } = require('../src/client/identity');
const { signMessage } = require('../src/client/crypto');

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

test('malformed inbound messages are rejected without session corruption', () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();
  const { client: alice, sent } = createClient(aliceIdentity);
  const { client: bob } = createClient(bobIdentity, {
    securityThresholds: {
      handshakeMismatches: 100,
      routeTagMismatches: 100,
      invalidSignatures: 100,
      relayFloodMessages: 1000,
      burstWindowMs: 2_000,
      replayAttempts: 100,
      droppedMessages: 100,
    },
  });

  alice.sendChat({
    content: 'seed',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    routeSecret: 'adv-route',
  });
  bob.decryptChat({
    message: sent[0],
    senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
    senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
    routeSecret: 'adv-route',
  });
  const session = bob.sessions.get(aliceIdentity.deviceId);
  const baselineCounter = session.receiveCounter;

  const malformed = [
    null,
    { type: 'chat' },
    { type: 'chat', senderDeviceId: 'x', encryptedPayload: '', timestamp: Date.now() },
  ];
  for (const message of malformed) {
    assert.throws(() => {
      bob.handleInboundMessage({
        message,
        senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
        senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
        routeSecret: 'adv-route',
      });
    });
  }

  const after = bob.sessions.get(aliceIdentity.deviceId);
  assert.equal(after.receiveCounter, baselineCounter);
  alice.close();
  bob.close();
});

test('client drops replay floods and rejects invalid counters/fake routeTags/oversized payloads', () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();
  const { client: alice, sent } = createClient(aliceIdentity, {
    securityThresholds: {
      handshakeMismatches: 100,
      routeTagMismatches: 100,
      invalidSignatures: 100,
      relayFloodMessages: 1000,
      burstWindowMs: 2_000,
      replayAttempts: 100,
      droppedMessages: 100,
    },
  });
  const { client: bob } = createClient(bobIdentity, {
    securityThresholds: {
      handshakeMismatches: 100,
      routeTagMismatches: 100,
      invalidSignatures: 100,
      relayFloodMessages: 1000,
      burstWindowMs: 2_000,
      replayAttempts: 100,
      droppedMessages: 100,
    },
  });

  alice.sendChat({
    content: 'baseline',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    routeSecret: 'adv-route-2',
  });
  const first = bob.decryptChat({
    message: sent[0],
    senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
    senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
    routeSecret: 'adv-route-2',
  });
  assert.equal(first.content, 'baseline');

  for (let i = 0; i < 20; i += 1) {
    const replay = bob.decryptChat({
      message: sent[0],
      senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
      senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
      routeSecret: 'adv-route-2',
    });
    assert.equal(replay, null);
  }

  alice.sendChat({
    content: 'forge',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    routeSecret: 'adv-route-2',
  });
  const forgedCounter = { ...sent[1], counter: 10_000, previousCounter: 9_999 };
  const aliceSession = alice.sessions.get(bobIdentity.deviceId);
  forgedCounter.routeTag = alice.computeRouteTagForSession(aliceSession, forgedCounter.counter, 'send', 0);
  forgedCounter.signature = signMessage(aliceIdentity.identityKeyPair.privateKey, forgedCounter);
  assert.throws(() => {
    bob.decryptChat({
      message: forgedCounter,
      senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
      senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
      routeSecret: 'adv-route-2',
    });
  }, /counter outside receive window/i);

  alice.sendChat({
    content: 'route-attack',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    routeSecret: 'adv-route-2',
  });
  const fakeRouteTag = { ...sent[2], routeTag: 'f'.repeat(128) };
  fakeRouteTag.signature = signMessage(aliceIdentity.identityKeyPair.privateKey, fakeRouteTag);
  const routeTagAttack = bob.decryptChat({
    message: fakeRouteTag,
    senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
    senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
    routeSecret: 'adv-route-2',
  });
  assert.equal(routeTagAttack, null);

  const oversized = {
    ...sent[2],
    encryptedPayload: 'a'.repeat(200_000),
  };
  oversized.signature = signMessage(aliceIdentity.identityKeyPair.privateKey, oversized);
  assert.throws(() => {
    bob.handleInboundMessage({
      message: oversized,
      senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
      senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
      routeSecret: 'adv-route-2',
    });
  }, /exceeds max length/i);

  const bobSession = bob.sessions.get(aliceIdentity.deviceId);
  assert.ok(bobSession.receiveCounter >= 1);
  assert.equal(typeof bob.getCurrentSecurityState(), 'object');
  alice.close();
  bob.close();
});
