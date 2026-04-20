const test = require('node:test');
const assert = require('node:assert/strict');
const { SecureClient } = require('../src/client/client');
const { generateIdentity } = require('../src/client/identity');
const { computeRouteTag } = require('../src/client/crypto');

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function createClient(identity, options = {}) {
  const client = new SecureClient({
    serverUrl: 'ws://127.0.0.1:1',
    identity,
    coverTrafficIntervalRangeMs: { min: 60_000, max: 60_000 },
    ...options,
  });
  const sent = [];
  client.sendRaw = (message) => sent.push(message);
  return { client, sent };
}

test('encrypted payloads are padded to configured bucket sizes', () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();
  const { client: alice, sent } = createClient(aliceIdentity, {
    sendDelayRangeMs: { min: 0, max: 0 },
    batchingWindowMs: 0,
    paddingSizeBuckets: [256, 512, 1024, 4096],
    parallelRouteTags: 1,
    pullNoiseLevel: 0,
    rateShaping: { minMessagesPerSecond: 1_000_000, maxMessagesPerSecond: 1_000_000 },
  });

  alice.sendChat({
    content: 'tiny',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    routeSecret: 'route-secret-padding',
  });
  alice.sendChat({
    content: 'x'.repeat(320),
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    routeSecret: 'route-secret-padding',
  });

  const shortCiphertext = Buffer.from(
    JSON.parse(sent[0].encryptedPayload).encryptedPayload.ciphertext,
    'base64',
  );
  const longCiphertext = Buffer.from(
    JSON.parse(sent[1].encryptedPayload).encryptedPayload.ciphertext,
    'base64',
  );

  assert.equal(shortCiphertext.length, 256);
  assert.equal(longCiphertext.length, 512);
});

test('dummy cover traffic decrypts and is discarded', () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();
  const options = {
    sendDelayRangeMs: { min: 0, max: 0 },
    batchingWindowMs: 0,
    parallelRouteTags: 1,
    pullNoiseLevel: 0,
    rateShaping: { minMessagesPerSecond: 1_000_000, maxMessagesPerSecond: 1_000_000 },
  };
  const { client: alice, sent } = createClient(aliceIdentity, options);
  const { client: bob } = createClient(bobIdentity, options);

  alice.sendChat({
    content: 'real',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    routeSecret: 'route-secret-dummy',
  });

  const session = alice.sessions.get(bobIdentity.deviceId);
  alice.queueOutboundMessage(alice.createDummyEnvelopeForSession(session));

  const real = bob.decryptChat({
    message: sent[0],
    senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
    senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
    routeSecret: 'route-secret-dummy',
  });
  const dummy = bob.decryptChat({
    message: sent[1],
    senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
    senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
    routeSecret: 'route-secret-dummy',
  });

  assert.equal(real.content, 'real');
  assert.equal(dummy, null);
});

test('multiple route tags map to the same logical session', () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();
  const options = {
    sendDelayRangeMs: { min: 0, max: 0 },
    batchingWindowMs: 0,
    parallelRouteTags: 4,
    pullNoiseLevel: 0,
    rateShaping: { minMessagesPerSecond: 1_000_000, maxMessagesPerSecond: 1_000_000 },
  };
  const { client: alice, sent } = createClient(aliceIdentity, options);
  const { client: bob } = createClient(bobIdentity, options);

  for (let i = 0; i < 20; i += 1) {
    alice.sendChat({
      content: `m-${i}`,
      recipientDeviceId: bobIdentity.deviceId,
      recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
      routeSecret: 'route-secret-multi-tag',
    });
  }

  const uniqueRouteTags = new Set(sent.map((message) => message.routeTag));
  assert.ok(uniqueRouteTags.size > 1);

  const inOrder = [...sent].sort((a, b) => a.counter - b.counter);
  for (let i = 0; i < inOrder.length; i += 1) {
    const decrypted = bob.decryptChat({
      message: inOrder[i],
      senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
      senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
      routeSecret: 'route-secret-multi-tag',
    });
    assert.equal(decrypted.content, `m-${i}`);
  }
  const bobSession = bob.sessions.get(aliceIdentity.deviceId);
  assert.equal(bobSession.receiveCounter, 20);
});

test('pull obfuscation adds noise tags without dropping expected tags', () => {
  const identity = generateIdentity();
  const { client, sent } = createClient(identity, {
    parallelRouteTags: 2,
    pullNoiseLevel: 5,
    sendDelayRangeMs: { min: 0, max: 0 },
    batchingWindowMs: 0,
  });

  const routeSecret = 'route-secret-pull-noise';
  const session = client.ensureSession({
    routeSecret,
    peerDeviceId: `_route_session:${routeSecret}`,
  });
  const expectedTag = computeRouteTag(session.rootKey, 0, 'send', 0);

  client.pull([routeSecret], { window: 1 });

  assert.equal(sent.length, 1);
  assert.equal(sent[0].type, 'control');
  assert.equal(sent[0].action, 'pull');
  assert.ok(sent[0].routeTags.length > 6);
  assert.ok(sent[0].routeTags.includes(expectedTag));
});

test('timing delay and batching preserve message order', async () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();
  const { client: alice, sent } = createClient(aliceIdentity, {
    sendDelayRangeMs: { min: 40, max: 40 },
    batchingWindowMs: 20,
    parallelRouteTags: 1,
    pullNoiseLevel: 0,
    rateShaping: { minMessagesPerSecond: 1_000_000, maxMessagesPerSecond: 1_000_000 },
  });

  alice.sendChat({
    content: 'first',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    routeSecret: 'route-secret-timing',
  });
  alice.sendChat({
    content: 'second',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    routeSecret: 'route-secret-timing',
  });

  assert.equal(sent.length, 0);
  await wait(80);
  assert.equal(sent.length, 2);
  assert.deepEqual(sent.map((message) => message.counter), [0, 1]);
});
