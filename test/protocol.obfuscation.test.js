const test = require('node:test');
const assert = require('node:assert/strict');
const { SecureClient } = require('../src/client/client');
const { generateIdentity } = require('../src/client/identity');
const { computeRouteTag, deriveRouteTagEpoch } = require('../src/client/crypto');

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function tryDecrypt(client, params) {
  try {
    return client.decryptChat(params);
  } catch {
    return null;
  }
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
    normalizedPullRouteTagCount: 24,
    sendDelayRangeMs: { min: 0, max: 0 },
    batchingWindowMs: 0,
  });

  const routeSecret = 'route-secret-pull-noise';
  const session = client.ensureSession({
    routeSecret,
    peerDeviceId: `_route_session:${routeSecret}`,
  });
  const expectedTag = computeRouteTag(
    session.rootKey,
    session.receiveCounter,
    'send',
    0,
    deriveRouteTagEpoch(session.rootKey, 0),
  );

  client.pull([routeSecret], { window: 1 });

  assert.equal(sent.length, 1);
  assert.equal(sent[0].type, 'control');
  assert.equal(sent[0].action, 'pull');
  assert.ok(sent[0].routeTags.length > 6);
  assert.ok(sent[0].routeTags.includes(expectedTag));
  assert.equal(sent[0].routeTags.length, 24);
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

test('constant traffic rate remains stable with and without user messages', async () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();
  const { client: alice, sent } = createClient(aliceIdentity, {
    constantTrafficEnabled: true,
    constantTrafficRatePerSecond: 20,
    outboundMixDelayRangeMs: { min: 0, max: 0 },
    routeTagEpochMessages: 4,
    decoySessionCount: 0,
  });

  alice.ensureSession({
    peerDeviceId: bobIdentity.deviceId,
    peerDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    routeSecret: 'route-secret-constant-rate',
  });

  alice.startCoverTraffic();
  await wait(260);
  const idleCount = sent.length;

  const realOne = alice.sendChat({
    content: 'real-1',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    routeSecret: 'route-secret-constant-rate',
  });
  const realTwo = alice.sendChat({
    content: 'real-2',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    routeSecret: 'route-secret-constant-rate',
  });

  await wait(260);
  const activeCount = sent.length - idleCount;
  alice.close();

  assert.ok(idleCount >= 4 && idleCount <= 8);
  assert.ok(activeCount >= 4 && activeCount <= 8);

  const sentIds = new Set(sent.map((message) => message.messageId));
  assert.equal(sentIds.has(realOne.messageId), true);
  assert.equal(sentIds.has(realTwo.messageId), true);
});

test('real messages are delivered correctly inside constant-traffic stream', async () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();
  const { client: alice, sent } = createClient(aliceIdentity, {
    constantTrafficEnabled: true,
    constantTrafficRatePerSecond: 24,
    outboundMixDelayRangeMs: { min: 0, max: 0 },
    routeTagEpochMessages: 2,
  });
  const { client: bob } = createClient(bobIdentity);

  alice.startCoverTraffic();
  alice.sendChat({
    content: 'embedded-real',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    routeSecret: 'route-secret-embedded',
  });
  await wait(240);
  alice.close();

  const payloads = [...sent]
    .sort((a, b) => a.counter - b.counter)
    .map((message) => tryDecrypt(bob, {
      message,
      senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
      senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
      routeSecret: 'route-secret-embedded',
    }))
    .filter(Boolean);
  assert.deepEqual(payloads.map((payload) => payload.content), ['embedded-real']);
});

test('outbound mixing delay keeps decrypt ordering safe', async () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();
  const { client: alice, sent } = createClient(aliceIdentity, {
    sendDelayRangeMs: { min: 0, max: 0 },
    batchingWindowMs: 0,
    outboundMixDelayRangeMs: { min: 20, max: 60 },
    parallelRouteTags: 1,
    rateShaping: { minMessagesPerSecond: 1_000_000, maxMessagesPerSecond: 1_000_000 },
  });
  const { client: bob } = createClient(bobIdentity, { receiveWindow: 20 });

  for (let i = 0; i < 6; i += 1) {
    alice.sendChat({
      content: `mix-${i}`,
      recipientDeviceId: bobIdentity.deviceId,
      recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
      routeSecret: 'route-secret-mix-order',
    });
  }
  await wait(120);

  const inOrder = [...sent].sort((a, b) => a.counter - b.counter);
  const decrypted = inOrder.map((message) => bob.decryptChat({
    message,
    senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
    senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
    routeSecret: 'route-secret-mix-order',
  }));
  assert.deepEqual(decrypted.map((payload) => payload.content), [
    'mix-0',
    'mix-1',
    'mix-2',
    'mix-3',
    'mix-4',
    'mix-5',
  ]);
});

test('auto-pull cadence remains consistent regardless of send activity', async () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();
  const { client: alice, sent } = createClient(aliceIdentity, {
    pullIntervalJitterMs: 8,
    normalizedPullRouteTagCount: 16,
  });

  alice.startAutoPull(['route-secret-auto-pull'], { intervalMs: 90, window: 1 });
  await wait(320);
  alice.sendChat({
    content: 'chat-while-pulling',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    routeSecret: 'route-secret-auto-pull',
  });
  await wait(320);
  alice.stopAutoPull();

  const pulls = sent.filter((message) => message.type === 'control' && message.action === 'pull');
  assert.ok(pulls.length >= 5);
  for (const pull of pulls) {
    assert.equal(pull.routeTags.length, 16);
  }
  const deltas = pulls.slice(1).map((pull, index) => pull.timestamp - pulls[index].timestamp);
  assert.equal(deltas.every((delta) => delta >= 75 && delta <= 120), true);
});

test('decoy sessions emit valid indistinguishable traffic', async () => {
  const identity = generateIdentity();
  const { client, sent } = createClient(identity, {
    constantTrafficEnabled: true,
    constantTrafficRatePerSecond: 18,
    decoySessionCount: 3,
    outboundMixDelayRangeMs: { min: 0, max: 0 },
  });

  client.startCoverTraffic();
  await wait(260);
  client.close();

  assert.ok(sent.length >= 3);
  assert.equal(sent.every((message) => message.type === 'chat'), true);
  assert.equal(sent.every((message) => typeof message.routeTag === 'string' && message.routeTag.length === 128), true);
  assert.equal(sent.every((message) => typeof message.signature === 'string'), true);
});

test('constant traffic interleaves multiple real sessions', async () => {
  const aliceIdentity = generateIdentity();
  const bobA = generateIdentity();
  const bobB = generateIdentity();
  const { client: alice, sent } = createClient(aliceIdentity, {
    constantTrafficEnabled: true,
    constantTrafficRatePerSecond: 26,
    outboundMixDelayRangeMs: { min: 0, max: 0 },
  });
  const { client: receiverA } = createClient(bobA, { receiveWindow: 20 });
  const { client: receiverB } = createClient(bobB, { receiveWindow: 20 });

  alice.startCoverTraffic();
  for (let i = 0; i < 4; i += 1) {
    alice.sendChat({
      content: `a-${i}`,
      recipientDeviceId: bobA.deviceId,
      recipientDevicePublicKey: bobA.deviceKeyPair.publicKey,
      routeSecret: 'route-secret-a',
    });
    alice.sendChat({
      content: `b-${i}`,
      recipientDeviceId: bobB.deviceId,
      recipientDevicePublicKey: bobB.deviceKeyPair.publicKey,
      routeSecret: 'route-secret-b',
    });
  }
  await wait(500);
  alice.close();

  const realLabels = [];
  for (const message of sent) {
    let decoded = null;
    try {
      decoded = receiverA.decryptChat({
        message,
        senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
        senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
        routeSecret: 'route-secret-a',
      });
      if (decoded) {
        realLabels.push('a');
        continue;
      }
    } catch (error) {
      void error;
      // message belongs to a different session
    }
    try {
      decoded = receiverB.decryptChat({
        message,
        senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
        senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
        routeSecret: 'route-secret-b',
      });
      if (decoded) {
        realLabels.push('b');
      }
    } catch (error) {
      void error;
      // message belongs to a different session
    }
  }

  assert.ok(realLabels.includes('a'));
  assert.ok(realLabels.includes('b'));
  assert.equal(realLabels.some((label, i) => i > 0 && label !== realLabels[i - 1]), true);
});
