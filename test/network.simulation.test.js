const test = require('node:test');
const assert = require('node:assert/strict');

const { SecureClient } = require('../src/client/client');
const { generateIdentity } = require('../src/client/identity');
const { decodeMessage } = require('../src/protocol/wire');

function createPrng(seed = 123456789) {
  let state = seed >>> 0;
  return () => {
    state = (1664525 * state + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

function routeSecretFor(a, b) {
  return [a, b].sort().join(':');
}

function makeClient(identity, network) {
  const client = new SecureClient({
    serverUrl: 'ws://127.0.0.1:1',
    identity,
    sendDelayRangeMs: { min: 0, max: 0 },
    batchingWindowMs: 0,
    parallelRouteTags: 1,
    pullNoiseLevel: 0,
    coverTrafficIntervalRangeMs: { min: 60_000, max: 60_000 },
    rateShaping: { minMessagesPerSecond: 1_000_000, maxMessagesPerSecond: 1_000_000 },
  });

  client.socket = {
    OPEN: 1,
    readyState: 1,
    send(payload) {
      network.push(payload);
    },
    close() {},
  };

  client.acknowledgeDelivery = () => {};
  return client;
}

test('simulated network with delay/reorder/dup/drop preserves safety and eventual decrypt', () => {
  const prng = createPrng(0xC0FFEE);
  const clientCount = 8;
  const identities = Array.from({ length: clientCount }, () => generateIdentity());
  const wire = [];
  const clients = identities.map((identity) => makeClient(identity, wire));
  const byDeviceId = new Map(clients.map((client) => [client.identity.deviceId, client]));

  let sentMessages = 0;
  for (let i = 0; i < clients.length; i += 1) {
    const sender = clients[i];
    const recipient = clients[(i + 1) % clients.length];
    for (let n = 0; n < 2; n += 1) {
      sender.sendChat({
        content: `msg-${i}-${n}`,
        recipientDeviceId: recipient.identity.deviceId,
        recipientDevicePublicKey: recipient.identity.deviceKeyPair.publicKey,
        recipientIdentityPublicKey: recipient.identity.identityKeyPair.publicKey,
        routeSecret: routeSecretFor(sender.identity.deviceId, recipient.identity.deviceId),
      });
      sentMessages += 1;
    }
  }

  const originalPackets = wire
    .map((payload) => ({ payload: Buffer.from(payload) }))
    .filter((packet) => decodeMessage(packet.payload, { strictMode: false }).type === 'chat');

  const dropped = [];
  const firstPass = [];
  let duplicateDeliveries = 0;
  for (const packet of originalPackets) {
    if (prng() < 0.2) {
      dropped.push(packet);
      continue;
    }
    firstPass.push({ ...packet, replay: false });
    if (prng() < 0.25) {
      firstPass.push({ ...packet, replay: true });
      duplicateDeliveries += 1;
    }
  }

  firstPass.sort(() => prng() - 0.5);

  let decryptCount = 0;
  let replayRejected = 0;
  let crashes = 0;

  function deliver(packet) {
    const decoded = decodeMessage(packet.payload, { strictMode: false });
    const target = byDeviceId.get(decoded.targetDeviceId);
    const sender = byDeviceId.get(decoded.senderDeviceId);
    if (!target || !sender) {
      return;
    }
    const payload = target.handleInboundMessage({
      message: packet.payload,
      senderDevicePublicKey: sender.identity.deviceKeyPair.publicKey,
      senderIdentityPublicKey: sender.identity.identityKeyPair.publicKey,
      routeSecret: routeSecretFor(sender.identity.deviceId, target.identity.deviceId),
    });
    if (payload && payload.content) {
      decryptCount += 1;
    }
    if (packet.replay && payload === null) {
      replayRejected += 1;
    }
  }

  for (const packet of firstPass) {
    try {
      deliver(packet);
    } catch {
      crashes += 1;
    }
  }

  for (const packet of dropped.reverse()) {
    try {
      deliver({ ...packet, replay: false });
    } catch {
      crashes += 1;
    }
  }

  assert.equal(crashes, 0);
  assert.equal(decryptCount, sentMessages);
  assert.ok(replayRejected >= Math.floor(duplicateDeliveries / 2));

  for (const client of clients) {
    for (const session of client.sessions.values()) {
      assert.ok(session.receiveCounter >= 0);
      assert.ok(session.skippedMessageKeys.size <= client.maxSkippedMessageKeys);
    }
    client.close();
  }
});
