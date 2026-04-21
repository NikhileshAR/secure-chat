const test = require('node:test');
const assert = require('node:assert/strict');
const { WebSocket } = require('ws');

const { SecureClient } = require('../src/client/client');
const { generateIdentity } = require('../src/client/identity');
const { RelayServer } = require('../src/server/relayServer');

function createClient(identity, options = {}) {
  const client = new SecureClient({
    serverUrl: 'ws://127.0.0.1:10001',
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

function openSocket(url) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url);
    socket.once('open', () => resolve(socket));
    socket.once('error', reject);
  });
}

test('malformed message payload is dropped without client crash or state corruption', () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();
  const { client: alice, sent } = createClient(aliceIdentity);
  const { client: bob } = createClient(bobIdentity);

  alice.sendChat({
    content: 'hello',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    recipientIdentityPublicKey: bobIdentity.identityKeyPair.publicKey,
    routeSecret: 'adversarial-route',
  });

  const malformed = { ...sent[0], encryptedPayload: '{not-json' };
  const sessionsBefore = bob.sessions.size;
  assert.throws(() => {
    bob.decryptChat({
      message: malformed,
      senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
      senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
      routeSecret: 'adversarial-route',
    });
  });

  assert.equal(bob.sessions.size, sessionsBefore);
  assert.ok(Array.isArray(bob.getSecuritySummary().warnings));
});

test('invalid counter gaps are rejected and do not corrupt receive chain state', () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();
  const { client: alice, sent } = createClient(aliceIdentity);
  const { client: bob } = createClient(bobIdentity);

  for (let i = 0; i < 15; i += 1) {
    alice.sendChat({
      content: `msg-${i}`,
      recipientDeviceId: bobIdentity.deviceId,
      recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
      recipientIdentityPublicKey: bobIdentity.identityKeyPair.publicKey,
      routeSecret: 'counter-gap-route',
    });
  }

  const farAhead = sent[sent.length - 1];
  assert.throws(() => {
    bob.decryptChat({
      message: farAhead,
      senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
      senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
      routeSecret: 'counter-gap-route',
    });
  }, /counter/i);

  const session = bob.sessions.get(aliceIdentity.deviceId);
  assert.equal(session.receiveCounter, 0);
  assert.ok(['DESYNC', 'SUSPECT', 'HEALTHY'].includes(bob.securityState.getCurrentState().sessionHealth));
});

test('replay flood is silently dropped without state corruption', () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();
  const { client: alice, sent } = createClient(aliceIdentity);
  const { client: bob } = createClient(bobIdentity);

  alice.sendChat({
    content: 'replay-target',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    recipientIdentityPublicKey: bobIdentity.identityKeyPair.publicKey,
    routeSecret: 'replay-route',
  });

  const first = bob.decryptChat({
    message: sent[0],
    senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
    senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
    routeSecret: 'replay-route',
  });
  assert.equal(first.content, 'replay-target');

  const session = bob.sessions.get(aliceIdentity.deviceId);
  const receiveCounterBefore = session.receiveCounter;
  for (let i = 0; i < 25; i += 1) {
    const replay = bob.decryptChat({
      message: sent[0],
      senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
      senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
      routeSecret: 'replay-route',
    });
    assert.equal(replay, null);
  }

  assert.equal(session.receiveCounter, receiveCounterBefore);
  assert.ok(session.skippedMessageKeys.size <= bob.maxSkippedMessageKeys);
});

test('fake routeTag messages are rejected and client remains usable', () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();
  const { client: alice, sent } = createClient(aliceIdentity);
  const { client: bob } = createClient(bobIdentity);

  alice.sendChat({
    content: 'valid-before-fake',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    recipientIdentityPublicKey: bobIdentity.identityKeyPair.publicKey,
    routeSecret: 'fake-routetag-route',
  });

  const fake = { ...sent[0], routeTag: `fake-${Date.now()}` };
  assert.throws(() => {
    bob.decryptChat({
      message: fake,
      senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
      senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
      routeSecret: 'fake-routetag-route',
    });
  }, /routeTag mismatch/i);

  // Client should still decrypt fresh valid traffic afterwards
  alice.sendChat({
    content: 'valid-after-fake',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    recipientIdentityPublicKey: bobIdentity.identityKeyPair.publicKey,
    routeSecret: 'fake-routetag-route',
  });

  const decrypted = bob.decryptChat({
    message: sent[1],
    senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
    senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
    routeSecret: 'fake-routetag-route',
  });
  assert.equal(decrypted.content, 'valid-after-fake');
});

test('relay drops oversized payload attack and remains stable', async () => {
  const port = 10100 + Math.floor(Math.random() * 300);
  const server = new RelayServer({
    host: '127.0.0.1',
    port,
    maxMessageSizeBytes: 512,
  });
  server.start();

  const attacker = await openSocket(`ws://127.0.0.1:${port}`);
  const attackerClosed = new Promise((resolve) => attacker.once('close', resolve));
  attacker.send(`${JSON.stringify({
    type: 'chat',
    protocolVersion: '1.0',
    senderDeviceId: 'attacker',
    routeTag: 'attack-route',
    messageId: 'attack-1',
    counter: 0,
    previousCounter: 0,
    dhPublicKey: 'k',
    encryptedPayload: 'X'.repeat(4096),
    timestamp: Date.now(),
    signature: 'sig',
  })}\n`);
  await attackerClosed;

  const benign = await openSocket(`ws://127.0.0.1:${port}`);
  benign.send(`${JSON.stringify({
    type: 'handshake',
    protocolVersion: '1.0',
    senderDeviceId: 'benign',
    encryptedPayload: '',
    timestamp: Date.now(),
  })}\n`);

  assert.equal(server.wss !== null, true);
  benign.close();
  server.stop();
});
