const test = require('node:test');
const assert = require('node:assert/strict');
const { SecureClient } = require('../src/client/client');
const { generateIdentity } = require('../src/client/identity');

function createClient(identity, options = {}) {
  const client = new SecureClient({ serverUrl: 'ws://127.0.0.1:1', identity, ...options });
  const sent = [];
  client.sendRaw = (message) => sent.push(message);
  return { client, sent };
}

test('client validates identity-device key binding from handshake', () => {
  const identity = generateIdentity();
  const { client } = createClient(generateIdentity());

  const validHandshake = {
    identityPublicKey: identity.identityKeyPair.publicKey,
    devicePublicKey: identity.deviceKeyPair.publicKey,
    deviceKeySignature: identity.deviceKeySignature,
  };
  const invalidHandshake = {
    ...validHandshake,
    devicePublicKey: `${identity.deviceKeyPair.publicKey}\n`,
  };

  assert.equal(client.isHandshakeValid(validHandshake), true);
  assert.equal(client.isHandshakeValid(invalidHandshake), false);
});

test('sendChat rotates routeTag and counters', () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();
  const { client: alice, sent } = createClient(aliceIdentity);

  alice.sendChat({
    content: 'first',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    routeSecret: 'shared-route-secret',
  });
  alice.sendChat({
    content: 'second',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    routeSecret: 'shared-route-secret',
  });

  assert.equal(sent.length, 2);
  assert.equal(sent[0].counter, 0);
  assert.equal(sent[1].counter, 1);
  assert.notEqual(sent[0].routeTag, sent[1].routeTag);
});

test('decryptChat drops replayed message ids and handles out-of-order counters', () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();
  const { client: alice, sent } = createClient(aliceIdentity);
  const { client: bob } = createClient(bobIdentity);

  alice.sendChat({
    content: 'first',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    routeSecret: 'shared-route-secret',
  });
  alice.sendChat({
    content: 'second',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    routeSecret: 'shared-route-secret',
  });

  const second = bob.decryptChat({
    message: sent[1],
    senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
    senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
    routeSecret: 'shared-route-secret',
  });
  const first = bob.decryptChat({
    message: sent[0],
    senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
    senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
    routeSecret: 'shared-route-secret',
  });
  const session = bob.sessions.get(aliceIdentity.deviceId);
  const beforeReceiveCounter = session.receiveCounter;
  const beforePendingSize = session.skippedMessageKeys.size;
  let replay = 'unset';
  assert.doesNotThrow(() => {
    replay = bob.decryptChat({
      message: sent[0],
      senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
      senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
    routeSecret: 'shared-route-secret',
    });
  });

  assert.equal(second.content, 'second');
  assert.equal(first.content, 'first');
  assert.equal(replay, null);
  assert.equal(session.receiveCounter, beforeReceiveCounter);
  assert.equal(session.skippedMessageKeys.size, beforePendingSize);
});

test('chat message format includes strict protocol fields', () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();
  const { client: alice, sent } = createClient(aliceIdentity);

  alice.sendChat({
    content: 'secure',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    recipientIdentityPublicKey: bobIdentity.identityKeyPair.publicKey,
    routeSecret: 'shared-route-secret',
  });

  const message = sent[0];
  assert.equal(typeof message.messageId, 'string');
  assert.equal(typeof message.counter, 'number');
  assert.equal(typeof message.previousCounter, 'number');
  assert.equal(typeof message.dhPublicKey, 'string');
  assert.equal(typeof message.routeTag, 'string');
  assert.equal(typeof message.signature, 'string');
});

test('decryptChat rejects messages missing required fields', () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();
  const { client: alice, sent } = createClient(aliceIdentity);
  const { client: bob } = createClient(bobIdentity);

  alice.sendChat({
    content: 'strict',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    recipientIdentityPublicKey: bobIdentity.identityKeyPair.publicKey,
    routeSecret: 'shared-route-secret',
  });

  const malformed = { ...sent[0] };
  delete malformed.previousCounter;

  assert.throws(() => {
    bob.decryptChat({
      message: malformed,
      senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
      senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
    routeSecret: 'shared-route-secret',
    });
  }, /missing required field/i);
});

test('receiving a new peer DH public key triggers receive ratchet step', () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();
  const { client: alice, sent: aliceSent } = createClient(aliceIdentity);
  const { client: bob } = createClient(bobIdentity);

  alice.sendChat({
    content: 'hello',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    recipientIdentityPublicKey: bobIdentity.identityKeyPair.publicKey,
      routeSecret: 'shared-route-secret',
  });
  bob.decryptChat({
    message: aliceSent[0],
    senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
    senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
      routeSecret: 'shared-route-secret',
  });

  const aliceSession = alice.sessions.get(bobIdentity.deviceId);
  const oldDh = aliceSession.selfDHKeyPair.publicKey;
  aliceSession.ratchetPending = true;
  alice.sendChat({
    content: 'new-dh',
    recipientDeviceId: bobIdentity.deviceId,
    recipientDevicePublicKey: bobIdentity.deviceKeyPair.publicKey,
    recipientIdentityPublicKey: bobIdentity.identityKeyPair.publicKey,
    routeSecret: 'shared-route-secret',
  });

  bob.decryptChat({
    message: aliceSent[1],
    senderDevicePublicKey: aliceIdentity.deviceKeyPair.publicKey,
    senderIdentityPublicKey: aliceIdentity.identityKeyPair.publicKey,
    routeSecret: 'shared-route-secret',
  });
  const bobSessionAfter = bob.sessions.get(aliceIdentity.deviceId);
  assert.notEqual(alice.sessions.get(bobIdentity.deviceId).selfDHKeyPair.publicKey, oldDh);
  assert.equal(bobSessionAfter.lastDHKey, aliceSent[1].dhPublicKey);
});

test('identity continuity rejects unexpected peer identity changes unless manually reset', () => {
  const aliceIdentity = generateIdentity();
  const bobIdentityV1 = generateIdentity();
  const bobIdentityV2 = generateIdentity();
  const { client: alice } = createClient(aliceIdentity);

  alice.ensureSession({
    peerDeviceId: bobIdentityV1.deviceId,
    peerIdentityPublicKey: bobIdentityV1.identityKeyPair.publicKey,
    peerDevicePublicKey: bobIdentityV1.deviceKeyPair.publicKey,
    routeSecret: 'shared-route-secret',
  });

  assert.throws(() => {
    alice.ensureSession({
      peerDeviceId: bobIdentityV1.deviceId,
      peerIdentityPublicKey: bobIdentityV2.identityKeyPair.publicKey,
      peerDevicePublicKey: bobIdentityV1.deviceKeyPair.publicKey,
      routeSecret: 'shared-route-secret',
    });
  }, /identity changed/i);

  assert.doesNotThrow(() => {
    alice.resetPeerIdentityTrust(bobIdentityV1.deviceId, bobIdentityV2.identityKeyPair.publicKey);
    alice.ensureSession({
      peerDeviceId: bobIdentityV1.deviceId,
      peerIdentityPublicKey: bobIdentityV2.identityKeyPair.publicKey,
      peerDevicePublicKey: bobIdentityV1.deviceKeyPair.publicKey,
      routeSecret: 'shared-route-secret',
    });
  });
});
