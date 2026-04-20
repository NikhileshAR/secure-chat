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
  const beforePendingSize = session.pendingReceiveKeys.size;
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
  assert.equal(session.pendingReceiveKeys.size, beforePendingSize);
});
