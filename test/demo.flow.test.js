const test = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');

const { SecureClient } = require('../src/client/client');
const { generateIdentity, formatIdentityFingerprint } = require('../src/client/identity');

function createDemoClient(identity) {
  const client = new SecureClient({
    serverUrl: 'ws://127.0.0.1:1',
    identity,
    sendDelayRangeMs: { min: 0, max: 0 },
    batchingWindowMs: 0,
    parallelRouteTags: 1,
    pullNoiseLevel: 0,
    coverTrafficIntervalRangeMs: { min: 60_000, max: 60_000 },
    rateShaping: { minMessagesPerSecond: 1_000_000, maxMessagesPerSecond: 1_000_000 },
    securityProfile: 'DEV',
  });

  const wire = [];
  client.sendRaw = (message) => {
    wire.push(message);
  };

  return { client, wire };
}

function buildIdentitySharePayload(identity, routeSecret) {
  return {
    identityPublicKey: identity.identityKeyPair.publicKey,
    fingerprint: formatIdentityFingerprint(identity.identityKeyPair.publicKey),
    deviceId: identity.deviceId,
    devicePublicKey: identity.deviceKeyPair.publicKey,
    routeSecret,
  };
}

test('demo flow: two clients exchange identity payloads and deliver messages', () => {
  const aliceIdentity = generateIdentity();
  const bobIdentity = generateIdentity();
  const { client: alice, wire: aliceWire } = createDemoClient(aliceIdentity);
  const { client: bob, wire: bobWire } = createDemoClient(bobIdentity);

  const aliceInboundRouteSecret = randomBytes(32).toString('base64');
  const bobInboundRouteSecret = randomBytes(32).toString('base64');

  const alicePayload = buildIdentitySharePayload(aliceIdentity, aliceInboundRouteSecret);
  const bobPayload = buildIdentitySharePayload(bobIdentity, bobInboundRouteSecret);

  assert.equal(alicePayload.fingerprint, formatIdentityFingerprint(alicePayload.identityPublicKey));
  assert.equal(bobPayload.fingerprint, formatIdentityFingerprint(bobPayload.identityPublicKey));

  alice.trustIdentity(bobPayload.identityPublicKey, 'Bob');
  bob.trustIdentity(alicePayload.identityPublicKey, 'Alice');
  assert.equal(alice.getTrustLevel(bobPayload.identityPublicKey), 'TRUSTED');
  assert.equal(bob.getTrustLevel(alicePayload.identityPublicKey), 'TRUSTED');

  const outboundA = alice.sendChat({
    content: 'hello from alice',
    recipientDeviceId: bobPayload.deviceId,
    recipientDevicePublicKey: bobPayload.devicePublicKey,
    recipientIdentityPublicKey: bobPayload.identityPublicKey,
    routeSecret: bobPayload.routeSecret,
  });

  let receivedByBob = null;
  assert.doesNotThrow(() => {
    receivedByBob = bob.handleInboundMessage({
      message: outboundA,
      senderDevicePublicKey: alicePayload.devicePublicKey,
      senderIdentityPublicKey: alicePayload.identityPublicKey,
      routeSecret: bobPayload.routeSecret,
    });
  });
  assert.equal(receivedByBob.content, 'hello from alice');

  const outboundB = bob.sendChat({
    content: 'hello from bob',
    recipientDeviceId: alicePayload.deviceId,
    recipientDevicePublicKey: alicePayload.devicePublicKey,
    recipientIdentityPublicKey: alicePayload.identityPublicKey,
    routeSecret: alicePayload.routeSecret,
  });

  let receivedByAlice = null;
  assert.doesNotThrow(() => {
    receivedByAlice = alice.handleInboundMessage({
      message: outboundB,
      senderDevicePublicKey: bobPayload.devicePublicKey,
      senderIdentityPublicKey: bobPayload.identityPublicKey,
      routeSecret: alicePayload.routeSecret,
    });
  });
  assert.equal(receivedByAlice.content, 'hello from bob');

  assert.equal(aliceWire.length > 0, true);
  assert.equal(bobWire.length > 0, true);

  alice.close();
  bob.close();
});
