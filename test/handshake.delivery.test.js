const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { randomBytes } = require('node:crypto');

const { SecureClient } = require('../src/client/client');
const { generateIdentity } = require('../src/client/identity');
const { decodeMessage } = require('../src/protocol/wire');
const { InstanceManager } = require('../app/server');

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function routeSecretFor(a, b) {
  return [a, b].sort().join(':');
}

function createConnectedPair() {
  const identityA = generateIdentity();
  const identityB = generateIdentity();
  const routeSecret = routeSecretFor(identityA.deviceId, identityB.deviceId);
  const clientA = new SecureClient({
    identity: identityA,
    securityProfile: 'DEV',
    enforceReadySession: true,
    sendDelayRangeMs: { min: 0, max: 0 },
    batchingWindowMs: 0,
    pullNoiseLevel: 0,
    coverTrafficIntervalRangeMs: { min: 60_000, max: 60_000 },
    rateShaping: { minMessagesPerSecond: 1_000_000, maxMessagesPerSecond: 1_000_000 },
  });
  const clientB = new SecureClient({
    identity: identityB,
    securityProfile: 'DEV',
    enforceReadySession: true,
    sendDelayRangeMs: { min: 0, max: 0 },
    batchingWindowMs: 0,
    pullNoiseLevel: 0,
    coverTrafficIntervalRangeMs: { min: 60_000, max: 60_000 },
    rateShaping: { minMessagesPerSecond: 1_000_000, maxMessagesPerSecond: 1_000_000 },
  });

  const byDeviceId = new Map([
    [clientA.identity.deviceId, clientA],
    [clientB.identity.deviceId, clientB],
  ]);

  const keyByDeviceId = new Map([
    [clientA.identity.deviceId, {
      identityPublicKey: clientA.identity.identityKeyPair.publicKey,
      devicePublicKey: clientA.identity.deviceKeyPair.publicKey,
    }],
    [clientB.identity.deviceId, {
      identityPublicKey: clientB.identity.identityKeyPair.publicKey,
      devicePublicKey: clientB.identity.deviceKeyPair.publicKey,
    }],
  ]);

  function wireSend(senderClient, payload) {
    const decoded = decodeMessage(Buffer.from(payload), { strictMode: senderClient.strictWireMode });
    if (!decoded.targetDeviceId) {
      return;
    }
    const target = byDeviceId.get(decoded.targetDeviceId);
    if (!target) {
      return;
    }
    const senderKeys = keyByDeviceId.get(senderClient.identity.deviceId);
    try {
      target.handleInboundMessage({
        message: decoded,
        senderIdentityPublicKey: senderKeys.identityPublicKey,
        senderDevicePublicKey: senderKeys.devicePublicKey,
        routeSecret,
      });
    } catch {
      // ignored for negative tests
    }
  }

  for (const client of [clientA, clientB]) {
    client.socket = {
      OPEN: 1,
      readyState: 1,
      send(payload) {
        wireSend(client, payload);
      },
      close() {},
    };
    client.acknowledgeDelivery = () => {};
  }

  return { clientA, clientB, routeSecret };
}

test('two clients complete handshake and deliver messages', async () => {
  const { clientA, clientB, routeSecret } = createConnectedPair();
  const ready = await clientA.ensureSessionReady(
    clientB.identity.identityKeyPair.publicKey,
    clientB.identity.deviceKeyPair.publicKey,
    { peerDeviceId: clientB.identity.deviceId, routeSecret },
  );
  assert.equal(ready.handshakeState, 'COMPLETE');
  assert.equal(ready.isReady, true);

  const envelope = clientA.sendChat({
    content: 'hello',
    recipientDeviceId: clientB.identity.deviceId,
    recipientDevicePublicKey: clientB.identity.deviceKeyPair.publicKey,
    recipientIdentityPublicKey: clientB.identity.identityKeyPair.publicKey,
    routeSecret,
  });
  assert.ok(envelope);
  clientA.close();
  clientB.close();
});

test('message sent before handshake is queued then delivered after handshake', async () => {
  const { clientA, clientB, routeSecret } = createConnectedPair();
  let delivered = null;
  const originalHandle = clientB.handleInboundMessage.bind(clientB);
  clientB.handleInboundMessage = (params) => {
    const result = originalHandle(params);
    if (result && result.content) {
      delivered = result;
    }
    return result;
  };

  const envelope = clientA.sendChat({
    content: 'queued message',
    recipientDeviceId: clientB.identity.deviceId,
    recipientDevicePublicKey: clientB.identity.deviceKeyPair.publicKey,
    recipientIdentityPublicKey: clientB.identity.identityKeyPair.publicKey,
    routeSecret,
  });
  assert.equal(envelope, null);

  for (let i = 0; i < 20 && !delivered; i += 1) {
    await wait(20);
  }
  assert.equal(delivered?.content, 'queued message');
  clientA.close();
  clientB.close();
});

test('missing contact bootstrap fields are rejected', (t) => {
  const manager = new InstanceManager();
  const context = manager.getContext(`hs-contact-${randomBytes(6).toString('hex')}`);
  t.after(() => {
    if (context.client) {
      context.client.close();
    }
    fs.rmSync(context.paths.baseDir, { recursive: true, force: true });
  });
  const payload = JSON.stringify({
    identityPublicKey: manager.ensureClient(context).identity.identityKeyPair.publicKey,
  });
  assert.throws(() => manager.addContactFromPayload(context, payload, 'Peer'));
});

test('routeTag mismatch causes message rejection', async () => {
  const { clientA, clientB, routeSecret } = createConnectedPair();
  await clientA.ensureSessionReady(
    clientB.identity.identityKeyPair.publicKey,
    clientB.identity.deviceKeyPair.publicKey,
    { peerDeviceId: clientB.identity.deviceId, routeSecret },
  );
  const outbound = clientA.sendChat({
    content: 'tamper',
    recipientDeviceId: clientB.identity.deviceId,
    recipientDevicePublicKey: clientB.identity.deviceKeyPair.publicKey,
    recipientIdentityPublicKey: clientB.identity.identityKeyPair.publicKey,
    routeSecret,
  });
  const tampered = { ...outbound, routeTag: `bad-${outbound.routeTag}` };
  const result = clientB.handleInboundMessage({
    message: tampered,
    senderIdentityPublicKey: clientA.identity.identityKeyPair.publicKey,
    senderDevicePublicKey: clientA.identity.deviceKeyPair.publicKey,
    routeSecret,
  });
  assert.equal(result, null);
  clientA.close();
  clientB.close();
});

test('duplicate message is rejected', async () => {
  const identityA = generateIdentity();
  const identityB = generateIdentity();
  const routeSecret = routeSecretFor(identityA.deviceId, identityB.deviceId);
  const clientA = new SecureClient({
    identity: identityA,
    securityProfile: 'DEV',
    sendDelayRangeMs: { min: 0, max: 0 },
    batchingWindowMs: 0,
  });
  const clientB = new SecureClient({
    identity: identityB,
    securityProfile: 'DEV',
    sendDelayRangeMs: { min: 0, max: 0 },
    batchingWindowMs: 0,
  });
  for (const client of [clientA, clientB]) {
    client.socket = {
      OPEN: 1,
      readyState: 1,
      send() {},
      close() {},
    };
    client.acknowledgeDelivery = () => {};
  }
  const outbound = clientA.sendChat({
    content: 'once',
    recipientDeviceId: identityB.deviceId,
    recipientDevicePublicKey: identityB.deviceKeyPair.publicKey,
    recipientIdentityPublicKey: identityB.identityKeyPair.publicKey,
    routeSecret,
  });
  const first = clientB.handleInboundMessage({
    message: outbound,
    senderIdentityPublicKey: identityA.identityKeyPair.publicKey,
    senderDevicePublicKey: identityA.deviceKeyPair.publicKey,
    routeSecret,
  });
  const second = clientB.handleInboundMessage({
    message: outbound,
    senderIdentityPublicKey: identityA.identityKeyPair.publicKey,
    senderDevicePublicKey: identityA.deviceKeyPair.publicKey,
    routeSecret,
  });
  assert.equal(first.content, 'once');
  assert.equal(second, null);
  clientA.close();
  clientB.close();
});
