const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { WebSocket } = require('ws');

const { NetworkIdentityManager } = require('../src/server/networkIdentity');
const { InviteManager } = require('../src/server/inviteManager');
const { NetworkTrustStore } = require('../src/client/networkTrustStore');
const { RelayServer } = require('../src/server/relayServer');
const { SecureClient } = require('../src/client/client');
const { generateIdentity } = require('../src/client/identity');

function makeDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function openSocket(url) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url);
    socket.once('open', () => resolve(socket));
    socket.once('error', reject);
  });
}

test('network identity persists across restart', () => {
  const dir = makeDir('securechat-network-id-');
  try {
    const m1 = new NetworkIdentityManager({ storageDir: dir });
    const id1 = m1.getNetworkIdentity();
    const m2 = new NetworkIdentityManager({ storageDir: dir });
    const id2 = m2.getNetworkIdentity();
    assert.equal(id1.networkId, id2.networkId);
    assert.equal(id1.networkPublicKey, id2.networkPublicKey);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('network key change is detected and blocked after trust', () => {
  const trustDir = makeDir('securechat-network-trust-');
  const netDirA = makeDir('securechat-network-a-');
  const netDirB = makeDir('securechat-network-b-');
  try {
    const trust = new NetworkTrustStore({ storageDir: trustDir });
    const managerA = new NetworkIdentityManager({ storageDir: netDirA });
    const managerB = new NetworkIdentityManager({ storageDir: netDirB });
    const identityA = managerA.getNetworkIdentity();
    const identityB = managerB.getNetworkIdentity();
    const metadataA = {
      networkId: identityA.networkId,
      networkPublicKey: identityA.networkPublicKey,
      accessMode: 'OPEN',
      ephemeralMode: true,
      issuedAt: Date.now(),
    };
    const metadataB = {
      networkId: identityA.networkId,
      networkPublicKey: identityB.networkPublicKey,
      accessMode: 'OPEN',
      ephemeralMode: true,
      issuedAt: Date.now(),
    };
    assert.equal(trust.verifyAndTrust({
      networkId: identityA.networkId,
      networkPublicKey: identityA.networkPublicKey,
      networkMetadata: metadataA,
      networkMetadataSignature: managerA.signNetworkMetadata(metadataA),
    }).ok, true);
    const changed = trust.verifyAndTrust({
      networkId: identityA.networkId,
      networkPublicKey: identityB.networkPublicKey,
      networkMetadata: metadataB,
      networkMetadataSignature: managerB.signNetworkMetadata(metadataB),
    });
    assert.equal(changed.ok, false);
    assert.equal(changed.reason, 'network_key_changed');
  } finally {
    fs.rmSync(trustDir, { recursive: true, force: true });
    fs.rmSync(netDirA, { recursive: true, force: true });
    fs.rmSync(netDirB, { recursive: true, force: true });
  }
});

test('valid invite token is accepted by invite-only relay', async () => {
  const dir = makeDir('securechat-network-invite-relay-');
  const port = 11000 + Math.floor(Math.random() * 400);
  const server = new RelayServer({
    host: '127.0.0.1',
    port,
    accessMode: 'INVITE_ONLY',
    networkIdentityStorageDir: dir,
  });
  server.start();
  try {
    const token = server.inviteManager.generateToken({
      usageLimit: 1,
      expiresAt: Date.now() + 60_000,
      label: 'test',
    });
    const socket = await openSocket(`ws://127.0.0.1:${port}`);
    socket.send(`${JSON.stringify({
      type: 'handshake',
      protocolVersion: '1.0',
      senderDeviceId: 'invite-user',
      encryptedPayload: '',
      timestamp: Date.now(),
      inviteToken: token,
    })}\n`);
    await new Promise((resolve) => setTimeout(resolve, 40));
    assert.equal(server.connections.has('invite-user'), true);
    socket.close();
  } finally {
    server.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('expired and tampered invite tokens are rejected', () => {
  const dir = makeDir('securechat-network-invite-verify-');
  try {
    const identity = new NetworkIdentityManager({ storageDir: dir });
    const manager = new InviteManager({ networkIdentity: identity, storageDir: dir });
    const expired = manager.generateToken({ expiresAt: Date.now() - 1, usageLimit: 1 });
    assert.equal(manager.verifyToken(expired).valid, false);

    const valid = manager.generateToken({ expiresAt: Date.now() + 60_000, usageLimit: 1 });
    const [payloadPart, signaturePart] = valid.split('.');
    const tamperedPayload = `${payloadPart.slice(0, -2)}zz`;
    const tampered = `${tamperedPayload}.${signaturePart}`;
    assert.equal(manager.verifyToken(tampered).valid, false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('locked network blocks new users while keeping existing sessions', async () => {
  const dir = makeDir('securechat-network-lock-');
  const port = 11450 + Math.floor(Math.random() * 200);
  const server = new RelayServer({
    host: '127.0.0.1',
    port,
    networkIdentityStorageDir: dir,
  });
  server.start();
  try {
    const existing = await openSocket(`ws://127.0.0.1:${port}`);
    existing.send(`${JSON.stringify({
      type: 'handshake',
      protocolVersion: '1.0',
      senderDeviceId: 'existing-user',
      encryptedPayload: '',
      timestamp: Date.now(),
    })}\n`);
    await new Promise((resolve) => setTimeout(resolve, 40));
    assert.equal(server.connections.has('existing-user'), true);

    server.lockNetwork();
    const newcomer = await openSocket(`ws://127.0.0.1:${port}`);
    newcomer.send(`${JSON.stringify({
      type: 'handshake',
      protocolVersion: '1.0',
      senderDeviceId: 'new-user',
      encryptedPayload: '',
      timestamp: Date.now(),
    })}\n`);
    await new Promise((resolve) => setTimeout(resolve, 40));
    assert.equal(server.connections.has('existing-user'), true);
    assert.equal(server.connections.has('new-user'), false);
    existing.close();
    newcomer.close();
  } finally {
    server.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('bundle mismatch is blocked by client relay verification', () => {
  const trustDir = makeDir('securechat-network-bundle-trust-');
  const netDir = makeDir('securechat-network-bundle-net-');
  try {
    const identity = new NetworkIdentityManager({ storageDir: netDir });
    const net = identity.getNetworkIdentity();
    const metadata = {
      networkId: net.networkId,
      networkPublicKey: net.networkPublicKey,
      accessMode: 'OPEN',
      ephemeralMode: true,
      issuedAt: Date.now(),
    };
    const client = new SecureClient({
      serverUrl: 'ws://127.0.0.1:9999',
      identity: generateIdentity(),
      networkTrustStore: new NetworkTrustStore({ storageDir: trustDir }),
      networkBundle: {
        relayUrl: 'ws://127.0.0.1:9999',
        networkId: 'mismatched-network-id',
        networkPublicKey: net.networkPublicKey,
        accessMode: 'OPEN',
      },
      sendDelayRangeMs: { min: 0, max: 0 },
      batchingWindowMs: 0,
      parallelRouteTags: 1,
      pullNoiseLevel: 0,
      coverTrafficIntervalRangeMs: { min: 60_000, max: 60_000 },
      rateShaping: { minMessagesPerSecond: 1000, maxMessagesPerSecond: 1000 },
      strictWireMode: false,
    });
    const valid = client.verifyRelayHandshake({
      type: 'handshake',
      senderDeviceId: 'relay',
      protocolVersion: '1.0',
      timestamp: Date.now(),
      encryptedPayload: '',
      networkId: net.networkId,
      networkPublicKey: net.networkPublicKey,
      networkMetadata: metadata,
      networkMetadataSignature: identity.signNetworkMetadata(metadata),
      accessMode: 'OPEN',
      ephemeralMode: true,
    });
    assert.equal(valid, false);
  } finally {
    fs.rmSync(trustDir, { recursive: true, force: true });
    fs.rmSync(netDir, { recursive: true, force: true });
  }
});
