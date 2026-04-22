const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { WebSocket } = require('ws');

const { loadConfig, startRelay } = require('../deploy/start-relay');
const { SecureClient } = require('../src/client/client');
const { generateIdentity } = require('../src/client/identity');

function openSocket(url) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url);
    socket.once('open', () => resolve(socket));
    socket.once('error', reject);
  });
}

function onceMessage(socket) {
  return new Promise((resolve) => socket.once('message', (data) => resolve(data.toString())));
}

test('relay starts with config via deployment loader', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'securechat-deploy-config-'));
  const configPath = path.join(dir, 'relay.config.json');
  const config = {
    host: '127.0.0.1',
    port: 16000 + Math.floor(Math.random() * 1000),
    maxConnections: 64,
    maxBufferedBytes: 128 * 1024,
    maxMessageSizeBytes: 64 * 1024,
    rateLimits: {
      connection: { windowMs: 1000, maxMessages: 400 },
      device: { windowMs: 1000, maxMessages: 400 },
      routeTag: { windowMs: 1000, maxMessages: 400 },
    },
    strictWireMode: true,
    securityProfile: 'BALANCED',
    ephemeralMode: true,
    logLevel: 'minimal',
    enableMetrics: true,
  };
  fs.writeFileSync(configPath, `${JSON.stringify(config)}\n`);

  const loaded = loadConfig(configPath);
  const { server } = startRelay(loaded);
  const metrics = server.getMetrics();

  assert.equal(metrics.ephemeralMode, true);
  assert.equal(metrics.activeConnections, 0);
  server.stop();
  fs.rmSync(dir, { recursive: true, force: true });
});

test('ephemeral relay mode clears buffered messages on restart', async () => {
  const port = 17000 + Math.floor(Math.random() * 500);
  const config = {
    host: '127.0.0.1',
    port,
    maxConnections: 64,
    maxBufferedBytes: 128 * 1024,
    maxMessageSizeBytes: 64 * 1024,
    rateLimits: {
      connection: { windowMs: 1000, maxMessages: 400 },
      device: { windowMs: 1000, maxMessages: 400 },
      routeTag: { windowMs: 1000, maxMessages: 400 },
    },
    strictWireMode: true,
    securityProfile: 'BALANCED',
    ephemeralMode: true,
    logLevel: 'minimal',
  };

  let runtime = startRelay(config);
  const sender = await openSocket(`ws://127.0.0.1:${port}`);
  sender.send(`${JSON.stringify({ type: 'handshake', senderDeviceId: 'sender', encryptedPayload: '', timestamp: Date.now() })}\n`);
  sender.send(`${JSON.stringify({
    type: 'chat',
    senderDeviceId: 'sender',
    routeTag: 'restart-route',
    messageId: 'm1',
    counter: 0,
    encryptedPayload: 'ciphertext',
    timestamp: Date.now(),
    signature: 'sig',
  })}\n`);
  sender.close();
  runtime.server.stop();

  runtime = startRelay(config);
  const receiver = await openSocket(`ws://127.0.0.1:${port}`);
  receiver.send(`${JSON.stringify({ type: 'handshake', senderDeviceId: 'receiver', encryptedPayload: '', timestamp: Date.now() })}\n`);
  const wait = onceMessage(receiver);
  receiver.send(`${JSON.stringify({
    type: 'control',
    action: 'pull',
    senderDeviceId: 'receiver',
    routeTags: ['restart-route'],
    encryptedPayload: '',
    timestamp: Date.now(),
  })}\n`);

  const response = JSON.parse((await wait).trim());
  const payload = JSON.parse(response.encryptedPayload);
  assert.equal(Array.isArray(payload.messages), true);
  assert.equal(payload.messages.length, 0);

  receiver.close();
  runtime.server.stop();
});

test('client hardened OPSEC mode blocks unsafe actions', () => {
  const client = new SecureClient({
    serverUrl: 'ws://127.0.0.1:1',
    identity: generateIdentity(),
    opsecMode: 'HARDENED',
    securityProfile: 'DEV',
    pullNoiseLevel: 0,
  });

  assert.throws(() => client.exportPrivateKeys('pass', { confirmed: true }), /blocked/i);
  assert.throws(() => client.setStrictWireMode(false, { confirmed: true }), /cannot be disabled/i);
  assert.throws(() => client.exportSecurityLog('/tmp/x.log', 'pass', { confirmed: true }), /double confirmation/i);
  client.close();
});

test('relay registry APIs are local and functional', async () => {
  const port = 17500 + Math.floor(Math.random() * 500);
  const { server } = startRelay({
    host: '127.0.0.1',
    port,
    maxConnections: 16,
    maxBufferedBytes: 128 * 1024,
    maxMessageSizeBytes: 64 * 1024,
    rateLimits: {
      connection: { windowMs: 1000, maxMessages: 200 },
      device: { windowMs: 1000, maxMessages: 200 },
      routeTag: { windowMs: 1000, maxMessages: 200 },
    },
    strictWireMode: true,
    securityProfile: 'BALANCED',
    ephemeralMode: true,
  });

  const client = new SecureClient({
    serverUrl: `ws://127.0.0.1:${port}`,
    identity: generateIdentity(),
    securityProfile: 'DEV',
    pullNoiseLevel: 0,
  });

  client.addRelay(`ws://127.0.0.1:${port}`, 'local-relay');
  assert.ok(client.listRelays().some((relay) => relay.url === `ws://127.0.0.1:${port}`));
  await client.connectToRelay(`ws://127.0.0.1:${port}`);
  client.removeRelay(`ws://127.0.0.1:${port}`);
  assert.equal(client.listRelays().some((relay) => relay.url === `ws://127.0.0.1:${port}`), false);

  client.close();
  server.stop();
});

test('backup export/import preserves encrypted state integrity', () => {
  const dirA = fs.mkdtempSync(path.join(os.tmpdir(), 'securechat-backup-a-'));
  const dirB = fs.mkdtempSync(path.join(os.tmpdir(), 'securechat-backup-b-'));

  const identity = generateIdentity();
  const clientA = new SecureClient({
    serverUrl: 'ws://127.0.0.1:1',
    identity,
    sessionStorageDir: dirA,
    trustStoreStorageDir: dirA,
    deviceSecret: 'backup-secret',
    securityProfile: 'DEV',
    pullNoiseLevel: 0,
  });
  clientA.ensureSession({ peerDeviceId: 'peer-1', routeSecret: 'route-1' });
  const backup = clientA.exportBackup('passphrase-1');

  const clientB = new SecureClient({
    serverUrl: 'ws://127.0.0.1:1',
    identity: generateIdentity(),
    sessionStorageDir: dirB,
    trustStoreStorageDir: dirB,
    deviceSecret: 'backup-secret',
    securityProfile: 'DEV',
    pullNoiseLevel: 0,
  });

  assert.throws(() => clientB.importBackup(backup, 'wrong-passphrase', { allowIdentityOverwrite: true }), /authentication failed/i);
  const result = clientB.importBackup(backup, 'passphrase-1', { allowIdentityOverwrite: true });

  assert.equal(result.importedSessions >= 1, true);
  assert.equal(clientB.identity.identityKeyPair.publicKey, clientA.identity.identityKeyPair.publicKey);

  clientA.close();
  clientB.close();
  fs.rmSync(dirA, { recursive: true, force: true });
  fs.rmSync(dirB, { recursive: true, force: true });
});
