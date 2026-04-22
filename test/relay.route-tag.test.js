const test = require('node:test');
const assert = require('node:assert/strict');
const { WebSocket } = require('ws');
const { RelayServer } = require('../src/server/relayServer');
const { computeRouteTag } = require('../src/client/crypto');

function openSocket(url) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url);
    socket.once('open', () => resolve(socket));
    socket.once('error', reject);
  });
}

function onceMessage(socket) {
  return new Promise((resolve) => {
    socket.once('message', (data) => resolve(data.toString()));
  });
}

function collectMessages(socket, expectedCount) {
  return new Promise((resolve) => {
    const messages = [];
    const listener = (data) => {
      messages.push(data.toString());
      if (messages.length >= expectedCount) {
        socket.off('message', listener);
        resolve(messages);
      }
    };
    socket.on('message', listener);
  });
}

test('receiver can pull buffered chat by routeTag', async () => {
  const port = 8900 + Math.floor(Math.random() * 200);
  const server = new RelayServer({ host: '127.0.0.1', port, messageTtlMs: 10_000 });
  server.start();

  const sender = await openSocket(`ws://127.0.0.1:${port}`);
  sender.send(`${JSON.stringify({
    type: 'handshake',
    senderDeviceId: 'sender-1',
    encryptedPayload: '',
    timestamp: Date.now(),
  })}\n`);

  const routeTag = computeRouteTag('shared-route-secret', 0);
  const messageId = 'message-1';
  sender.send(`${JSON.stringify({
    type: 'chat',
    senderDeviceId: 'sender-1',
    routeTag,
    messageId,
    counter: 0,
    encryptedPayload: 'ciphertext',
    timestamp: Date.now(),
    signature: 'sig',
  })}\n`);

  const receiver = await openSocket(`ws://127.0.0.1:${port}`);
  receiver.send(`${JSON.stringify({
    type: 'handshake',
    senderDeviceId: 'receiver-1',
    encryptedPayload: '',
    timestamp: Date.now(),
  })}\n`);

  const responseWait = onceMessage(receiver);
  receiver.send(`${JSON.stringify({
    type: 'control',
    action: 'pull',
    senderDeviceId: 'receiver-1',
    routeTags: [routeTag],
    encryptedPayload: '',
    timestamp: Date.now(),
  })}\n`);

  const response = JSON.parse((await responseWait).trim());
  const payload = JSON.parse(response.encryptedPayload);

  assert.equal(response.type, 'control');
  assert.equal(response.action, 'deliver');
  assert.equal(payload.messages.length, 1);
  assert.equal(payload.messages[0].encryptedPayload, 'ciphertext');

  sender.close();
  receiver.close();
  server.stop();
});

test('server closes connections that repeatedly send malformed messages', async () => {
  const port = 9100 + Math.floor(Math.random() * 200);
  const server = new RelayServer({ host: '127.0.0.1', port, messageTtlMs: 10_000 });
  server.start();

  const socket = await openSocket(`ws://127.0.0.1:${port}`);
  const closeWait = new Promise((resolve) => socket.once('close', resolve));
  for (let i = 0; i < 5; i += 1) {
    socket.send('{not-json}\n');
  }

  await closeWait;
  assert.equal(socket.readyState, socket.CLOSED);
  server.stop();
});

test('server applies soft per-device rate limiting with silent drops', async () => {
  const port = 9300 + Math.floor(Math.random() * 200);
  const server = new RelayServer({
    host: '127.0.0.1',
    port,
    messageTtlMs: 10_000,
    perDeviceRateLimit: { windowMs: 1_000, maxMessages: 2 },
  });
  server.start();

  const socket = await openSocket(`ws://127.0.0.1:${port}`);
  for (let i = 0; i < 3; i += 1) {
    socket.send(`${JSON.stringify({
      type: 'control',
      action: 'pull',
      senderDeviceId: 'rate-limited-device',
      routeTags: [],
      encryptedPayload: '',
      timestamp: Date.now(),
    })}\n`);
  }
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.notEqual(socket.readyState, socket.CLOSED);
  socket.close();
  server.stop();
});

test('server enforces max message size', async () => {
  const port = 9500 + Math.floor(Math.random() * 200);
  const server = new RelayServer({
    host: '127.0.0.1',
    port,
    messageTtlMs: 10_000,
    maxMessageSizeBytes: 128,
  });
  server.start();

  const socket = await openSocket(`ws://127.0.0.1:${port}`);
  const closeWait = new Promise((resolve) => socket.once('close', resolve));
  socket.send(`${'x'.repeat(512)}\n`);
  await closeWait;

  assert.equal(socket.readyState, socket.CLOSED);
  server.stop();
});

test('relay delivers padded envelopes in shuffled/batched responses without decrypting payloads', async () => {
  const port = 9700 + Math.floor(Math.random() * 200);
  const server = new RelayServer({
    host: '127.0.0.1',
    port,
    messageTtlMs: 10_000,
    relayBatchSize: 2,
    shuffleDelivery: true,
  });
  server.start();

  const sender = await openSocket(`ws://127.0.0.1:${port}`);
  sender.send(`${JSON.stringify({
    type: 'handshake',
    senderDeviceId: 'sender-batch',
    encryptedPayload: '',
    timestamp: Date.now(),
  })}\n`);

  const routeTag = computeRouteTag('shared-route-secret', 0);
  for (let i = 0; i < 3; i += 1) {
    sender.send(`${JSON.stringify({
      type: 'chat',
      senderDeviceId: 'sender-batch',
      routeTag,
      messageId: `message-${i}`,
      counter: i,
      encryptedPayload: JSON.stringify({
        encryptedPayload: {
          iv: 'AAAAAAAAAAAAAAAA',
          ciphertext: Buffer.alloc(256, i).toString('base64'),
          tag: 'AAAAAAAAAAAAAAAAAAAAAA==',
        },
      }),
      timestamp: Date.now(),
      signature: 'sig',
    })}\n`);
  }

  const receiver = await openSocket(`ws://127.0.0.1:${port}`);
  receiver.send(`${JSON.stringify({
    type: 'handshake',
    senderDeviceId: 'receiver-batch',
    encryptedPayload: '',
    timestamp: Date.now(),
  })}\n`);

  const responseWait = collectMessages(receiver, 2);
  receiver.send(`${JSON.stringify({
    type: 'control',
    action: 'pull',
    senderDeviceId: 'receiver-batch',
    routeTags: [routeTag],
    encryptedPayload: '',
    timestamp: Date.now(),
  })}\n`);

  const responseMessages = await responseWait;
  const decoded = responseMessages.map((raw) => JSON.parse(raw.trim()));
  const payloads = decoded.map((message) => JSON.parse(message.encryptedPayload));
  const delivered = payloads.flatMap((payload) => payload.messages);

  assert.equal(decoded.every((message) => message.action === 'deliver'), true);
  assert.equal(payloads[0].messages.length, 2);
  assert.equal(payloads[1].messages.length, 1);
  assert.equal(delivered.length, 3);
  assert.equal(delivered.every((message) => typeof message.encryptedPayload === 'string'), true);

  sender.close();
  receiver.close();
  server.stop();
});

test('relay remains stable under burst flood with bounded storage', async () => {
  const port = 9900 + Math.floor(Math.random() * 200);
  const server = new RelayServer({
    host: '127.0.0.1',
    port,
    messageTtlMs: 10_000,
    maxMessagesPerRouteTag: 40,
    maxTotalMessages: 120,
    maxConcurrentConnections: 100,
    maxBufferedBytes: 256 * 1024,
  });
  server.start();

  const sender = await openSocket(`ws://127.0.0.1:${port}`);
  sender.send(`${JSON.stringify({
    type: 'handshake',
    protocolVersion: '1.0',
    senderDeviceId: 'sender-flood',
    encryptedPayload: '',
    timestamp: Date.now(),
  })}\n`);
  const routeTag = computeRouteTag('flood-route', 0);

  for (let i = 0; i < 500; i += 1) {
    sender.send(`${JSON.stringify({
      type: 'chat',
      protocolVersion: '1.0',
      senderDeviceId: 'sender-flood',
      routeTag,
      messageId: `flood-${i}`,
      counter: i,
      encryptedPayload: 'ciphertext',
      timestamp: Date.now(),
      signature: 'sig',
    })}\n`);
  }

  assert.ok(server.totalStoredMessages() <= 120);
  sender.close();
  server.stop();
});
