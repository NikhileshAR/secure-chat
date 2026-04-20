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

  const routeTag = computeRouteTag('shared-route-secret');
  sender.send(`${JSON.stringify({
    type: 'chat',
    senderDeviceId: 'sender-1',
    routeTag,
    encryptedPayload: 'ciphertext',
    timestamp: Date.now(),
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
