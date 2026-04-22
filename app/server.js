#!/usr/bin/env node
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { randomBytes } = require('node:crypto');

const { SecureClient } = require('../src/client/client');
const { formatIdentityFingerprint, fingerprintIdentityPublicKey } = require('../src/client/identity');
const { decodeMessage } = require('../src/protocol/wire');

const PORT = Number(process.env.APP_PORT || 8787);
const HOST = process.env.APP_HOST || '127.0.0.1';
const APP_DIR = __dirname;
const PUBLIC_DIR = path.join(APP_DIR, 'public');
const DATA_DIR = path.join(APP_DIR, 'data');
const STATE_PATH = path.join(DATA_DIR, 'app-state.json');
const CLIENT_STORE_DIR = path.join(DATA_DIR, 'client-store');

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(CLIENT_STORE_DIR, { recursive: true });

function randomRouteSecret() {
  return randomBytes(32).toString('base64');
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      if (!chunks.length) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, code, payload) {
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8' });
  res.end(`${JSON.stringify(payload)}\n`);
}

function readPersistedState() {
  if (!fs.existsSync(STATE_PATH)) {
    return {
      relays: [],
      contacts: [],
      shareRouteSecret: randomRouteSecret(),
    };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(STATE_PATH, 'utf8'));
    return {
      relays: Array.isArray(parsed.relays) ? parsed.relays : [],
      contacts: Array.isArray(parsed.contacts) ? parsed.contacts : [],
      shareRouteSecret: typeof parsed.shareRouteSecret === 'string' && parsed.shareRouteSecret
        ? parsed.shareRouteSecret
        : randomRouteSecret(),
    };
  } catch {
    return {
      relays: [],
      contacts: [],
      shareRouteSecret: randomRouteSecret(),
    };
  }
}

const persisted = readPersistedState();

const state = {
  connected: false,
  connecting: false,
  connectionStatus: 'DISCONNECTED',
  lastError: null,
  activeRelayUrl: null,
  activeRelayIndex: -1,
  relays: [...new Set(persisted.relays.map((url) => String(url || '').trim()).filter(Boolean))],
  contacts: new Map(),
  messages: new Map(),
  shareRouteSecret: persisted.shareRouteSecret,
  intentionalDisconnect: false,
};

for (const contact of persisted.contacts) {
  if (!contact || !contact.fingerprint || !contact.identityPublicKey) {
    continue;
  }
  state.contacts.set(contact.fingerprint, {
    id: contact.fingerprint,
    fingerprint: contact.fingerprint,
    identityPublicKey: contact.identityPublicKey,
    label: contact.label || contact.fingerprint.slice(0, 12),
    deviceId: contact.deviceId || null,
    devicePublicKey: contact.devicePublicKey || null,
    routeSecret: contact.routeSecret || randomRouteSecret(),
    addedAt: contact.addedAt || Date.now(),
  });
}

let client = null;

function persistState() {
  const payload = {
    relays: state.relays,
    contacts: [...state.contacts.values()].map((contact) => ({
      fingerprint: contact.fingerprint,
      identityPublicKey: contact.identityPublicKey,
      label: contact.label,
      deviceId: contact.deviceId,
      devicePublicKey: contact.devicePublicKey,
      routeSecret: contact.routeSecret,
      addedAt: contact.addedAt,
    })),
    shareRouteSecret: state.shareRouteSecret,
  };
  fs.writeFileSync(STATE_PATH, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
}

function ensureClient() {
  if (client) {
    return client;
  }

  const deviceSecretPath = path.join(CLIENT_STORE_DIR, 'device.secret');
  let deviceSecret = null;
  if (fs.existsSync(deviceSecretPath)) {
    deviceSecret = fs.readFileSync(deviceSecretPath, 'utf8').trim();
  } else {
    deviceSecret = randomBytes(32).toString('hex');
    fs.writeFileSync(deviceSecretPath, `${deviceSecret}\n`, { mode: 0o600 });
  }

  client = new SecureClient({
    serverUrl: state.relays[0],
    relaySelectionStrategy: 'ROTATE',
    sessionStorageDir: CLIENT_STORE_DIR,
    trustStoreStorageDir: CLIENT_STORE_DIR,
    keyVaultStorageDir: CLIENT_STORE_DIR,
    deviceSecret,
    securityProfile: 'BALANCED',
  });

  for (const url of state.relays) {
    try {
      client.addRelay(url, 'saved');
    } catch {
      // ignore invalid persisted relay rows
    }
  }

  for (const contact of state.contacts.values()) {
    try {
      client.trustIdentity(contact.identityPublicKey, contact.label);
    } catch {
      // keep app usable even if trust store has stale entries
    }
  }

  return client;
}

function listContactsWithTrust() {
  const activeClient = ensureClient();
  return [...state.contacts.values()].map((contact) => ({
    ...contact,
    trustLevel: activeClient.getTrustLevel(contact.identityPublicKey) || 'UNKNOWN',
  }));
}

function listMessagesForContact(contactId) {
  return state.messages.get(contactId) || [];
}

function pushMessage(contactId, message) {
  const current = state.messages.get(contactId) || [];
  current.push(message);
  state.messages.set(contactId, current.slice(-500));
}

function extractLines(raw) {
  return String(raw || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
}

function contactCandidatesForMessage(message) {
  const contacts = [...state.contacts.values()];
  if (message?.senderDeviceId) {
    const preferred = contacts.filter((contact) => contact.deviceId === message.senderDeviceId);
    if (preferred.length) {
      const others = contacts.filter((contact) => contact.deviceId !== message.senderDeviceId);
      return [...preferred, ...others];
    }
  }
  return contacts;
}

function ingestChatMessage(message) {
  const activeClient = ensureClient();
  for (const contact of contactCandidatesForMessage(message)) {
    try {
      const payload = activeClient.handleInboundMessage({
        message,
        senderIdentityPublicKey: contact.identityPublicKey,
        senderDevicePublicKey: contact.devicePublicKey || undefined,
        routeSecret: contact.routeSecret,
      });
      if (payload && payload.content) {
        pushMessage(contact.id, {
          id: message.messageId || randomBytes(8).toString('hex'),
          direction: 'in',
          status: 'received',
          content: payload.content,
          timestamp: message.timestamp || Date.now(),
        });
        return true;
      }
    } catch {
      // try next contact candidate
    }
  }
  return false;
}

function processInboundEnvelope(envelope) {
  if (!envelope || typeof envelope !== 'object') {
    return;
  }

  if (envelope.type === 'ack') {
    try {
      ensureClient().handleInboundMessage({ message: envelope });
    } catch {
      // ignore invalid acks
    }
    return;
  }

  if (envelope.type === 'deliver') {
    let payload;
    try {
      payload = JSON.parse(envelope.encryptedPayload || '{}');
    } catch {
      return;
    }
    const messages = Array.isArray(payload.messages) ? payload.messages : [];
    for (const message of messages) {
      if (message?.type === 'chat') {
        ingestChatMessage(message);
      } else if (message?.type === 'ack') {
        try {
          ensureClient().handleInboundMessage({ message });
        } catch {
          // ignore invalid ack payload
        }
      }
    }
    return;
  }

  if (envelope.type === 'chat') {
    ingestChatMessage(envelope);
  }
}

let reconnectTimer = null;
let pollTimer = null;

function scheduleReconnect(delayMs = 2000) {
  if (state.intentionalDisconnect) {
    return;
  }
  if (reconnectTimer) {
    return;
  }
  reconnectTimer = setTimeout(async () => {
    reconnectTimer = null;
    try {
      await connectWithFailover((state.activeRelayIndex + 1) % Math.max(1, state.relays.length));
    } catch {
      scheduleReconnect(4000);
    }
  }, delayMs);
}

function attachSocketListeners() {
  if (!client?.socket) {
    return;
  }
  client.socket.removeAllListeners('message');
  client.socket.removeAllListeners('close');
  client.socket.removeAllListeners('error');

  client.socket.on('message', (raw) => {
    for (const line of extractLines(raw.toString())) {
      try {
        const envelope = decodeMessage(Buffer.from(line, 'utf8'), { strictMode: client.strictWireMode });
        processInboundEnvelope(envelope);
      } catch {
        // ignore malformed relay payloads
      }
    }
  });

  client.socket.on('close', () => {
    state.connected = false;
    state.connectionStatus = 'DISCONNECTED';
    state.activeRelayUrl = null;
    scheduleReconnect();
  });

  client.socket.on('error', (error) => {
    state.connected = false;
    state.connectionStatus = 'ERROR';
    state.lastError = error?.message || 'relay socket error';
    scheduleReconnect();
  });
}

async function connectWithFailover(startIndex = 0) {
  const activeClient = ensureClient();
  if (!state.relays.length) {
    throw new Error('No relay URLs configured');
  }
  state.connecting = true;
  state.connectionStatus = 'CONNECTING';
  state.lastError = null;

  let lastError = null;
  for (let i = 0; i < state.relays.length; i += 1) {
    const relayIndex = (startIndex + i) % state.relays.length;
    const relayUrl = state.relays[relayIndex];
    try {
      await activeClient.connectToRelay(relayUrl);
      state.connected = true;
      state.connecting = false;
      state.connectionStatus = 'CONNECTED';
      state.activeRelayUrl = relayUrl;
      state.activeRelayIndex = relayIndex;
      attachSocketListeners();
      return relayUrl;
    } catch (error) {
      lastError = error;
    }
  }

  state.connecting = false;
  state.connected = false;
  state.connectionStatus = 'ERROR';
  state.lastError = lastError?.message || 'failed to connect to all relays';
  throw lastError || new Error(state.lastError);
}

function schedulePollLoop() {
  if (pollTimer) {
    clearTimeout(pollTimer);
  }

  const run = () => {
    const activeClient = ensureClient();
    if (state.connected) {
      const routeSecrets = [...new Set([...state.contacts.values()].map((contact) => contact.routeSecret).filter(Boolean))];
      if (routeSecrets.length) {
        try {
          activeClient.pull(routeSecrets, { window: activeClient.receiveWindow });
        } catch {
          // keep polling loop alive
        }
      }
    }

    const jitterMs = 1500 + Math.floor(Math.random() * 2500);
    pollTimer = setTimeout(run, jitterMs);
  };

  run();
}

function relayUrlsFromConfig(config) {
  if (!config || typeof config !== 'object') {
    return [];
  }
  const urls = [];
  if (typeof config.publicUrl === 'string' && config.publicUrl.trim()) {
    urls.push(config.publicUrl.trim());
  }
  if (typeof config.relayUrl === 'string' && config.relayUrl.trim()) {
    urls.push(config.relayUrl.trim());
  }
  if (Array.isArray(config.relayUrls)) {
    for (const url of config.relayUrls) {
      if (typeof url === 'string' && url.trim()) {
        urls.push(url.trim());
      }
    }
  }
  return [...new Set(urls)];
}

function setRelays(inputUrls) {
  const next = [...new Set((inputUrls || []).map((url) => String(url || '').trim()).filter(Boolean))];
  if (!next.length) {
    return;
  }
  state.relays = next;
  const activeClient = ensureClient();
  for (const url of state.relays) {
    try {
      activeClient.addRelay(url, 'user');
    } catch {
      // ignore duplicates/invalid rows
    }
  }
  persistState();
}

function getIdentitySharePayload() {
  const activeClient = ensureClient();
  const payload = {
    identityPublicKey: activeClient.identity.identityKeyPair.publicKey,
    fingerprint: formatIdentityFingerprint(activeClient.identity.identityKeyPair.publicKey),
    deviceId: activeClient.identity.deviceId,
    devicePublicKey: activeClient.identity.deviceKeyPair.publicKey,
    routeSecret: state.shareRouteSecret,
  };
  const text = JSON.stringify(payload);
  return {
    payload,
    text,
    qrImageUrl: `https://api.qrserver.com/v1/create-qr-code/?size=256x256&data=${encodeURIComponent(text)}`,
  };
}

function parseContactPayload(text) {
  let parsed = text;
  if (typeof text === 'string') {
    parsed = JSON.parse(text);
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('Invalid contact payload');
  }
  if (!parsed.identityPublicKey || !parsed.fingerprint) {
    throw new Error('Contact payload must include identityPublicKey and fingerprint');
  }

  const normalizedFingerprint = formatIdentityFingerprint(parsed.identityPublicKey);
  if (normalizedFingerprint !== parsed.fingerprint) {
    throw new Error('Fingerprint does not match identity public key');
  }

  return {
    identityPublicKey: parsed.identityPublicKey,
    fingerprint: parsed.fingerprint,
    deviceId: parsed.deviceId || null,
    devicePublicKey: parsed.devicePublicKey || null,
    routeSecret: parsed.routeSecret || randomRouteSecret(),
  };
}

function addContactFromPayload(payloadText, label) {
  const activeClient = ensureClient();
  const parsed = parseContactPayload(payloadText);

  const contact = {
    id: parsed.fingerprint,
    fingerprint: parsed.fingerprint,
    identityPublicKey: parsed.identityPublicKey,
    label: String(label || parsed.fingerprint.slice(0, 12)),
    deviceId: parsed.deviceId,
    devicePublicKey: parsed.devicePublicKey,
    routeSecret: parsed.routeSecret,
    addedAt: Date.now(),
  };

  state.contacts.set(contact.id, contact);
  activeClient.trustIdentity(contact.identityPublicKey, contact.label);
  persistState();
  return {
    ...contact,
    trustLevel: activeClient.getTrustLevel(contact.identityPublicKey) || 'UNKNOWN',
  };
}

function serializeState() {
  const activeClient = ensureClient();
  const identityPublicKey = activeClient.identity.identityKeyPair.publicKey;
  return {
    connection: {
      connected: state.connected,
      connecting: state.connecting,
      status: state.connectionStatus,
      activeRelayUrl: state.activeRelayUrl,
      relays: state.relays,
      lastError: state.lastError,
    },
    identity: {
      fingerprint: formatIdentityFingerprint(identityPublicKey),
      publicKey: identityPublicKey,
      deviceId: activeClient.identity.deviceId,
    },
    contacts: listContactsWithTrust(),
  };
}

function serveStatic(req, res) {
  const safePath = req.url === '/' ? '/index.html' : req.url;
  const filePath = path.join(PUBLIC_DIR, safePath.replace(/^\/+/, ''));
  if (!filePath.startsWith(PUBLIC_DIR)) {
    sendJson(res, 403, { error: 'Forbidden' });
    return;
  }
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    sendJson(res, 404, { error: 'Not found' });
    return;
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = ext === '.html'
    ? 'text/html; charset=utf-8'
    : ext === '.js'
      ? 'application/javascript; charset=utf-8'
      : ext === '.css'
        ? 'text/css; charset=utf-8'
        : 'application/octet-stream';
  res.writeHead(200, { 'content-type': contentType });
  res.end(fs.readFileSync(filePath));
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/api/state') {
      sendJson(res, 200, serializeState());
      return;
    }

    if (req.method === 'GET' && req.url === '/api/identity/share') {
      sendJson(res, 200, getIdentitySharePayload());
      return;
    }

    if (req.method === 'GET' && req.url.startsWith('/api/messages')) {
      const url = new URL(req.url, `http://${req.headers.host}`);
      const contactId = url.searchParams.get('contactId');
      if (!contactId) {
        sendJson(res, 400, { error: 'contactId is required' });
        return;
      }
      sendJson(res, 200, { contactId, messages: listMessagesForContact(contactId) });
      return;
    }

    if (req.method === 'POST' && req.url === '/api/connection/connect') {
      const body = await readJsonBody(req);
      const configUrls = relayUrlsFromConfig(body.clientConfig);
      const inputUrls = [
        ...(Array.isArray(body.relayUrls) ? body.relayUrls : []),
        ...(body.relayUrl ? [body.relayUrl] : []),
        ...configUrls,
      ];
      setRelays(inputUrls);
      const selected = await connectWithFailover(0);
      sendJson(res, 200, { ok: true, connectedRelay: selected, relays: state.relays });
      return;
    }

    if (req.method === 'POST' && req.url === '/api/connection/disconnect') {
      state.intentionalDisconnect = true;
      if (client) {
        client.close();
      }
      state.connected = false;
      state.connectionStatus = 'DISCONNECTED';
      state.activeRelayUrl = null;
      state.activeRelayIndex = -1;
      sendJson(res, 200, { ok: true });
      return;
    }

    if (req.method === 'POST' && req.url === '/api/contacts/add') {
      const body = await readJsonBody(req);
      const added = addContactFromPayload(body.payloadText, body.label);
      sendJson(res, 200, { ok: true, contact: added, contacts: listContactsWithTrust() });
      return;
    }

    if (req.method === 'POST' && req.url === '/api/chat/send') {
      const body = await readJsonBody(req);
      const contact = state.contacts.get(body.contactId);
      if (!contact) {
        sendJson(res, 404, { error: 'Contact not found' });
        return;
      }
      const activeClient = ensureClient();
      if (!state.connected) {
        sendJson(res, 400, { error: 'Not connected to relay' });
        return;
      }
      const envelope = activeClient.sendChat({
        content: String(body.content || ''),
        recipientDeviceId: contact.deviceId || undefined,
        recipientDevicePublicKey: contact.devicePublicKey || undefined,
        recipientIdentityPublicKey: contact.identityPublicKey,
        routeSecret: contact.routeSecret,
      });
      const outbound = {
        id: envelope?.messageId || randomBytes(8).toString('hex'),
        direction: 'out',
        status: 'sent',
        content: String(body.content || ''),
        timestamp: envelope?.timestamp || Date.now(),
      };
      pushMessage(contact.id, outbound);
      sendJson(res, 200, { ok: true, message: outbound });
      return;
    }

    serveStatic(req, res);
  } catch (error) {
    sendJson(res, 500, { error: error.message });
  }
});

server.listen(PORT, HOST, () => {
  ensureClient();
  persistState();
  schedulePollLoop();
  console.log(`Secure Chat app listening on http://${HOST}:${PORT}`);
});
