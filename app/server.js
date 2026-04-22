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
const INSTANCES_DIR = path.join(DATA_DIR, 'instances');

fs.mkdirSync(INSTANCES_DIR, { recursive: true });

function randomRouteSecret() {
  return randomBytes(32).toString('base64');
}

function defaultDeviceName() {
  return `Device-${Math.floor(Math.random() * 10_000).toString().padStart(4, '0')}`;
}

function normalizeInstanceId(value) {
  const fallback = 'default';
  const raw = String(value || '').trim();
  if (!raw) {
    return fallback;
  }
  const safe = raw.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
  return safe || fallback;
}

function shortIdFromFingerprint(fingerprint) {
  return String(fingerprint || '').replace(/:/g, '').slice(0, 8);
}

function parseDeviceName(value) {
  const text = String(value || '').trim();
  if (!text) {
    return null;
  }
  return text.slice(0, 64);
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

class InstanceManager {
  constructor() {
    this.contexts = new Map();
  }

  contextPaths(instanceId) {
    const baseDir = path.join(INSTANCES_DIR, instanceId);
    return {
      baseDir,
      statePath: path.join(baseDir, 'app-state.json'),
      clientStoreDir: path.join(baseDir, 'client-store'),
      deviceSecretPath: path.join(baseDir, 'client-store', 'device.secret'),
    };
  }

  readPersistedState(statePath) {
    if (!fs.existsSync(statePath)) {
      return {
        relays: [],
        contacts: [],
        shareRouteSecret: randomRouteSecret(),
        deviceName: defaultDeviceName(),
      };
    }
    try {
      const parsed = JSON.parse(fs.readFileSync(statePath, 'utf8'));
      return {
        relays: Array.isArray(parsed.relays) ? parsed.relays : [],
        contacts: Array.isArray(parsed.contacts) ? parsed.contacts : [],
        shareRouteSecret: typeof parsed.shareRouteSecret === 'string' && parsed.shareRouteSecret
          ? parsed.shareRouteSecret
          : randomRouteSecret(),
        deviceName: parseDeviceName(parsed.deviceName) || defaultDeviceName(),
      };
    } catch {
      return {
        relays: [],
        contacts: [],
        shareRouteSecret: randomRouteSecret(),
        deviceName: defaultDeviceName(),
      };
    }
  }

  createContext(instanceId) {
    const paths = this.contextPaths(instanceId);
    fs.mkdirSync(paths.baseDir, { recursive: true });
    fs.mkdirSync(paths.clientStoreDir, { recursive: true });

    const persisted = this.readPersistedState(paths.statePath);
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
      deviceName: persisted.deviceName,
    };

    for (const contact of persisted.contacts) {
      if (!contact || !contact.fingerprint || !contact.identityPublicKey) {
        continue;
      }
      state.contacts.set(contact.fingerprint, {
        id: contact.fingerprint,
        fingerprint: contact.fingerprint,
        identityPublicKey: contact.identityPublicKey,
        label: contact.label || contact.deviceName || contact.fingerprint.slice(0, 12),
        deviceName: parseDeviceName(contact.deviceName) || contact.label || 'Peer',
        deviceId: contact.deviceId || null,
        devicePublicKey: contact.devicePublicKey || null,
        routeSecret: contact.routeSecret || randomRouteSecret(),
        relayUrl: contact.relayUrl || null,
        addedAt: contact.addedAt || Date.now(),
      });
    }

    return {
      instanceId,
      paths,
      state,
      client: null,
      reconnectTimer: null,
      pollTimer: null,
    };
  }

  getContext(instanceId) {
    const safeId = normalizeInstanceId(instanceId);
    if (!this.contexts.has(safeId)) {
      this.contexts.set(safeId, this.createContext(safeId));
    }
    return this.contexts.get(safeId);
  }

  persistState(ctx) {
    const payload = {
      relays: ctx.state.relays,
      contacts: [...ctx.state.contacts.values()].map((contact) => ({
        fingerprint: contact.fingerprint,
        identityPublicKey: contact.identityPublicKey,
        label: contact.label,
        deviceName: contact.deviceName,
        deviceId: contact.deviceId,
        devicePublicKey: contact.devicePublicKey,
        routeSecret: contact.routeSecret,
        relayUrl: contact.relayUrl,
        addedAt: contact.addedAt,
      })),
      shareRouteSecret: ctx.state.shareRouteSecret,
      deviceName: ctx.state.deviceName,
    };
    fs.writeFileSync(ctx.paths.statePath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  }

  setDeviceName(ctx, name) {
    const normalized = parseDeviceName(name);
    if (!normalized || normalized === ctx.state.deviceName) {
      return;
    }
    ctx.state.deviceName = normalized;
    this.persistState(ctx);
  }

  ensureClient(ctx) {
    if (ctx.client) {
      return ctx.client;
    }

    let deviceSecret = null;
    if (fs.existsSync(ctx.paths.deviceSecretPath)) {
      deviceSecret = fs.readFileSync(ctx.paths.deviceSecretPath, 'utf8').trim();
    } else {
      deviceSecret = randomBytes(32).toString('hex');
      fs.writeFileSync(ctx.paths.deviceSecretPath, `${deviceSecret}\n`, { mode: 0o600 });
    }

    ctx.client = new SecureClient({
      serverUrl: ctx.state.relays[0],
      relaySelectionStrategy: 'ROTATE',
      sessionStorageDir: ctx.paths.clientStoreDir,
      trustStoreStorageDir: ctx.paths.clientStoreDir,
      keyVaultStorageDir: ctx.paths.clientStoreDir,
      deviceSecret,
      securityProfile: 'BALANCED',
    });

    for (const url of ctx.state.relays) {
      try {
        ctx.client.addRelay(url, 'saved');
      } catch {
        // ignore invalid persisted relays
      }
    }

    for (const contact of ctx.state.contacts.values()) {
      try {
        ctx.client.trustIdentity(contact.identityPublicKey, contact.label);
      } catch {
        // ignore invalid persisted trust rows
      }
    }

    this.schedulePollLoop(ctx);
    return ctx.client;
  }

  listContactsWithTrust(ctx) {
    const activeClient = this.ensureClient(ctx);
    return [...ctx.state.contacts.values()].map((contact) => ({
      ...contact,
      trustLevel: activeClient.getTrustLevel(contact.identityPublicKey) || 'UNKNOWN',
      shortId: shortIdFromFingerprint(contact.fingerprint),
    }));
  }

  listMessagesForContact(ctx, contactId) {
    return ctx.state.messages.get(contactId) || [];
  }

  pushMessage(ctx, contactId, message) {
    const current = ctx.state.messages.get(contactId) || [];
    current.push(message);
    ctx.state.messages.set(contactId, current.slice(-500));
  }

  extractLines(raw) {
    return String(raw || '')
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean);
  }

  contactCandidatesForMessage(ctx, message) {
    const contacts = [...ctx.state.contacts.values()];
    if (message?.senderDeviceId) {
      const preferred = contacts.filter((contact) => contact.deviceId === message.senderDeviceId);
      if (preferred.length) {
        const others = contacts.filter((contact) => contact.deviceId !== message.senderDeviceId);
        return [...preferred, ...others];
      }
    }
    return contacts;
  }

  ingestChatMessage(ctx, message) {
    const activeClient = this.ensureClient(ctx);
    for (const contact of this.contactCandidatesForMessage(ctx, message)) {
      try {
        const payload = activeClient.handleInboundMessage({
          message,
          senderIdentityPublicKey: contact.identityPublicKey,
          senderDevicePublicKey: contact.devicePublicKey || undefined,
          routeSecret: contact.routeSecret,
        });
        if (payload && payload.content) {
          this.pushMessage(ctx, contact.id, {
            id: message.messageId || randomBytes(8).toString('hex'),
            direction: 'in',
            status: 'received',
            senderIdentityPublicKey: message.identityPublicKey || contact.identityPublicKey,
            senderDeviceId: message.senderDeviceId || contact.deviceId,
            senderLabel: contact.deviceName || contact.label,
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

  processInboundEnvelope(ctx, envelope) {
    if (!envelope || typeof envelope !== 'object') {
      return;
    }

    if (envelope.type === 'ack') {
      try {
        this.ensureClient(ctx).handleInboundMessage({ message: envelope });
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
          this.ingestChatMessage(ctx, message);
        } else if (message?.type === 'ack') {
          try {
            this.ensureClient(ctx).handleInboundMessage({ message });
          } catch {
            // ignore invalid ack payload
          }
        }
      }
      return;
    }

    if (envelope.type === 'chat') {
      this.ingestChatMessage(ctx, envelope);
    }
  }

  scheduleReconnect(ctx, delayMs = 2000) {
    if (ctx.state.intentionalDisconnect || ctx.reconnectTimer) {
      return;
    }
    ctx.reconnectTimer = setTimeout(async () => {
      ctx.reconnectTimer = null;
      try {
        await this.connectWithFailover(ctx, (ctx.state.activeRelayIndex + 1) % Math.max(1, ctx.state.relays.length));
      } catch {
        this.scheduleReconnect(ctx, 4000);
      }
    }, delayMs);
  }

  attachSocketListeners(ctx) {
    if (!ctx.client?.socket) {
      return;
    }

    ctx.client.socket.removeAllListeners('message');
    ctx.client.socket.removeAllListeners('close');
    ctx.client.socket.removeAllListeners('error');

    ctx.client.socket.on('message', (raw) => {
      for (const line of this.extractLines(raw.toString())) {
        try {
          const envelope = decodeMessage(Buffer.from(line, 'utf8'), { strictMode: ctx.client.strictWireMode });
          this.processInboundEnvelope(ctx, envelope);
        } catch {
          // ignore malformed relay payloads
        }
      }
    });

    ctx.client.socket.on('close', () => {
      ctx.state.connected = false;
      ctx.state.connectionStatus = 'DISCONNECTED';
      ctx.state.activeRelayUrl = null;
      this.scheduleReconnect(ctx);
    });

    ctx.client.socket.on('error', (error) => {
      ctx.state.connected = false;
      ctx.state.connectionStatus = 'ERROR';
      ctx.state.lastError = error?.message || 'relay socket error';
      this.scheduleReconnect(ctx);
    });
  }

  async connectWithFailover(ctx, startIndex = 0) {
    const activeClient = this.ensureClient(ctx);
    if (!ctx.state.relays.length) {
      throw new Error('No relay URLs configured');
    }

    ctx.state.intentionalDisconnect = false;
    ctx.state.connecting = true;
    ctx.state.connectionStatus = 'CONNECTING';
    ctx.state.lastError = null;

    let lastError = null;
    for (let i = 0; i < ctx.state.relays.length; i += 1) {
      const relayIndex = (startIndex + i) % ctx.state.relays.length;
      const relayUrl = ctx.state.relays[relayIndex];
      try {
        await activeClient.connectToRelay(relayUrl);
        ctx.state.connected = true;
        ctx.state.connecting = false;
        ctx.state.connectionStatus = 'CONNECTED';
        ctx.state.activeRelayUrl = relayUrl;
        ctx.state.activeRelayIndex = relayIndex;
        this.attachSocketListeners(ctx);
        return relayUrl;
      } catch (error) {
        lastError = error;
      }
    }

    ctx.state.connecting = false;
    ctx.state.connected = false;
    ctx.state.connectionStatus = 'ERROR';
    ctx.state.lastError = lastError?.message || 'failed to connect to all relays';
    throw lastError || new Error(ctx.state.lastError);
  }

  schedulePollLoop(ctx) {
    if (ctx.pollTimer) {
      clearTimeout(ctx.pollTimer);
    }

    const run = () => {
      if (ctx.state.connected && ctx.client) {
        const routeSecrets = [...new Set([...ctx.state.contacts.values()].map((contact) => contact.routeSecret).filter(Boolean))];
        if (routeSecrets.length) {
          try {
            ctx.client.pull(routeSecrets, { window: ctx.client.receiveWindow });
          } catch {
            // keep polling loop alive
          }
        }
      }
      const jitterMs = 1500 + Math.floor(Math.random() * 2500);
      ctx.pollTimer = setTimeout(run, jitterMs);
    };

    run();
  }

  setRelays(ctx, inputUrls) {
    const next = [...new Set((inputUrls || []).map((url) => String(url || '').trim()).filter(Boolean))];
    if (!next.length) {
      return;
    }
    ctx.state.relays = next;

    const activeClient = this.ensureClient(ctx);
    for (const url of ctx.state.relays) {
      try {
        activeClient.addRelay(url, 'user');
      } catch {
        // ignore duplicate/invalid rows
      }
    }

    this.persistState(ctx);
  }

  getIdentitySharePayload(ctx) {
    const activeClient = this.ensureClient(ctx);
    const relayUrl = ctx.state.activeRelayUrl || ctx.state.relays[0] || activeClient.serverUrl || null;
    const payload = {
      identityPublicKey: activeClient.identity.identityKeyPair.publicKey,
      fingerprint: formatIdentityFingerprint(activeClient.identity.identityKeyPair.publicKey),
      relayUrl,
      deviceName: ctx.state.deviceName,
      deviceId: activeClient.identity.deviceId,
      devicePublicKey: activeClient.identity.deviceKeyPair.publicKey,
      routeSecret: ctx.state.shareRouteSecret,
    };
    const text = JSON.stringify(payload);
    return {
      payload,
      text,
      qrImageUrl: `https://api.qrserver.com/v1/create-qr-code/?size=256x256&data=${encodeURIComponent(text)}`,
    };
  }

  parseContactPayload(text) {
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
      relayUrl: parsed.relayUrl || null,
      deviceName: parseDeviceName(parsed.deviceName) || null,
      deviceId: parsed.deviceId || null,
      devicePublicKey: parsed.devicePublicKey || null,
      routeSecret: parsed.routeSecret || randomRouteSecret(),
    };
  }

  addContactFromPayload(ctx, payloadText, label) {
    const activeClient = this.ensureClient(ctx);
    const parsed = this.parseContactPayload(payloadText);

    const selectedLabel = String(label || parsed.deviceName || parsed.fingerprint.slice(0, 12));
    const contact = {
      id: parsed.fingerprint,
      fingerprint: parsed.fingerprint,
      identityPublicKey: parsed.identityPublicKey,
      label: selectedLabel,
      deviceName: parsed.deviceName || selectedLabel,
      deviceId: parsed.deviceId,
      devicePublicKey: parsed.devicePublicKey,
      routeSecret: parsed.routeSecret,
      relayUrl: parsed.relayUrl,
      addedAt: Date.now(),
    };

    ctx.state.contacts.set(contact.id, contact);
    if (parsed.relayUrl) {
      this.setRelays(ctx, [...ctx.state.relays, parsed.relayUrl]);
    }
    activeClient.trustIdentity(contact.identityPublicKey, contact.label);
    this.persistState(ctx);

    return {
      ...contact,
      trustLevel: activeClient.getTrustLevel(contact.identityPublicKey) || 'UNKNOWN',
      shortId: shortIdFromFingerprint(contact.fingerprint),
    };
  }

  serializeState(ctx) {
    const activeClient = this.ensureClient(ctx);
    const identityPublicKey = activeClient.identity.identityKeyPair.publicKey;
    return {
      connection: {
        connected: ctx.state.connected,
        connecting: ctx.state.connecting,
        status: ctx.state.connectionStatus,
        activeRelayUrl: ctx.state.activeRelayUrl,
        relays: ctx.state.relays,
        lastError: ctx.state.lastError,
      },
      identity: {
        fingerprint: formatIdentityFingerprint(identityPublicKey),
        publicKey: identityPublicKey,
        shortId: shortIdFromFingerprint(formatIdentityFingerprint(identityPublicKey)),
        deviceId: activeClient.identity.deviceId,
        deviceName: ctx.state.deviceName,
      },
      contacts: this.listContactsWithTrust(ctx),
      debug: {
        fingerprint: formatIdentityFingerprint(identityPublicKey),
        relayUrl: ctx.state.activeRelayUrl,
        connectionStatus: ctx.state.connectionStatus,
        sessionCount: activeClient.sessions?.size || 0,
      },
    };
  }

  resetIdentity(ctx) {
    ctx.state.intentionalDisconnect = true;
    if (ctx.client) {
      try {
        ctx.client.close();
      } catch {
        // ignore close errors
      }
    }
    ctx.client = null;
    fs.rmSync(ctx.paths.clientStoreDir, { recursive: true, force: true });
    fs.mkdirSync(ctx.paths.clientStoreDir, { recursive: true });

    ctx.state.connected = false;
    ctx.state.connecting = false;
    ctx.state.connectionStatus = 'DISCONNECTED';
    ctx.state.activeRelayUrl = null;
    ctx.state.activeRelayIndex = -1;
    ctx.state.lastError = null;
    ctx.state.shareRouteSecret = randomRouteSecret();
    ctx.state.messages.clear();

    this.persistState(ctx);
    this.ensureClient(ctx);
    return this.serializeState(ctx);
  }
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

function createAppServer() {
  const manager = new InstanceManager();

  const server = http.createServer(async (req, res) => {
    try {
      const context = manager.getContext(req.headers['x-client-instance-id']);
      const requestedDeviceName = parseDeviceName(req.headers['x-device-name']);
      if (requestedDeviceName) {
        manager.setDeviceName(context, requestedDeviceName);
      }

      if (req.method === 'GET' && req.url === '/api/state') {
        sendJson(res, 200, manager.serializeState(context));
        return;
      }

      if (req.method === 'GET' && req.url === '/api/identity/share') {
        sendJson(res, 200, manager.getIdentitySharePayload(context));
        return;
      }

      if (req.method === 'POST' && req.url === '/api/identity/reset') {
        sendJson(res, 200, { ok: true, state: manager.resetIdentity(context) });
        return;
      }

      if (req.method === 'GET' && req.url.startsWith('/api/messages')) {
        const url = new URL(req.url, `http://${req.headers.host}`);
        const contactId = url.searchParams.get('contactId');
        if (!contactId) {
          sendJson(res, 400, { error: 'contactId is required' });
          return;
        }
        sendJson(res, 200, { contactId, messages: manager.listMessagesForContact(context, contactId) });
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
        manager.setRelays(context, inputUrls);
        const selected = await manager.connectWithFailover(context, 0);
        sendJson(res, 200, { ok: true, connectedRelay: selected, relays: context.state.relays });
        return;
      }

      if (req.method === 'POST' && req.url === '/api/connection/disconnect') {
        context.state.intentionalDisconnect = true;
        if (context.client) {
          context.client.close();
        }
        context.state.connected = false;
        context.state.connectionStatus = 'DISCONNECTED';
        context.state.activeRelayUrl = null;
        context.state.activeRelayIndex = -1;
        sendJson(res, 200, { ok: true });
        return;
      }

      if (req.method === 'POST' && req.url === '/api/contacts/add') {
        const body = await readJsonBody(req);
        const added = manager.addContactFromPayload(context, body.payloadText, body.label);
        sendJson(res, 200, { ok: true, contact: added, contacts: manager.listContactsWithTrust(context) });
        return;
      }

      if (req.method === 'POST' && req.url === '/api/chat/send') {
        const body = await readJsonBody(req);
        const contact = context.state.contacts.get(body.contactId);
        if (!contact) {
          sendJson(res, 404, { error: 'Contact not found' });
          return;
        }
        const activeClient = manager.ensureClient(context);
        if (!context.state.connected) {
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
          senderIdentityPublicKey: activeClient.identity.identityKeyPair.publicKey,
          senderDeviceId: activeClient.identity.deviceId,
          senderLabel: context.state.deviceName,
          content: String(body.content || ''),
          timestamp: envelope?.timestamp || Date.now(),
        };

        manager.pushMessage(context, contact.id, outbound);
        sendJson(res, 200, { ok: true, message: outbound });
        return;
      }

      serveStatic(req, res);
    } catch (error) {
      sendJson(res, 500, { error: error.message });
    }
  });

  return { server, manager };
}

if (require.main === module) {
  const { server } = createAppServer();
  server.listen(PORT, HOST, () => {
    console.log(`Secure Chat app listening on http://${HOST}:${PORT}`);
  });
}

module.exports = {
  createAppServer,
  InstanceManager,
  normalizeInstanceId,
  shortIdFromFingerprint,
  defaultDeviceName,
  randomRouteSecret,
  relayUrlsFromConfig,
  fingerprintIdentityPublicKey,
};
