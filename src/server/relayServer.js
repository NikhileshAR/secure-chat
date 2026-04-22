const { WebSocketServer } = require('ws');
const { createHash, randomBytes, randomInt } = require('node:crypto');
const path = require('node:path');
const os = require('node:os');
const {
  normalizeControlMessage,
  ensureProtocolVersion,
  PROTOCOL_VERSION,
} = require('../protocol/schema');
const { NetworkIdentityManager } = require('./networkIdentity');
const { InviteManager } = require('./inviteManager');

class RelayServer {
  constructor({
    host = '127.0.0.1',
    port = 8080,
    messageTtlMs = 60_000,
    maxMessagesPerRouteTag = 100,
    maxTotalMessages = 5_000,
    duplicateWindowMs = 5_000,
    maxMessageSizeBytes = 64 * 1024,
    perDeviceRateLimit = { windowMs: 1_000, maxMessages: 120 },
    perRouteTagRateLimit = { windowMs: 1_000, maxMessages: 200 },
    connectionRateLimit = { windowMs: 1_000, maxMessages: 300 },
    relayBatchSize = 50,
    shuffleDelivery = true,
    maxConcurrentConnections = 1_000,
    maxBufferedBytes = 512 * 1024,
    maxPullRouteTags = 2_048,
    accessMode = 'OPEN',
    ephemeralMode = true,
    trafficJitterMs = { min: 0, max: 25 },
    networkIdentityStorageDir = path.join(os.homedir(), '.secure-chat-relay'),
    networkIdentityFilename,
    inviteUsageFilename,
  } = {}) {
    this.host = host;
    this.port = port;
    this.messageTtlMs = messageTtlMs;
    this.maxMessagesPerRouteTag = maxMessagesPerRouteTag;
    this.maxTotalMessages = maxTotalMessages;
    this.duplicateWindowMs = duplicateWindowMs;
    this.maxMessageSizeBytes = maxMessageSizeBytes;
    this.perDeviceRateLimit = perDeviceRateLimit;
    this.perRouteTagRateLimit = perRouteTagRateLimit;
    this.connectionRateLimit = connectionRateLimit;
    this.relayBatchSize = Math.max(1, Number(relayBatchSize) || 50);
    this.shuffleDelivery = Boolean(shuffleDelivery);
    this.maxConcurrentConnections = Math.max(1, Number(maxConcurrentConnections) || 1_000);
    this.maxBufferedBytes = Math.max(32 * 1024, Number(maxBufferedBytes) || 512 * 1024);
    this.maxPullRouteTags = Math.max(1, Number(maxPullRouteTags) || 2_048);
    this.accessMode = accessMode === 'INVITE_ONLY' ? 'INVITE_ONLY' : 'OPEN';
    this.ephemeralMode = ephemeralMode !== false;
    this.trafficJitterMs = {
      min: Math.max(0, Number(trafficJitterMs?.min) || 0),
      max: Math.max(0, Number(trafficJitterMs?.max) || 0),
    };
    if (this.trafficJitterMs.max < this.trafficJitterMs.min) {
      this.trafficJitterMs.max = this.trafficJitterMs.min;
    }

    this.connections = new Map();
    this.connectionIds = new WeakMap();
    this.routeStore = new Map();
    this.invalidMessageCounts = new WeakMap();
    this.recentPayloadFingerprints = new Map();
    this.deviceMessageRates = new Map();
    this.routeTagMessageRates = new Map();
    this.connectionMessageRates = new WeakMap();
    this.locked = false;
    this.networkIdentity = new NetworkIdentityManager({
      storageDir: networkIdentityStorageDir,
      filename: networkIdentityFilename,
    });
    this.inviteManager = new InviteManager({
      networkIdentity: this.networkIdentity,
      storageDir: networkIdentityStorageDir,
      usageFilename: inviteUsageFilename,
    });
    this.wss = null;
  }

  start() {
    if (this.wss) {
      return;
    }

    this.wss = new WebSocketServer({ host: this.host, port: this.port });
    this.wss.on('connection', (socket) => {
      if (this.wss.clients.size > this.maxConcurrentConnections) {
        socket.close();
        return;
      }
      this.connectionIds.set(socket, randomBytes(16).toString('hex'));
      this.sendRelayHandshake(socket);
      socket.on('message', (data) => this.handleMessage(socket, data.toString()));
      socket.on('close', () => this.cleanupSocket(socket));
    });
  }

  stop() {
    if (!this.wss) {
      return;
    }
    this.wss.close();
    this.wss = null;
    this.connections.clear();
    this.routeStore.clear();
    this.recentPayloadFingerprints.clear();
    this.deviceMessageRates.clear();
    this.routeTagMessageRates.clear();
    this.connectionIds = new WeakMap();
  }

  cleanupSocket(socket) {
    for (const [deviceId, candidate] of this.connections.entries()) {
      if (candidate === socket) {
        this.connections.delete(deviceId);
      }
    }
    this.connectionMessageRates.delete(socket);
    this.connectionIds.delete(socket);
  }

  lockNetwork() {
    this.locked = true;
  }

  unlockNetwork() {
    this.locked = false;
  }

  buildSignedNetworkMetadata() {
    const identity = this.networkIdentity.getNetworkIdentity();
    const metadata = {
      networkId: identity.networkId,
      networkPublicKey: identity.networkPublicKey,
      accessMode: this.accessMode,
      ephemeralMode: this.ephemeralMode,
      issuedAt: Date.now(),
    };
    const signature = this.networkIdentity.signNetworkMetadata(metadata);
    return {
      ...identity,
      metadata,
      signature,
    };
  }

  sendRelayHandshake(socket) {
    if (!socket || socket.readyState !== socket.OPEN) {
      return;
    }
    const {
      networkId,
      networkPublicKey,
      metadata,
      signature,
    } = this.buildSignedNetworkMetadata();
    socket.send(`${JSON.stringify({
      type: 'handshake',
      protocolVersion: PROTOCOL_VERSION,
      senderDeviceId: 'relay',
      encryptedPayload: '',
      timestamp: Date.now(),
      networkId,
      networkPublicKey,
      networkMetadata: metadata,
      networkMetadataSignature: signature,
      accessMode: this.accessMode,
      ephemeralMode: this.ephemeralMode,
    })}\n`);
  }

  checkRateLimit(store, key, { maxMessages, windowMs }, now = Date.now()) {
    const events = (store.get(key) || []).filter((timestamp) => now - timestamp <= windowMs);
    if (events.length >= maxMessages) {
      store.set(key, events);
      return false;
    }
    events.push(now);
    store.set(key, events);
    return true;
  }

  checkConnectionRateLimit(socket, now = Date.now()) {
    const events = (this.connectionMessageRates.get(socket) || [])
      .filter((timestamp) => now - timestamp <= this.connectionRateLimit.windowMs);

    if (events.length >= this.connectionRateLimit.maxMessages) {
      this.connectionMessageRates.set(socket, events);
      return false;
    }
    events.push(now);
    this.connectionMessageRates.set(socket, events);
    return true;
  }

  handleMessage(socket, rawMessage) {
    if (Buffer.byteLength(rawMessage, 'utf8') > this.maxMessageSizeBytes) {
      socket.close();
      return;
    }

    const lines = rawMessage.split('\n').map((line) => line.trim()).filter(Boolean);
    for (const line of lines) {
      if (Buffer.byteLength(line, 'utf8') > this.maxMessageSizeBytes) {
        socket.close();
        return;
      }

      if (!this.checkConnectionRateLimit(socket)) {
        continue;
      }

      let message;
      try {
        const parsedLine = JSON.parse(line);
        const normalizedMessage = normalizeControlMessage(parsedLine);
        message = ensureProtocolVersion(normalizedMessage);
      } catch {
        const invalidCount = (this.invalidMessageCounts.get(socket) || 0) + 1;
        this.invalidMessageCounts.set(socket, invalidCount);
        if (invalidCount >= 5) {
          socket.close();
        }
        continue;
      }
      this.invalidMessageCounts.delete(socket);

      if (message.senderDeviceId) {
        const ok = this.checkRateLimit(
          this.deviceMessageRates,
          message.senderDeviceId,
          this.perDeviceRateLimit,
        );
        if (!ok) {
          continue;
        }
      }

      if (message.type === 'handshake') {
        if (
          this.locked
          && typeof message.senderDeviceId === 'string'
          && !this.connections.has(message.senderDeviceId)
        ) {
          continue;
        }
        if (this.accessMode === 'INVITE_ONLY') {
          const token = message.inviteToken;
          if (typeof token !== 'string' || !token.length) {
            continue;
          }
          const tokenCheck = this.inviteManager.verifyToken(token, { consume: true });
          if (!tokenCheck.valid) {
            continue;
          }
        }
        this.connections.set(message.senderDeviceId, socket);
        continue;
      }

      if (message.type === 'chat' || message.type === 'ack') {
        if (typeof message.senderDeviceId !== 'string' || typeof message.encryptedPayload !== 'string') {
          continue;
        }
        if (
          message.senderDeviceId.length > 512
          || message.encryptedPayload.length > this.maxMessageSizeBytes
          || (typeof message.messageId === 'string' && message.messageId.length > 512)
          || (typeof message.routeTag === 'string' && message.routeTag.length > 4096)
        ) {
          continue;
        }
        if (message.routeTag) {
          const routeOk = this.checkRateLimit(
            this.routeTagMessageRates,
            message.routeTag,
            this.perRouteTagRateLimit,
          );
          if (!routeOk) {
            continue;
          }
        }

        this.storeChatByRouteTag(message);

        const target = message.targetDeviceId && this.connections.get(message.targetDeviceId);
        if (target && target.readyState === target.OPEN) {
          if (target.bufferedAmount > this.maxBufferedBytes) {
            target.close();
            continue;
          }
          target.send(`${JSON.stringify(message)}\n`);
        }
        continue;
      }

      if (message.type === 'pull') {
        if ((message.routeTags || []).length > this.maxPullRouteTags) {
          socket.close();
          return;
        }
        this.flushRouteTags(socket, message.routeTags || []);
      }
    }
  }

  storeChatByRouteTag(message) {
    if (!message.routeTag) {
      return;
    }
    if (this.isDuplicatePayload(message)) {
      return;
    }

    const expiresAt = Date.now() + this.messageTtlMs;
    const storedAt = Date.now();
    const existing = this.routeStore.get(message.routeTag) || [];
    existing.push({ payload: JSON.stringify(message), expiresAt, storedAt });
    if (existing.length > this.maxMessagesPerRouteTag) {
      existing.shift();
    }
    this.routeStore.set(message.routeTag, existing);
    this.enforceTotalStoreLimit();
  }

  flushRouteTags(socket, routeTags) {
    this.evictExpired();

    const matches = [];
    for (const routeTag of routeTags) {
      const stored = this.routeStore.get(routeTag) || [];
      for (const entry of stored) {
        if (entry.expiresAt > Date.now()) {
          matches.push(JSON.parse(entry.payload));
        }
      }
      this.routeStore.delete(routeTag);
    }

    if (this.shuffleDelivery && matches.length > 1) {
      for (let i = matches.length - 1; i > 0; i -= 1) {
        const j = Math.floor(Math.random() * (i + 1));
        [matches[i], matches[j]] = [matches[j], matches[i]];
      }
    }

    const totalBatches = Math.max(1, Math.ceil(matches.length / this.relayBatchSize));
    for (let batchIndex = 0; batchIndex < totalBatches; batchIndex += 1) {
      if (socket.bufferedAmount > this.maxBufferedBytes) {
        socket.close();
        break;
      }
      const start = batchIndex * this.relayBatchSize;
      const batchMessages = matches.slice(start, start + this.relayBatchSize);
      const payload = `${JSON.stringify({
        type: 'control',
        action: 'deliver',
        protocolVersion: PROTOCOL_VERSION,
        encryptedPayload: JSON.stringify({
          messages: batchMessages,
          batchIndex,
          totalBatches,
          more: batchIndex < totalBatches - 1,
        }),
        senderDeviceId: 'relay',
        timestamp: Date.now(),
      })}\n`;
      const jitter = this.trafficJitterMs.max > 0
        ? randomInt(this.trafficJitterMs.min, this.trafficJitterMs.max + 1)
        : 0;
      if (jitter > 0) {
        setTimeout(() => {
          if (socket.readyState === socket.OPEN) {
            socket.send(payload);
          }
        }, jitter);
      } else {
        socket.send(payload);
      }
    }
  }

  evictExpired() {
    const now = Date.now();
    for (const [routeTag, entries] of this.routeStore.entries()) {
      const live = entries.filter((entry) => entry.expiresAt > now);
      if (live.length) {
        this.routeStore.set(routeTag, live);
      } else {
        this.routeStore.delete(routeTag);
      }
    }
  }

  isDuplicatePayload(message) {
    const now = Date.now();
    const routeTag = message.routeTag;
    const payload = JSON.stringify([
      message.senderDeviceId || '',
      message.messageId || '',
      typeof message.counter === 'number' ? message.counter : '',
      message.encryptedPayload || '',
    ]);
    const fingerprint = createHash('sha256').update(payload).digest('hex');
    const entries = this.recentPayloadFingerprints.get(routeTag) || [];
    const live = entries.filter((entry) => now - entry.seenAt <= this.duplicateWindowMs);
    const alreadySeen = live.some((entry) => entry.fingerprint === fingerprint);
    if (!alreadySeen) {
      live.push({ fingerprint, seenAt: now });
    }
    this.recentPayloadFingerprints.set(routeTag, live);
    return alreadySeen;
  }

  totalStoredMessages() {
    let total = 0;
    for (const entries of this.routeStore.values()) {
      total += entries.length;
    }
    return total;
  }

  enforceTotalStoreLimit() {
    while (this.totalStoredMessages() > this.maxTotalMessages) {
      let oldestRouteTag;
      let oldestIndex = -1;
      let earliestStoredAt = Infinity;
      for (const [routeTag, entries] of this.routeStore.entries()) {
        for (let i = 0; i < entries.length; i += 1) {
          if (entries[i].storedAt < earliestStoredAt) {
            earliestStoredAt = entries[i].storedAt;
            oldestRouteTag = routeTag;
            oldestIndex = i;
          }
        }
      }
      if (!oldestRouteTag || oldestIndex < 0) {
        break;
      }
      const entries = this.routeStore.get(oldestRouteTag) || [];
      entries.splice(oldestIndex, 1);
      if (entries.length) {
        this.routeStore.set(oldestRouteTag, entries);
      } else {
        this.routeStore.delete(oldestRouteTag);
      }
    }
  }
}

if (require.main === module) {
  const host = process.env.SECURE_RELAY_HOST || process.env.SEKURE_RELAY_HOST || '0.0.0.0';
  const port = Number(process.env.SECURE_RELAY_PORT || process.env.SEKURE_RELAY_PORT || 8080);
  const ttl = Number(process.env.SECURE_RELAY_TTL_MS || process.env.SEKURE_RELAY_TTL_MS || 60_000);
  const accessMode = process.env.SECURE_RELAY_ACCESS_MODE === 'INVITE_ONLY' ? 'INVITE_ONLY' : 'OPEN';
  const identityDir = process.env.SECURE_RELAY_IDENTITY_DIR;

  const server = new RelayServer({
    host,
    port,
    messageTtlMs: ttl,
    accessMode,
    ...(identityDir ? { networkIdentityStorageDir: identityDir } : {}),
  });
  server.start();
}

module.exports = {
  RelayServer,
};
