const { WebSocketServer } = require('ws');
const { createHash } = require('node:crypto');
const {
  normalizeControlMessage,
  ensureProtocolVersion,
  PROTOCOL_VERSION,
} = require('../protocol/schema');

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

    this.connections = new Map();
    this.routeStore = new Map();
    this.invalidMessageCounts = new WeakMap();
    this.recentPayloadFingerprints = new Map();
    this.deviceMessageRates = new Map();
    this.routeTagMessageRates = new Map();
    this.connectionMessageRates = new WeakMap();
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
  }

  cleanupSocket(socket) {
    for (const [deviceId, candidate] of this.connections.entries()) {
      if (candidate === socket) {
        this.connections.delete(deviceId);
      }
    }
    this.connectionMessageRates.delete(socket);
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
        socket.close();
        return;
      }

      let message;
      try {
        message = ensureProtocolVersion(normalizeControlMessage(JSON.parse(line)));
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
          socket.close();
          return;
        }
      }

      if (message.type === 'handshake') {
        this.connections.set(message.senderDeviceId, socket);
        continue;
      }

      if (message.type === 'chat' || message.type === 'ack') {
        if (typeof message.senderDeviceId !== 'string' || typeof message.encryptedPayload !== 'string') {
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
      socket.send(`${JSON.stringify({
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
      })}\n`);
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

  const server = new RelayServer({ host, port, messageTtlMs: ttl });
  server.start();
}

module.exports = {
  RelayServer,
};
