const { WebSocketServer } = require('ws');
const { createHash } = require('node:crypto');

class RelayServer {
  constructor({
    host = '127.0.0.1',
    port = 8080,
    messageTtlMs = 60_000,
    maxMessagesPerRouteTag = 100,
    maxTotalMessages = 5_000,
    duplicateWindowMs = 5_000,
  } = {}) {
    this.host = host;
    this.port = port;
    this.messageTtlMs = messageTtlMs;
    this.maxMessagesPerRouteTag = maxMessagesPerRouteTag;
    this.maxTotalMessages = maxTotalMessages;
    this.duplicateWindowMs = duplicateWindowMs;
    this.connections = new Map();
    this.routeStore = new Map();
    this.invalidMessageCounts = new WeakMap();
    this.recentPayloadFingerprints = new Map();
    this.wss = null;
  }

  start() {
    if (this.wss) {
      return;
    }

    this.wss = new WebSocketServer({ host: this.host, port: this.port });
    this.wss.on('connection', (socket) => {
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
  }

  cleanupSocket(socket) {
    for (const [deviceId, candidate] of this.connections.entries()) {
      if (candidate === socket) {
        this.connections.delete(deviceId);
      }
    }
  }

  handleMessage(socket, rawMessage) {
    const lines = rawMessage.split('\n').map((line) => line.trim()).filter(Boolean);
    for (const line of lines) {
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        const invalidCount = (this.invalidMessageCounts.get(socket) || 0) + 1;
        this.invalidMessageCounts.set(socket, invalidCount);
        if (invalidCount >= 5) {
          socket.close();
        }
        continue;
      }
      this.invalidMessageCounts.delete(socket);

      if (message.type === 'handshake') {
        this.connections.set(message.senderDeviceId, socket);
        continue;
      }

      if (message.type === 'chat') {
        this.storeChatByRouteTag(message);

        const target = message.targetDeviceId && this.connections.get(message.targetDeviceId);
        if (target && target.readyState === target.OPEN) {
          target.send(`${JSON.stringify(message)}\n`);
        }
        continue;
      }

      if (message.type === 'control' && message.action === 'pull') {
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

    socket.send(`${JSON.stringify({
      type: 'control',
      action: 'deliver',
      encryptedPayload: JSON.stringify({ messages: matches }),
      senderDeviceId: 'relay',
      timestamp: Date.now(),
    })}\n`);
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
    const payload = `${message.senderDeviceId || ''}:${message.encryptedPayload || ''}`;
    const fingerprint = createHash('sha256').update(payload).digest('hex');
    const entries = this.recentPayloadFingerprints.get(routeTag) || [];
    const live = entries.filter((entry) => now - entry.seenAt <= this.duplicateWindowMs);
    const alreadySeen = live.some((entry) => entry.fingerprint === fingerprint);
    live.push({ fingerprint, seenAt: now });
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
      let oldestStoredAt = Infinity;
      for (const [routeTag, entries] of this.routeStore.entries()) {
        for (let i = 0; i < entries.length; i += 1) {
          if (entries[i].storedAt < oldestStoredAt) {
            oldestStoredAt = entries[i].storedAt;
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
