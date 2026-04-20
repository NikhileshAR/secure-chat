const { WebSocket } = require('ws');
const { randomUUID, randomBytes } = require('node:crypto');
const { generateIdentity } = require('./identity');
const { verifyDeviceKeyBinding } = require('./identity');
const {
  computeRouteTag,
  signMessage,
  verifyMessage,
  deriveSharedSecret,
  deriveInitialChainKey,
  deriveMessageKey,
  deriveNextChainKey,
  encryptPayloadWithMessageKey,
  decryptPayloadWithMessageKey,
} = require('./crypto');

class SecureClient {
  constructor({
    serverUrl,
    identity = generateIdentity(),
    postQuantumPublicKey,
    replayTtlMs = 120_000,
    receiveWindow = 10,
    maxPendingReceiveKeys = 256,
    maxPullWindow = 50,
  }) {
    this.serverUrl = serverUrl;
    this.identity = identity;
    this.postQuantumPublicKey = postQuantumPublicKey || randomBytes(32).toString('base64');
    this.socket = null;
    this.replayTtlMs = replayTtlMs;
    this.receiveWindow = receiveWindow;
    this.maxPendingReceiveKeys = maxPendingReceiveKeys;
    this.maxPullWindow = maxPullWindow;
    this.sessions = new Map();
  }

  async connect() {
    this.socket = new WebSocket(this.serverUrl);

    await new Promise((resolve, reject) => {
      this.socket.once('open', resolve);
      this.socket.once('error', reject);
    });

    this.sendRaw({
      type: 'handshake',
      senderDeviceId: this.identity.deviceId,
      timestamp: Date.now(),
      encryptedPayload: '',
      identityPublicKey: this.identity.identityKeyPair.publicKey,
      devicePublicKey: this.identity.deviceKeyPair.publicKey,
      deviceKeySignature: this.identity.deviceKeySignature,
      publicKeys: {
        identity: this.identity.identityKeyPair.publicKey,
        classicalDevice: this.identity.deviceKeyPair.publicKey,
        postQuantumDevice: this.postQuantumPublicKey,
      },
    });
  }

  sendRaw(message) {
    if (!this.socket || this.socket.readyState !== this.socket.OPEN) {
      throw new Error('Client is not connected');
    }
    this.socket.send(`${JSON.stringify(message)}\n`);
  }

  ensureSession({ peerDeviceId, peerDevicePublicKey, routeSecret }) {
    const sessionId = peerDeviceId || peerDevicePublicKey;
    if (!sessionId) {
      throw new Error('peerDeviceId or peerDevicePublicKey is required');
    }
    if (this.sessions.has(sessionId)) {
      return this.sessions.get(sessionId);
    }

    const sharedSecret = routeSecret
      ? Buffer.from(String(routeSecret))
      : deriveSharedSecret(this.identity.deviceKeyPair.privateKey, peerDevicePublicKey);
    const initialChainKey = deriveInitialChainKey(sharedSecret);
    const session = {
      sharedSecret,
      sendCounter: 0,
      receiveCounter: 0,
      chainKeySend: Buffer.from(initialChainKey),
      chainKeyReceive: Buffer.from(initialChainKey),
      seenMessageIds: new Map(),
      pendingReceiveKeys: new Map(),
    };
    this.sessions.set(sessionId, session);
    return session;
  }

  pruneSeenMessageIds(seenMessageIds) {
    const now = Date.now();
    for (const [messageId, expiresAt] of seenMessageIds.entries()) {
      if (expiresAt <= now) {
        seenMessageIds.delete(messageId);
      }
    }
  }

  prunePendingReceiveKeys(session) {
    const minLiveCounter = Math.max(0, session.receiveCounter - this.receiveWindow);
    for (const counter of session.pendingReceiveKeys.keys()) {
      if (counter < minLiveCounter) {
        session.pendingReceiveKeys.delete(counter);
      }
    }
    if (session.pendingReceiveKeys.size <= this.maxPendingReceiveKeys) {
      return;
    }
    const counters = [...session.pendingReceiveKeys.keys()].sort((a, b) => a - b);
    const removeCount = session.pendingReceiveKeys.size - this.maxPendingReceiveKeys;
    for (let i = 0; i < removeCount; i += 1) {
      session.pendingReceiveKeys.delete(counters[i]);
    }
  }

  isHandshakeValid(handshakeMessage) {
    const identityPublicKey = handshakeMessage.identityPublicKey
      || handshakeMessage.publicKeys?.identity;
    const devicePublicKey = handshakeMessage.devicePublicKey
      || handshakeMessage.publicKeys?.classicalDevice;

    return verifyDeviceKeyBinding(
      identityPublicKey,
      devicePublicKey,
      handshakeMessage.deviceKeySignature,
    );
  }

  sendChat({
    content,
    recipientDevicePublicKey,
    recipientDeviceId,
    routeSecret,
    attachments,
  }) {
    const session = this.ensureSession({
      peerDeviceId: recipientDeviceId,
      peerDevicePublicKey: recipientDevicePublicKey,
      routeSecret,
    });
    const messageId = randomUUID();
    const counter = session.sendCounter;
    const routeTag = computeRouteTag(session.sharedSecret, counter);
    const messageKey = deriveMessageKey(session.chainKeySend);
    const encrypted = encryptPayloadWithMessageKey(
      { content, attachments },
      messageKey,
    );
    session.chainKeySend = deriveNextChainKey(session.chainKeySend);
    session.sendCounter += 1;

    const baseMessage = {
      type: 'chat',
      senderDeviceId: this.identity.deviceId,
      routeTag,
      messageId,
      counter,
      encryptedPayload: JSON.stringify(encrypted),
      timestamp: Date.now(),
    };

    const signature = signMessage(this.identity.identityKeyPair.privateKey, {
      messageId: baseMessage.messageId,
      counter: baseMessage.counter,
      encryptedPayload: baseMessage.encryptedPayload,
      timestamp: baseMessage.timestamp,
    });
    this.sendRaw({ ...baseMessage, signature });

    return baseMessage;
  }

  decryptChat({ message, senderDevicePublicKey, senderIdentityPublicKey, routeSecret }) {
    if (!message.messageId || typeof message.counter !== 'number' || !message.timestamp) {
      throw new Error('Missing secure message metadata');
    }

    if (message.signature) {
      if (!verifyMessage(senderIdentityPublicKey, {
        messageId: message.messageId,
        counter: message.counter,
        encryptedPayload: message.encryptedPayload,
        timestamp: message.timestamp,
      }, message.signature)) {
        throw new Error('Invalid message signature');
      }
    }

    const session = this.ensureSession({
      peerDeviceId: message.senderDeviceId,
      peerDevicePublicKey: senderDevicePublicKey,
      routeSecret,
    });
    this.pruneSeenMessageIds(session.seenMessageIds);
    if (session.seenMessageIds.has(message.messageId)) {
      return null;
    }
    session.seenMessageIds.set(message.messageId, Date.now() + this.replayTtlMs);

    const expectedRouteTag = computeRouteTag(session.sharedSecret, message.counter);
    if (message.routeTag !== expectedRouteTag) {
      throw new Error('Invalid route tag');
    }

    let messageKey;
    if (session.pendingReceiveKeys.has(message.counter)) {
      messageKey = session.pendingReceiveKeys.get(message.counter);
      session.pendingReceiveKeys.delete(message.counter);
    } else {
      if (message.counter < session.receiveCounter) {
        throw new Error('Out-of-window counter');
      }
      if (message.counter > session.receiveCounter + this.receiveWindow) {
        throw new Error('Counter exceeded receive window');
      }

      let chainKey = session.chainKeyReceive;
      for (let counter = session.receiveCounter; counter <= message.counter; counter += 1) {
        const derivedKey = deriveMessageKey(chainKey);
        chainKey = deriveNextChainKey(chainKey);
        if (counter === message.counter) {
          messageKey = derivedKey;
        } else {
          session.pendingReceiveKeys.set(counter, derivedKey);
        }
      }
      session.chainKeyReceive = chainKey;
      session.receiveCounter = message.counter + 1;
      this.prunePendingReceiveKeys(session);
    }

    return decryptPayloadWithMessageKey(JSON.parse(message.encryptedPayload), messageKey);
  }

  pull(routeSecrets = [], { window = this.receiveWindow } = {}) {
    const boundedWindow = Math.max(0, Math.min(window, this.maxPullWindow));
    const routeTags = [];
    for (const routeSecret of routeSecrets) {
      const session = this.ensureSession({ routeSecret, peerDeviceId: `route:${routeSecret}` });
      const start = Math.max(0, session.receiveCounter - boundedWindow);
      const end = session.receiveCounter + boundedWindow;
      for (let counter = start; counter <= end; counter += 1) {
        routeTags.push(computeRouteTag(session.sharedSecret, counter));
      }
    }

    this.sendRaw({
      type: 'control',
      senderDeviceId: this.identity.deviceId,
      encryptedPayload: '',
      timestamp: Date.now(),
      action: 'pull',
      routeTags,
    });
  }

  close() {
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
  }
}

module.exports = {
  SecureClient,
  SekureClient: SecureClient,
};
