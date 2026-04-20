const { WebSocket } = require('ws');
const { randomUUID, randomBytes, generateKeyPairSync } = require('node:crypto');
const {
  generateIdentity,
  verifyDeviceKeyBinding,
  fingerprintIdentityPublicKey,
  formatIdentityFingerprint,
} = require('./identity');
const {
  computeRouteTag,
  signMessage,
  verifyMessage,
  deriveSharedSecret,
  deriveInitialRootAndChainKeys,
  deriveRootAndChainFromDh,
  deriveMessageKey,
  deriveNextChainKey,
  encryptPayloadWithMessageKey,
  decryptPayloadWithMessageKey,
} = require('./crypto');

const REQUIRED_CHAT_FIELDS = [
  'type',
  'messageId',
  'senderDeviceId',
  'counter',
  'previousCounter',
  'dhPublicKey',
  'routeTag',
  'encryptedPayload',
  'timestamp',
  'signature',
];

class SecureClient {
  constructor({
    serverUrl,
    identity = generateIdentity(),
    postQuantumPublicKey,
    replayTtlMs = 120_000,
    receiveWindow = 10,
    maxPendingReceiveKeys = 256,
    maxPullWindow = 50,
    maxPullRouteTags = 500,
    sessionTtlMs = 10 * 60_000,
    maxSkippedMessageKeys,
  }) {
    this.serverUrl = serverUrl;
    this.identity = identity;
    this.postQuantumPublicKey = postQuantumPublicKey || randomBytes(32).toString('base64');
    this.socket = null;
    this.replayTtlMs = replayTtlMs;
    this.receiveWindow = receiveWindow;
    this.maxPendingReceiveKeys = maxPendingReceiveKeys;
    this.maxSkippedMessageKeys = maxSkippedMessageKeys || maxPendingReceiveKeys;
    this.maxPullWindow = maxPullWindow;
    this.maxPullRouteTags = maxPullRouteTags;
    this.sessionTtlMs = sessionTtlMs;
    this.sessions = new Map();
    this.knownPeerIdentities = new Map();
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

  createDhKeyPair() {
    const { publicKey, privateKey } = generateKeyPairSync('x25519');
    return {
      publicKey: publicKey.export({ type: 'spki', format: 'pem' }),
      privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    };
  }

  getSessionId({ peerDeviceId, peerDevicePublicKey, routeSecret }) {
    if (peerDeviceId) {
      return peerDeviceId;
    }
    if (peerDevicePublicKey) {
      return peerDevicePublicKey;
    }
    if (routeSecret) {
      return `_route_session:${routeSecret}`;
    }
    throw new Error('peerDeviceId, peerDevicePublicKey or routeSecret is required');
  }

  isInitiatorForPeer(peerDeviceId, peerDevicePublicKey) {
    const selfRef = `${this.identity.deviceId}:${this.identity.deviceKeyPair.publicKey}`;
    const peerRef = `${peerDeviceId || ''}:${peerDevicePublicKey || ''}`;
    return selfRef.localeCompare(peerRef) <= 0;
  }

  isSessionExpired(session, now = Date.now()) {
    return typeof session.expiresAt === 'number' && now >= session.expiresAt;
  }

  touchSession(session, now = Date.now()) {
    session.expiresAt = now + this.sessionTtlMs;
  }

  rememberPeerIdentity(peerDeviceId, peerIdentityPublicKey, { allowChange = false } = {}) {
    if (!peerDeviceId || !peerIdentityPublicKey) {
      return;
    }
    const existing = this.knownPeerIdentities.get(peerDeviceId);
    if (existing && existing !== peerIdentityPublicKey && !allowChange) {
      const oldFingerprint = formatIdentityFingerprint(existing);
      const newFingerprint = formatIdentityFingerprint(peerIdentityPublicKey);
      throw new Error(
        `Peer identity changed for ${peerDeviceId}: ${oldFingerprint} -> ${newFingerprint}. `
        + 'Call resetPeerIdentityTrust to accept the new identity.',
      );
    }
    this.knownPeerIdentities.set(peerDeviceId, peerIdentityPublicKey);
  }

  resetPeerIdentityTrust(peerDeviceId, peerIdentityPublicKey) {
    if (!peerDeviceId || !peerIdentityPublicKey) {
      throw new Error('peerDeviceId and peerIdentityPublicKey are required to reset trust');
    }
    this.rememberPeerIdentity(peerDeviceId, peerIdentityPublicKey, { allowChange: true });
    this.sessions.delete(peerDeviceId);
  }

  getPeerIdentityFingerprint(peerIdentityPublicKey) {
    return fingerprintIdentityPublicKey(peerIdentityPublicKey);
  }

  getPeerIdentityFingerprintDisplay(peerIdentityPublicKey) {
    return formatIdentityFingerprint(peerIdentityPublicKey);
  }

  ensureSession({ peerDeviceId, peerIdentityPublicKey, peerDevicePublicKey, routeSecret }) {
    const sessionId = this.getSessionId({ peerDeviceId, peerDevicePublicKey, routeSecret });
    const now = Date.now();

    if (peerIdentityPublicKey && peerDeviceId) {
      this.rememberPeerIdentity(peerDeviceId, peerIdentityPublicKey);
    }

    const existing = this.sessions.get(sessionId);
    if (existing && !this.isSessionExpired(existing, now)) {
      if (
        peerIdentityPublicKey
        && existing.peerIdentityPublicKey
        && peerIdentityPublicKey !== existing.peerIdentityPublicKey
      ) {
        throw new Error('Session peer identity mismatch; reset trust before continuing');
      }
      if (
        peerDevicePublicKey
        && existing.peerDevicePublicKey
        && peerDevicePublicKey !== existing.peerDevicePublicKey
      ) {
        this.sessions.delete(sessionId);
      } else {
        this.touchSession(existing, now);
        return existing;
      }
    }

    if (existing && this.isSessionExpired(existing, now)) {
      this.sessions.delete(sessionId);
    }

    const sharedSecret = routeSecret
      ? Buffer.from(String(routeSecret))
      : deriveSharedSecret(this.identity.deviceKeyPair.privateKey, peerDevicePublicKey);
    const initial = deriveInitialRootAndChainKeys(
      sharedSecret,
      this.isInitiatorForPeer(peerDeviceId, peerDevicePublicKey),
    );

    const session = {
      peerDeviceId,
      peerIdentityPublicKey,
      peerDevicePublicKey,
      rootKey: Buffer.from(initial.rootKey),
      chainKeySend: Buffer.from(initial.chainKeySend),
      chainKeyReceive: Buffer.from(initial.chainKeyReceive),
      sendCounter: 0,
      receiveCounter: 0,
      previousCounter: 0,
      skippedMessageKeys: new Map(),
      seenMessageIds: new Map(),
      lastDHKey: peerDevicePublicKey,
      selfDHKeyPair: this.identity.deviceKeyPair,
      currentReceiveDhKey: peerDevicePublicKey,
      ratchetPending: false,
      expiresAt: now + this.sessionTtlMs,
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

  makeSkippedKeyId(dhPublicKey, counter) {
    return JSON.stringify([dhPublicKey, counter]);
  }

  pruneSkippedMessageKeys(session) {
    if (session.skippedMessageKeys.size <= this.maxSkippedMessageKeys) {
      return;
    }
    const overflow = session.skippedMessageKeys.size - this.maxSkippedMessageKeys;
    const keys = session.skippedMessageKeys.keys();
    for (let i = 0; i < overflow; i += 1) {
      const next = keys.next();
      if (next.done) {
        break;
      }
      session.skippedMessageKeys.delete(next.value);
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

  maybeRatchetSendChain(session) {
    if (!session.ratchetPending || !session.lastDHKey) {
      return;
    }

    const newDhKeyPair = this.createDhKeyPair();
    const newSharedSecret = deriveSharedSecret(newDhKeyPair.privateKey, session.lastDHKey);
    const next = deriveRootAndChainFromDh(session.rootKey, newSharedSecret);

    session.previousCounter = session.sendCounter;
    session.sendCounter = 0;
    session.selfDHKeyPair = newDhKeyPair;
    session.rootKey = Buffer.from(next.rootKey);
    session.chainKeySend = Buffer.from(next.chainKey);
    session.ratchetPending = false;
  }

  validateRequiredChatMessageFields(message) {
    for (const field of REQUIRED_CHAT_FIELDS) {
      if (message[field] === undefined || message[field] === null) {
        throw new Error(`Protocol violation: missing required field ${field}`);
      }
    }
    if (message.type !== 'chat') {
      throw new Error('Protocol violation: invalid message type');
    }
    if (!Number.isInteger(message.counter) || message.counter < 0) {
      throw new Error('Protocol violation: invalid counter');
    }
    if (!Number.isInteger(message.previousCounter) || message.previousCounter < 0) {
      throw new Error('Protocol violation: invalid previousCounter');
    }
    if (!Number.isFinite(message.timestamp) || message.timestamp <= 0) {
      throw new Error('Protocol violation: invalid timestamp');
    }
  }

  sendChat({
    content,
    recipientDevicePublicKey,
    recipientDeviceId,
    recipientIdentityPublicKey,
    routeSecret,
    attachments,
  }) {
    const session = this.ensureSession({
      peerDeviceId: recipientDeviceId,
      peerIdentityPublicKey: recipientIdentityPublicKey,
      peerDevicePublicKey: recipientDevicePublicKey,
      routeSecret,
    });

    this.maybeRatchetSendChain(session);

    const messageId = randomUUID();
    const counter = session.sendCounter;
    const previousCounter = session.previousCounter;
    const dhPublicKey = session.selfDHKeyPair.publicKey;
    const routeTag = computeRouteTag(session.rootKey, counter, 'send');
    const messageKey = deriveMessageKey(session.chainKeySend);
    const encrypted = encryptPayloadWithMessageKey({ content, attachments }, messageKey);

    session.chainKeySend = deriveNextChainKey(session.chainKeySend);
    session.sendCounter += 1;
    this.touchSession(session);

    const baseMessage = {
      type: 'chat',
      senderDeviceId: this.identity.deviceId,
      routeTag,
      messageId,
      counter,
      previousCounter,
      dhPublicKey,
      encryptedPayload: JSON.stringify(encrypted),
      timestamp: Date.now(),
    };

    const signature = signMessage(this.identity.identityKeyPair.privateKey, baseMessage);
    this.sendRaw({ ...baseMessage, signature });

    return baseMessage;
  }

  applyReceiveRatchetIfNeeded(session, incomingDhPublicKey) {
    if (!incomingDhPublicKey) {
      throw new Error('Protocol violation: dhPublicKey is required');
    }
    if (session.lastDHKey === incomingDhPublicKey) {
      return;
    }

    const newSharedSecret = deriveSharedSecret(session.selfDHKeyPair.privateKey, incomingDhPublicKey);
    const next = deriveRootAndChainFromDh(session.rootKey, newSharedSecret);
    session.rootKey = Buffer.from(next.rootKey);
    session.chainKeyReceive = Buffer.from(next.chainKey);
    session.receiveCounter = 0;
    session.currentReceiveDhKey = incomingDhPublicKey;
    session.lastDHKey = incomingDhPublicKey;
    session.ratchetPending = true;
  }

  deriveReceiveMessageKey(session, message) {
    const skippedKeyId = this.makeSkippedKeyId(message.dhPublicKey, message.counter);
    if (session.skippedMessageKeys.has(skippedKeyId)) {
      const messageKey = session.skippedMessageKeys.get(skippedKeyId);
      session.skippedMessageKeys.delete(skippedKeyId);
      return messageKey;
    }

    if (message.counter < session.receiveCounter) {
      throw new Error('Protocol violation: invalid counter (replay or outside receive window)');
    }
    if (message.counter > session.receiveCounter + this.receiveWindow) {
      throw new Error(`Protocol violation: counter outside receive window (${this.receiveWindow})`);
    }

    let chainKey = session.chainKeyReceive;
    for (let counter = session.receiveCounter; counter < message.counter; counter += 1) {
      const skippedKey = deriveMessageKey(chainKey);
      chainKey = deriveNextChainKey(chainKey);
      session.skippedMessageKeys.set(
        this.makeSkippedKeyId(session.currentReceiveDhKey, counter),
        skippedKey,
      );
      this.pruneSkippedMessageKeys(session);
    }

    const messageKey = deriveMessageKey(chainKey);
    session.chainKeyReceive = deriveNextChainKey(chainKey);
    session.receiveCounter = message.counter + 1;
    return messageKey;
  }

  decryptChat({ message, senderDevicePublicKey, senderIdentityPublicKey, routeSecret }) {
    this.validateRequiredChatMessageFields(message);

    if (!verifyMessage(senderIdentityPublicKey, message, message.signature)) {
      throw new Error('Protocol violation: invalid message signature');
    }

    const session = this.ensureSession({
      peerDeviceId: message.senderDeviceId,
      peerIdentityPublicKey: senderIdentityPublicKey,
      peerDevicePublicKey: senderDevicePublicKey,
      routeSecret,
    });

    this.pruneSeenMessageIds(session.seenMessageIds);
    if (session.seenMessageIds.has(message.messageId)) {
      return null;
    }
    session.seenMessageIds.set(message.messageId, Date.now() + this.replayTtlMs);

    this.applyReceiveRatchetIfNeeded(session, message.dhPublicKey);

    const expectedRouteTag = computeRouteTag(session.rootKey, message.counter, 'send');
    if (message.routeTag !== expectedRouteTag) {
      throw new Error('Protocol violation: routeTag mismatch');
    }

    const messageKey = this.deriveReceiveMessageKey(session, message);
    this.touchSession(session);

    return decryptPayloadWithMessageKey(JSON.parse(message.encryptedPayload), messageKey);
  }

  pull(routeSecrets = [], { window = this.receiveWindow } = {}) {
    const boundedWindow = Math.max(0, Math.min(window, this.maxPullWindow));
    const routeTags = [];
    for (const routeSecret of routeSecrets) {
      const session = this.ensureSession({ routeSecret, peerDeviceId: `_route_session:${routeSecret}` });
      const start = Math.max(0, session.receiveCounter - boundedWindow);
      const end = session.receiveCounter + boundedWindow;
      for (let counter = start; counter <= end; counter += 1) {
        routeTags.push(computeRouteTag(session.rootKey, counter, 'send'));
        if (routeTags.length >= this.maxPullRouteTags) {
          break;
        }
      }
      if (routeTags.length >= this.maxPullRouteTags) {
        break;
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
