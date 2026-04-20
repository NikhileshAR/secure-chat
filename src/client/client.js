const { WebSocket } = require('ws');
const {
  randomUUID,
  randomBytes,
  randomInt,
  generateKeyPairSync,
  createHash,
} = require('node:crypto');
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
  normalizePaddingBuckets,
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

const DEFAULT_PADDING_BUCKETS = [256, 512, 1024, 4096];
const DEFAULT_COVER_TRAFFIC_RANGE_MS = { min: 2_000, max: 10_000 };
const DEFAULT_SEND_DELAY_RANGE_MS = { min: 50, max: 500 };
const DEFAULT_BATCHING_WINDOW_MS = 120;
const DEFAULT_PARALLEL_ROUTE_TAGS = 4;
const DEFAULT_PULL_NOISE_LEVEL = 6;
const DEFAULT_PULL_INTERVAL_JITTER_MS = 250;
const DEFAULT_RATE_SHAPING = { minMessagesPerSecond: 0.2, maxMessagesPerSecond: 5 };

function normalizeRange(range, fallback) {
  const min = Number(range?.min ?? fallback.min);
  const max = Number(range?.max ?? fallback.max);
  if (!Number.isFinite(min) || !Number.isFinite(max) || min < 0 || max < min) {
    return { ...fallback };
  }
  return { min, max };
}

function shuffleInPlace(values) {
  const output = [...values];
  for (let i = output.length - 1; i > 0; i -= 1) {
    const j = randomInt(i + 1);
    [output[i], output[j]] = [output[j], output[i]];
  }
  return output;
}

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
    paddingSizeBuckets = DEFAULT_PADDING_BUCKETS,
    coverTrafficIntervalRangeMs = DEFAULT_COVER_TRAFFIC_RANGE_MS,
    sendDelayRangeMs = DEFAULT_SEND_DELAY_RANGE_MS,
    batchingWindowMs = DEFAULT_BATCHING_WINDOW_MS,
    parallelRouteTags = DEFAULT_PARALLEL_ROUTE_TAGS,
    pullNoiseLevel = DEFAULT_PULL_NOISE_LEVEL,
    pullIntervalJitterMs = DEFAULT_PULL_INTERVAL_JITTER_MS,
    rateShaping = DEFAULT_RATE_SHAPING,
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
    this.paddingSizeBuckets = normalizePaddingBuckets(paddingSizeBuckets);
    this.coverTrafficIntervalRangeMs = normalizeRange(
      coverTrafficIntervalRangeMs,
      DEFAULT_COVER_TRAFFIC_RANGE_MS,
    );
    this.sendDelayRangeMs = normalizeRange(sendDelayRangeMs, DEFAULT_SEND_DELAY_RANGE_MS);
    this.batchingWindowMs = Math.max(0, Number.isFinite(batchingWindowMs)
      ? Number(batchingWindowMs)
      : DEFAULT_BATCHING_WINDOW_MS);
    this.parallelRouteTags = Math.max(1, Number(parallelRouteTags) || DEFAULT_PARALLEL_ROUTE_TAGS);
    this.pullNoiseLevel = Math.max(0, Number(pullNoiseLevel) || 0);
    this.pullIntervalJitterMs = Math.max(0, Number(pullIntervalJitterMs) || 0);

    const minMessagesPerSecond = Number(rateShaping?.minMessagesPerSecond);
    const maxMessagesPerSecond = Number(rateShaping?.maxMessagesPerSecond);
    const boundedMin = Number.isFinite(minMessagesPerSecond) && minMessagesPerSecond > 0
      ? minMessagesPerSecond
      : DEFAULT_RATE_SHAPING.minMessagesPerSecond;
    const boundedMax = Number.isFinite(maxMessagesPerSecond) && maxMessagesPerSecond >= boundedMin
      ? maxMessagesPerSecond
      : Math.max(DEFAULT_RATE_SHAPING.maxMessagesPerSecond, boundedMin);
    this.rateShaping = {
      minMessagesPerSecond: boundedMin,
      maxMessagesPerSecond: boundedMax,
    };

    this.outboundQueue = [];
    this.outboundFlushTimer = null;
    this.lastOutboundSentAt = 0;
    this.coverTrafficTimer = null;
    this.coverTrafficEnabled = false;
    this.autoPullTimer = null;
    this.autoPullActive = false;
    this.autoPullRouteSecrets = [];
    this.autoPullBaseIntervalMs = 0;
    this.pullNoiseSeed = randomBytes(32).toString('hex');
    this.pullNoiseCounter = 0;
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
    this.startCoverTraffic();
  }

  sendRaw(message) {
    if (!this.socket || this.socket.readyState !== this.socket.OPEN) {
      throw new Error('Client is not connected');
    }
    this.socket.send(`${JSON.stringify(message)}\n`);
  }

  randomInRange({ min, max }) {
    if (max <= min) {
      return min;
    }
    return randomInt(Math.floor(min), Math.floor(max) + 1);
  }

  getMinSendIntervalMs() {
    return Math.max(0, Math.floor(1_000 / this.rateShaping.maxMessagesPerSecond));
  }

  getMaxSendIntervalMs() {
    return Math.max(0, Math.floor(1_000 / this.rateShaping.minMessagesPerSecond));
  }

  computeQueueDelayMs() {
    return this.randomInRange(this.sendDelayRangeMs) + this.batchingWindowMs;
  }

  pickRouteTagIndex() {
    return randomInt(this.parallelRouteTags);
  }

  computeRouteTagCandidates(rootKey, counter, direction = 'send') {
    const tags = [];
    for (let index = 0; index < this.parallelRouteTags; index += 1) {
      tags.push(computeRouteTag(rootKey, counter, direction, index));
    }
    return tags;
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
    const routeTag = computeRouteTag(session.rootKey, counter, 'send', this.pickRouteTagIndex());
    const messageKey = deriveMessageKey(session.chainKeySend);
    const encrypted = encryptPayloadWithMessageKey(
      { content, attachments, isDummy: false },
      messageKey,
      { paddingSizeBuckets: this.paddingSizeBuckets },
    );

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
    const envelope = { ...baseMessage, signature };
    this.queueOutboundMessage(envelope);
    return envelope;
  }

  queueOutboundMessage(message) {
    this.outboundQueue.push(message);
    this.scheduleOutboundFlush();
  }

  scheduleOutboundFlush(delayMs = this.computeQueueDelayMs()) {
    if (this.outboundFlushTimer) {
      return;
    }
    const effectiveDelay = Math.max(0, Number(delayMs) || 0);
    if (effectiveDelay === 0) {
      this.flushOutboundQueue();
      return;
    }
    this.outboundFlushTimer = setTimeout(() => {
      this.outboundFlushTimer = null;
      this.flushOutboundQueue();
    }, effectiveDelay);
  }

  flushOutboundQueue() {
    if (!this.outboundQueue.length) {
      return;
    }

    const now = Date.now();
    const minIntervalMs = this.getMinSendIntervalMs();
    if (minIntervalMs > 0 && this.lastOutboundSentAt > 0) {
      const elapsed = now - this.lastOutboundSentAt;
      if (elapsed < minIntervalMs) {
        this.scheduleOutboundFlush(minIntervalMs - elapsed);
        return;
      }
    }

    const batch = this.outboundQueue.splice(0, this.outboundQueue.length);
    for (const message of batch) {
      this.sendRaw(message);
    }
    this.lastOutboundSentAt = Date.now();

    if (this.outboundQueue.length) {
      this.scheduleOutboundFlush(this.getMinSendIntervalMs());
    }
  }

  createDummyEnvelopeForSession(session) {
    this.maybeRatchetSendChain(session);
    const messageId = randomUUID();
    const counter = session.sendCounter;
    const previousCounter = session.previousCounter;
    const dhPublicKey = session.selfDHKeyPair.publicKey;
    const routeTag = computeRouteTag(session.rootKey, counter, 'send', this.pickRouteTagIndex());
    const messageKey = deriveMessageKey(session.chainKeySend);
    const encrypted = encryptPayloadWithMessageKey(
      { content: '', attachments: undefined, isDummy: true },
      messageKey,
      { paddingSizeBuckets: this.paddingSizeBuckets },
    );

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
    return { ...baseMessage, signature };
  }

  sendDummyTraffic() {
    for (const session of this.sessions.values()) {
      if (!session || !session.rootKey || !session.selfDHKeyPair?.publicKey) {
        continue;
      }
      this.queueOutboundMessage(this.createDummyEnvelopeForSession(session));
    }
  }

  scheduleNextCoverTraffic() {
    if (!this.coverTrafficEnabled) {
      return;
    }
    const randomInterval = this.randomInRange(this.coverTrafficIntervalRangeMs);
    const maxInterval = this.getMaxSendIntervalMs();
    const effectiveInterval = maxInterval > 0 ? Math.min(randomInterval, maxInterval) : randomInterval;
    this.coverTrafficTimer = setTimeout(() => {
      this.coverTrafficTimer = null;
      this.sendDummyTraffic();
      this.scheduleNextCoverTraffic();
    }, Math.max(0, effectiveInterval));
  }

  startCoverTraffic() {
    if (this.coverTrafficEnabled) {
      return;
    }
    this.coverTrafficEnabled = true;
    this.scheduleNextCoverTraffic();
  }

  stopCoverTraffic() {
    this.coverTrafficEnabled = false;
    if (this.coverTrafficTimer) {
      clearTimeout(this.coverTrafficTimer);
      this.coverTrafficTimer = null;
    }
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

    const expectedRouteTags = this.computeRouteTagCandidates(session.rootKey, message.counter, 'send');
    if (!expectedRouteTags.includes(message.routeTag)) {
      throw new Error('Protocol violation: routeTag mismatch');
    }

    const messageKey = this.deriveReceiveMessageKey(session, message);
    this.touchSession(session);

    const payload = decryptPayloadWithMessageKey(JSON.parse(message.encryptedPayload), messageKey);
    if (payload?.isDummy) {
      return null;
    }
    return payload;
  }

  pull(routeSecrets = [], { window = this.receiveWindow } = {}) {
    const boundedWindow = Math.max(0, Math.min(window, this.maxPullWindow));
    const routeTags = [];
    for (const routeSecret of routeSecrets) {
      const session = this.ensureSession({ routeSecret, peerDeviceId: `_route_session:${routeSecret}` });
      const start = Math.max(0, session.receiveCounter - boundedWindow);
      const end = session.receiveCounter + boundedWindow;
      for (let counter = start; counter <= end; counter += 1) {
        for (let index = 0; index < this.parallelRouteTags; index += 1) {
          routeTags.push(computeRouteTag(session.rootKey, counter, 'send', index));
          if (routeTags.length >= this.maxPullRouteTags) {
            break;
          }
        }
        if (routeTags.length >= this.maxPullRouteTags) {
          break;
        }
      }
      if (routeTags.length >= this.maxPullRouteTags) {
        break;
      }
    }

    const noiseToAdd = Math.min(this.pullNoiseLevel, Math.max(0, this.maxPullRouteTags - routeTags.length));
    for (let i = 0; i < noiseToAdd; i += 1) {
      const noiseRoot = createHash('sha512')
        .update(`${this.pullNoiseSeed}:${this.pullNoiseCounter++}`)
        .digest('hex');
      const noiseCounter = randomInt(Math.max(1, boundedWindow + 1));
      const noiseIndex = randomInt(this.parallelRouteTags);
      routeTags.push(computeRouteTag(noiseRoot, noiseCounter, 'send', noiseIndex));
    }

    this.sendRaw({
      type: 'control',
      senderDeviceId: this.identity.deviceId,
      encryptedPayload: '',
      timestamp: Date.now(),
      action: 'pull',
      routeTags: shuffleInPlace(routeTags),
    });
  }

  startAutoPull(routeSecrets = [], { intervalMs = 2_000, window = this.receiveWindow } = {}) {
    this.autoPullActive = true;
    this.autoPullRouteSecrets = [...routeSecrets];
    this.autoPullBaseIntervalMs = Math.max(0, Number(intervalMs) || 0);

    const schedule = () => {
      if (!this.autoPullActive) {
        return;
      }
      const jitter = this.pullIntervalJitterMs > 0
        ? randomInt(-this.pullIntervalJitterMs, this.pullIntervalJitterMs + 1)
        : 0;
      const nextInterval = Math.max(0, this.autoPullBaseIntervalMs + jitter);
      this.autoPullTimer = setTimeout(() => {
        this.autoPullTimer = null;
        this.pull(this.autoPullRouteSecrets, { window });
        schedule();
      }, nextInterval);
    };

    schedule();
  }

  stopAutoPull() {
    this.autoPullActive = false;
    if (this.autoPullTimer) {
      clearTimeout(this.autoPullTimer);
      this.autoPullTimer = null;
    }
  }

  close() {
    if (this.outboundFlushTimer) {
      clearTimeout(this.outboundFlushTimer);
      this.outboundFlushTimer = null;
    }
    this.stopCoverTraffic();
    this.stopAutoPull();
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
