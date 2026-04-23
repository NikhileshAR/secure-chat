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
  compareFingerprints,
  generateVerificationString,
} = require('./identity');
const {
  computeRouteTag,
  deriveRouteTagEpoch,
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
  secureZero,
} = require('./crypto');
const { validateMessage, PROTOCOL_VERSION } = require('../protocol/schema');
const { encodeMessage, decodeMessage } = require('../protocol/wire');
const { assertInvariant } = require('../protocol/invariants');
const { SUPPORTED_VERSIONS, negotiateProtocolVersion } = require('../protocol/spec');
const { SessionStore } = require('./storage/sessionStore');
const {
  KeyVault,
  encryptBlobWithArgon2Passphrase,
  decryptBlobWithArgon2Passphrase,
} = require('./storage/keyVault');
const { TrustStore, TRUST_LEVELS } = require('./storage/trustStore');
const { RelayRegistry } = require('./relayRegistry');
const {
  SecurityStateEngine,
  SECURITY_EVENTS,
  IDENTITY_INTEGRITY,
  SESSION_HEALTH,
  ENVIRONMENT_RISK,
} = require('./securityState');
const { SecurityLog } = require('./securityLog');
const { validateConfig } = require('./configGuard');
const {
  getEnvironmentRisk,
  observeMessageProcessingDuration,
  evaluateEnvironmentSignals,
} = require('./environment');

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
const DEFAULT_CONSTANT_TRAFFIC_RATE_PER_SECOND = 2;
const DEFAULT_ROUTE_TAG_EPOCH_MESSAGES = 32;
const DEFAULT_MIXING_DELAY_RANGE_MS = { min: 0, max: 0 };
const DEFAULT_INBOUND_DELAY_RANGE_MS = { min: 5, max: 35 };
const DEFAULT_SMOOTHING_WINDOW_MS = 5_000;
const DEFAULT_SMOOTHING_VARIANCE = 0.15;
const ROUTE_SESSION_PREFIX = '_route_ref:';
const LEGACY_ROUTE_SESSION_PREFIX = '_route_session:';
const DECOY_SESSION_PREFIX = '_decoy_session:';
const DEFAULT_LONG_INACTIVITY_MS = 10 * 60_000;
const DEFAULT_MAX_QUARANTINE_MESSAGES = 128;
const DEFAULT_SECURITY_THRESHOLDS = {
  handshakeMismatches: 6,
  routeTagMismatches: 24,
  invalidSignatures: 12,
  relayFloodMessages: 120,
  burstWindowMs: 2_500,
  replayAttempts: 20,
  droppedMessages: 32,
};
const OPSEC_MODES = {
  NORMAL: 'NORMAL',
  HARDENED: 'HARDENED',
};
const DEFAULT_KEY_VAULT_AUTO_LOCK_TIMEOUT_MS = 60_000;
const HANDSHAKE_STATES = {
  NONE: 'NONE',
  INITIATED: 'INITIATED',
  COMPLETE: 'COMPLETE',
};
const DEFAULT_HANDSHAKE_RETRY_INTERVAL_MS = 2_000;
const DEFAULT_MAX_HANDSHAKE_ATTEMPTS = 8;
const DEFAULT_RELIABLE_PULL_MAX_BACKOFF_MS = 12_000;

function encodeBackupValue(value) {
  if (Buffer.isBuffer(value)) {
    return { __type: 'Buffer', data: value.toString('base64') };
  }
  if (value instanceof Map) {
    return { __type: 'Map', data: [...value.entries()].map(([key, item]) => [key, encodeBackupValue(item)]) };
  }
  if (Array.isArray(value)) {
    return value.map((item) => encodeBackupValue(item));
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, encodeBackupValue(item)]));
  }
  return value;
}

function decodeBackupValue(value) {
  if (!value || typeof value !== 'object') {
    return value;
  }
  if (value.__type === 'Buffer') {
    return Buffer.from(value.data, 'base64');
  }
  if (value.__type === 'Map') {
    return new Map((value.data || []).map(([key, item]) => [key, decodeBackupValue(item)]));
  }
  if (Array.isArray(value)) {
    return value.map((item) => decodeBackupValue(item));
  }
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, decodeBackupValue(item)]));
}

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

function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  }
  if (!value || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
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
    constantTrafficEnabled = false,
    constantTrafficRatePerSecond = DEFAULT_CONSTANT_TRAFFIC_RATE_PER_SECOND,
    routeTagEpochMessages = DEFAULT_ROUTE_TAG_EPOCH_MESSAGES,
    outboundMixDelayRangeMs = DEFAULT_MIXING_DELAY_RANGE_MS,
    inboundProcessDelayRangeMs = DEFAULT_INBOUND_DELAY_RANGE_MS,
    trafficSmoothingWindowMs = DEFAULT_SMOOTHING_WINDOW_MS,
    trafficSmoothingVariance = DEFAULT_SMOOTHING_VARIANCE,
    normalizedPullRouteTagCount,
    decoySessionCount = 0,
    sessionStore,
    sessionStorageDir,
    keyVault,
    keyVaultStorageDir,
    deviceSecret,
    trustStore,
    trustStoreStorageDir,
    ackRetryIntervalMs = 2_000,
    ackMaxRetries = 5,
    longInactivityMs = DEFAULT_LONG_INACTIVITY_MS,
    maxQuarantineMessages = DEFAULT_MAX_QUARANTINE_MESSAGES,
    securityThresholds = DEFAULT_SECURITY_THRESHOLDS,
    securityState,
    securityLog,
    securityProfile,
    productionMode,
    environmentRiskEvaluator = getEnvironmentRisk,
    strictWireMode,
    supportedVersions = SUPPORTED_VERSIONS,
    opsecMode = OPSEC_MODES.NORMAL,
    keyVaultAutoLockTimeoutMs = DEFAULT_KEY_VAULT_AUTO_LOCK_TIMEOUT_MS,
    maxActiveSessions = 512,
    relayRegistry,
    relaySelectionStrategy = 'FIXED',
    enforceReadySession = false,
    debugDelivery = false,
    handshakeRetryIntervalMs = DEFAULT_HANDSHAKE_RETRY_INTERVAL_MS,
    maxHandshakeAttempts = DEFAULT_MAX_HANDSHAKE_ATTEMPTS,
    reliablePullMaxBackoffMs = DEFAULT_RELIABLE_PULL_MAX_BACKOFF_MS,
  }) {
    const rawConfig = {
      mode: process.env.NODE_ENV,
      productionMode,
      securityProfile,
      strictWireMode,
      constantTrafficEnabled,
      paddingSizeBuckets,
      pullNoiseLevel,
      rateShaping,
    };
    const effectiveSecurityLog = securityLog || new SecurityLog();
    const {
      safeConfig,
      warnings: configWarnings,
      criticalViolations,
    } = validateConfig(rawConfig);
    const shouldFailClosed = safeConfig.securityProfile !== 'DEV';
    for (const warning of configWarnings) {
      effectiveSecurityLog.append('config_warning', { warning });
    }
    if (criticalViolations.length && shouldFailClosed) {
      throw new Error(`Unsafe client configuration: ${criticalViolations.join('; ')}`);
    }

    const effectivePaddingSizeBuckets = safeConfig.paddingSizeBuckets || paddingSizeBuckets;
    const effectivePullNoiseLevel = safeConfig.pullNoiseLevel;
    const effectiveConstantTrafficEnabled = safeConfig.constantTrafficEnabled;
    const effectiveRateShaping = safeConfig.rateShaping || rateShaping;
    const effectiveOpsecMode = String(opsecMode || OPSEC_MODES.NORMAL).toUpperCase() === OPSEC_MODES.HARDENED
      ? OPSEC_MODES.HARDENED
      : OPSEC_MODES.NORMAL;
    const effectiveStrictWireMode = effectiveOpsecMode === OPSEC_MODES.HARDENED
      ? true
      : safeConfig.strictWireMode;

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
    this.routeSessionMap = new Map();
    this.knownPeerIdentities = new Map();
    this.securityProfile = safeConfig.securityProfile;
    this.opsecMode = effectiveOpsecMode;
    this.productionMode = safeConfig.productionMode;
    this.paddingSizeBuckets = normalizePaddingBuckets(effectivePaddingSizeBuckets);
    this.coverTrafficIntervalRangeMs = normalizeRange(
      coverTrafficIntervalRangeMs,
      DEFAULT_COVER_TRAFFIC_RANGE_MS,
    );
    this.sendDelayRangeMs = normalizeRange(sendDelayRangeMs, DEFAULT_SEND_DELAY_RANGE_MS);
    this.batchingWindowMs = Math.max(0, Number.isFinite(batchingWindowMs)
      ? Number(batchingWindowMs)
      : DEFAULT_BATCHING_WINDOW_MS);
    this.parallelRouteTags = Math.max(1, Number(parallelRouteTags) || DEFAULT_PARALLEL_ROUTE_TAGS);
    this.pullNoiseLevel = Math.max(0, Number(effectivePullNoiseLevel) || 0);
    this.pullIntervalJitterMs = Math.max(
      effectiveOpsecMode === OPSEC_MODES.HARDENED ? DEFAULT_PULL_INTERVAL_JITTER_MS : 0,
      Number(pullIntervalJitterMs) || 0,
    );
    this.constantTrafficEnabled = Boolean(effectiveConstantTrafficEnabled);
    this.constantTrafficRatePerSecond = Math.max(
      0.1,
      Number(constantTrafficRatePerSecond) || DEFAULT_CONSTANT_TRAFFIC_RATE_PER_SECOND,
    );
    this.routeTagEpochMessages = Math.max(
      1,
      Number(routeTagEpochMessages) || DEFAULT_ROUTE_TAG_EPOCH_MESSAGES,
    );
    this.outboundMixDelayRangeMs = normalizeRange(
      outboundMixDelayRangeMs,
      DEFAULT_MIXING_DELAY_RANGE_MS,
    );
    this.inboundProcessDelayRangeMs = normalizeRange(
      inboundProcessDelayRangeMs,
      DEFAULT_INBOUND_DELAY_RANGE_MS,
    );
    this.trafficSmoothingWindowMs = Math.max(
      250,
      Number(trafficSmoothingWindowMs) || DEFAULT_SMOOTHING_WINDOW_MS,
    );
    this.trafficSmoothingVariance = Math.min(
      0.45,
      Math.max(0.01, Number(trafficSmoothingVariance) || DEFAULT_SMOOTHING_VARIANCE),
    );
    const normalizedPullCount = Number(normalizedPullRouteTagCount);
    this.normalizedPullRouteTagCount = Math.max(
      1,
      Math.min(
        this.maxPullRouteTags,
        Number.isFinite(normalizedPullCount) ? normalizedPullCount : this.maxPullRouteTags,
      ),
    );
    this.decoySessionCount = Math.max(0, Number(decoySessionCount) || 0);
    this.maxActiveSessions = Math.max(4, Number(maxActiveSessions) || 512);
    this.relaySelectionStrategy = String(relaySelectionStrategy || 'FIXED').toUpperCase();
    this.relayRegistry = relayRegistry || new RelayRegistry();
    this.enforceReadySession = Boolean(enforceReadySession);
    this.debugDelivery = Boolean(debugDelivery || process.env.DEBUG_DELIVERY === '1');
    this.handshakeRetryIntervalMs = Math.max(250, Number(handshakeRetryIntervalMs) || DEFAULT_HANDSHAKE_RETRY_INTERVAL_MS);
    this.maxHandshakeAttempts = Math.max(1, Number(maxHandshakeAttempts) || DEFAULT_MAX_HANDSHAKE_ATTEMPTS);
    this.reliablePullMaxBackoffMs = Math.max(
      1_000,
      Number(reliablePullMaxBackoffMs) || DEFAULT_RELIABLE_PULL_MAX_BACKOFF_MS,
    );

    const minMessagesPerSecond = Number(effectiveRateShaping?.minMessagesPerSecond);
    const maxMessagesPerSecond = Number(effectiveRateShaping?.maxMessagesPerSecond);
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
    this.outboundSequence = 0;
    this.constantTrafficTimer = null;
    this.lastTrafficSlotScheduledAt = 0;
    this.sentTrafficTimestamps = [];
    this.dummySessionRoundRobin = 0;
    this.decoyRouteSecrets = [];
    this.coverTrafficTimer = null;
    this.coverTrafficEnabled = false;
    this.autoPullTimer = null;
    this.autoPullActive = false;
    this.autoPullRouteSecrets = [];
    this.autoPullBaseIntervalMs = 0;
    this.pullNoiseSeed = randomBytes(32).toString('hex');
    this.pullNoiseCounter = 0;
    this.protocolVersion = PROTOCOL_VERSION;
    this.strictWireMode = Boolean(effectiveStrictWireMode);
    this.supportedVersions = Array.isArray(supportedVersions) && supportedVersions.length
      ? [...new Set(supportedVersions.filter((version) => typeof version === 'string'))]
      : [...SUPPORTED_VERSIONS];
    this.peerProtocolVersions = new Map();
    this.pendingAcks = new Map();
    this.ackRetryIntervalMs = Math.max(250, Number(ackRetryIntervalMs) || 2_000);
    this.ackMaxRetries = Math.max(1, Number(ackMaxRetries) || 5);
    this.ackRetryTimer = null;
    this.longInactivityMs = Math.max(30_000, Number(longInactivityMs) || DEFAULT_LONG_INACTIVITY_MS);
    this.maxQuarantineMessages = Math.max(16, Number(maxQuarantineMessages) || DEFAULT_MAX_QUARANTINE_MESSAGES);
    this.securityThresholds = {
      ...DEFAULT_SECURITY_THRESHOLDS,
      ...(securityThresholds || {}),
    };
    this.safeMode = false;
    this.manualResumeRequired = false;
    this.environmentRiskEvaluator = environmentRiskEvaluator;
    this.quarantineQueue = [];
    this.operationalWarnings = [];
    this.securityState = securityState || new SecurityStateEngine();
    this.securityLog = effectiveSecurityLog;
    this.securityMetrics = {
      handshakeMismatches: 0,
      routeTagMismatches: 0,
      invalidSignatures: 0,
      replayAttempts: 0,
      droppedMessages: 0,
      messageFailures: 0,
      inboundTimestamps: [],
    };

    this.sessionStore = sessionStore || (sessionStorageDir && deviceSecret
      ? new SessionStore({
        storageDir: sessionStorageDir,
        deviceSecret,
        maxSkippedMessageKeys: this.maxSkippedMessageKeys,
        ttlMs: this.sessionTtlMs,
      })
      : null);
    this.keyVault = keyVault || (keyVaultStorageDir ? new KeyVault({ storageDir: keyVaultStorageDir }) : null);
    this.keyVaultAutoLockTimeoutMs = Math.max(1_000, Number(keyVaultAutoLockTimeoutMs) || DEFAULT_KEY_VAULT_AUTO_LOCK_TIMEOUT_MS);
    this.keyVaultAutoLockTimer = null;
    this.pendingReadySessions = new Map();
    this.pendingSessionMessages = [];
    this.pendingSessionRetryTimer = null;
    this.reliablePullState = null;
    this.trustStore = trustStore || ((trustStoreStorageDir || sessionStorageDir) && deviceSecret
      ? new TrustStore({
        storageDir: trustStoreStorageDir || sessionStorageDir,
        deviceSecret,
      })
      : null);

    if (this.sessionStore) {
      this.loadPersistedSessions();
    }
    if (this.trustStore) {
      this.trustStore.loadTrust();
    }
    if (this.serverUrl) {
      this.relayRegistry.addRelay(this.serverUrl, 'default');
    }
    this.evaluateEnvironmentRisk();
    this.securityState.subscribe((state) => {
      if (!this.safeMode && state.sessionHealth === SESSION_HEALTH.HEALTHY) {
        this.retryQuarantinedMessages();
      }
    });
  }

  loadPersistedSessions() {
    try {
      const loaded = this.sessionStore.loadSessions();
      if (loaded instanceof Map) {
        this.sessions = loaded;
        const now = Date.now();
        for (const [sessionId, session] of [...this.sessions.entries()]) {
          let effectiveSessionId = sessionId;
          if (typeof sessionId === 'string' && sessionId.startsWith(LEGACY_ROUTE_SESSION_PREFIX)) {
            const legacyRouteSecret = sessionId.slice(LEGACY_ROUTE_SESSION_PREFIX.length);
            const migratedId = this.getOpaqueRouteSessionId(legacyRouteSecret);
            if (!this.sessions.has(migratedId)) {
              this.sessions.set(migratedId, session);
            }
            this.sessions.delete(sessionId);
            effectiveSessionId = migratedId;
            if (!session.routeSecretRef) {
              session.routeSecretRef = this.getRouteSessionRef(legacyRouteSecret);
            }
          }
          if (session && typeof session === 'object') {
            if (
              typeof session.peerDeviceId === 'string'
              && session.peerDeviceId.startsWith(LEGACY_ROUTE_SESSION_PREFIX)
            ) {
              session.peerDeviceId = undefined;
            }
            if (!session.routeSecretRef && typeof effectiveSessionId === 'string' && effectiveSessionId.startsWith(ROUTE_SESSION_PREFIX)) {
              session.routeSecretRef = effectiveSessionId.slice(ROUTE_SESSION_PREFIX.length);
            }
            session.ratchetPending = true;
            session.forceRatchetOnNextSend = true;
            session.lastActivityAt = now;
            if (session.skippedMessageKeys instanceof Map) {
              session.skippedMessageKeys.clear();
            }
            session.handshakeState = HANDSHAKE_STATES.COMPLETE;
            session.isReady = true;
            this.indexRouteSession(effectiveSessionId, session);
          }
        }
      }
    } catch (error) {
      this.sessions = new Map();
      this.routeSessionMap = new Map();
      if (process.env.SECURECHAT_DEBUG_PERSISTENCE === '1') {
        console.warn('SecureClient: failed to load persisted sessions:', error.message);
      }
    }
  }

  persistSessions() {
    if (!this.sessionStore) {
      return;
    }
    this.sessionStore.saveSessions(this.sessions);
  }

  appendSecurityEvent(type, details = {}) {
    this.securityLog.append(type, details);
  }

  debugDeliveryLog(event, details = {}) {
    if (!this.debugDelivery) {
      return;
    }
    console.log(`[securechat:delivery] ${event}`, details);
  }

  assertProtocolInvariant(name, condition, details = {}) {
    return assertInvariant(name, condition, {
      details,
      securityLog: this.securityLog,
      emitSecurityEvent: (eventType, payload) => this.appendSecurityEvent(eventType, payload),
    });
  }

  updateSecurityState(event) {
    const state = this.securityState.updateState(event);
    const eventType = typeof event === 'string' ? event : event?.type;
    if (eventType === SECURITY_EVENTS.TRUST_DOWNGRADE) {
      this.registerOperationalWarning('trust_downgrade', 'warning');
    }
    if (eventType === SECURITY_EVENTS.ABNORMAL_TIMING_BURST) {
      this.registerOperationalWarning('abnormal_timing', 'warning');
    }
    this.appendSecurityEvent('security_state_update', {
      event: eventType,
      state,
    });
    this.evaluateSafetyEscalation();
    return state;
  }

  getCurrentSecurityState() {
    return this.securityState.getCurrentState();
  }

  subscribeSecurityState(callback) {
    return this.securityState.subscribe(callback);
  }

  getSecuritySummary({ identityPublicKey } = {}) {
    const state = this.getCurrentSecurityState();
    const warnings = [];
    const reasons = [];
    const recommendations = [];
    if (this.safeMode) {
      warnings.push('SAFE_MODE_ACTIVE');
      reasons.push('SAFE mode is active');
      recommendations.push('Review warnings and manually resume only after verification');
    }
    if (state.identityIntegrity === IDENTITY_INTEGRITY.CHANGED) {
      warnings.push('IDENTITY_CHANGED');
      reasons.push('Identity fingerprint changed');
      recommendations.push('Re-verify peer identity out-of-band');
    }
    if (state.sessionHealth === SESSION_HEALTH.SUSPECT) {
      warnings.push('SESSION_SUSPECT');
      reasons.push('Session health is suspect');
      recommendations.push('Pause sensitive actions until state stabilizes');
    }
    if (state.environmentRisk !== ENVIRONMENT_RISK.LOW) {
      warnings.push(`ENVIRONMENT_RISK_${state.environmentRisk}`);
      reasons.push(`${state.environmentRisk} environment risk detected`);
      recommendations.push('Reduce debugging/instrumentation and check host integrity');
    }
    if (this.quarantineQueue.length) {
      warnings.push('QUARANTINED_MESSAGES_PENDING');
      reasons.push('Quarantined messages pending');
      recommendations.push('Review quarantined traffic and clear anomalies');
    }
    if (!this.constantTrafficEnabled) {
      reasons.push('Constant traffic disabled');
      recommendations.push('Enable constant traffic to reduce traffic analysis exposure');
    }
    if (state.identityIntegrity === IDENTITY_INTEGRITY.UNVERIFIED) {
      reasons.push('Unverified identity in active session');
      recommendations.push('Verify identity before sensitive communication');
    }
    const overallSafety = this.safeMode
      || state.environmentRisk === ENVIRONMENT_RISK.HIGH
      || state.identityIntegrity === IDENTITY_INTEGRITY.CHANGED
      ? 'DANGER'
      : (warnings.length ? 'WARNING' : 'SAFE');
    return {
      trustLevel: identityPublicKey ? (this.getTrustLevel(identityPublicKey) || state.trustLevel) : state.trustLevel,
      fingerprintStatus: state.identityIntegrity,
      warnings,
      overallSafety,
      reasons: [...new Set(reasons)],
      recommendations: [...new Set(recommendations)],
    };
  }

  registerOperationalWarning(reason, severity = 'warning') {
    const warning = {
      reason: String(reason || 'unknown_warning'),
      severity,
      at: Date.now(),
    };
    this.operationalWarnings.push(warning);
    if (this.operationalWarnings.length > 128) {
      this.operationalWarnings.splice(0, this.operationalWarnings.length - 128);
    }
    this.appendSecurityEvent('operational_warning', warning);
  }

  evaluateSafetyEscalation() {
    const state = this.getCurrentSecurityState();
    const recentWarnings = this.operationalWarnings.filter((warning) => Date.now() - warning.at < 5 * 60_000);
    const reasons = new Set(recentWarnings.map((warning) => warning.reason));
    const hasSignatureFailures = reasons.has('signature_failures');
    const hasTrustDowngrade = reasons.has('trust_downgrade');
    const hasTimingAnomaly = reasons.has('abnormal_timing');
    const shouldEscalate = (
      (state.environmentRisk === ENVIRONMENT_RISK.HIGH && hasSignatureFailures)
      || (hasTrustDowngrade && hasTimingAnomaly)
      || (this.securityProfile === 'MAX' && (hasSignatureFailures || hasTrustDowngrade || hasTimingAnomaly))
    );
    if (shouldEscalate) {
      this.enterSafeMode('auto_escalation');
    }
  }

  evaluateEnvironmentRisk() {
    const risk = this.environmentRiskEvaluator();
    if (risk === ENVIRONMENT_RISK.HIGH) {
      const reasons = evaluateEnvironmentSignals();
      this.updateSecurityState({ environmentRisk: ENVIRONMENT_RISK.HIGH });
      this.registerOperationalWarning('environment_high_risk', 'high');
      this.appendSecurityEvent('environment_risk_high', { reasons });
      if (this.securityProfile === 'MAX' || this.securityProfile === 'BALANCED') {
        this.enterSafeMode('environment_high_risk');
      }
    } else if (risk === ENVIRONMENT_RISK.MEDIUM) {
      this.updateSecurityState({ environmentRisk: ENVIRONMENT_RISK.MEDIUM });
      this.registerOperationalWarning('environment_medium_risk', 'warning');
    } else {
      this.updateSecurityState({ environmentRisk: ENVIRONMENT_RISK.LOW });
    }
    return risk;
  }

  trackInboundTiming() {
    const now = Date.now();
    const cutoff = now - this.securityThresholds.burstWindowMs;
    this.securityMetrics.inboundTimestamps.push(now);
    this.securityMetrics.inboundTimestamps = this.securityMetrics.inboundTimestamps
      .filter((timestamp) => timestamp >= cutoff);
    if (this.securityMetrics.inboundTimestamps.length >= this.securityThresholds.relayFloodMessages) {
      this.updateSecurityState({ type: SECURITY_EVENTS.RELAY_FLOODING_DETECTED });
      this.enterSafeMode('relay_flooding_detected');
      return true;
    }
    if (this.securityMetrics.inboundTimestamps.length >= Math.max(8, this.securityThresholds.relayFloodMessages / 2)) {
      const delta = this.securityMetrics.inboundTimestamps[this.securityMetrics.inboundTimestamps.length - 1]
        - this.securityMetrics.inboundTimestamps[0];
      if (delta < Math.max(300, this.securityThresholds.burstWindowMs / 4)) {
        this.updateSecurityState({ type: SECURITY_EVENTS.ABNORMAL_TIMING_BURST });
        this.enterSafeMode('abnormal_timing_burst');
        return true;
      }
    }
    return false;
  }

  incrementSecurityMetric(metricName) {
    if (!Object.prototype.hasOwnProperty.call(this.securityMetrics, metricName)) {
      return;
    }
    this.securityMetrics[metricName] += 1;
    const thresholds = this.securityThresholds;
    if (
      metricName === 'handshakeMismatches'
      && this.securityMetrics.handshakeMismatches >= thresholds.handshakeMismatches
    ) {
      this.updateSecurityState({ type: SECURITY_EVENTS.HANDSHAKE_MISMATCH_SPIKE });
      this.enterSafeMode('handshake_mismatch_spike');
      return;
    }
    if (
      metricName === 'routeTagMismatches'
      && this.securityMetrics.routeTagMismatches >= thresholds.routeTagMismatches
    ) {
      this.updateSecurityState({ type: SECURITY_EVENTS.ROUTE_TAG_MISMATCH_SPIKE });
      this.enterSafeMode('route_tag_mismatch_spike');
      return;
    }
    if (
      metricName === 'invalidSignatures'
      && this.securityMetrics.invalidSignatures >= thresholds.invalidSignatures
    ) {
      this.registerOperationalWarning('signature_failures', 'high');
      this.updateSecurityState({ type: SECURITY_EVENTS.INVALID_SIGNATURE_SPIKE });
      this.enterSafeMode('invalid_signature_spike');
      return;
    }
    if (
      metricName === 'replayAttempts'
      && this.securityMetrics.replayAttempts >= thresholds.replayAttempts
    ) {
      this.updateSecurityState({ type: SECURITY_EVENTS.EXCESSIVE_REPLAY_ATTEMPTS });
    }
    if (
      metricName === 'droppedMessages'
      && this.securityMetrics.droppedMessages >= thresholds.droppedMessages
    ) {
      this.updateSecurityState({ type: SECURITY_EVENTS.HIGH_DROPPED_MESSAGE_RATE });
    }
    if (metricName === 'messageFailures' && this.securityMetrics.messageFailures >= 5) {
      this.updateSecurityState({ type: SECURITY_EVENTS.REPEATED_MESSAGE_FAILURES });
    }
    this.evaluateSafetyEscalation();
  }

  enterSafeMode(reason) {
    if (this.safeMode) {
      return;
    }
    this.safeMode = true;
    this.manualResumeRequired = true;
    this.stopAutoPull();
    if (this.socket && this.socket.readyState === this.socket.OPEN) {
      this.startCoverTraffic();
    }
    this.appendSecurityEvent('safe_mode_entered', { reason });
  }

  resumeFromSafeMode() {
    this.safeMode = false;
    this.manualResumeRequired = false;
    this.securityMetrics.handshakeMismatches = 0;
    this.securityMetrics.routeTagMismatches = 0;
    this.securityMetrics.invalidSignatures = 0;
    this.securityMetrics.replayAttempts = 0;
    this.securityMetrics.messageFailures = 0;
    this.securityMetrics.droppedMessages = 0;
    this.updateSecurityState({ type: SECURITY_EVENTS.STATE_STABILIZED });
    this.appendSecurityEvent('safe_mode_resumed', {});
    this.retryQuarantinedMessages();
  }

  shouldQuarantineMessages() {
    const state = this.getCurrentSecurityState();
    return state.sessionHealth === SESSION_HEALTH.SUSPECT;
  }

  quarantineInboundMessage(params) {
    if (this.quarantineQueue.length >= this.maxQuarantineMessages) {
      this.quarantineQueue.shift();
    }
    this.quarantineQueue.push({
      queuedAt: Date.now(),
      params,
    });
    this.incrementSecurityMetric('droppedMessages');
    this.appendSecurityEvent('message_quarantined', {
      senderDeviceId: params?.message?.senderDeviceId,
      messageId: params?.message?.messageId,
    });
  }

  retryQuarantinedMessages() {
    if (this.safeMode || this.shouldQuarantineMessages() || !this.quarantineQueue.length) {
      return [];
    }
    const queue = this.quarantineQueue.splice(0, this.quarantineQueue.length);
    const outputs = [];
    for (const entry of queue) {
      try {
        outputs.push(this.decryptChat(entry.params));
      } catch (error) {
        this.incrementSecurityMetric('messageFailures');
        this.appendSecurityEvent('quarantine_retry_failed', {
          message: error.message,
        });
      }
    }
    return outputs.filter(Boolean);
  }

  startAckRetryLoop() {
    if (this.ackRetryTimer || !this.socket) {
      return;
    }
    this.ackRetryTimer = setInterval(() => {
      this.retryUnackedMessages();
    }, this.ackRetryIntervalMs);
  }

  stopAckRetryLoop() {
    if (this.ackRetryTimer) {
      clearInterval(this.ackRetryTimer);
      this.ackRetryTimer = null;
    }
  }

  lockPrivateKeys(passphrase, options = {}) {
    if (!this.keyVault) {
      throw new Error('Key vault is not configured');
    }
    this.keyVault.lockKeys({
      identityPrivateKey: this.identity.identityKeyPair.privateKey,
      devicePrivateKey: this.identity.deviceKeyPair.privateKey,
    }, passphrase, options);
    this.touchKeyVaultActivity();
  }

  unlockPrivateKeys(passphrase) {
    if (!this.keyVault) {
      throw new Error('Key vault is not configured');
    }
    const unlocked = this.keyVault.unlock(passphrase);
    this.identity = {
      ...this.identity,
      identityKeyPair: {
        ...this.identity.identityKeyPair,
        privateKey: unlocked.identityPrivateKey,
      },
      deviceKeyPair: {
        ...this.identity.deviceKeyPair,
        privateKey: unlocked.devicePrivateKey,
      },
    };
    this.touchKeyVaultActivity();
    return unlocked;
  }

  touchKeyVaultActivity() {
    if (!this.keyVault) {
      return;
    }
    if (this.keyVaultAutoLockTimer) {
      clearTimeout(this.keyVaultAutoLockTimer);
      this.keyVaultAutoLockTimer = null;
    }
    this.keyVaultAutoLockTimer = setTimeout(() => {
      this.keyVaultAutoLockTimer = null;
      this.keyVault.clearUnlockedKeys();
      this.appendSecurityEvent('keyvault_auto_locked', { timeoutMs: this.keyVaultAutoLockTimeoutMs });
    }, this.keyVaultAutoLockTimeoutMs);
  }

  addRelay(url, label) {
    this.relayRegistry.addRelay(url, label);
    return this.listRelays();
  }

  removeRelay(url) {
    this.relayRegistry.removeRelay(url);
    return this.listRelays();
  }

  listRelays() {
    return this.relayRegistry.listRelays();
  }

  selectRelay() {
    if (this.relaySelectionStrategy === 'RANDOM_PER_SESSION') {
      return this.relayRegistry.chooseRandomRelay();
    }
    if (this.relaySelectionStrategy === 'ROTATE') {
      return this.relayRegistry.chooseNextRelay();
    }
    if (this.serverUrl) {
      return { url: this.serverUrl };
    }
    return this.relayRegistry.chooseNextRelay();
  }

  async connectToRelay(url) {
    const nextUrl = String(url || '').trim();
    if (!nextUrl) {
      throw new Error('Relay URL is required');
    }
    this.relayRegistry.addRelay(nextUrl, 'manual');
    this.serverUrl = nextUrl;
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    await this.connect();
    this.relayRegistry.markSeen(nextUrl);
    return nextUrl;
  }

  trackAck(envelope) {
    this.pendingAcks.set(envelope.messageId, {
      envelope,
      attempts: 0,
      lastAttemptAt: Date.now(),
    });
  }

  retryUnackedMessages() {
    if (!this.socket || this.socket.readyState !== this.socket.OPEN) {
      return;
    }
    const now = Date.now();
    for (const [ackId, pending] of this.pendingAcks.entries()) {
      if (pending.attempts >= this.ackMaxRetries) {
        this.pendingAcks.delete(ackId);
        continue;
      }
      if (now - pending.lastAttemptAt < this.ackRetryIntervalMs) {
        continue;
      }
      pending.attempts += 1;
      pending.lastAttemptAt = now;
      const retryEnvelope = { ...pending.envelope };
      delete retryEnvelope.deliveredAt;
      this.sendRaw(retryEnvelope);
    }
  }

  acknowledgeDelivery(message) {
    if (!message?.messageId) {
      return;
    }
    const ack = {
      type: 'ack',
      protocolVersion: this.protocolVersion,
      ackId: message.messageId,
      senderDeviceId: this.identity.deviceId,
      targetDeviceId: message.senderDeviceId,
      routeTag: message.routeTag,
      deliveredAt: Date.now(),
      encryptedPayload: '',
      timestamp: Date.now(),
    };
    this.sendRaw(ack);
  }

  receiveAck(message) {
    const normalized = validateMessage(message);
    if (normalized.type !== 'ack') {
      return;
    }
    if (normalized.ackId) {
      this.pendingAcks.delete(normalized.ackId);
    }
  }

  async connect() {
    if (!this.serverUrl) {
      const selectedRelay = this.selectRelay();
      if (!selectedRelay?.url) {
        throw new Error('No relay URL configured');
      }
      this.serverUrl = selectedRelay.url;
    }
    this.socket = new WebSocket(this.serverUrl);

    await new Promise((resolve, reject) => {
      this.socket.once('open', resolve);
      this.socket.once('error', reject);
    });

    this.sendRaw({
      type: 'handshake',
      protocolVersion: this.protocolVersion,
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
      supportedVersions: this.supportedVersions,
    });
    for (const session of this.sessions.values()) {
      if (session && typeof session === 'object') {
        session.ratchetPending = true;
        session.forceRatchetOnNextSend = true;
      }
    }
    this.startAckRetryLoop();
    this.startCoverTraffic();
    this.retryPendingSessionMessages();
    this.triggerImmediateReliablePull();
    this.relayRegistry.markSeen(this.serverUrl);
  }

  sendRaw(message) {
    if (!this.socket || this.socket.readyState !== this.socket.OPEN) {
      throw new Error('Client is not connected');
    }
    const withVersion = {
      ...message,
      protocolVersion: this.protocolVersion,
    };
    const encoded = encodeMessage(withVersion, { strictMode: this.strictWireMode });
    this.socket.send(encoded);
  }

  randomInRange({ min, max }) {
    if (max <= min) {
      return min;
    }
    return randomInt(Math.floor(min), Math.floor(max) + 1);
  }

  getMinSendIntervalMs() {
    if (this.constantTrafficEnabled) {
      return this.getBaseTrafficSlotIntervalMs();
    }
    return Math.max(0, Math.floor(1_000 / this.rateShaping.maxMessagesPerSecond));
  }

  getMaxSendIntervalMs() {
    if (this.constantTrafficEnabled) {
      return this.getBaseTrafficSlotIntervalMs();
    }
    return Math.max(0, Math.floor(1_000 / this.rateShaping.minMessagesPerSecond));
  }

  getBaseTrafficSlotIntervalMs() {
    return Math.max(1, Math.floor(1_000 / this.constantTrafficRatePerSecond));
  }

  computeQueueDelayMs() {
    return this.randomInRange(this.sendDelayRangeMs) + this.batchingWindowMs;
  }

  pickRouteTagIndex() {
    return randomInt(0, this.parallelRouteTags);
  }

  getRouteTagEpochCounter(counter) {
    return Math.floor(counter / this.routeTagEpochMessages);
  }

  deriveRouteTagEpochForCounter(session, counter) {
    return deriveRouteTagEpoch(session.rootKey, this.getRouteTagEpochCounter(counter));
  }

  computeRouteTagForSession(session, counter, direction = 'send', index = this.pickRouteTagIndex()) {
    return computeRouteTag(
      session.rootKey,
      counter,
      direction,
      index,
      this.deriveRouteTagEpochForCounter(session, counter),
    );
  }

  computeRouteTagCandidates(rootKey, counter, direction = 'send') {
    const tags = [];
    const routeTagEpoch = deriveRouteTagEpoch(rootKey, this.getRouteTagEpochCounter(counter));
    for (let index = 0; index < this.parallelRouteTags; index += 1) {
      tags.push(computeRouteTag(rootKey, counter, direction, index, routeTagEpoch));
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
      return this.getRouteMappedSessionId(routeSecret);
    }
    throw new Error('peerDeviceId, peerDevicePublicKey or routeSecret is required');
  }

  getRouteSessionRef(routeSecret) {
    return createHash('sha256')
      .update(`route-session:${String(routeSecret)}`)
      .digest('hex');
  }

  getOpaqueRouteSessionId(routeSecret) {
    return `${ROUTE_SESSION_PREFIX}${this.getRouteSessionRef(routeSecret)}`;
  }

  getRouteMappedSessionId(routeSecret) {
    const routeSecretRef = this.getRouteSessionRef(routeSecret);
    return this.routeSessionMap.get(routeSecretRef) || `${ROUTE_SESSION_PREFIX}${routeSecretRef}`;
  }

  isRouteOnlySessionId(sessionId) {
    return typeof sessionId === 'string' && sessionId.startsWith(ROUTE_SESSION_PREFIX);
  }

  indexRouteSession(sessionId, session) {
    if (!session?.routeSecretRef) {
      return;
    }
    const mapped = this.routeSessionMap.get(session.routeSecretRef);
    if (
      !mapped
      || mapped === sessionId
      || (this.isRouteOnlySessionId(mapped) && !this.isRouteOnlySessionId(sessionId))
      || (this.isRouteOnlySessionId(mapped) && this.isRouteOnlySessionId(sessionId))
    ) {
      this.routeSessionMap.set(session.routeSecretRef, sessionId);
    }
  }

  remapPendingSessionReferences(fromSessionId, toSessionId) {
    if (!fromSessionId || !toSessionId || fromSessionId === toSessionId) {
      return;
    }
    const fromReady = this.pendingReadySessions.get(fromSessionId);
    if (fromReady?.length) {
      const toReady = this.pendingReadySessions.get(toSessionId) || [];
      this.pendingReadySessions.set(toSessionId, [...toReady, ...fromReady]);
      this.pendingReadySessions.delete(fromSessionId);
    }
    for (const entry of this.pendingSessionMessages) {
      if (entry.sessionId === fromSessionId) {
        entry.sessionId = toSessionId;
      }
    }
  }

  remapSessionId(fromSessionId, toSessionId, updates = {}) {
    if (!fromSessionId || !toSessionId || fromSessionId === toSessionId) {
      return this.sessions.get(toSessionId) || null;
    }
    const existing = this.sessions.get(fromSessionId);
    if (!existing || this.sessions.has(toSessionId)) {
      return this.sessions.get(toSessionId) || existing || null;
    }
    this.sessions.delete(fromSessionId);
    this.sessions.set(toSessionId, {
      ...existing,
      ...updates,
    });
    this.remapPendingSessionReferences(fromSessionId, toSessionId);
    return this.sessions.get(toSessionId);
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
    session.lastActivityAt = now;
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
    const routeSecretRef = routeSecret ? this.getRouteSessionRef(routeSecret) : undefined;
    const now = Date.now();

    if (routeSecretRef && peerDeviceId) {
      const mappedSessionId = this.routeSessionMap.get(routeSecretRef);
      if (
        mappedSessionId
        && mappedSessionId !== sessionId
        && this.isRouteOnlySessionId(mappedSessionId)
        && !this.sessions.has(sessionId)
      ) {
        this.remapSessionId(mappedSessionId, sessionId, {
          peerDeviceId,
          peerIdentityPublicKey,
          peerDevicePublicKey,
          routeSecretRef,
        });
      }
    }

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
          if (routeSecretRef) {
            existing.routeSecretRef = routeSecretRef;
            this.indexRouteSession(sessionId, existing);
          }
          if (!existing.handshakeState) {
            existing.handshakeState = HANDSHAKE_STATES.COMPLETE;
          }
        if (typeof existing.isReady !== 'boolean') {
          existing.isReady = existing.handshakeState === HANDSHAKE_STATES.COMPLETE;
        }
        if (typeof existing.lastActivityAt === 'number' && now - existing.lastActivityAt > this.longInactivityMs) {
          existing.ratchetPending = true;
          existing.forceRatchetOnNextSend = true;
        }
        this.touchSession(existing, now);
        this.persistSessions();
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
      routeSecretRef,
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
      forceRatchetOnNextSend: false,
      expiresAt: now + this.sessionTtlMs,
      lastActivityAt: now,
      handshakeState: this.enforceReadySession ? HANDSHAKE_STATES.NONE : HANDSHAKE_STATES.COMPLETE,
      isReady: !this.enforceReadySession,
      handshakeAttempts: 0,
      lastHandshakeAt: 0,
      isDecoy: typeof peerDeviceId === 'string' && peerDeviceId.startsWith(DECOY_SESSION_PREFIX),
      preferredRelayUrl: this.selectRelay()?.url || this.serverUrl || null,
    };

    this.sessions.set(sessionId, session);
    this.indexRouteSession(sessionId, session);
    this.debugDeliveryLog('session_created', {
      sessionId,
      peerDeviceId,
      handshakeState: session.handshakeState,
      isReady: session.isReady,
    });
    this.pruneActiveSessions();
    this.persistSessions();
    return session;
  }

  markSessionHandshakeState(sessionId, state) {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return null;
    }
    session.handshakeState = state;
    session.isReady = state === HANDSHAKE_STATES.COMPLETE;
    if (session.isReady) {
      session.handshakeAttempts = 0;
      this.resolveSessionReady(sessionId, session);
      this.flushPendingMessagesForSession(sessionId);
    }
    this.persistSessions();
    this.debugDeliveryLog('handshake_state', {
      sessionId,
      state: session.handshakeState,
      isReady: session.isReady,
    });
    return session;
  }

  resolveSessionReady(sessionId, session) {
    const waiters = this.pendingReadySessions.get(sessionId) || [];
    this.pendingReadySessions.delete(sessionId);
    for (const waiter of waiters) {
      waiter.resolve(session);
    }
  }

  rejectSessionReady(sessionId, error) {
    const waiters = this.pendingReadySessions.get(sessionId) || [];
    this.pendingReadySessions.delete(sessionId);
    for (const waiter of waiters) {
      waiter.reject(error);
    }
  }

  queuePendingSessionMessage(entry) {
    const queued = {
      ...entry,
      queuedAt: Date.now(),
      retries: entry.retries || 0,
      nextAttemptAt: Date.now(),
    };
    this.pendingSessionMessages.push(queued);
    this.schedulePendingSessionRetry(0);
    return queued;
  }

  schedulePendingSessionRetry(delayMs = this.handshakeRetryIntervalMs) {
    if (this.pendingSessionRetryTimer) {
      return;
    }
    this.pendingSessionRetryTimer = setTimeout(() => {
      this.pendingSessionRetryTimer = null;
      this.retryPendingSessionMessages();
    }, Math.max(0, Number(delayMs) || 0));
  }

  retryPendingSessionMessages() {
    if (!this.pendingSessionMessages.length) {
      return;
    }
    const now = Date.now();
    const pending = this.pendingSessionMessages.splice(0, this.pendingSessionMessages.length);
    for (const item of pending) {
      if (item.nextAttemptAt > now) {
        this.pendingSessionMessages.push(item);
        continue;
      }
      const sent = this.trySendChatImmediate(item.params, { bypassReadiness: false });
      if (!sent) {
        item.retries += 1;
        item.nextAttemptAt = now + Math.min(
          this.reliablePullMaxBackoffMs,
          this.handshakeRetryIntervalMs * Math.max(1, item.retries),
        );
        this.pendingSessionMessages.push(item);
      }
    }
    if (this.pendingSessionMessages.length) {
      this.schedulePendingSessionRetry();
    }
  }

  flushPendingMessagesForSession(sessionId) {
    if (!this.pendingSessionMessages.length) {
      return;
    }
    const remaining = [];
    for (const entry of this.pendingSessionMessages) {
      if (entry.sessionId !== sessionId) {
        remaining.push(entry);
        continue;
      }
      const sent = this.trySendChatImmediate(entry.params, { bypassReadiness: true });
      if (!sent) {
        remaining.push(entry);
      }
    }
    this.pendingSessionMessages = remaining;
    if (this.pendingSessionMessages.length) {
      this.schedulePendingSessionRetry();
    }
  }

  createSessionHandshakeEnvelope({
    peerDeviceId,
    peerIdentityPublicKey,
    peerDevicePublicKey,
    routeSecret,
    stage = 'init',
  }) {
    return {
      type: 'handshake',
      protocolVersion: this.protocolVersion,
      senderDeviceId: this.identity.deviceId,
      targetDeviceId: peerDeviceId,
      timestamp: Date.now(),
      encryptedPayload: JSON.stringify({
        stage,
        routeSecretHash: routeSecret
          ? createHash('sha256').update(String(routeSecret)).digest('hex')
          : null,
      }),
      identityPublicKey: this.identity.identityKeyPair.publicKey,
      devicePublicKey: this.identity.deviceKeyPair.publicKey,
      deviceKeySignature: this.identity.deviceKeySignature,
      publicKeys: {
        identity: this.identity.identityKeyPair.publicKey,
        classicalDevice: this.identity.deviceKeyPair.publicKey,
        postQuantumDevice: this.postQuantumPublicKey,
      },
      supportedVersions: this.supportedVersions,
    };
  }

  initiateSessionHandshake({
    peerDeviceId,
    peerIdentityPublicKey,
    peerDevicePublicKey,
    routeSecret,
  }) {
    const sessionId = this.getSessionId({ peerDeviceId, peerDevicePublicKey, routeSecret });
    const session = this.ensureSession({
      peerDeviceId,
      peerIdentityPublicKey,
      peerDevicePublicKey,
      routeSecret,
    });
    if (!this.enforceReadySession || session.isReady) {
      return session;
    }
    const attempts = Number(session.handshakeAttempts || 0);
    if (attempts >= this.maxHandshakeAttempts) {
      const error = new Error(`Handshake failed for session ${sessionId}`);
      this.rejectSessionReady(sessionId, error);
      throw error;
    }
    session.handshakeAttempts = attempts + 1;
    session.lastHandshakeAt = Date.now();
    this.markSessionHandshakeState(sessionId, HANDSHAKE_STATES.INITIATED);
    this.debugDeliveryLog('handshake_start', { sessionId, peerDeviceId, attempt: session.handshakeAttempts });
    this.sendRaw(this.createSessionHandshakeEnvelope({
      peerDeviceId,
      peerIdentityPublicKey,
      peerDevicePublicKey,
      routeSecret,
      stage: 'init',
    }));
    return session;
  }

  ensureSessionReady(identityPublicKey, devicePublicKey, options = {}) {
    const {
      peerDeviceId,
      routeSecret,
      timeoutMs = 15_000,
    } = options || {};
    const sessionId = this.getSessionId({
      peerDeviceId,
      peerDevicePublicKey: devicePublicKey,
      routeSecret,
    });
    const session = this.ensureSession({
      peerDeviceId,
      peerIdentityPublicKey: identityPublicKey,
      peerDevicePublicKey: devicePublicKey,
      routeSecret,
    });
    if (!this.enforceReadySession || session.isReady) {
      return Promise.resolve(session);
    }
    return new Promise((resolve, reject) => {
      const waiters = this.pendingReadySessions.get(sessionId) || [];
      waiters.push({ resolve, reject });
      this.pendingReadySessions.set(sessionId, waiters);
      const refreshed = this.sessions.get(sessionId);
      if (refreshed?.isReady) {
        this.resolveSessionReady(sessionId, refreshed);
        return;
      }
      try {
        const elapsed = Date.now() - Number(refreshed?.lastHandshakeAt || 0);
        if (
          refreshed?.handshakeState !== HANDSHAKE_STATES.INITIATED
          || elapsed >= this.handshakeRetryIntervalMs
        ) {
          this.initiateSessionHandshake({
            peerDeviceId,
            peerIdentityPublicKey: identityPublicKey,
            peerDevicePublicKey: devicePublicKey,
            routeSecret,
          });
        }
      } catch (error) {
        this.rejectSessionReady(sessionId, error);
        return;
      }
      if (timeoutMs > 0) {
        setTimeout(() => {
          const active = this.pendingReadySessions.get(sessionId) || [];
          const index = active.findIndex((entry) => entry.resolve === resolve);
          if (index >= 0) {
            active.splice(index, 1);
            if (active.length) {
              this.pendingReadySessions.set(sessionId, active);
            } else {
              this.pendingReadySessions.delete(sessionId);
            }
            reject(new Error(`Session bootstrap timeout for ${sessionId}`));
          }
        }, timeoutMs);
      }
    });
  }

  getSessionReadiness({ peerDeviceId, peerDevicePublicKey, routeSecret } = {}) {
    try {
      const sessionId = this.getSessionId({ peerDeviceId, peerDevicePublicKey, routeSecret });
      const session = this.sessions.get(sessionId);
      if (!session) {
        return {
          exists: false,
          handshakeState: HANDSHAKE_STATES.NONE,
          isReady: false,
        };
      }
      return {
        exists: true,
        handshakeState: session.handshakeState || HANDSHAKE_STATES.NONE,
        isReady: Boolean(session.isReady),
      };
    } catch {
      return {
        exists: false,
        handshakeState: HANDSHAKE_STATES.NONE,
        isReady: false,
      };
    }
  }

  pruneActiveSessions() {
    if (this.sessions.size <= this.maxActiveSessions) {
      return;
    }
    const sorted = [...this.sessions.entries()]
      .sort((a, b) => (a[1]?.lastActivityAt || 0) - (b[1]?.lastActivityAt || 0));
    const overflow = this.sessions.size - this.maxActiveSessions;
    for (let i = 0; i < overflow; i += 1) {
      this.sessions.delete(sorted[i][0]);
    }
    this.appendSecurityEvent('sessions_pruned', { removed: overflow, maxActiveSessions: this.maxActiveSessions });
  }

  ensureDecoySessions() {
    if (!this.decoySessionCount) {
      return;
    }
    while (this.decoyRouteSecrets.length < this.decoySessionCount) {
      const routeSecret = `decoy:${this.identity.deviceId}:${randomUUID()}`;
      const peerDeviceId = `${DECOY_SESSION_PREFIX}${this.decoyRouteSecrets.length}:${routeSecret}`;
      this.ensureSession({ routeSecret, peerDeviceId });
      this.decoyRouteSecrets.push(routeSecret);
    }
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
    const boundedMax = Math.min(this.maxSkippedMessageKeys, 128);
    if (session.skippedMessageKeys.size <= boundedMax) {
      return;
    }
    const overflow = session.skippedMessageKeys.size - boundedMax;
    const keys = session.skippedMessageKeys.keys();
    for (let i = 0; i < overflow; i += 1) {
      const next = keys.next();
      if (next.done) {
        break;
      }
      session.skippedMessageKeys.delete(next.value);
    }
    this.assertProtocolInvariant(
      'skipped_message_keys_bounded',
      session.skippedMessageKeys.size <= boundedMax,
      {
        size: session.skippedMessageKeys.size,
        boundedMax,
      },
    );
  }

  isHandshakeValid(handshakeMessage) {
    const remoteSupportedVersions = handshakeMessage.supportedVersions
      || (handshakeMessage.protocolVersion
        ? [handshakeMessage.protocolVersion]
        : [this.protocolVersion]);
    const negotiatedVersion = negotiateProtocolVersion(
      this.supportedVersions,
      remoteSupportedVersions,
    );
    if (!negotiatedVersion) {
      this.incrementSecurityMetric('handshakeMismatches');
      this.appendSecurityEvent('handshake_version_mismatch', {
        senderDeviceId: handshakeMessage?.senderDeviceId,
        localSupportedVersions: this.supportedVersions,
        remoteSupportedVersions,
      });
      return false;
    }

    const identityPublicKey = handshakeMessage.identityPublicKey
      || handshakeMessage.publicKeys?.identity;
    const devicePublicKey = handshakeMessage.devicePublicKey
      || handshakeMessage.publicKeys?.classicalDevice;

    const valid = verifyDeviceKeyBinding(
      identityPublicKey,
      devicePublicKey,
      handshakeMessage.deviceKeySignature,
    );
    if (!valid) {
      this.incrementSecurityMetric('handshakeMismatches');
      this.appendSecurityEvent('handshake_mismatch', {
        senderDeviceId: handshakeMessage?.senderDeviceId,
      });
    }
    if (valid && handshakeMessage?.senderDeviceId) {
      this.peerProtocolVersions.set(handshakeMessage.senderDeviceId, negotiatedVersion);
    }
    return valid;
  }

  parseHandshakePayload(message) {
    if (!message?.encryptedPayload) {
      return {};
    }
    try {
      const parsed = JSON.parse(message.encryptedPayload);
      return parsed && typeof parsed === 'object' ? parsed : {};
    } catch {
      return {};
    }
  }

  handleHandshakeMessage({
    message,
    senderDevicePublicKey,
    senderIdentityPublicKey,
    routeSecret,
  }) {
    if (!this.isHandshakeValid(message)) {
      return null;
    }
    const payload = this.parseHandshakePayload(message);
    const stage = payload.stage === 'response' ? 'response' : 'init';
    const session = this.ensureSession({
      peerDeviceId: message.senderDeviceId,
      peerIdentityPublicKey: senderIdentityPublicKey
        || message.identityPublicKey
        || message.publicKeys?.identity,
      peerDevicePublicKey: senderDevicePublicKey
        || message.devicePublicKey
        || message.publicKeys?.classicalDevice,
      routeSecret,
    });
    const sessionId = this.getSessionId({
      peerDeviceId: message.senderDeviceId,
      peerDevicePublicKey: senderDevicePublicKey || message.devicePublicKey,
      routeSecret,
    });
    this.markSessionHandshakeState(sessionId, HANDSHAKE_STATES.COMPLETE);
    this.debugDeliveryLog('handshake_complete', {
      sessionId,
      stage,
      from: message.senderDeviceId,
    });
    if (stage === 'init') {
      try {
        this.sendRaw(this.createSessionHandshakeEnvelope({
          peerDeviceId: message.senderDeviceId,
          peerIdentityPublicKey: session.peerIdentityPublicKey,
          peerDevicePublicKey: session.peerDevicePublicKey,
          routeSecret,
          stage: 'response',
        }));
      } catch {
        // response will be retried on next session-ready demand
      }
    }
    return session;
  }

  maybeRatchetSendChain(session) {
    const now = Date.now();
    if (
      typeof session.lastActivityAt === 'number'
      && now - session.lastActivityAt > this.longInactivityMs
    ) {
      session.ratchetPending = true;
      session.forceRatchetOnNextSend = true;
    }
    if (!session.ratchetPending || !session.lastDHKey) {
      return;
    }

    const previousRootKey = Buffer.from(session.rootKey);
    const previousChainSend = Buffer.from(session.chainKeySend);
    const previousChainReceive = Buffer.from(session.chainKeyReceive);
    const newDhKeyPair = this.createDhKeyPair();
    let newSharedSecret = null;
    let next = null;
    try {
      newSharedSecret = deriveSharedSecret(newDhKeyPair.privateKey, session.lastDHKey);
      next = deriveRootAndChainFromDh(session.rootKey, newSharedSecret);
    } finally {
      secureZero(newSharedSecret);
    }

    session.previousCounter = session.sendCounter;
    session.sendCounter = 0;
    session.selfDHKeyPair = newDhKeyPair;
    session.rootKey = Buffer.from(next.rootKey);
    session.chainKeySend = Buffer.from(next.chainKey);
    session.ratchetPending = false;
    session.forceRatchetOnNextSend = false;
    if (session.skippedMessageKeys instanceof Map) {
      session.skippedMessageKeys.clear();
    }
    secureZero(previousRootKey);
    secureZero(previousChainSend);
    secureZero(previousChainReceive);
  }

  validateRequiredChatMessageFields(message) {
    const normalized = validateMessage(message);
    if (normalized.type !== 'chat') {
      throw new Error('Protocol violation: invalid message type');
    }
  }

  trySendChatImmediate(params, { bypassReadiness = false } = {}) {
    try {
      return this.sendChat({
        ...params,
        __bypassReadiness: bypassReadiness,
      });
    } catch {
      return null;
    }
  }

  sendChat({
    content,
    recipientDevicePublicKey,
    recipientDeviceId,
    recipientIdentityPublicKey,
    routeSecret,
    attachments,
    __bypassReadiness = false,
  }) {
    if (this.safeMode) {
      this.queueDummyForTrafficSlot();
      this.appendSecurityEvent('safe_mode_real_send_blocked', {
        recipientDeviceId,
      });
      return null;
    }
    const sessionId = this.getSessionId({
      peerDeviceId: recipientDeviceId,
      peerDevicePublicKey: recipientDevicePublicKey,
      routeSecret,
    });
    const session = this.ensureSession({
      peerDeviceId: recipientDeviceId,
      peerIdentityPublicKey: recipientIdentityPublicKey,
      peerDevicePublicKey: recipientDevicePublicKey,
      routeSecret,
    });
    if (this.enforceReadySession && !__bypassReadiness && (!session || !session.isReady)) {
      this.queuePendingSessionMessage({
        sessionId,
        params: {
          content,
          recipientDevicePublicKey,
          recipientDeviceId,
          recipientIdentityPublicKey,
          routeSecret,
          attachments,
        },
      });
      this.ensureSessionReady(recipientIdentityPublicKey, recipientDevicePublicKey, {
        peerDeviceId: recipientDeviceId,
        routeSecret,
      }).catch(() => {
        this.schedulePendingSessionRetry();
      });
      return null;
    }

    this.maybeRatchetSendChain(session);

    const messageId = randomUUID();
    const counter = session.sendCounter;
    const previousCounter = session.previousCounter;
    const dhPublicKey = session.selfDHKeyPair.publicKey;
    const routeTag = this.computeRouteTagForSession(session, counter, 'send', this.pickRouteTagIndex());
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
      protocolVersion: this.protocolVersion,
      senderDeviceId: this.identity.deviceId,
      targetDeviceId: recipientDeviceId,
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
    this.queueOutboundMessage(envelope, { sessionId });
    this.trackAck(envelope);
    this.triggerImmediateReliablePull();
    this.debugDeliveryLog('message_send', {
      messageId,
      targetDeviceId: recipientDeviceId,
      routeTag,
      sessionId,
    });
    if (this.opsecMode === OPSEC_MODES.HARDENED && this.keyVault && !this.keyVault.isLocked()) {
      this.keyVault.clearUnlockedKeys();
    }
    this.touchKeyVaultActivity();
    this.persistSessions();
    return envelope;
  }

  sendChatToIdentityDevices({
    content,
    recipientIdentity,
    routeSecretByDevice = {},
    attachments,
  }) {
    const entries = Object.entries(recipientIdentity?.deviceRegistry || {});
    return entries.map(([recipientDeviceId, record]) => this.sendChat({
      content,
      attachments,
      recipientDeviceId,
      recipientDevicePublicKey: record.devicePublicKey,
      recipientIdentityPublicKey: recipientIdentity.identityKeyPair?.publicKey,
      routeSecret: routeSecretByDevice[recipientDeviceId] || routeSecretByDevice.default,
    }));
  }

  computeMixDelayMs() {
    return this.randomInRange(this.outboundMixDelayRangeMs);
  }

  queueOutboundMessage(message, { sessionId = message?.sessionId || 'default', isDummy = false } = {}) {
    this.outboundQueue.push({
      message,
      sessionId,
      isDummy,
      queuedAt: Date.now(),
      releaseAt: Date.now() + this.computeMixDelayMs(),
      sequence: this.outboundSequence++,
    });
    this.scheduleOutboundFlush();
  }

  scheduleOutboundFlush(delayMs = this.computeQueueDelayMs()) {
    if (this.constantTrafficEnabled) {
      return;
    }
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
    if (this.constantTrafficEnabled) {
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

    const ready = this.outboundQueue
      .filter((entry) => entry.releaseAt <= now)
      .sort((a, b) => a.sequence - b.sequence);
    if (!ready.length) {
      const nextReadyAt = Math.min(...this.outboundQueue.map((entry) => entry.releaseAt));
      this.scheduleOutboundFlush(Math.max(1, nextReadyAt - now));
      return;
    }

    for (const entry of ready) {
      try {
        this.sendRaw(entry.message);
        const index = this.outboundQueue.findIndex((candidate) => candidate.sequence === entry.sequence);
        if (index >= 0) {
          this.outboundQueue.splice(index, 1);
        }
      } catch {
        entry.releaseAt = Date.now() + this.handshakeRetryIntervalMs;
        entry.retries = (entry.retries || 0) + 1;
      }
    }
    this.lastOutboundSentAt = Date.now();

    if (this.outboundQueue.length) {
      this.scheduleOutboundFlush(this.getMinSendIntervalMs());
    }
  }

  pickRandomSession(values) {
    if (!values.length) {
      return null;
    }
    const index = randomInt(values.length);
    return values[index];
  }

  pickReadyPerSessionHeads(now = Date.now()) {
    const headBySession = new Map();
    for (const entry of this.outboundQueue.sort((a, b) => a.sequence - b.sequence)) {
      if (!headBySession.has(entry.sessionId)) {
        headBySession.set(entry.sessionId, entry);
      }
    }
    const heads = [...headBySession.values()];
    const readyHeads = heads.filter((entry) => entry.releaseAt <= now);
    return readyHeads.length ? readyHeads : heads;
  }

  popOutboundEntryBySequence(sequence) {
    const index = this.outboundQueue.findIndex((entry) => entry.sequence === sequence);
    if (index < 0) {
      return null;
    }
    const [entry] = this.outboundQueue.splice(index, 1);
    return entry;
  }

  selectSessionForDummy() {
    const sessions = [...this.sessions.entries()]
      .filter(([, session]) => session && session.rootKey && session.selfDHKeyPair?.publicKey);
    const sessionCount = sessions.length;
    if (!sessionCount) {
      return null;
    }
    const index = this.opsecMode === OPSEC_MODES.HARDENED
      ? randomInt(sessionCount)
      : this.dummySessionRoundRobin % sessionCount;
    if (this.opsecMode !== OPSEC_MODES.HARDENED) {
      this.dummySessionRoundRobin += 1;
    }
    return sessions[index];
  }

  queueDummyForTrafficSlot() {
    const selected = this.selectSessionForDummy();
    if (!selected) {
      return;
    }
    const [sessionId, session] = selected;
    const envelope = this.createDummyEnvelopeForSession(session);
    this.queueOutboundMessage(envelope, { sessionId, isDummy: true });
  }

  calculateSmoothingAdjustedInterval(baseIntervalMs) {
    const now = Date.now();
    this.sentTrafficTimestamps = this.sentTrafficTimestamps
      .filter((timestamp) => now - timestamp <= this.trafficSmoothingWindowMs);

    const expectedInWindow = (this.trafficSmoothingWindowMs / 1_000) * this.constantTrafficRatePerSecond;
    const lowerBound = expectedInWindow * (1 - this.trafficSmoothingVariance);
    const upperBound = expectedInWindow * (1 + this.trafficSmoothingVariance);
    const observed = this.sentTrafficTimestamps.length;

    if (observed > upperBound) {
      return Math.ceil(baseIntervalMs * 1.2);
    }
    if (observed < lowerBound) {
      return Math.max(1, Math.floor(baseIntervalMs * 0.85));
    }
    return baseIntervalMs;
  }

  sendConstantTrafficSlot() {
    if (!this.constantTrafficEnabled) {
      return;
    }

    if (!this.outboundQueue.length) {
      this.queueDummyForTrafficSlot();
    }

    const candidates = this.pickReadyPerSessionHeads(Date.now());
    if (!candidates.length) {
      return;
    }

    const picked = this.pickRandomSession(candidates);
    const entry = this.popOutboundEntryBySequence(picked.sequence);
    if (!entry) {
      return;
    }

    this.sendRaw(entry.message);
    const now = Date.now();
    this.lastOutboundSentAt = now;
    this.sentTrafficTimestamps.push(now);
  }

  scheduleNextConstantTrafficSlot() {
    if (!this.constantTrafficEnabled) {
      return;
    }
    const baseInterval = this.getBaseTrafficSlotIntervalMs();
    const smoothedInterval = this.calculateSmoothingAdjustedInterval(baseInterval);
    this.constantTrafficTimer = setTimeout(() => {
      this.constantTrafficTimer = null;
      this.sendConstantTrafficSlot();
      this.scheduleNextConstantTrafficSlot();
    }, smoothedInterval);
  }

  startConstantTrafficLoop() {
    if (!this.constantTrafficEnabled || this.constantTrafficTimer) {
      return;
    }
    this.ensureDecoySessions();
    this.sendConstantTrafficSlot();
    this.scheduleNextConstantTrafficSlot();
  }

  stopConstantTrafficLoop() {
    if (this.constantTrafficTimer) {
      clearTimeout(this.constantTrafficTimer);
      this.constantTrafficTimer = null;
    }
  }

  createDummyEnvelopeForSession(session) {
    this.maybeRatchetSendChain(session);
    const messageId = randomUUID();
    const counter = session.sendCounter;
    const previousCounter = session.previousCounter;
    const dhPublicKey = session.selfDHKeyPair.publicKey;
    const routeTag = this.computeRouteTagForSession(session, counter, 'send', this.pickRouteTagIndex());
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
      protocolVersion: this.protocolVersion,
      senderDeviceId: this.identity.deviceId,
      targetDeviceId: session.peerDeviceId,
      routeTag,
      messageId,
      counter,
      previousCounter,
      dhPublicKey,
      encryptedPayload: JSON.stringify(encrypted),
      timestamp: Date.now(),
    };
    const signature = signMessage(this.identity.identityKeyPair.privateKey, baseMessage);
    this.persistSessions();
    return { ...baseMessage, signature };
  }

  sendDummyTraffic() {
    this.queueDummyForTrafficSlot();
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
    this.ensureDecoySessions();
    if (this.constantTrafficEnabled) {
      this.startConstantTrafficLoop();
      return;
    }
    this.scheduleNextCoverTraffic();
  }

  stopCoverTraffic() {
    this.coverTrafficEnabled = false;
    this.stopConstantTrafficLoop();
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

    const previousRootKey = Buffer.from(session.rootKey);
    const previousChainReceive = Buffer.from(session.chainKeyReceive);
    let newSharedSecret = null;
    let next = null;
    try {
      newSharedSecret = deriveSharedSecret(session.selfDHKeyPair.privateKey, incomingDhPublicKey);
      next = deriveRootAndChainFromDh(session.rootKey, newSharedSecret);
    } finally {
      secureZero(newSharedSecret);
    }
    session.rootKey = Buffer.from(next.rootKey);
    session.chainKeyReceive = Buffer.from(next.chainKey);
    session.receiveCounter = 0;
    session.currentReceiveDhKey = incomingDhPublicKey;
    session.lastDHKey = incomingDhPublicKey;
    session.ratchetPending = true;
    session.forceRatchetOnNextSend = true;
    if (session.skippedMessageKeys instanceof Map) {
      session.skippedMessageKeys.clear();
    }
    secureZero(previousRootKey);
    secureZero(previousChainReceive);
  }

  deriveReceiveMessageKey(session, message) {
    const previousReceiveCounter = session.receiveCounter;
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
    this.assertProtocolInvariant(
      'receive_counter_monotonic',
      session.receiveCounter >= previousReceiveCounter,
      {
        previousReceiveCounter,
        nextReceiveCounter: session.receiveCounter,
        messageCounter: message.counter,
      },
    );
    return messageKey;
  }

  decryptChat({ message, senderDevicePublicKey, senderIdentityPublicKey, routeSecret }) {
    const normalizedMessage = validateMessage(message);
    this.validateRequiredChatMessageFields(normalizedMessage);
    if (this.shouldQuarantineMessages()) {
      this.quarantineInboundMessage({
        message: normalizedMessage,
        senderDevicePublicKey,
        senderIdentityPublicKey,
        routeSecret,
      });
      return null;
    }

    let messageKey = null;
    try {
      if (senderIdentityPublicKey) {
        const trustResult = this.checkAndUpdateTrust(senderIdentityPublicKey, senderDevicePublicKey);
        if (trustResult === 'BLOCKED') {
          this.incrementSecurityMetric('droppedMessages');
          this.appendSecurityEvent('blocked_message_dropped', {
            senderDeviceId: normalizedMessage.senderDeviceId,
            messageId: normalizedMessage.messageId,
          });
          return null;
        }
      }

      const securityState = this.getCurrentSecurityState();
      this.assertProtocolInvariant(
        'verified_identity_immutability',
        !(
          securityState.identityIntegrity === IDENTITY_INTEGRITY.CHANGED
          && securityState.trustLevel === TRUST_LEVELS.VERIFIED
        ),
        {
          senderDeviceId: normalizedMessage.senderDeviceId,
          trustLevel: securityState.trustLevel,
          identityIntegrity: securityState.identityIntegrity,
        },
      );

      const signatureVerified = verifyMessage(
        senderIdentityPublicKey,
        normalizedMessage,
        normalizedMessage.signature,
      );
      if (!signatureVerified) {
        this.incrementSecurityMetric('invalidSignatures');
        throw new Error('Protocol violation: invalid message signature');
      }

      const session = this.ensureSession({
        peerDeviceId: normalizedMessage.senderDeviceId,
        peerIdentityPublicKey: senderIdentityPublicKey,
        peerDevicePublicKey: senderDevicePublicKey,
        routeSecret,
      });
      if (this.enforceReadySession && !session.isReady) {
        const sessionId = this.getSessionId({
          peerDeviceId: normalizedMessage.senderDeviceId,
          peerDevicePublicKey: senderDevicePublicKey,
          routeSecret,
        });
        this.markSessionHandshakeState(sessionId, HANDSHAKE_STATES.COMPLETE);
      }

      this.pruneSeenMessageIds(session.seenMessageIds);
      if (session.seenMessageIds.has(normalizedMessage.messageId)) {
        this.incrementSecurityMetric('replayAttempts');
        return null;
      }
      session.seenMessageIds.set(normalizedMessage.messageId, Date.now() + this.replayTtlMs);

      this.applyReceiveRatchetIfNeeded(session, normalizedMessage.dhPublicKey);

      const expectedRouteTags = this.computeRouteTagCandidates(session.rootKey, normalizedMessage.counter, 'send');
      const routeTagMatches = expectedRouteTags.includes(normalizedMessage.routeTag);
      if (!routeTagMatches) {
        this.incrementSecurityMetric('routeTagMismatches');
        this.debugDeliveryLog('route_tag_mismatch', {
          messageId: normalizedMessage.messageId,
          routeTag: normalizedMessage.routeTag,
          expectedRouteTags,
        });
        return null;
      }
      this.assertProtocolInvariant(
        'route_tag_derived_match',
        routeTagMatches,
        {
          senderDeviceId: normalizedMessage.senderDeviceId,
          counter: normalizedMessage.counter,
        },
      );

      if (normalizedMessage.counter > session.receiveCounter + Math.max(1, this.receiveWindow / 2)) {
        this.updateSecurityState({ type: SECURITY_EVENTS.ABNORMAL_COUNTER_GAPS });
      }

      messageKey = this.deriveReceiveMessageKey(session, normalizedMessage);
      this.touchSession(session);
      this.persistSessions();

      this.assertProtocolInvariant(
        'signature_verified_before_decrypt',
        signatureVerified === true,
        {
          senderDeviceId: normalizedMessage.senderDeviceId,
          messageId: normalizedMessage.messageId,
        },
      );
      const payload = decryptPayloadWithMessageKey(JSON.parse(normalizedMessage.encryptedPayload), messageKey);
      if (payload?.isDummy) {
        return null;
      }
      this.acknowledgeDelivery(normalizedMessage);
      this.debugDeliveryLog('decrypt_success', {
        messageId: normalizedMessage.messageId,
        senderDeviceId: normalizedMessage.senderDeviceId,
      });
      return payload;
    } catch (error) {
      this.incrementSecurityMetric('messageFailures');
      this.debugDeliveryLog('decrypt_failure', {
        messageId: normalizedMessage?.messageId,
        senderDeviceId: normalizedMessage?.senderDeviceId,
        error: error.message,
      });
      this.appendSecurityEvent('protocol_violation', {
        message: error.message,
        senderDeviceId: normalizedMessage.senderDeviceId,
        messageId: normalizedMessage.messageId,
      });
      throw error;
    } finally {
      secureZero(messageKey);
    }
  }

  delayInboundProcessing(task, { min, max } = this.inboundProcessDelayRangeMs) {
    const range = normalizeRange({ min, max }, this.inboundProcessDelayRangeMs);
    const delayMs = this.randomInRange(range);
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        try {
          resolve(task());
        } catch (error) {
          reject(error);
        }
      }, delayMs);
    });
  }

  decryptChatWithDelay(params) {
    return this.delayInboundProcessing(() => this.decryptChat(params));
  }

  handleInboundMessage(params) {
    const startedAt = process.hrtime.bigint();
    const inboundMessage = params?.message;
    const normalized = typeof inboundMessage === 'string'
      || Buffer.isBuffer(inboundMessage)
      || inboundMessage instanceof Uint8Array
      ? decodeMessage(inboundMessage, { strictMode: this.strictWireMode })
      : decodeMessage(
        encodeMessage(inboundMessage, { strictMode: this.strictWireMode }),
        { strictMode: this.strictWireMode },
      );
    observeMessageProcessingDuration(Number(process.hrtime.bigint() - startedAt) / 1e6);
    this.evaluateEnvironmentRisk();
    this.trackInboundTiming();
    if (normalized.type === 'ack') {
      this.receiveAck(normalized);
      return null;
    }
    if (normalized.type === 'handshake') {
      return this.handleHandshakeMessage({ ...params, message: normalized });
    }
    if (normalized.type === 'chat') {
      const deviceIdMatches = !normalized.targetDeviceId || normalized.targetDeviceId === this.identity.deviceId;
      this.debugDeliveryLog('device_id_match', {
        messageId: normalized.messageId,
        targetDeviceId: normalized.targetDeviceId,
        localDeviceId: this.identity.deviceId,
        matches: deviceIdMatches,
      });
      if (!deviceIdMatches) {
        return null;
      }
      this.debugDeliveryLog('message_receive', {
        messageId: normalized.messageId,
        routeTag: normalized.routeTag,
        targetDeviceId: normalized.targetDeviceId,
      });
      return this.decryptChat({ ...params, message: normalized });
    }
    return null;
  }

  pull(routeSecrets = [], { window = this.receiveWindow } = {}) {
    if (this.safeMode) {
      return;
    }
    const boundedWindow = Math.max(0, Math.min(window, this.maxPullWindow));
    const effectiveRouteSecrets = [...new Set([...routeSecrets, ...this.decoyRouteSecrets])];
    const routeTags = [];
    for (const routeSecret of effectiveRouteSecrets) {
      const session = this.ensureSession({ routeSecret });
      const start = Math.max(0, session.receiveCounter - boundedWindow);
      const end = session.receiveCounter + boundedWindow;
      for (let counter = start; counter <= end; counter += 1) {
        const routeTagEpoch = this.deriveRouteTagEpochForCounter(session, counter);
        for (let index = 0; index < this.parallelRouteTags; index += 1) {
          routeTags.push(computeRouteTag(session.rootKey, counter, 'send', index, routeTagEpoch));
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
    for (const session of this.sessions.values()) {
      if (!session?.rootKey || !session?.isReady || session.isDecoy) {
        continue;
      }
      const start = Math.max(0, session.receiveCounter - boundedWindow);
      const end = session.receiveCounter + boundedWindow;
      for (let counter = start; counter <= end; counter += 1) {
        const routeTagEpoch = this.deriveRouteTagEpochForCounter(session, counter);
        for (let index = 0; index < this.parallelRouteTags; index += 1) {
          routeTags.push(computeRouteTag(session.rootKey, counter, 'send', index, routeTagEpoch));
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

    let referenceCounter = 0;
    if (effectiveRouteSecrets.length) {
      const referenceSession = this.ensureSession({
        routeSecret: effectiveRouteSecrets[0],
      });
      referenceCounter = referenceSession.receiveCounter;
    }
    const noiseStart = Math.max(0, referenceCounter - boundedWindow);
    const noiseEnd = referenceCounter + boundedWindow;
    const pullTargetCount = Math.min(this.maxPullRouteTags, this.normalizedPullRouteTagCount);
    const noiseToAdd = Math.max(0, pullTargetCount - routeTags.length);
    for (let i = 0; i < noiseToAdd; i += 1) {
      const noiseRoot = createHash('sha512')
        .update(`${this.pullNoiseSeed}:${this.pullNoiseCounter++}`)
        .digest('hex');
      const noiseCounter = noiseStart + randomInt(0, Math.max(1, noiseEnd - noiseStart + 1));
      const noiseIndex = randomInt(0, this.parallelRouteTags);
      routeTags.push(computeRouteTag(
        noiseRoot,
        noiseCounter,
        'send',
        noiseIndex,
        deriveRouteTagEpoch(noiseRoot, this.getRouteTagEpochCounter(noiseCounter)),
      ));
    }
    const normalizedTags = shuffleInPlace(routeTags).slice(0, pullTargetCount);
    this.debugDeliveryLog('pull_route_tags', {
      routeTagCount: normalizedTags.length,
      sample: normalizedTags.slice(0, 5),
    });

    this.sendRaw({
      type: 'control',
      senderDeviceId: this.identity.deviceId,
      encryptedPayload: '',
      timestamp: Date.now(),
      action: 'pull',
      routeTags: normalizedTags,
    });
  }

  startReliablePullLoop(routeSecrets = [], { intervalMs = 2_000, window = this.receiveWindow } = {}) {
    if (this.safeMode) {
      return;
    }
    this.stopReliablePullLoop();
    this.ensureDecoySessions();
    this.reliablePullState = {
      routeSecrets: [...routeSecrets],
      window,
      baseIntervalMs: Math.max(0, Number(intervalMs) || 0),
      failures: 0,
      active: true,
      timer: null,
    };
    this.autoPullActive = true;
    this.autoPullRouteSecrets = [...routeSecrets];
    this.autoPullBaseIntervalMs = Math.max(0, Number(intervalMs) || 0);
    const schedule = () => {
      if (!this.reliablePullState?.active) {
        return;
      }
      const jitter = this.pullIntervalJitterMs > 0
        ? randomInt(-this.pullIntervalJitterMs, this.pullIntervalJitterMs + 1)
        : 0;
      const hardenedJitter = this.opsecMode === OPSEC_MODES.HARDENED
        ? randomInt(-100, 101)
        : 0;
      const backoff = Math.min(
        this.reliablePullMaxBackoffMs,
        this.reliablePullState.baseIntervalMs * (2 ** this.reliablePullState.failures),
      );
      const nextInterval = Math.max(0, backoff + jitter + hardenedJitter);
      this.reliablePullState.timer = setTimeout(() => {
        this.reliablePullState.timer = null;
        try {
          this.pull(this.reliablePullState.routeSecrets, { window: this.reliablePullState.window });
          this.reliablePullState.failures = 0;
        } catch {
          this.reliablePullState.failures = Math.min(10, this.reliablePullState.failures + 1);
        }
        schedule();
      }, nextInterval);
    };
    schedule();
  }

  triggerImmediateReliablePull() {
    if (!this.reliablePullState?.active) {
      return;
    }
    try {
      this.pull(this.reliablePullState.routeSecrets, { window: this.reliablePullState.window });
      this.reliablePullState.failures = 0;
    } catch {
      this.reliablePullState.failures = Math.min(10, this.reliablePullState.failures + 1);
    }
  }

  stopReliablePullLoop() {
    if (!this.reliablePullState) {
      return;
    }
    this.reliablePullState.active = false;
    if (this.reliablePullState.timer) {
      clearTimeout(this.reliablePullState.timer);
      this.reliablePullState.timer = null;
    }
    this.reliablePullState = null;
  }

  startAutoPull(routeSecrets = [], { intervalMs = 2_000, window = this.receiveWindow } = {}) {
    if (this.safeMode) {
      return;
    }
    this.ensureDecoySessions();
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
      const hardenedJitter = this.opsecMode === OPSEC_MODES.HARDENED
        ? randomInt(-100, 101)
        : 0;
      const nextInterval = Math.max(0, this.autoPullBaseIntervalMs + jitter + hardenedJitter);
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

  // ---------------------------------------------------------------------------
  // Trust & Identity Verification API
  // ---------------------------------------------------------------------------

  /**
   * Core trust-enforcement logic called on every inbound message.
   * Mutates the TrustStore entry as needed and throws / returns silently
   * according to the enforcement rules.
   *
   * @param {string} identityPublicKey  PEM
   * @param {string} [devicePublicKey]  PEM (optional – for device tracking)
   * @throws if the identity is BLOCKED or a VERIFIED identity has changed key
   * @returns {'BLOCKED'|null} 'BLOCKED' when the message must be silently dropped
   */
  checkAndUpdateTrust(identityPublicKey, devicePublicKey) {
    if (!this.trustStore || !identityPublicKey) {
      return null;
    }

    const fingerprint = fingerprintIdentityPublicKey(identityPublicKey);
    const now = Date.now();
    const existing = this.trustStore.get(fingerprint);

    if (!existing) {
      // CASE A: first time seeing this identity
      const entry = {
        identityPublicKey,
        fingerprint,
        level: TRUST_LEVELS.UNKNOWN,
        firstSeen: now,
        lastSeen: now,
        deviceFingerprints: devicePublicKey
          ? [this.fingerprintDevicePublicKey(devicePublicKey)]
          : [],
      };
      this.trustStore.set(fingerprint, entry);
      this.updateSecurityState({
        trustLevel: TRUST_LEVELS.UNKNOWN,
        identityIntegrity: IDENTITY_INTEGRITY.UNVERIFIED,
      });
      return null;
    }

    // CASE B: identity already seen – update lastSeen
    const updated = { ...existing, lastSeen: now };

    // Check for identity key change (potential MITM): direct PEM comparison
    if (existing.identityPublicKey !== identityPublicKey) {
      updated.lastFingerprintChange = now;
      this.appendSecurityEvent('identity_change_detected', {
        fingerprint,
        previousFingerprint: existing.fingerprint,
      });
      this.updateSecurityState({
        type: SECURITY_EVENTS.IDENTITY_KEY_CHANGE_DETECTED,
        trustLevel: existing.level,
      });

      if (existing.level === TRUST_LEVELS.VERIFIED) {
        // Hard block – VERIFIED identity cannot silently change key
        throw new Error(
          'Security alert: identity key changed for a VERIFIED contact. '
          + `Previous fingerprint: ${existing.fingerprint}. Message rejected.`,
        );
      }

      // Downgrade trust to UNKNOWN for non-verified contacts
      updated.level = TRUST_LEVELS.UNKNOWN;
      updated.identityPublicKey = identityPublicKey;
      updated.fingerprint = fingerprint;
    }

    // Enforce BLOCKED rule – return sentinel so caller can drop silently
    if (updated.level === TRUST_LEVELS.BLOCKED) {
      this.trustStore.set(fingerprint, updated);
      this.updateSecurityState({
        trustLevel: TRUST_LEVELS.BLOCKED,
      });
      this.appendSecurityEvent('blocked_message_dropped', {
        fingerprint,
      });
      return 'BLOCKED';
    }

    // Track device fingerprint
    if (devicePublicKey) {
      const deviceFp = this.fingerprintDevicePublicKey(devicePublicKey);
      if (!updated.deviceFingerprints) {
        updated.deviceFingerprints = [];
      }
      if (!updated.deviceFingerprints.includes(deviceFp)) {
        updated.deviceFingerprints = [...updated.deviceFingerprints, deviceFp];
      }
    }

    this.trustStore.set(fingerprint, updated);
    this.updateSecurityState({
      trustLevel: updated.level || TRUST_LEVELS.UNKNOWN,
      identityIntegrity: updated.level === TRUST_LEVELS.VERIFIED ? IDENTITY_INTEGRITY.OK : IDENTITY_INTEGRITY.UNVERIFIED,
    });
    return null;
  }

  /**
   * Returns SHA-256 hex fingerprint of a device public key PEM.
   *
   * @param {string} devicePublicKeyPem
   * @returns {string}
   */
  fingerprintDevicePublicKey(devicePublicKeyPem) {
    return createHash('sha256').update(devicePublicKeyPem).digest('hex');
  }

  /**
   * Mark an identity as TRUSTED (user explicitly trusts it).
   */
  trustIdentity(identityPublicKey, label) {
    if (!this.trustStore) {
      throw new Error('TrustStore is not configured');
    }
    const fingerprint = fingerprintIdentityPublicKey(identityPublicKey);
    const now = Date.now();
    const existing = this.trustStore.get(fingerprint) || {
      identityPublicKey,
      fingerprint,
      firstSeen: now,
      deviceFingerprints: [],
    };
    this.trustStore.set(fingerprint, {
      ...existing,
      identityPublicKey,
      fingerprint,
      level: TRUST_LEVELS.TRUSTED,
      lastSeen: now,
      label: label !== undefined ? label : (existing.label || undefined),
    });
    this.updateSecurityState({
      trustLevel: TRUST_LEVELS.TRUSTED,
      identityIntegrity: IDENTITY_INTEGRITY.UNVERIFIED,
    });
    this.appendSecurityEvent('trust_changed', {
      fingerprint,
      level: TRUST_LEVELS.TRUSTED,
    });
  }

  /**
   * Mark an identity as VERIFIED (safety-number / out-of-band confirmation).
   */
  verifyIdentity(identityPublicKey, confirmation = {}) {
    this.confirmSensitiveAction({
      action: 'verifyIdentity',
      fingerprint: fingerprintIdentityPublicKey(identityPublicKey),
      verificationString: this.generateVerificationString(identityPublicKey).numeric,
      confirmed: confirmation.confirmed,
    });
    if (!this.trustStore) {
      throw new Error('TrustStore is not configured');
    }
    const fingerprint = fingerprintIdentityPublicKey(identityPublicKey);
    const now = Date.now();
    const existing = this.trustStore.get(fingerprint) || {
      identityPublicKey,
      fingerprint,
      firstSeen: now,
      deviceFingerprints: [],
    };
    this.trustStore.set(fingerprint, {
      ...existing,
      identityPublicKey,
      fingerprint,
      level: TRUST_LEVELS.VERIFIED,
      lastSeen: now,
      verifiedAt: now,
    });
    this.updateSecurityState({
      trustLevel: TRUST_LEVELS.VERIFIED,
      identityIntegrity: IDENTITY_INTEGRITY.OK,
    });
    this.appendSecurityEvent('trust_changed', {
      fingerprint,
      level: TRUST_LEVELS.VERIFIED,
    });
  }

  /**
   * Block an identity – future messages from it will be silently dropped.
   */
  blockIdentity(identityPublicKey) {
    if (!this.trustStore) {
      throw new Error('TrustStore is not configured');
    }
    const fingerprint = fingerprintIdentityPublicKey(identityPublicKey);
    const now = Date.now();
    const existing = this.trustStore.get(fingerprint) || {
      identityPublicKey,
      fingerprint,
      firstSeen: now,
      deviceFingerprints: [],
    };
    this.trustStore.set(fingerprint, {
      ...existing,
      identityPublicKey,
      fingerprint,
      level: TRUST_LEVELS.BLOCKED,
      lastSeen: now,
    });
    this.updateSecurityState({
      trustLevel: TRUST_LEVELS.BLOCKED,
    });
    this.appendSecurityEvent('trust_changed', {
      fingerprint,
      level: TRUST_LEVELS.BLOCKED,
    });
  }

  /**
   * Remove a block, reverting the identity to UNKNOWN.
   */
  unblockIdentity(identityPublicKey, confirmation = {}) {
    this.confirmSensitiveAction({
      action: 'unblockIdentity',
      fingerprint: fingerprintIdentityPublicKey(identityPublicKey),
      verificationString: this.generateVerificationString(identityPublicKey).numeric,
      confirmed: confirmation.confirmed,
    });
    if (!this.trustStore) {
      throw new Error('TrustStore is not configured');
    }
    const fingerprint = fingerprintIdentityPublicKey(identityPublicKey);
    const existing = this.trustStore.get(fingerprint);
    if (!existing) {
      return;
    }
    this.trustStore.set(fingerprint, {
      ...existing,
      level: TRUST_LEVELS.UNKNOWN,
      lastSeen: Date.now(),
    });
    this.updateSecurityState({
      type: SECURITY_EVENTS.TRUST_DOWNGRADE,
      trustLevel: TRUST_LEVELS.UNKNOWN,
      identityIntegrity: IDENTITY_INTEGRITY.UNVERIFIED,
    });
    this.appendSecurityEvent('trust_changed', {
      fingerprint,
      level: TRUST_LEVELS.UNKNOWN,
    });
    this.registerOperationalWarning('trust_downgrade', 'warning');
    this.evaluateSafetyEscalation();
  }

  /**
   * Returns the current trust level string for an identity,
   * or null if it has never been seen.
   *
   * @returns {string|null}
   */
  getTrustLevel(identityPublicKey) {
    if (!this.trustStore) {
      return null;
    }
    const fingerprint = fingerprintIdentityPublicKey(identityPublicKey);
    const entry = this.trustStore.get(fingerprint);
    return entry ? entry.level : null;
  }

  /**
   * Returns all TrustEntry objects with level TRUSTED or VERIFIED.
   *
   * @returns {Array}
   */
  listTrustedIdentities() {
    if (!this.trustStore) {
      return [];
    }
    return this.trustStore.list().filter(
      (e) => e.level === TRUST_LEVELS.TRUSTED || e.level === TRUST_LEVELS.VERIFIED,
    );
  }

  /**
   * Compares two identity fingerprints in a timing-safe manner.
   *
   * @param {string} fp1
   * @param {string} fp2
   * @returns {boolean}
   */
  compareFingerprints(fp1, fp2) {
    return compareFingerprints(fp1, fp2);
  }

  /**
   * Generate a verification string (Safety-Number style) for out-of-band
   * identity confirmation between this client and a peer.
   *
   * @param {string} peerIdentityPublicKey  PEM
   * @returns {{ numeric: string, words: string[] }}
   */
  generateVerificationString(peerIdentityPublicKey) {
    return generateVerificationString(
      this.identity.identityKeyPair.publicKey,
      peerIdentityPublicKey,
    );
  }

  confirmSensitiveAction({
    action,
    fingerprint,
    verificationString,
    confirmed = false,
  } = {}) {
    this.appendSecurityEvent('sensitive_action_confirmation_required', {
      action,
      fingerprint,
      verificationString,
    });
    if (confirmed !== true) {
      throw new Error(`Sensitive action "${action}" rejected: confirmation required`);
    }
    this.appendSecurityEvent('sensitive_action_confirmed', {
      action,
      fingerprint,
      verificationString,
    });
    return true;
  }

  setStrictWireMode(enabled, confirmation = {}) {
    if (this.opsecMode === OPSEC_MODES.HARDENED && !enabled) {
      throw new Error('strictWireMode cannot be disabled in HARDENED opsec mode');
    }
    if (!enabled) {
      this.confirmSensitiveAction({
        action: 'disableStrictWireMode',
        fingerprint: this.getConfigFingerprint(),
        verificationString: this.identity.deviceId,
        confirmed: confirmation.confirmed,
      });
    }
    this.strictWireMode = Boolean(enabled);
    return this.strictWireMode;
  }

  exportSecurityLog(filePath, passphrase, confirmation = {}) {
    if (this.opsecMode === OPSEC_MODES.HARDENED && (!confirmation.confirmed || !confirmation.secondConfirmed)) {
      throw new Error('exportSecurityLog blocked in HARDENED mode without double confirmation');
    }
    this.confirmSensitiveAction({
      action: 'exportSecurityLog',
      fingerprint: this.getConfigFingerprint(),
      verificationString: this.identity.deviceId,
      confirmed: confirmation.confirmed,
    });
    this.securityLog.persistEncrypted(filePath, passphrase);
  }

  exportPrivateKeys(passphrase, confirmation = {}) {
    if (this.opsecMode === OPSEC_MODES.HARDENED) {
      throw new Error('exportPrivateKeys is blocked in HARDENED opsec mode');
    }
    this.confirmSensitiveAction({
      action: 'exportPrivateKeys',
      fingerprint: this.getConfigFingerprint(),
      verificationString: this.identity.deviceId,
      confirmed: confirmation.confirmed,
    });
    return this.unlockPrivateKeys(passphrase);
  }

  exportBackup(passphrase, { includeSessions = true } = {}) {
    const payload = {
      schemaVersion: 1,
      createdAt: Date.now(),
      opsecMode: this.opsecMode,
      identity: this.identity,
      trustEntries: this.trustStore ? this.trustStore.list() : [],
      sessions: includeSessions ? [...this.sessions.entries()].map(([sessionId, session]) => [
        sessionId,
        encodeBackupValue(session),
      ]) : [],
    };
    return encryptBlobWithArgon2Passphrase(payload, passphrase);
  }

  importBackup(blob, passphrase, { allowIdentityOverwrite = false } = {}) {
    const parsed = decryptBlobWithArgon2Passphrase(blob, passphrase);
    if (!parsed || parsed.schemaVersion !== 1) {
      throw new Error('Backup schema mismatch');
    }
    if (!parsed.identity || !parsed.identity.identityKeyPair || !parsed.identity.deviceKeyPair) {
      throw new Error('Backup is missing identity keys');
    }
    const currentIdentity = this.identity?.identityKeyPair?.publicKey;
    const nextIdentity = parsed.identity.identityKeyPair.publicKey;
    if (currentIdentity && currentIdentity !== nextIdentity && !allowIdentityOverwrite) {
      this.appendSecurityEvent('backup_identity_overwrite_warning', {
        currentFingerprint: formatIdentityFingerprint(currentIdentity),
        incomingFingerprint: formatIdentityFingerprint(nextIdentity),
      });
      throw new Error('Backup import would overwrite existing identity');
    }

    this.identity = parsed.identity;
    if (this.trustStore) {
      const map = new Map((parsed.trustEntries || []).map((entry) => [entry.fingerprint, entry]));
      this.trustStore.saveTrust(map);
      this.trustStore.loadTrust();
    }
    if (Array.isArray(parsed.sessions) && parsed.sessions.length) {
      this.sessions = new Map(parsed.sessions.map(([sessionId, session]) => [sessionId, decodeBackupValue(session)]));
      this.pruneActiveSessions();
      this.persistSessions();
    }
    return {
      importedSessions: this.sessions.size,
      importedTrustEntries: parsed.trustEntries?.length || 0,
    };
  }

  getConfigFingerprint() {
    const configSnapshot = {
      securityProfile: this.securityProfile,
      opsecMode: this.opsecMode,
      productionMode: this.productionMode,
      strictWireMode: this.strictWireMode,
      constantTrafficEnabled: this.constantTrafficEnabled,
      constantTrafficRatePerSecond: this.constantTrafficRatePerSecond,
      pullNoiseLevel: this.pullNoiseLevel,
      paddingSizeBuckets: this.paddingSizeBuckets,
      rateShaping: this.rateShaping,
      parallelRouteTags: this.parallelRouteTags,
      routeTagEpochMessages: this.routeTagEpochMessages,
    };
    return createHash('sha256')
      .update(stableStringify(configSnapshot))
      .digest('hex');
  }

  close() {
    if (this.outboundFlushTimer) {
      clearTimeout(this.outboundFlushTimer);
      this.outboundFlushTimer = null;
    }
    this.stopCoverTraffic();
    this.stopAutoPull();
    this.stopReliablePullLoop();
    this.stopAckRetryLoop();
    if (this.pendingSessionRetryTimer) {
      clearTimeout(this.pendingSessionRetryTimer);
      this.pendingSessionRetryTimer = null;
    }
    if (this.keyVaultAutoLockTimer) {
      clearTimeout(this.keyVaultAutoLockTimer);
      this.keyVaultAutoLockTimer = null;
    }
    this.persistSessions();
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
  }
}

module.exports = {
  SecureClient,
  SekureClient: SecureClient,
  OPSEC_MODES,
};
