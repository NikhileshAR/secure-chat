const IDENTITY_INTEGRITY = {
  OK: 'OK',
  CHANGED: 'CHANGED',
  UNVERIFIED: 'UNVERIFIED',
};

const TRUST_LEVEL = {
  UNKNOWN: 'UNKNOWN',
  TRUSTED: 'TRUSTED',
  VERIFIED: 'VERIFIED',
  BLOCKED: 'BLOCKED',
};

const SESSION_HEALTH = {
  HEALTHY: 'HEALTHY',
  DESYNC: 'DESYNC',
  SUSPECT: 'SUSPECT',
};

const ENVIRONMENT_RISK = {
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
};

const SECURITY_EVENTS = {
  IDENTITY_KEY_CHANGE_DETECTED: 'identity_key_change_detected',
  TRUST_DOWNGRADE: 'trust_downgrade',
  REPEATED_MESSAGE_FAILURES: 'repeated_message_failures',
  EXCESSIVE_REPLAY_ATTEMPTS: 'excessive_replay_attempts',
  ABNORMAL_COUNTER_GAPS: 'abnormal_counter_gaps',
  HIGH_DROPPED_MESSAGE_RATE: 'high_dropped_message_rate',
  STATE_STABILIZED: 'state_stabilized',
  HANDSHAKE_MISMATCH_SPIKE: 'handshake_mismatch_spike',
  ROUTE_TAG_MISMATCH_SPIKE: 'route_tag_mismatch_spike',
  INVALID_SIGNATURE_SPIKE: 'invalid_signature_spike',
  RELAY_FLOODING_DETECTED: 'relay_flooding_detected',
  ABNORMAL_TIMING_BURST: 'abnormal_timing_burst',
};

function cloneState(state) {
  return {
    identityIntegrity: state.identityIntegrity,
    trustLevel: state.trustLevel,
    sessionHealth: state.sessionHealth,
    environmentRisk: state.environmentRisk,
    lastSecurityEvent: state.lastSecurityEvent,
  };
}

class SecurityStateEngine {
  constructor() {
    this.state = {
      identityIntegrity: IDENTITY_INTEGRITY.UNVERIFIED,
      trustLevel: TRUST_LEVEL.UNKNOWN,
      sessionHealth: SESSION_HEALTH.HEALTHY,
      environmentRisk: ENVIRONMENT_RISK.LOW,
      lastSecurityEvent: Date.now(),
    };
    this.subscribers = new Set();
  }

  updateState(event) {
    const normalized = typeof event === 'string' ? { type: event } : (event || {});
    const eventType = normalized.type;
    const now = Date.now();
    const next = cloneState(this.state);

    switch (eventType) {
      case SECURITY_EVENTS.IDENTITY_KEY_CHANGE_DETECTED:
        next.identityIntegrity = IDENTITY_INTEGRITY.CHANGED;
        if (normalized?.trustLevel && Object.values(TRUST_LEVEL).includes(normalized.trustLevel)) {
          next.trustLevel = normalized.trustLevel;
        }
        break;
      case SECURITY_EVENTS.TRUST_DOWNGRADE:
        next.trustLevel = normalized?.trustLevel && Object.values(TRUST_LEVEL).includes(normalized.trustLevel)
          ? normalized.trustLevel
          : TRUST_LEVEL.UNKNOWN;
        if (next.trustLevel !== TRUST_LEVEL.VERIFIED) {
          next.identityIntegrity = IDENTITY_INTEGRITY.UNVERIFIED;
        }
        break;
      case SECURITY_EVENTS.REPEATED_MESSAGE_FAILURES:
      case SECURITY_EVENTS.EXCESSIVE_REPLAY_ATTEMPTS:
      case SECURITY_EVENTS.ABNORMAL_COUNTER_GAPS:
      case SECURITY_EVENTS.HIGH_DROPPED_MESSAGE_RATE:
        next.sessionHealth = SESSION_HEALTH.SUSPECT;
        break;
      case SECURITY_EVENTS.HANDSHAKE_MISMATCH_SPIKE:
      case SECURITY_EVENTS.ROUTE_TAG_MISMATCH_SPIKE:
      case SECURITY_EVENTS.INVALID_SIGNATURE_SPIKE:
      case SECURITY_EVENTS.RELAY_FLOODING_DETECTED:
      case SECURITY_EVENTS.ABNORMAL_TIMING_BURST:
        next.environmentRisk = ENVIRONMENT_RISK.HIGH;
        next.sessionHealth = SESSION_HEALTH.SUSPECT;
        break;
      case SECURITY_EVENTS.STATE_STABILIZED:
        next.sessionHealth = SESSION_HEALTH.HEALTHY;
        if (next.environmentRisk === ENVIRONMENT_RISK.HIGH) {
          next.environmentRisk = ENVIRONMENT_RISK.MEDIUM;
        } else {
          next.environmentRisk = ENVIRONMENT_RISK.LOW;
        }
        if (next.identityIntegrity !== IDENTITY_INTEGRITY.CHANGED) {
          next.identityIntegrity = next.trustLevel === TRUST_LEVEL.VERIFIED
            ? IDENTITY_INTEGRITY.OK
            : IDENTITY_INTEGRITY.UNVERIFIED;
        }
        break;
      default:
        if (normalized?.trustLevel && Object.values(TRUST_LEVEL).includes(normalized.trustLevel)) {
          next.trustLevel = normalized.trustLevel;
          next.identityIntegrity = normalized.trustLevel === TRUST_LEVEL.VERIFIED
            ? IDENTITY_INTEGRITY.OK
            : next.identityIntegrity;
        }
        if (normalized?.sessionHealth && Object.values(SESSION_HEALTH).includes(normalized.sessionHealth)) {
          next.sessionHealth = normalized.sessionHealth;
        }
        if (normalized?.environmentRisk && Object.values(ENVIRONMENT_RISK).includes(normalized.environmentRisk)) {
          next.environmentRisk = normalized.environmentRisk;
        }
        if (normalized?.identityIntegrity && Object.values(IDENTITY_INTEGRITY).includes(normalized.identityIntegrity)) {
          next.identityIntegrity = normalized.identityIntegrity;
        }
        break;
    }

    next.lastSecurityEvent = now;
    this.state = next;
    const snapshot = cloneState(this.state);
    for (const subscriber of this.subscribers) {
      subscriber(snapshot, normalized);
    }
    return snapshot;
  }

  getCurrentState() {
    return cloneState(this.state);
  }

  subscribe(callback) {
    if (typeof callback !== 'function') {
      throw new Error('SecurityStateEngine.subscribe expects a callback function');
    }
    this.subscribers.add(callback);
    return () => {
      this.subscribers.delete(callback);
    };
  }
}

module.exports = {
  SecurityStateEngine,
  SECURITY_EVENTS,
  IDENTITY_INTEGRITY,
  TRUST_LEVEL,
  SESSION_HEALTH,
  ENVIRONMENT_RISK,
};
