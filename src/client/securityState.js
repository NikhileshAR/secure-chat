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

function nowTs() {
  return Date.now();
}

class SecurityState {
  constructor(initial = {}) {
    this.state = {
      identityIntegrity: IDENTITY_INTEGRITY.UNVERIFIED,
      trustLevel: TRUST_LEVEL.UNKNOWN,
      sessionHealth: SESSION_HEALTH.HEALTHY,
      environmentRisk: ENVIRONMENT_RISK.LOW,
      lastSecurityEvent: nowTs(),
      ...initial,
    };
    this.listeners = new Set();
  }

  updateState(event = {}) {
    const normalized = typeof event === 'string' ? { type: event } : event;
    const type = normalized.type || 'generic';
    const next = { ...this.state };

    if (normalized.identityIntegrity) {
      next.identityIntegrity = normalized.identityIntegrity;
    }
    if (normalized.trustLevel) {
      next.trustLevel = normalized.trustLevel;
    }
    if (normalized.sessionHealth) {
      next.sessionHealth = normalized.sessionHealth;
    }
    if (normalized.environmentRisk) {
      next.environmentRisk = normalized.environmentRisk;
    }

    switch (type) {
      case 'identity_key_change_detected':
        next.identityIntegrity = IDENTITY_INTEGRITY.CHANGED;
        break;
      case 'identity_verified':
        next.identityIntegrity = IDENTITY_INTEGRITY.OK;
        next.trustLevel = TRUST_LEVEL.VERIFIED;
        break;
      case 'trust_downgrade':
        next.trustLevel = normalized.to || TRUST_LEVEL.UNKNOWN;
        next.identityIntegrity = IDENTITY_INTEGRITY.UNVERIFIED;
        break;
      case 'trust_blocked':
        next.trustLevel = TRUST_LEVEL.BLOCKED;
        break;
      case 'repeated_message_failures':
      case 'excessive_replay_attempts':
      case 'high_dropped_message_rate':
        next.sessionHealth = SESSION_HEALTH.SUSPECT;
        next.environmentRisk = ENVIRONMENT_RISK.HIGH;
        break;
      case 'abnormal_counter_gaps':
        next.sessionHealth = SESSION_HEALTH.DESYNC;
        next.environmentRisk = ENVIRONMENT_RISK.MEDIUM;
        break;
      case 'state_stabilized':
        next.sessionHealth = SESSION_HEALTH.HEALTHY;
        if (next.environmentRisk !== ENVIRONMENT_RISK.HIGH) {
          next.environmentRisk = ENVIRONMENT_RISK.LOW;
        }
        if (next.trustLevel === TRUST_LEVEL.VERIFIED) {
          next.identityIntegrity = IDENTITY_INTEGRITY.OK;
        }
        break;
      case 'safe_mode_triggered':
        next.environmentRisk = ENVIRONMENT_RISK.HIGH;
        next.sessionHealth = SESSION_HEALTH.SUSPECT;
        break;
      case 'manual_resume':
        next.sessionHealth = SESSION_HEALTH.HEALTHY;
        next.environmentRisk = ENVIRONMENT_RISK.MEDIUM;
        break;
      default:
        break;
    }

    next.lastSecurityEvent = normalized.timestamp || nowTs();
    this.state = next;
    for (const listener of this.listeners) {
      listener({ ...this.state }, normalized);
    }
    return { ...this.state };
  }

  getCurrentState() {
    return { ...this.state };
  }

  subscribe(callback) {
    if (typeof callback !== 'function') {
      throw new Error('SecurityState subscribe callback must be a function');
    }
    this.listeners.add(callback);
    return () => this.listeners.delete(callback);
  }
}

module.exports = {
  SecurityState,
  IDENTITY_INTEGRITY,
  TRUST_LEVEL,
  SESSION_HEALTH,
  ENVIRONMENT_RISK,
};
