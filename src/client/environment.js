const { randomBytes } = require('node:crypto');
const { monitorEventLoopDelay } = require('node:perf_hooks');

const ENVIRONMENT_RISK = {
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
};

const loopLagMonitor = monitorEventLoopDelay({ resolution: 20 });
loopLagMonitor.enable();
const baselineWallClockMs = Date.now();
const baselineHighResMs = Number(process.hrtime.bigint() / 1_000_000n);

const state = {
  processingDurationsMs: [],
  maxSamples: 64,
};

function isDebugMode() {
  return process.env.NODE_ENV !== 'production'
    || process.env.SECURECHAT_DEBUG === '1'
    || process.execArgv.some((arg) => arg.includes('--inspect') || arg.includes('--debug'));
}

function hasHighClockSkew() {
  const wallElapsed = Date.now() - baselineWallClockMs;
  const hrElapsed = Number(process.hrtime.bigint() / 1_000_000n) - baselineHighResMs;
  return Math.abs(wallElapsed - hrElapsed) > 120_000;
}

function hasExcessiveEventLoopLag() {
  const p99Ms = Number(loopLagMonitor.percentile(99)) / 1e6;
  return Number.isFinite(p99Ms) && p99Ms > 250;
}

function hasSuspiciouslyFastProcessing() {
  if (state.processingDurationsMs.length < 12) {
    return false;
  }
  const avg = state.processingDurationsMs.reduce((sum, value) => sum + value, 0) / state.processingDurationsMs.length;
  return avg >= 0 && avg < 0.1;
}

function hasLowEntropyRandomness() {
  const sample = randomBytes(64);
  const unique = new Set(sample.values()).size;
  return unique < 8;
}

function observeMessageProcessingDuration(durationMs) {
  const value = Number(durationMs);
  if (!Number.isFinite(value) || value < 0) {
    return;
  }
  state.processingDurationsMs.push(value);
  if (state.processingDurationsMs.length > state.maxSamples) {
    state.processingDurationsMs.splice(0, state.processingDurationsMs.length - state.maxSamples);
  }
}

function evaluateEnvironmentSignals() {
  const reasons = [];
  if (isDebugMode()) {
    reasons.push('debug_mode_detected');
  }
  if (hasHighClockSkew()) {
    reasons.push('high_clock_skew');
  }
  if (hasExcessiveEventLoopLag()) {
    reasons.push('high_event_loop_lag');
  }
  if (hasSuspiciouslyFastProcessing()) {
    reasons.push('suspiciously_fast_processing');
  }
  if (hasLowEntropyRandomness()) {
    reasons.push('low_entropy_randomness');
  }
  return reasons;
}

function getEnvironmentRisk() {
  const reasons = evaluateEnvironmentSignals();
  const severe = reasons.includes('high_clock_skew')
    || reasons.includes('high_event_loop_lag')
    || reasons.includes('low_entropy_randomness');
  if (severe || reasons.length >= 3) {
    return ENVIRONMENT_RISK.HIGH;
  }
  if (reasons.length >= 1) {
    return ENVIRONMENT_RISK.MEDIUM;
  }
  return ENVIRONMENT_RISK.LOW;
}

module.exports = {
  ENVIRONMENT_RISK,
  getEnvironmentRisk,
  observeMessageProcessingDuration,
  evaluateEnvironmentSignals,
};
