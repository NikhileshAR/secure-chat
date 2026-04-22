const DEFAULT_SECURITY_PROFILE = 'BALANCED';
const SUPPORTED_SECURITY_PROFILES = new Set(['MAX', 'BALANCED', 'DEV']);
const DEFAULT_PADDING_BUCKETS = [256, 512, 1024, 4096];
const DEFAULT_PULL_NOISE_BY_PROFILE = {
  MAX: 8,
  BALANCED: 6,
  DEV: 1,
};
const MAX_RATE_SHAPING_BURST_RATIO_BY_PROFILE = {
  MAX: 8,
  BALANCED: 12,
  DEV: 50,
};

function asNumber(value, fallback) {
  const next = Number(value);
  return Number.isFinite(next) ? next : fallback;
}

function normalizePaddingBuckets(input) {
  if (!Array.isArray(input)) {
    return null;
  }
  return [...new Set(
    input
      .map((size) => Number(size))
      .filter((size) => Number.isInteger(size) && size > 8),
  )].sort((a, b) => a - b);
}

function detectProductionMode(config) {
  if (typeof config.productionMode === 'boolean') {
    return config.productionMode;
  }
  if (typeof config.mode === 'string') {
    return config.mode.toLowerCase() === 'production';
  }
  return process.env.NODE_ENV === 'production';
}

function applyProfileDefaults(config, profile) {
  const next = { ...config };
  if (profile === 'MAX') {
    next.strictWireMode = true;
    next.constantTrafficEnabled = true;
    next.rateShaping = {
      minMessagesPerSecond: Math.max(0.2, asNumber(config?.rateShaping?.minMessagesPerSecond, 0.2)),
      maxMessagesPerSecond: Math.min(4, asNumber(config?.rateShaping?.maxMessagesPerSecond, 4)),
    };
  } else if (profile === 'BALANCED') {
    next.rateShaping = {
      minMessagesPerSecond: Math.max(0.2, asNumber(config?.rateShaping?.minMessagesPerSecond, 0.2)),
      maxMessagesPerSecond: Math.max(3, asNumber(config?.rateShaping?.maxMessagesPerSecond, 5)),
    };
  }
  return next;
}

function validateConfig(config = {}) {
  const warnings = [];
  const criticalViolations = [];

  const normalizedProfile = typeof config.securityProfile === 'string'
    ? config.securityProfile.toUpperCase()
    : DEFAULT_SECURITY_PROFILE;
  const securityProfile = SUPPORTED_SECURITY_PROFILES.has(normalizedProfile)
    ? normalizedProfile
    : DEFAULT_SECURITY_PROFILE;
  if (!SUPPORTED_SECURITY_PROFILES.has(normalizedProfile)) {
    warnings.push(`Unsupported securityProfile "${config.securityProfile}"; using ${DEFAULT_SECURITY_PROFILE}`);
  }

  const productionMode = detectProductionMode(config);
  let safeConfig = applyProfileDefaults({ ...config, securityProfile, productionMode }, securityProfile);

  const explicitStrictDisable = config.strictWireMode === false;
  if (typeof config.strictWireMode === 'undefined') {
    safeConfig.strictWireMode = true;
    warnings.push('strictWireMode defaulted to true');
  } else {
    safeConfig.strictWireMode = Boolean(config.strictWireMode);
  }
  if (explicitStrictDisable) {
    warnings.push('strictWireMode explicitly disabled');
    if (productionMode) {
      criticalViolations.push('strict mode off + production flag on');
    }
    if (securityProfile === 'MAX') {
      safeConfig.strictWireMode = true;
      criticalViolations.push('MAX profile requires strictWireMode');
    }
  }

  safeConfig.constantTrafficEnabled = Boolean(safeConfig.constantTrafficEnabled);
  if (productionMode && !safeConfig.constantTrafficEnabled) {
    criticalViolations.push('No cover traffic');
  }
  if (securityProfile === 'MAX' && !safeConfig.constantTrafficEnabled) {
    criticalViolations.push('MAX profile requires constant traffic');
  }

  const paddingBuckets = normalizePaddingBuckets(config.paddingSizeBuckets ?? DEFAULT_PADDING_BUCKETS);
  if (!paddingBuckets || !paddingBuckets.length) {
    criticalViolations.push('No padding');
    safeConfig.paddingSizeBuckets = [...DEFAULT_PADDING_BUCKETS];
  } else if (paddingBuckets.length < 3) {
    const expanded = [...new Set([...paddingBuckets, ...DEFAULT_PADDING_BUCKETS])].sort((a, b) => a - b).slice(0, 4);
    safeConfig.paddingSizeBuckets = expanded;
    warnings.push('paddingSizeBuckets had fewer than 3 sizes; expanded to safe defaults');
  } else {
    safeConfig.paddingSizeBuckets = paddingBuckets;
  }

  const defaultPullNoise = DEFAULT_PULL_NOISE_BY_PROFILE[securityProfile];
  const pullNoiseLevel = asNumber(config.pullNoiseLevel, defaultPullNoise);
  safeConfig.pullNoiseLevel = pullNoiseLevel;
  if (pullNoiseLevel <= 0) {
    if (securityProfile === 'DEV' && !productionMode) {
      warnings.push('pullNoiseLevel is zero in DEV profile');
    } else {
      safeConfig.pullNoiseLevel = defaultPullNoise;
      warnings.push(`pullNoiseLevel was non-positive; reset to ${defaultPullNoise}`);
    }
  }
  if (productionMode && pullNoiseLevel <= 0) {
    criticalViolations.push('disabled pull noise');
  }

  const minRate = Math.max(0.01, asNumber(safeConfig?.rateShaping?.minMessagesPerSecond, 0.2));
  const maxRateRaw = Math.max(minRate, asNumber(safeConfig?.rateShaping?.maxMessagesPerSecond, 5));
  const burstLimit = MAX_RATE_SHAPING_BURST_RATIO_BY_PROFILE[securityProfile] || 12;
  const maxRate = maxRateRaw > minRate * burstLimit
    ? minRate * burstLimit
    : maxRateRaw;
  if (maxRate !== maxRateRaw) {
    warnings.push(`rateShaping burst too high; capped to ${maxRate.toFixed(4)} msg/s`);
  }
  safeConfig.rateShaping = {
    minMessagesPerSecond: minRate,
    maxMessagesPerSecond: maxRate,
  };

  return {
    safeConfig,
    warnings,
    criticalViolations,
  };
}

module.exports = {
  validateConfig,
  DEFAULT_SECURITY_PROFILE,
  SUPPORTED_SECURITY_PROFILES: [...SUPPORTED_SECURITY_PROFILES],
};
