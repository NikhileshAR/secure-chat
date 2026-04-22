const os = require('node:os');
const { randomBytes } = require('node:crypto');

const MIN_NODE_MAJOR = 20;
const MIN_FREE_MEMORY_BYTES = 128 * 1024 * 1024;
const MAX_CLOCK_DRIFT_MS = 120_000;

function parseNodeMajor(version = process.versions.node) {
  return Number(String(version).split('.')[0]);
}

function checkEntropyAvailability() {
  try {
    const sample = randomBytes(64);
    const unique = new Set(sample.values()).size;
    return unique >= 8;
  } catch {
    return false;
  }
}

function checkClockSyncSanity() {
  const now = Date.now();
  if (!Number.isFinite(now) || now < 1577836800000) {
    return false;
  }
  const wallStart = Date.now();
  const hrStart = Number(process.hrtime.bigint() / 1_000_000n);
  const wallEnd = Date.now();
  const hrEnd = Number(process.hrtime.bigint() / 1_000_000n);
  const wallDelta = wallEnd - wallStart;
  const hrDelta = hrEnd - hrStart;
  if (!Number.isFinite(wallDelta) || !Number.isFinite(hrDelta) || wallDelta < 0 || hrDelta < 0) {
    return false;
  }
  return Math.abs(wallDelta - hrDelta) < Math.min(MAX_CLOCK_DRIFT_MS, 5_000);
}

function runSystemCheck() {
  const failures = [];
  const warnings = [];

  if (parseNodeMajor() < MIN_NODE_MAJOR) {
    failures.push(`Node.js >= ${MIN_NODE_MAJOR} is required`);
  }
  if (!checkEntropyAvailability()) {
    failures.push('Entropy source unavailable or low quality');
  }
  if (!checkClockSyncSanity()) {
    failures.push('Clock sync sanity check failed');
  }
  const free = os.freemem();
  if (free < MIN_FREE_MEMORY_BYTES) {
    failures.push('Insufficient free memory for safe relay operation');
  }
  if ((os.totalmem() / (1024 * 1024)) < 512) {
    warnings.push('Low total system memory may degrade reliability');
  }

  return {
    ok: failures.length === 0,
    failures,
    warnings,
    details: {
      nodeVersion: process.versions.node,
      freeMemoryBytes: free,
      totalMemoryBytes: os.totalmem(),
      platform: process.platform,
    },
  };
}

if (require.main === module) {
  const result = runSystemCheck();
  if (!result.ok) {
    console.error('System check failed:');
    for (const failure of result.failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
  }
  console.log('System check passed.');
  for (const warning of result.warnings) {
    console.log(`Warning: ${warning}`);
  }
}

module.exports = {
  runSystemCheck,
};
