const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { SecureClient } = require('../src/client/client');
const { generateIdentity } = require('../src/client/identity');

function createClient(identity, options = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'securechat-operational-'));
  const client = new SecureClient({
    serverUrl: 'ws://127.0.0.1:1',
    identity,
    sendDelayRangeMs: { min: 0, max: 0 },
    batchingWindowMs: 0,
    parallelRouteTags: 1,
    coverTrafficIntervalRangeMs: { min: 60_000, max: 60_000 },
    rateShaping: { minMessagesPerSecond: 1, maxMessagesPerSecond: 5 },
    trustStoreStorageDir: dir,
    deviceSecret: 'test-device-secret',
    ...options,
  });
  client.sendRaw = () => {};
  client.__tmpDir = dir;
  return client;
}

test('unsafe production config fails closed at startup', () => {
  const identity = generateIdentity();
  assert.throws(() => {
    createClient(identity, {
      productionMode: true,
      securityProfile: 'BALANCED',
      constantTrafficEnabled: false,
      strictWireMode: false,
      pullNoiseLevel: 0,
      paddingSizeBuckets: [],
    });
  }, /Unsafe client configuration/i);
});

test('HIGH environment risk updates security state and triggers safe mode', () => {
  const identity = generateIdentity();
  const client = createClient(identity, {
    securityProfile: 'MAX',
    environmentRiskEvaluator: () => 'HIGH',
  });

  const state = client.getCurrentSecurityState();
  assert.equal(state.environmentRisk, 'HIGH');
  assert.equal(client.safeMode, true);
});

test('sensitive actions require explicit confirmation', () => {
  const client = createClient(generateIdentity(), { securityProfile: 'DEV', strictWireMode: false, pullNoiseLevel: 0 });
  const peer = generateIdentity();

  assert.throws(() => {
    client.verifyIdentity(peer.identityKeyPair.publicKey);
  }, /confirmation required/i);

  assert.doesNotThrow(() => {
    client.verifyIdentity(peer.identityKeyPair.publicKey, { confirmed: true });
  });

  client.blockIdentity(peer.identityKeyPair.publicKey);
  assert.throws(() => {
    client.unblockIdentity(peer.identityKeyPair.publicKey);
  }, /confirmation required/i);
  assert.doesNotThrow(() => {
    client.unblockIdentity(peer.identityKeyPair.publicKey, { confirmed: true });
  });

  assert.throws(() => {
    client.setStrictWireMode(false, { confirmed: false });
  }, /confirmation required/i);
});

test('security profiles enforce expected defaults', () => {
  assert.throws(() => {
    createClient(generateIdentity(), {
      securityProfile: 'MAX',
      strictWireMode: false,
      constantTrafficEnabled: true,
    });
  }, /Unsafe client configuration/i);

  const maxClient = createClient(generateIdentity(), {
    securityProfile: 'MAX',
    strictWireMode: true,
    constantTrafficEnabled: true,
  });
  assert.equal(maxClient.strictWireMode, true);
  assert.equal(maxClient.constantTrafficEnabled, true);

  const devClient = createClient(generateIdentity(), {
    securityProfile: 'DEV',
    strictWireMode: false,
    pullNoiseLevel: 0,
    constantTrafficEnabled: false,
  });
  assert.equal(devClient.strictWireMode, false);
  assert.equal(devClient.pullNoiseLevel, 0);
  const warnings = devClient.securityLog.getEntries().filter((entry) => entry.type === 'config_warning');
  assert.ok(warnings.length > 0);
});

test('security summary reports safety reasons and recommendations', () => {
  const client = createClient(generateIdentity(), {
    securityProfile: 'DEV',
    strictWireMode: false,
    constantTrafficEnabled: false,
    environmentRiskEvaluator: () => 'HIGH',
  });

  const summary = client.getSecuritySummary();
  assert.equal(summary.overallSafety, 'DANGER');
  assert.ok(summary.reasons.some((reason) => /Constant traffic disabled/i.test(reason)));
  assert.ok(summary.reasons.some((reason) => /environment risk/i.test(reason)));
  assert.ok(summary.recommendations.length > 0);
});

test('auto escalation enters safe mode after warning combinations', () => {
  const client = createClient(generateIdentity(), {
    securityProfile: 'DEV',
    environmentRiskEvaluator: () => 'LOW',
  });

  client.updateSecurityState({ environmentRisk: 'HIGH' });
  client.registerOperationalWarning('signature_failures', 'high');
  client.evaluateSafetyEscalation();

  assert.equal(client.safeMode, true);
});

test('config fingerprint is stable and detects security config changes', () => {
  const one = createClient(generateIdentity(), {
    securityProfile: 'BALANCED',
    pullNoiseLevel: 3,
    constantTrafficEnabled: false,
  });
  const two = createClient(generateIdentity(), {
    securityProfile: 'BALANCED',
    pullNoiseLevel: 3,
    constantTrafficEnabled: false,
  });
  const three = createClient(generateIdentity(), {
    securityProfile: 'BALANCED',
    pullNoiseLevel: 7,
    constantTrafficEnabled: false,
  });

  assert.equal(one.getConfigFingerprint(), two.getConfigFingerprint());
  assert.notEqual(one.getConfigFingerprint(), three.getConfigFingerprint());
});
