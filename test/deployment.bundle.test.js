const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { buildSetupConfig } = require('../deploy/setup');
const { generateClientBundle } = require('../deploy/generateClientBundle');
const { renderHtml } = require('../deploy/dashboard');

test('setup config builder generates safe defaults', () => {
  const config = buildSetupConfig({
    port: 8081,
    maxConnections: 250,
    logLevel: 'minimal',
    securityProfile: 'MAX',
  });

  assert.equal(config.port, 8081);
  assert.equal(config.maxConnections, 250);
  assert.equal(config.ephemeralMode, true);
  assert.equal(config.strictWireMode, true);
  assert.equal(config.securityProfile, 'MAX');
});

test('docker deployment configuration is valid', () => {
  const repoRoot = path.resolve(__dirname, '..');
  const dockerfile = fs.readFileSync(path.join(repoRoot, 'deploy', 'Dockerfile'), 'utf8');
  const compose = fs.readFileSync(path.join(repoRoot, 'docker-compose.yml'), 'utf8');

  assert.match(dockerfile, /EPHEMERAL_MODE=true/);
  assert.match(compose, /restart:\s*unless-stopped/);
  assert.match(compose, /dockerfile:\s*deploy\/Dockerfile/);

  const dockerCheck = spawnSync('docker', ['compose', '-f', path.join(repoRoot, 'docker-compose.yml'), 'config'], {
    encoding: 'utf8',
  });
  if (dockerCheck.error && dockerCheck.error.code === 'ENOENT') {
    return;
  }
  assert.equal(dockerCheck.status, 0, dockerCheck.stderr || dockerCheck.stdout);
});

test('client bundle generation outputs required fields and files', () => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'securechat-bundle-'));
  const config = generateClientBundle({
    relayUrl: 'ws://127.0.0.1:8080',
    relayId: 'relay-123',
    outDir,
  });

  const configPath = path.join(outDir, 'client-config.json');
  const instructionsPath = path.join(outDir, 'connect-instructions.txt');
  const qrPath = path.join(outDir, 'qr.png');

  assert.equal(fs.existsSync(configPath), true);
  assert.equal(fs.existsSync(instructionsPath), true);
  assert.equal(fs.existsSync(qrPath), true);
  assert.equal(config.relayUrl, 'ws://127.0.0.1:8080');
  assert.equal(config.relayId, 'relay-123');
  assert.equal(config.securityDefaults.strictWireMode, true);

  fs.rmSync(outDir, { recursive: true, force: true });
});

test('dashboard output contains only aggregate safe metrics', () => {
  const html = renderHtml({
    activeConnections: 12,
    relayedMessages: 333,
    uptimeMs: 9999,
  }, 'HEALTHY');

  assert.match(html, /Active connections:\s*12/);
  assert.match(html, /Messages relayed:\s*333/);
  assert.equal(html.includes('ciphertext'), false);
  assert.equal(html.includes('PRIVATE KEY'), false);
  assert.equal(html.includes('device-abc'), false);
});
