#!/usr/bin/env node
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { NetworkIdentityManager } = require('../src/server/networkIdentity');

function main() {
  const cwd = process.cwd();
  const deployDir = path.join(cwd, 'deploy');
  const relayConfigPath = path.join(deployDir, 'relay-config.json');
  const outputPath = path.join(deployDir, 'client-config.json');
  if (!fs.existsSync(relayConfigPath)) {
    throw new Error(`Missing relay config: ${relayConfigPath}`);
  }
  const relayConfig = JSON.parse(fs.readFileSync(relayConfigPath, 'utf8'));
  const relayDataDir = relayConfig.relayDataDir || process.env.SECURE_RELAY_IDENTITY_DIR || path.join(os.homedir(), '.secure-chat-relay');
  const identityManager = new NetworkIdentityManager({ storageDir: relayDataDir });
  const identity = identityManager.getNetworkIdentity();

  const bundle = {
    relayUrl: relayConfig.relayUrl || `ws://${relayConfig.host || '127.0.0.1'}:${relayConfig.port || 8080}`,
    networkId: identity.networkId,
    networkPublicKey: identity.networkPublicKey,
    accessMode: relayConfig.accessMode || 'OPEN',
  };

  fs.mkdirSync(deployDir, { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(bundle, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${outputPath}\n`);
}

try {
  main();
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
