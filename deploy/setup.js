#!/usr/bin/env node
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline/promises');
const { stdin, stdout } = require('node:process');
const { fork } = require('node:child_process');

const { NetworkIdentityManager } = require('../src/server/networkIdentity');

function printPseudoQr(value) {
  const bytes = Buffer.from(String(value), 'utf8');
  const size = 21;
  let cursor = 0;
  const rows = [];
  for (let y = 0; y < size; y += 1) {
    let row = '';
    for (let x = 0; x < size; x += 1) {
      const bit = ((bytes[cursor % bytes.length] || 0) >> (cursor % 8)) & 1;
      row += bit ? '██' : '  ';
      cursor += 1;
    }
    rows.push(row);
  }
  return rows.join('\n');
}

async function main() {
  const rl = readline.createInterface({ input: stdin, output: stdout });
  try {
    const host = (await rl.question('Relay host [0.0.0.0]: ')).trim() || '0.0.0.0';
    const portInput = (await rl.question('Relay port [8080]: ')).trim() || '8080';
    const modeInput = (await rl.question('Access mode OPEN/INVITE_ONLY [OPEN]: ')).trim().toUpperCase() || 'OPEN';
    const accessMode = modeInput === 'INVITE_ONLY' ? 'INVITE_ONLY' : 'OPEN';
    const port = Number(portInput) || 8080;

    const deployDir = path.join(process.cwd(), 'deploy');
    const relayDataDir = path.join(os.homedir(), '.secure-chat-relay');
    fs.mkdirSync(deployDir, { recursive: true });
    fs.mkdirSync(relayDataDir, { recursive: true });

    const identityManager = new NetworkIdentityManager({ storageDir: relayDataDir });
    const identity = identityManager.getNetworkIdentity();
    const relayUrl = `ws://${host === '0.0.0.0' ? '127.0.0.1' : host}:${port}`;
    const configPath = path.join(deployDir, 'relay-config.json');
    fs.writeFileSync(configPath, `${JSON.stringify({
      host,
      port,
      accessMode,
      relayDataDir,
      relayUrl,
    }, null, 2)}\n`, { mode: 0o600 });

    const child = fork(path.join(process.cwd(), 'src/server/relayServer.js'), [], {
      detached: true,
      stdio: 'ignore',
      env: {
        ...process.env,
        SECURE_RELAY_HOST: host,
        SECURE_RELAY_PORT: String(port),
        SECURE_RELAY_ACCESS_MODE: accessMode,
        SECURE_RELAY_IDENTITY_DIR: relayDataDir,
      },
    });
    child.unref();

    const qrPayload = JSON.stringify({
      relayUrl,
      networkId: identity.networkId,
      networkPublicKey: identity.networkPublicKey,
      accessMode,
    });

    stdout.write('\nSystem check: OK\n');
    stdout.write(`Relay URL: ${relayUrl}\n`);
    stdout.write(`Network ID: ${identity.networkId}\n`);
    stdout.write('QR code:\n');
    stdout.write(`${printPseudoQr(qrPayload)}\n`);
  } finally {
    rl.close();
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
