#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline/promises');
const { stdin, stdout } = require('node:process');
const { randomBytes, createHash } = require('node:crypto');
const { runSystemCheck } = require('./systemCheck');
const { startRelay } = require('./start-relay');

function asciiQr(seed) {
  const hash = createHash('sha256').update(seed).digest();
  const rows = [];
  for (let y = 0; y < 12; y += 1) {
    let row = '';
    for (let x = 0; x < 12; x += 1) {
      const bit = hash[(x + y) % hash.length] & (1 << (x % 8));
      row += bit ? '██' : '  ';
    }
    rows.push(row);
  }
  return rows.join('\n');
}

function buildSetupConfig({
  port = 8080,
  maxConnections = 1000,
  logLevel = 'minimal',
  securityProfile = 'BALANCED',
  publicUrl = '',
} = {}) {
  const normalizedProfile = String(securityProfile || 'BALANCED').toUpperCase();
  return {
    host: '0.0.0.0',
    port: Number(port),
    publicUrl: String(publicUrl || '').trim(),
    maxConnections: Number(maxConnections),
    maxBufferedBytes: 512 * 1024,
    maxMessageSizeBytes: 64 * 1024,
    rateLimits: {
      connection: { windowMs: 1_000, maxMessages: normalizedProfile === 'MAX' ? 200 : 300 },
      device: { windowMs: 1_000, maxMessages: normalizedProfile === 'MAX' ? 80 : 120 },
      routeTag: { windowMs: 1_000, maxMessages: normalizedProfile === 'MAX' ? 150 : 200 },
    },
    relayBatchSize: 50,
    shuffleDelivery: true,
    logLevel,
    enableMetrics: true,
    ephemeralMode: true,
    strictWireMode: true,
    securityProfile: normalizedProfile,
  };
}

async function promptConfig() {
  const rl = readline.createInterface({ input: stdin, output: stdout });
  const port = Number((await rl.question('Port (default 8080): ')).trim() || '8080');
  const maxConnections = Number((await rl.question('Max connections (default 1000): ')).trim() || '1000');
  const logLevel = (await rl.question('Log level (minimal|debug, default minimal): ')).trim() || 'minimal';
  const securityProfile = ((await rl.question('Security profile (MAX|BALANCED, default BALANCED): ')).trim() || 'BALANCED').toUpperCase();
  const publicUrl = (await rl.question('Public relay URL for clients (optional, e.g. ws://example.com:8080): ')).trim();
  await rl.close();

  return buildSetupConfig({ port, maxConnections, logLevel, securityProfile, publicUrl });
}

async function main() {
  const check = runSystemCheck();
  if (!check.ok) {
    console.error('Unsafe environment.');
    for (const failure of check.failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
  }

  const config = await promptConfig();
  const configPath = path.resolve(process.cwd(), 'relay.config.json');
  fs.writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });

  const { server, relayId } = startRelay(config, { skipSystemCheck: true, printBanner: false });
  const localUrl = `ws://127.0.0.1:${config.port}`;
  const advertisedUrl = config.publicUrl || localUrl;
  const token = randomBytes(8).toString('hex');

  console.log('Your private relay is running');
  console.log(`Local access URL: ${localUrl}`);
  if (config.publicUrl) {
    console.log(`Public access URL: ${config.publicUrl}`);
  }
  console.log(`Relay ID: ${relayId}`);
  console.log('Scan/share this connection token (ASCII QR):');
  console.log(asciiQr(`${advertisedUrl}|${relayId}|${token}`));
  console.log('Connection steps for users:');
  console.log(`1) Open client settings\n2) Add relay URL: ${advertisedUrl}\n3) Enable HARDENED OPSEC mode`);
  console.log('Warning: This system does not allow you to read messages. It only relays encrypted data.');

  process.on('SIGINT', () => {
    server.stop();
    process.exit(0);
  });
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}

module.exports = {
  promptConfig,
  buildSetupConfig,
};
