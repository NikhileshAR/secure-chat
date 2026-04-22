#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');

const TINY_PNG_BASE64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO7+3NwAAAAASUVORK5CYII=';

function parseArgs(argv = process.argv.slice(2)) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token.startsWith('--')) {
      args[token.slice(2)] = argv[i + 1];
      i += 1;
    }
  }
  return args;
}

function uniqueUrls(urls = []) {
  return [...new Set(urls.map((url) => String(url || '').trim()).filter(Boolean))];
}

function generateClientBundle({
  relayUrl,
  publicUrl,
  relayUrls = [],
  relayId,
  outDir = path.resolve(process.cwd(), 'bundle'),
}) {
  const mergedRelayUrls = uniqueUrls([publicUrl, relayUrl, ...relayUrls]);
  if (!mergedRelayUrls.length) {
    throw new Error('At least one relay URL is required');
  }

  fs.mkdirSync(outDir, { recursive: true });
  const config = {
    relayUrl: mergedRelayUrls[0],
    publicUrl: publicUrl ? String(publicUrl).trim() : undefined,
    relayUrls: mergedRelayUrls,
    relayId: relayId || 'unknown',
    securityDefaults: {
      opsecMode: 'HARDENED',
      strictWireMode: true,
      ephemeralMode: true,
    },
  };

  fs.writeFileSync(path.join(outDir, 'client-config.json'), `${JSON.stringify(config, null, 2)}\n`, 'utf8');
  fs.writeFileSync(path.join(outDir, 'connect-instructions.txt'), [
    'Secure Chat Relay Connection',
    `Relay URL: ${config.relayUrl}`,
    ...(config.publicUrl ? [`Public URL: ${config.publicUrl}`] : []),
    `Relay failover URLs: ${config.relayUrls.join(', ')}`,
    `Relay ID: ${config.relayId}`,
    'Import client-config.json in your client and keep OPSEC mode set to HARDENED.',
  ].join('\n'), 'utf8');
  fs.writeFileSync(path.join(outDir, 'qr.png'), Buffer.from(TINY_PNG_BASE64, 'base64'));
  return config;
}

if (require.main === module) {
  const args = parseArgs();
  const config = generateClientBundle({
    relayUrl: args.relayUrl,
    publicUrl: args.publicUrl,
    relayUrls: args.relayUrls ? args.relayUrls.split(',').map((value) => value.trim()).filter(Boolean) : [],
    relayId: args.relayId,
    outDir: args.outDir && path.resolve(args.outDir),
  });
  console.log(`Bundle created at ${path.resolve(args.outDir || 'bundle')}`);
  console.log(JSON.stringify(config));
}

module.exports = {
  generateClientBundle,
  parseArgs,
  uniqueUrls,
};
