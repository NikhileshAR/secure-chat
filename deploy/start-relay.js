#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const { RelayServer } = require('../src/server/relayServer');
const { runSystemCheck } = require('./systemCheck');

function parseArgs(argv = process.argv.slice(2)) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--config') {
      args.config = argv[i + 1];
      i += 1;
    }
  }
  return args;
}

function asBoolean(value, fallback) {
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'string') {
    if (value.toLowerCase() === 'true') return true;
    if (value.toLowerCase() === 'false') return false;
  }
  return fallback;
}

function loadConfig(configPath) {
  const resolved = path.resolve(configPath || 'relay.config.json');
  const raw = fs.readFileSync(resolved, 'utf8');
  const fromFile = JSON.parse(raw);

  return {
    ...fromFile,
    port: Number(process.env.RELAY_PORT || fromFile.port || 8080),
    maxConnections: Number(process.env.MAX_CONNECTIONS || fromFile.maxConnections || 1000),
    maxBufferedBytes: Number(process.env.MAX_BUFFERED_BYTES || fromFile.maxBufferedBytes || 512 * 1024),
    maxMessageSizeBytes: Number(process.env.MAX_MESSAGE_SIZE_BYTES || fromFile.maxMessageSizeBytes || 64 * 1024),
    ephemeralMode: asBoolean(process.env.EPHEMERAL_MODE, fromFile.ephemeralMode !== false),
    enableMetrics: asBoolean(process.env.ENABLE_METRICS, Boolean(fromFile.enableMetrics)),
    logLevel: process.env.LOG_LEVEL || fromFile.logLevel || 'minimal',
  };
}

function assertSafeConfig(config) {
  const profile = String(config.securityProfile || 'BALANCED').toUpperCase();
  const strictWireMode = config.strictWireMode !== false;
  if (profile === 'MAX' && !config.ephemeralMode) {
    throw new Error('Unsafe config: MAX profile requires ephemeralMode=true');
  }
  if (profile === 'MAX' && !strictWireMode) {
    throw new Error('Unsafe config: MAX profile requires strictWireMode=true');
  }
}

function buildRelayOptions(config) {
  return {
    host: config.host || '0.0.0.0',
    port: config.port,
    maxConcurrentConnections: config.maxConnections,
    maxBufferedBytes: config.maxBufferedBytes,
    maxMessageSizeBytes: config.maxMessageSizeBytes,
    perDeviceRateLimit: config.rateLimits?.device,
    perRouteTagRateLimit: config.rateLimits?.routeTag,
    connectionRateLimit: config.rateLimits?.connection,
    relayBatchSize: config.relayBatchSize,
    shuffleDelivery: config.shuffleDelivery,
    logLevel: config.logLevel,
    enableMetrics: config.enableMetrics,
    ephemeralMode: config.ephemeralMode !== false,
  };
}

function printStatus(server, relayId) {
  const metrics = server.getMetrics();
  console.log(`[relay] id=${relayId} uptimeMs=${metrics.uptimeMs} connections=${metrics.activeConnections}`);
}

function startRelay(config, { skipSystemCheck = false, printBanner = true } = {}) {
  if (!skipSystemCheck) {
    const check = runSystemCheck();
    if (!check.ok) {
      throw new Error(`System check failed: ${check.failures.join('; ')}`);
    }
  }

  assertSafeConfig(config);
  const relayId = randomBytes(16).toString('hex');
  const server = new RelayServer(buildRelayOptions(config));
  server.relayId = relayId;
  server.start();

  if (printBanner) {
    console.log(`Relay started on ws://${config.host || '0.0.0.0'}:${config.port}`);
    printStatus(server, relayId);
  }

  return { server, relayId };
}

if (require.main === module) {
  const args = parseArgs();
  try {
    const config = loadConfig(args.config || 'relay.config.json');
    const { server, relayId } = startRelay(config);
    const statusTimer = setInterval(() => printStatus(server, relayId), 30_000);

    process.on('SIGINT', () => {
      clearInterval(statusTimer);
      server.stop();
      console.log('Relay shut down gracefully.');
      process.exit(0);
    });
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

module.exports = {
  parseArgs,
  loadConfig,
  startRelay,
  assertSafeConfig,
};
