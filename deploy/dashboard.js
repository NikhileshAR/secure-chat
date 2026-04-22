#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { loadConfig, startRelay } = require('./start-relay');
const { runSystemCheck } = require('./systemCheck');

function renderHtml(metrics, health) {
  return `<!doctype html>
<html>
<head><meta charset="utf-8"><title>Secure Relay Dashboard</title></head>
<body>
  <h1>Secure Relay Dashboard (Local Only)</h1>
  <ul>
    <li>Active connections: ${metrics.activeConnections}</li>
    <li>Messages relayed: ${metrics.relayedMessages}</li>
    <li>Uptime (ms): ${metrics.uptimeMs}</li>
    <li>System health: ${health}</li>
  </ul>
  <p>No message content, identities, or user logs are stored or shown.</p>
</body>
</html>`;
}

function startDashboard({ configPath = path.resolve(process.cwd(), 'relay.config.json'), port = 8787 } = {}) {
  const config = fs.existsSync(configPath)
    ? loadConfig(configPath)
    : loadConfig(path.resolve(__dirname, 'relay.config.example.json'));
  const { server: relay } = startRelay(config);

  const dashboard = http.createServer((req, res) => {
    const metrics = relay.getMetrics();
    const check = runSystemCheck();
    const health = check.ok ? 'HEALTHY' : 'DEGRADED';
    if (req.url === '/metrics') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        activeConnections: metrics.activeConnections,
        relayedMessages: metrics.relayedMessages,
        uptimeMs: metrics.uptimeMs,
        health,
      }));
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(renderHtml(metrics, health));
  });

  dashboard.listen(port, '127.0.0.1');
  console.log(`Dashboard listening on http://127.0.0.1:${port}`);

  process.on('SIGINT', () => {
    dashboard.close();
    relay.stop();
    process.exit(0);
  });

  return { dashboard, relay };
}

if (require.main === module) {
  startDashboard();
}

module.exports = {
  startDashboard,
  renderHtml,
};
