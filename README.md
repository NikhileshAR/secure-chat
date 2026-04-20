# sekure

Privacy-first self-hosted communication baseline implementation.

## Features currently implemented

- Stateless WebSocket relay server (`src/server/relayServer.js`)
- Client identity generation and rotation (`src/client/identity.js`)
- End-to-end payload encryption/decryption helpers (`src/client/crypto.js`)
- Client handshake + encrypted chat + routeTag pull flow (`src/client/client.js`)
- RouteTag-based ephemeral relay buffering with TTL expiry

## Run relay server

```bash
npm install
npm run start:server
```

Config via env vars:

- `SEKURE_RELAY_HOST` (default `0.0.0.0`)
- `SEKURE_RELAY_PORT` (default `8080`)
- `SEKURE_RELAY_TTL_MS` (default `60000`)

## Run tests

```bash
npm test
```
