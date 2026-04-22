# secure-chat

Privacy-first self-hosted communication baseline implementation.

## Features currently implemented

- Stateless WebSocket relay server (`src/server/relayServer.js`)
- Client identity generation and rotation (`src/client/identity.js`)
- End-to-end payload encryption/decryption helpers (`src/client/crypto.js`)
- Client handshake + encrypted chat + routeTag pull flow (`src/client/client.js`)
- RouteTag-based ephemeral relay buffering with TTL expiry
- Strict protocol schema + versioning validation (`src/protocol/schema.js`)
- Encrypted session persistence and key vault storage (`src/client/storage/*`)
- Multi-device registry linking and ACK-aware delivery retries

## Run relay server

```bash
npm install
npm run start:server
```

## Run minimal demo client app

```bash
npm install
npm run start:app
```

Then open `http://127.0.0.1:8787`.
Use the connection screen to import `client-config.json` or enter a relay URL.

Config via env vars:

- `SECURE_RELAY_HOST` (default `0.0.0.0`, falls back to `SEKURE_RELAY_HOST`)
- `SECURE_RELAY_PORT` (default `8080`, falls back to `SEKURE_RELAY_PORT`)
- `SECURE_RELAY_TTL_MS` (default `60000`, falls back to `SEKURE_RELAY_TTL_MS`)

## Run tests

```bash
npm test
```

## Deployment docs

- `docs/self-hosting.md`
- `docs/public-relay.md`
- `docs/demo-flow.md`
