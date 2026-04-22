# Self-hosting the Secure Chat Relay

## Run a relay

1. Install dependencies:
   - `npm install`
2. Generate config and start interactively:
   - `node deploy/setup.js`

Or start directly from a config file:

- `node deploy/start-relay.js --config relay.config.json`

For public internet deployment guidance (public IP, firewall ports, CGNAT, `publicUrl`), see:

- `docs/public-relay.md`

## What the relay can see

A relay can see:

- connection timing
- message sizes
- route-tag traffic patterns
- aggregate counts (if metrics are enabled)

A relay cannot decrypt chat contents when clients are configured correctly.

## What the relay cannot see

The relay does not have client private keys and does not decrypt encrypted payloads.
It only forwards encrypted data and short-lived route-tag buffers.

## Hosting risks (honest summary)

Self-hosting reduces central trust but does not remove all metadata risk.
Operators still control network infrastructure and can observe traffic flow patterns.
Compromised hosts, weak OS security, poor key handling, and unsafe client settings can still expose users.

## Why trust is still minimized

- There is no mandatory global relay directory.
- Clients can keep local relay lists and rotate relays.
- Relay memory mode is ephemeral by default (no message disk persistence).
- Client HARDENED OPSEC mode enforces stricter behavior for risky actions.
