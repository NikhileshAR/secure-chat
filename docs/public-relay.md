# Public Relay Readiness

This guide is for running a relay that remote users can actually reach.

## 1) Use a public network path

Your relay must be reachable from outside your home/local network.
Use one of:

- a VPS/cloud server with a public IP
- a machine with a public IP + router port forwarding

If your relay only listens on `127.0.0.1`, remote users cannot connect.

## 2) Open the relay port

Default relay port is `8080`.

Make sure this port is open in:

- cloud firewall/security groups
- host firewall (ufw/iptables/windows firewall)
- router forwarding rules (if hosted at home)

## 3) CGNAT limitation (important)

If your ISP uses CGNAT, inbound connections from the internet usually do **not** reach your home router.
In that case, normal port-forwarding will not work.

Simple fix: run relay on a VPS/public cloud instance instead.

## 4) `publicUrl` in relay config

You can now set an optional `publicUrl` in `relay.config.json`:

```json
{
  "host": "0.0.0.0",
  "port": 8080,
  "publicUrl": "ws://relay.example.com:8080"
}
```

When provided, client bundle generation and app import should use `publicUrl` instead of local addresses.

## 5) Client connection behavior

Client config can include multiple relay URLs:

- `relayUrl` (primary)
- `relayUrls` (failover list)

The demo app stores multiple relays and attempts the next one if the current relay fails.
