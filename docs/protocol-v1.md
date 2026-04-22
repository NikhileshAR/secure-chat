# Secure Chat Protocol v1.0

> Auto-generated from `src/protocol/spec.js`. Do not edit manually.

## Message formats

## handshake

- Required fields: `type`, `protocolVersion`, `senderDeviceId`, `timestamp`, `encryptedPayload`
- Optional fields: `identityPublicKey`, `devicePublicKey`, `deviceKeySignature`, `publicKeys`, `supportedVersions`

| Field | Type | Required | Max length/items |
|---|---|---|---|
| `type` | string | yes | - |
| `protocolVersion` | string | yes | - |
| `senderDeviceId` | string | yes | 512 |
| `timestamp` | number | yes | - |
| `encryptedPayload` | string | yes | - |
| `identityPublicKey` | string | no | - |
| `devicePublicKey` | string | no | - |
| `deviceKeySignature` | string | no | - |
| `publicKeys` | object | no | - |
| `supportedVersions` | array:string | no | 16 |

## chat

- Required fields: `type`, `protocolVersion`, `messageId`, `senderDeviceId`, `counter`, `previousCounter`, `dhPublicKey`, `routeTag`, `encryptedPayload`, `timestamp`, `signature`
- Optional fields: `targetDeviceId`, `targetDeviceIds`, `ackId`, `deliveredAt`

| Field | Type | Required | Max length/items |
|---|---|---|---|
| `type` | string | yes | - |
| `protocolVersion` | string | yes | - |
| `messageId` | string | yes | 512 |
| `senderDeviceId` | string | yes | 512 |
| `counter` | integer | yes | - |
| `previousCounter` | integer | yes | - |
| `dhPublicKey` | string | yes | 4096 |
| `routeTag` | string | yes | 4096 |
| `encryptedPayload` | string | yes | - |
| `timestamp` | number | yes | - |
| `signature` | string | yes | - |
| `targetDeviceId` | string | no | 512 |
| `targetDeviceIds` | array:string | no | 128 |
| `ackId` | string | no | 512 |
| `deliveredAt` | number | no | - |

## pull

- Required fields: `type`, `protocolVersion`, `senderDeviceId`, `timestamp`, `encryptedPayload`, `routeTags`
- Optional fields: None

| Field | Type | Required | Max length/items |
|---|---|---|---|
| `type` | string | yes | - |
| `protocolVersion` | string | yes | - |
| `senderDeviceId` | string | yes | 512 |
| `timestamp` | number | yes | - |
| `encryptedPayload` | string | yes | - |
| `routeTags` | array:string | yes | 2048 |

## deliver

- Required fields: `type`, `protocolVersion`, `senderDeviceId`, `timestamp`, `encryptedPayload`
- Optional fields: None

| Field | Type | Required | Max length/items |
|---|---|---|---|
| `type` | string | yes | - |
| `protocolVersion` | string | yes | - |
| `senderDeviceId` | string | yes | 512 |
| `timestamp` | number | yes | - |
| `encryptedPayload` | string | yes | - |

## ack

- Required fields: `type`, `protocolVersion`, `ackId`, `senderDeviceId`, `timestamp`, `encryptedPayload`
- Optional fields: `targetDeviceId`, `routeTag`, `deliveredAt`, `signature`

| Field | Type | Required | Max length/items |
|---|---|---|---|
| `type` | string | yes | - |
| `protocolVersion` | string | yes | - |
| `ackId` | string | yes | 512 |
| `senderDeviceId` | string | yes | 512 |
| `timestamp` | number | yes | - |
| `encryptedPayload` | string | yes | - |
| `targetDeviceId` | string | no | 512 |
| `routeTag` | string | no | 4096 |
| `deliveredAt` | number | no | - |
| `signature` | string | no | - |

## Validation rules

- Protocol version must match `1.0`.
- Required fields must exist for each message type.
- Field types must match the spec exactly.
- Strict mode rejects unknown fields and disables normalization.
- Non-strict mode can normalize compatibility aliases (for example control/pull, control/deliver).

## Invariants

- **receiveCounterMonotonic**: receiveCounter never decreases
- **skippedMessageKeysBounded**: skippedMessageKeys remains bounded by maxSkippedMessageKeys
- **routeTagCandidateMatch**: routeTag must match expected derived route tag set
- **verifyBeforeDecrypt**: message signature must be verified before payload decrypt
- **verifiedIdentityImmutable**: VERIFIED identity keys cannot change silently

## Simplified state transitions

- Handshake validates identity/device binding and negotiates protocol version.
- Chat receive path verifies signature, validates routeTag candidate set, advances ratchet receive counter, then decrypts.
- Replay detection is enforced by message-id cache and monotonic receive counters.

## Threat model summary

- Wire encoding determinism is constrained to pre-encryption structure and ordering only.
- Ciphertext, padding randomness, and timing obfuscation remain randomized and are not part of deterministic vectors.
- RouteTag and counter invariants block malformed routing and replay attempts.
- Verified identities cannot silently mutate without triggering security controls.
