const { ProtocolSpec } = require('./spec');

function renderMessageType(typeName, spec) {
  const required = spec.requiredFields.map((field) => `\`${field}\``).join(', ') || 'None';
  const optional = spec.optionalFields.map((field) => `\`${field}\``).join(', ') || 'None';
  const fields = [...new Set([...spec.requiredFields, ...spec.optionalFields])]
    .map((field) => {
      const type = spec.fieldTypes[field] || 'unknown';
      const maxLength = spec.maxLengths[field];
      return `| \`${field}\` | ${type} | ${spec.requiredFields.includes(field) ? 'yes' : 'no'} | ${maxLength ?? '-'} |`;
    })
    .join('\n');

  return [
    `## ${typeName}`,
    '',
    `- Required fields: ${required}`,
    `- Optional fields: ${optional}`,
    '',
    '| Field | Type | Required | Max length/items |',
    '|---|---|---|---|',
    fields,
    '',
  ].join('\n');
}

function generateProtocolMarkdown(spec = ProtocolSpec) {
  const messageSections = Object.entries(spec.messageTypes)
    .map(([typeName, typeSpec]) => renderMessageType(typeName, typeSpec))
    .join('\n');

  const invariants = Object.entries(spec.invariants)
    .map(([name, description]) => `- **${name}**: ${description}`)
    .join('\n');

  return [
    '# Secure Chat Protocol v1.0',
    '',
    '> Auto-generated from `src/protocol/spec.js`. Do not edit manually.',
    '',
    '## Message formats',
    '',
    messageSections,
    '## Validation rules',
    '',
    `- Protocol version must match \`${spec.version}\`.`,
    '- Required fields must exist for each message type.',
    '- Field types must match the spec exactly.',
    '- Strict mode rejects unknown fields and disables normalization.',
    '- Non-strict mode can normalize compatibility aliases (for example control/pull, control/deliver).',
    '',
    '## Invariants',
    '',
    invariants,
    '',
    '## Simplified state transitions',
    '',
    '- Handshake validates identity/device binding and negotiates protocol version.',
    '- Chat receive path verifies signature, validates routeTag candidate set, advances ratchet receive counter, then decrypts.',
    '- Replay detection is enforced by message-id cache and monotonic receive counters.',
    '',
    '## Threat model summary',
    '',
    '- Wire encoding determinism is constrained to pre-encryption structure and ordering only.',
    '- Ciphertext, padding randomness, and timing obfuscation remain randomized and are not part of deterministic vectors.',
    '- RouteTag and counter invariants block malformed routing and replay attempts.',
    '- Verified identities cannot silently mutate without triggering security controls.',
    '',
  ].join('\n');
}

module.exports = {
  generateProtocolMarkdown,
};
