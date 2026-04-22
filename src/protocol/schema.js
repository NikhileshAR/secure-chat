const {
  PROTOCOL_VERSION,
  ProtocolSpec,
  ensureProtocolVersion,
  normalizeControlMessage,
  validateMessageAgainstSpec,
} = require('./spec');

function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item));
  }
  if (!value || typeof value !== 'object') {
    return value;
  }
  const out = {};
  for (const key of Object.keys(value).sort()) {
    out[key] = canonicalize(value[key]);
  }
  return out;
}

function canonicalSerialize(value) {
  return JSON.stringify(canonicalize(value));
}

function validateMessage(message, options = {}) {
  return validateMessageAgainstSpec(message, {
    strictMode: Boolean(options.strictMode),
    allowLegacy: options.allowLegacy !== false,
  });
}

module.exports = {
  PROTOCOL_VERSION,
  schemas: ProtocolSpec.messageTypes,
  canonicalize,
  canonicalSerialize,
  ensureProtocolVersion,
  normalizeControlMessage,
  validateMessage,
};
