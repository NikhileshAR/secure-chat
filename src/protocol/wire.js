const { createHash } = require('node:crypto');
const { canonicalSerialize, validateMessage } = require('./schema');

function toWireString(bufferOrString) {
  if (Buffer.isBuffer(bufferOrString)) {
    return bufferOrString.toString('utf8');
  }
  if (bufferOrString instanceof Uint8Array) {
    return Buffer.from(bufferOrString).toString('utf8');
  }
  return String(bufferOrString || '');
}

function encodeMessage(message, { strictMode = false } = {}) {
  const normalized = validateMessage(message, {
    strictMode,
    allowLegacy: !strictMode,
  });
  return Buffer.from(canonicalSerialize(normalized), 'utf8');
}

function decodeMessage(buffer, { strictMode = false } = {}) {
  const raw = toWireString(buffer).trim();
  if (!raw) {
    throw new Error('Protocol violation: empty wire payload');
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('Protocol violation: invalid wire payload');
  }
  return validateMessage(parsed, {
    strictMode,
    allowLegacy: !strictMode,
  });
}

function hashWireMessage(buffer) {
  const bytes = Buffer.isBuffer(buffer)
    ? buffer
    : (buffer instanceof Uint8Array ? Buffer.from(buffer) : Buffer.from(String(buffer || ''), 'utf8'));
  return createHash('sha256').update(bytes).digest('hex');
}

module.exports = {
  encodeMessage,
  decodeMessage,
  hashWireMessage,
};
