const PROTOCOL_VERSION = '1.0';
const MAX_STRING_FIELD = 128 * 1024;

function isPlainObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item));
  }
  if (!isPlainObject(value)) {
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

function normalizeControlMessage(message) {
  if (!isPlainObject(message)) {
    return message;
  }
  if (message.type !== 'control') {
    return message;
  }
  if (message.action === 'pull') {
    return { ...message, type: 'pull' };
  }
  if (message.action === 'deliver') {
    return { ...message, type: 'deliver' };
  }
  return message;
}

function ensureProtocolVersion(message, { allowLegacy = true } = {}) {
  if (!isPlainObject(message)) {
    throw new Error('Protocol violation: message must be an object');
  }
  if (!message.protocolVersion) {
    if (!allowLegacy) {
      throw new Error('Protocol violation: missing protocolVersion');
    }
    return {
      ...message,
      protocolVersion: PROTOCOL_VERSION,
      _legacyVersionApplied: true,
    };
  }
  if (message.protocolVersion !== PROTOCOL_VERSION) {
    throw new Error(`Protocol violation: unsupported protocolVersion ${message.protocolVersion}`);
  }
  return message;
}

function validateField(name, value, rule) {
  if (value === undefined || value === null) {
    if (rule.required) {
      throw new Error(`Protocol violation: missing required field ${name}`);
    }
    return;
  }

  if (rule.type === 'string') {
    if (typeof value !== 'string') {
      throw new Error(`Protocol violation: field ${name} must be a string`);
    }
    if (value.length > (rule.maxLength || MAX_STRING_FIELD)) {
      throw new Error(`Protocol violation: field ${name} exceeds max length`);
    }
    return;
  }

  if (rule.type === 'number') {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      throw new Error(`Protocol violation: field ${name} must be a number`);
    }
    if (rule.integer && !Number.isInteger(value)) {
      throw new Error(`Protocol violation: field ${name} must be an integer`);
    }
    if (rule.min !== undefined && value < rule.min) {
      throw new Error(`Protocol violation: field ${name} is below minimum`);
    }
    return;
  }

  if (rule.type === 'array') {
    if (!Array.isArray(value)) {
      throw new Error(`Protocol violation: field ${name} must be an array`);
    }
    if (rule.maxItems !== undefined && value.length > rule.maxItems) {
      throw new Error(`Protocol violation: field ${name} exceeds max items`);
    }
    if (rule.itemType) {
      for (const item of value) {
        if (typeof item !== rule.itemType) {
          throw new Error(`Protocol violation: field ${name} has invalid item type`);
        }
      }
    }
    return;
  }

  if (rule.type === 'object' && !isPlainObject(value)) {
    throw new Error(`Protocol violation: field ${name} must be an object`);
  }
}

const schemas = {
  handshake: {
    type: { type: 'string', required: true },
    protocolVersion: { type: 'string', required: true },
    senderDeviceId: { type: 'string', required: true, maxLength: 512 },
    timestamp: { type: 'number', required: true, min: 1 },
    encryptedPayload: { type: 'string', required: true },
    identityPublicKey: { type: 'string', required: false },
    devicePublicKey: { type: 'string', required: false },
    deviceKeySignature: { type: 'string', required: false },
    publicKeys: { type: 'object', required: false },
  },
  chat: {
    type: { type: 'string', required: true },
    protocolVersion: { type: 'string', required: true },
    messageId: { type: 'string', required: true, maxLength: 512 },
    senderDeviceId: { type: 'string', required: true, maxLength: 512 },
    targetDeviceId: { type: 'string', required: false, maxLength: 512 },
    targetDeviceIds: { type: 'array', required: false, maxItems: 128, itemType: 'string' },
    counter: { type: 'number', required: true, integer: true, min: 0 },
    previousCounter: { type: 'number', required: true, integer: true, min: 0 },
    dhPublicKey: { type: 'string', required: true, maxLength: 4096 },
    routeTag: { type: 'string', required: true, maxLength: 4096 },
    encryptedPayload: { type: 'string', required: true },
    timestamp: { type: 'number', required: true, min: 1 },
    signature: { type: 'string', required: true },
    ackId: { type: 'string', required: false, maxLength: 512 },
    deliveredAt: { type: 'number', required: false, min: 1 },
  },
  pull: {
    type: { type: 'string', required: true },
    protocolVersion: { type: 'string', required: true },
    senderDeviceId: { type: 'string', required: true, maxLength: 512 },
    timestamp: { type: 'number', required: true, min: 1 },
    encryptedPayload: { type: 'string', required: true },
    routeTags: { type: 'array', required: true, maxItems: 2_048, itemType: 'string' },
  },
  deliver: {
    type: { type: 'string', required: true },
    protocolVersion: { type: 'string', required: true },
    senderDeviceId: { type: 'string', required: true, maxLength: 512 },
    timestamp: { type: 'number', required: true, min: 1 },
    encryptedPayload: { type: 'string', required: true },
  },
  ack: {
    type: { type: 'string', required: true },
    protocolVersion: { type: 'string', required: true },
    ackId: { type: 'string', required: true, maxLength: 512 },
    senderDeviceId: { type: 'string', required: true, maxLength: 512 },
    targetDeviceId: { type: 'string', required: false, maxLength: 512 },
    routeTag: { type: 'string', required: false, maxLength: 4096 },
    timestamp: { type: 'number', required: true, min: 1 },
    deliveredAt: { type: 'number', required: false, min: 1 },
    encryptedPayload: { type: 'string', required: true },
    signature: { type: 'string', required: false },
  },
};

function getSchemaType(message) {
  const normalized = normalizeControlMessage(message);
  if (!normalized || typeof normalized.type !== 'string') {
    throw new Error('Protocol violation: message type is required');
  }
  const known = ['handshake', 'chat', 'pull', 'deliver', 'ack'];
  if (!known.includes(normalized.type)) {
    throw new Error(`Protocol violation: unknown message type ${normalized.type}`);
  }
  return normalized.type;
}

function validateMessage(message, options = {}) {
  const normalizedControl = normalizeControlMessage(message);
  const normalized = ensureProtocolVersion(normalizedControl, options);
  const schemaType = getSchemaType(normalized);
  const schema = schemas[schemaType];

  for (const [field, rule] of Object.entries(schema)) {
    validateField(field, normalized[field], rule);
  }

  return normalized;
}

module.exports = {
  PROTOCOL_VERSION,
  schemas,
  canonicalize,
  canonicalSerialize,
  ensureProtocolVersion,
  normalizeControlMessage,
  validateMessage,
};
