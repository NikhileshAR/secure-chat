const PROTOCOL_VERSION = '1.0';
const SUPPORTED_VERSIONS = [PROTOCOL_VERSION];

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
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

function normalizeSupportedVersions(value) {
  if (Array.isArray(value)) {
    return value.filter((entry) => typeof entry === 'string');
  }
  if (typeof value === 'string') {
    return [value];
  }
  return [];
}

function compareVersions(left, right) {
  const a = String(left || '').split('.').map((part) => Number(part) || 0);
  const b = String(right || '').split('.').map((part) => Number(part) || 0);
  const max = Math.max(a.length, b.length);
  for (let i = 0; i < max; i += 1) {
    const delta = (a[i] || 0) - (b[i] || 0);
    if (delta !== 0) {
      return delta;
    }
  }
  return 0;
}

function negotiateProtocolVersion(localSupported = SUPPORTED_VERSIONS, remoteSupported = []) {
  const local = normalizeSupportedVersions(localSupported);
  const remote = normalizeSupportedVersions(remoteSupported);
  const remoteSet = new Set(remote);
  const intersection = local.filter((version) => remoteSet.has(version));
  if (!intersection.length) {
    return null;
  }
  return intersection.sort((a, b) => compareVersions(b, a))[0];
}

function baseNormalize(message) {
  const normalized = normalizeControlMessage(message);
  if (!isPlainObject(normalized)) {
    return normalized;
  }
  if (normalized.protocolVersion) {
    return normalized;
  }
  return {
    ...normalized,
    protocolVersion: PROTOCOL_VERSION,
    _legacyVersionApplied: true,
  };
}

function normalizeHandshake(message) {
  if (!isPlainObject(message)) {
    return message;
  }
  const supported = normalizeSupportedVersions(message.supportedVersions);
  if (supported.length) {
    return { ...message, supportedVersions: supported };
  }
  return {
    ...message,
    supportedVersions: [message.protocolVersion || PROTOCOL_VERSION],
  };
}

const ProtocolSpec = {
  version: PROTOCOL_VERSION,
  messageTypes: {
    handshake: {
      requiredFields: ['type', 'protocolVersion', 'senderDeviceId', 'timestamp', 'encryptedPayload'],
      optionalFields: [
        'identityPublicKey',
        'devicePublicKey',
        'deviceKeySignature',
        'publicKeys',
        'supportedVersions',
        'targetDeviceId',
      ],
      fieldTypes: {
        type: 'string',
        protocolVersion: 'string',
        senderDeviceId: 'string',
        targetDeviceId: 'string',
        timestamp: 'number',
        encryptedPayload: 'string',
        identityPublicKey: 'string',
        devicePublicKey: 'string',
        deviceKeySignature: 'string',
        publicKeys: 'object',
        supportedVersions: 'array:string',
      },
      maxLengths: {
        senderDeviceId: 512,
        targetDeviceId: 512,
        supportedVersions: 16,
      },
      normalize: (message) => normalizeHandshake(baseNormalize(message)),
    },
    chat: {
      requiredFields: [
        'type',
        'protocolVersion',
        'messageId',
        'senderDeviceId',
        'counter',
        'previousCounter',
        'dhPublicKey',
        'routeTag',
        'encryptedPayload',
        'timestamp',
        'signature',
      ],
      optionalFields: [
        'targetDeviceId',
        'targetDeviceIds',
        'ackId',
        'deliveredAt',
      ],
      fieldTypes: {
        type: 'string',
        protocolVersion: 'string',
        messageId: 'string',
        senderDeviceId: 'string',
        targetDeviceId: 'string',
        targetDeviceIds: 'array:string',
        counter: 'integer',
        previousCounter: 'integer',
        dhPublicKey: 'string',
        routeTag: 'string',
        encryptedPayload: 'string',
        timestamp: 'number',
        signature: 'string',
        ackId: 'string',
        deliveredAt: 'number',
      },
      maxLengths: {
        messageId: 512,
        senderDeviceId: 512,
        targetDeviceId: 512,
        targetDeviceIds: 128,
        dhPublicKey: 4096,
        routeTag: 4096,
        ackId: 512,
      },
      normalize: (message) => baseNormalize(message),
    },
    pull: {
      requiredFields: ['type', 'protocolVersion', 'senderDeviceId', 'timestamp', 'encryptedPayload', 'routeTags'],
      optionalFields: [],
      fieldTypes: {
        type: 'string',
        protocolVersion: 'string',
        senderDeviceId: 'string',
        timestamp: 'number',
        encryptedPayload: 'string',
        routeTags: 'array:string',
      },
      maxLengths: {
        senderDeviceId: 512,
        routeTags: 2_048,
      },
      normalize: (message) => baseNormalize(message),
    },
    deliver: {
      requiredFields: ['type', 'protocolVersion', 'senderDeviceId', 'timestamp', 'encryptedPayload'],
      optionalFields: [],
      fieldTypes: {
        type: 'string',
        protocolVersion: 'string',
        senderDeviceId: 'string',
        timestamp: 'number',
        encryptedPayload: 'string',
      },
      maxLengths: {
        senderDeviceId: 512,
      },
      normalize: (message) => baseNormalize(message),
    },
    ack: {
      requiredFields: ['type', 'protocolVersion', 'ackId', 'senderDeviceId', 'timestamp', 'encryptedPayload'],
      optionalFields: ['targetDeviceId', 'routeTag', 'deliveredAt', 'signature'],
      fieldTypes: {
        type: 'string',
        protocolVersion: 'string',
        ackId: 'string',
        senderDeviceId: 'string',
        targetDeviceId: 'string',
        routeTag: 'string',
        timestamp: 'number',
        deliveredAt: 'number',
        encryptedPayload: 'string',
        signature: 'string',
      },
      maxLengths: {
        ackId: 512,
        senderDeviceId: 512,
        targetDeviceId: 512,
        routeTag: 4096,
      },
      normalize: (message) => baseNormalize(message),
    },
  },
  limits: {
    maxStringField: 128 * 1024,
    maxPullRouteTags: 2_048,
    maxTargetDeviceIds: 128,
    maxRouteTagLength: 4096,
  },
  invariants: {
    receiveCounterMonotonic: 'receiveCounter never decreases',
    skippedMessageKeysBounded: 'skippedMessageKeys remains bounded by maxSkippedMessageKeys',
    routeTagCandidateMatch: 'routeTag must match expected derived route tag set',
    verifyBeforeDecrypt: 'message signature must be verified before payload decrypt',
    verifiedIdentityImmutable: 'VERIFIED identity keys cannot change silently',
  },
};

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
      protocolVersion: ProtocolSpec.version,
      _legacyVersionApplied: true,
    };
  }
  if (message.protocolVersion !== ProtocolSpec.version) {
    throw new Error(`Protocol violation: unsupported protocolVersion ${message.protocolVersion}`);
  }
  return message;
}

function getMessageType(message) {
  const normalized = normalizeControlMessage(message);
  const type = normalized?.type;
  if (typeof type !== 'string') {
    throw new Error('Protocol violation: message type is required');
  }
  const spec = ProtocolSpec.messageTypes[type];
  if (!spec) {
    throw new Error(`Protocol violation: unknown message type ${type}`);
  }
  return type;
}

function validateType(name, value, expectedType) {
  if (value === undefined || value === null) {
    return;
  }

  if (expectedType === 'string' && typeof value !== 'string') {
    throw new Error(`Protocol violation: field ${name} must be a string`);
  }
  if (expectedType === 'number' && (typeof value !== 'number' || !Number.isFinite(value))) {
    throw new Error(`Protocol violation: field ${name} must be a number`);
  }
  if (expectedType === 'integer' && (!Number.isInteger(value) || !Number.isFinite(value))) {
    throw new Error(`Protocol violation: field ${name} must be an integer`);
  }
  if (expectedType === 'object' && !isPlainObject(value)) {
    throw new Error(`Protocol violation: field ${name} must be an object`);
  }
  if (expectedType === 'array' && !Array.isArray(value)) {
    throw new Error(`Protocol violation: field ${name} must be an array`);
  }
  if (expectedType === 'array:string') {
    if (!Array.isArray(value)) {
      throw new Error(`Protocol violation: field ${name} must be an array`);
    }
    for (const item of value) {
      if (typeof item !== 'string') {
        throw new Error(`Protocol violation: field ${name} has invalid item type`);
      }
    }
  }
}

function enforceMaxLength(name, value, maxLength, fallbackStringLimit) {
  if (value === undefined || value === null) {
    return;
  }

  if (typeof value === 'string') {
    if (value.length > (maxLength || fallbackStringLimit)) {
      throw new Error(`Protocol violation: field ${name} exceeds max length`);
    }
    return;
  }

  if (Array.isArray(value) && maxLength !== undefined && value.length > maxLength) {
    throw new Error(`Protocol violation: field ${name} exceeds max items`);
  }
}

function validateMessageAgainstSpec(message, { strictMode = false, allowLegacy = true } = {}) {
  if (!isPlainObject(message)) {
    throw new Error('Protocol violation: message must be an object');
  }

  const incomingType = getMessageType(message);
  const incomingSpec = ProtocolSpec.messageTypes[incomingType];
  let normalized = strictMode ? message : incomingSpec.normalize(message);
  normalized = ensureProtocolVersion(normalized, { allowLegacy });

  const messageType = getMessageType(normalized);
  const messageSpec = ProtocolSpec.messageTypes[messageType];
  const requiredFields = new Set(messageSpec.requiredFields);
  const optionalFields = new Set(messageSpec.optionalFields);
  const knownFields = new Set([...requiredFields, ...optionalFields]);

  for (const field of requiredFields) {
    if (normalized[field] === undefined || normalized[field] === null) {
      throw new Error(`Protocol violation: missing required field ${field}`);
    }
  }

  for (const [field, expectedType] of Object.entries(messageSpec.fieldTypes)) {
    validateType(field, normalized[field], expectedType);
    if (expectedType === 'string') {
      enforceMaxLength(
        field,
        normalized[field],
        messageSpec.maxLengths[field],
        ProtocolSpec.limits.maxStringField,
      );
    }
  }

  for (const [field, maxLength] of Object.entries(messageSpec.maxLengths)) {
    if (messageSpec.fieldTypes[field] !== 'string') {
      enforceMaxLength(field, normalized[field], maxLength, ProtocolSpec.limits.maxStringField);
    }
  }

  if (strictMode) {
    for (const field of Object.keys(normalized)) {
      if (!knownFields.has(field)) {
        throw new Error(`Protocol violation: unknown field ${field}`);
      }
    }
  }

  return normalized;
}

module.exports = {
  PROTOCOL_VERSION,
  SUPPORTED_VERSIONS,
  ProtocolSpec,
  isPlainObject,
  normalizeControlMessage,
  normalizeSupportedVersions,
  compareVersions,
  negotiateProtocolVersion,
  ensureProtocolVersion,
  validateMessageAgainstSpec,
  getMessageType,
};
