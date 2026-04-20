const {
  createHash,
  createHmac,
  createPublicKey,
  createPrivateKey,
  diffieHellman,
  randomBytes,
  createCipheriv,
  createDecipheriv,
  sign,
  verify,
} = require('node:crypto');

const ROUTE_COUNTER_SIZE = 8;
const ROOT_KEY_SIZE = 32;
const CHAIN_KEY_SIZE = 32;
const MESSAGE_KEY_SIZE = 32;

function sha512(input) {
  return createHash('sha512').update(input).digest('hex');
}

function toBuffer(value) {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (value === undefined || value === null) {
    throw new Error('toBuffer: value cannot be null or undefined');
  }
  return Buffer.from(String(value));
}

function encodeCounter(counter) {
  if (!Number.isSafeInteger(counter) || counter < 0) {
    throw new Error('Counter must be a non-negative integer');
  }
  const counterBuffer = Buffer.alloc(ROUTE_COUNTER_SIZE);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  return counterBuffer;
}

function hkdfSha512(ikm, info, length, salt = Buffer.alloc(64, 0)) {
  if (!Number.isInteger(length) || length <= 0) {
    throw new Error('HKDF output length must be a positive integer');
  }
  const prk = createHmac('sha512', toBuffer(salt)).update(toBuffer(ikm)).digest();
  let prev = Buffer.alloc(0);
  const output = [];
  let i = 1;
  while (Buffer.concat(output).length < length) {
    prev = createHmac('sha512', prk)
      .update(Buffer.concat([prev, Buffer.from(String(info)), Buffer.from([i])]))
      .digest();
    output.push(prev);
    i += 1;
  }
  return Buffer.concat(output).subarray(0, length);
}

function computeRouteTag(rootKey, counter = 0, direction = 'send') {
  if (direction !== 'send' && direction !== 'receive') {
    throw new Error('Route tag direction must be send or receive');
  }
  return createHash('sha512')
    .update(Buffer.concat([
      toBuffer(rootKey),
      Buffer.from([0]),
      encodeCounter(counter),
      Buffer.from([0]),
      Buffer.from(direction),
    ]))
    .digest('hex');
}

function deriveInitialRootAndChainKeys(sharedSecret, isInitiator = true) {
  const material = hkdfSha512(toBuffer(sharedSecret), 'secure-double-ratchet-init', 96);
  const rootKey = material.subarray(0, ROOT_KEY_SIZE);
  const firstChain = material.subarray(ROOT_KEY_SIZE, ROOT_KEY_SIZE + CHAIN_KEY_SIZE);
  const secondChain = material.subarray(ROOT_KEY_SIZE + CHAIN_KEY_SIZE, ROOT_KEY_SIZE + CHAIN_KEY_SIZE * 2);

  return {
    rootKey,
    chainKeySend: isInitiator ? firstChain : secondChain,
    chainKeyReceive: isInitiator ? secondChain : firstChain,
  };
}

function deriveRootAndChainFromDh(rootKey, dhSharedSecret) {
  const material = hkdfSha512(
    toBuffer(dhSharedSecret),
    'secure-double-ratchet-step',
    ROOT_KEY_SIZE + CHAIN_KEY_SIZE,
    toBuffer(rootKey),
  );

  return {
    rootKey: material.subarray(0, ROOT_KEY_SIZE),
    chainKey: material.subarray(ROOT_KEY_SIZE, ROOT_KEY_SIZE + CHAIN_KEY_SIZE),
  };
}

function encryptAesGcm(plaintextBuffer, key, { iv } = {}) {
  const effectiveIv = iv ? toBuffer(iv) : randomBytes(12);
  if (effectiveIv.length !== 12) {
    throw new Error('AES-GCM IV must be 12 bytes');
  }
  const cipher = createCipheriv('aes-256-gcm', toBuffer(key), effectiveIv);
  const encrypted = Buffer.concat([cipher.update(plaintextBuffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: effectiveIv.toString('base64'),
    ciphertext: encrypted.toString('base64'),
    tag: tag.toString('base64'),
  };
}

function decryptAesGcm(payload, key) {
  if (!payload || !payload.iv || !payload.ciphertext || !payload.tag) {
    throw new Error('Encrypted payload is missing required AES-GCM fields');
  }
  const decipher = createDecipheriv('aes-256-gcm', toBuffer(key), Buffer.from(payload.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(payload.tag, 'base64'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(payload.ciphertext, 'base64')),
    decipher.final(),
  ]);
  return decrypted;
}

function encryptPayload(payload, senderDevicePrivateKeyPem, recipientDevicePublicKeyPem) {
  const payloadBytes = Buffer.from(JSON.stringify(payload));
  const recipientPublicKey = createPublicKey(recipientDevicePublicKeyPem);
  const senderPrivateKey = createPrivateKey(senderDevicePrivateKeyPem);
  const sharedSecret = diffieHellman({ privateKey: senderPrivateKey, publicKey: recipientPublicKey });
  const messageKey = hkdfSha512(sharedSecret, 'secure-msg-key', MESSAGE_KEY_SIZE);
  const encryptedPayload = encryptAesGcm(payloadBytes, messageKey);

  return {
    encryptedPayload,
  };
}

function decryptPayload(encryptedMessage, recipientDevicePrivateKeyPem, senderDevicePublicKeyPem) {
  const senderPublicKey = createPublicKey(senderDevicePublicKeyPem);
  const recipientPrivateKey = createPrivateKey(recipientDevicePrivateKeyPem);
  const sharedSecret = diffieHellman({ privateKey: recipientPrivateKey, publicKey: senderPublicKey });
  const messageKey = hkdfSha512(sharedSecret, 'secure-msg-key', MESSAGE_KEY_SIZE);
  const decryptedPayload = decryptAesGcm(encryptedMessage.encryptedPayload, messageKey);
  return JSON.parse(decryptedPayload.toString('utf8'));
}

function encryptPayloadWithMessageKey(payload, messageKey, options) {
  const payloadBytes = Buffer.from(JSON.stringify(payload));
  return {
    encryptedPayload: encryptAesGcm(payloadBytes, messageKey, options),
  };
}

function decryptPayloadWithMessageKey(encryptedMessage, messageKey) {
  const decryptedPayload = decryptAesGcm(encryptedMessage.encryptedPayload, messageKey);
  return JSON.parse(decryptedPayload.toString('utf8'));
}

function deriveSharedSecret(senderDevicePrivateKeyPem, recipientDevicePublicKeyPem) {
  const recipientPublicKey = createPublicKey(recipientDevicePublicKeyPem);
  const senderPrivateKey = createPrivateKey(senderDevicePrivateKeyPem);
  return diffieHellman({ privateKey: senderPrivateKey, publicKey: recipientPublicKey });
}

function deriveInitialChainKey(sharedSecret) {
  return hkdfSha512(toBuffer(sharedSecret), 'secure-chain-key', 64);
}

function deriveMessageKey(chainKey) {
  return createHmac('sha512', toBuffer(chainKey)).update('msg').digest().subarray(0, MESSAGE_KEY_SIZE);
}

function deriveNextChainKey(chainKey) {
  return createHmac('sha512', toBuffer(chainKey)).update('chain').digest().subarray(0, CHAIN_KEY_SIZE);
}

function createMessageSignaturePayload(messageObject) {
  const required = [
    'messageId',
    'counter',
    'previousCounter',
    'dhPublicKey',
    'encryptedPayload',
    'timestamp',
  ];
  for (const field of required) {
    if (messageObject[field] === undefined || messageObject[field] === null) {
      throw new Error(`Missing signature field: ${field}`);
    }
  }
  return {
    messageId: messageObject.messageId,
    counter: messageObject.counter,
    previousCounter: messageObject.previousCounter,
    dhPublicKey: messageObject.dhPublicKey,
    encryptedPayload: messageObject.encryptedPayload,
    timestamp: messageObject.timestamp,
  };
}

function signMessage(identityPrivateKeyPem, messageObject) {
  const payload = Buffer.from(JSON.stringify(createMessageSignaturePayload(messageObject)));
  return sign(null, payload, createPrivateKey(identityPrivateKeyPem)).toString('base64');
}

function verifyMessage(identityPublicKeyPem, messageObject, signature) {
  const payload = Buffer.from(JSON.stringify(createMessageSignaturePayload(messageObject)));
  return verify(null, payload, createPublicKey(identityPublicKeyPem), Buffer.from(signature, 'base64'));
}

module.exports = {
  sha512,
  computeRouteTag,
  hkdfSha512,
  deriveInitialRootAndChainKeys,
  deriveRootAndChainFromDh,
  encryptPayload,
  decryptPayload,
  encryptPayloadWithMessageKey,
  decryptPayloadWithMessageKey,
  deriveSharedSecret,
  deriveInitialChainKey,
  deriveMessageKey,
  deriveNextChainKey,
  createMessageSignaturePayload,
  signMessage,
  verifyMessage,
};
