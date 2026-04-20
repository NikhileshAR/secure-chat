const {
  createHash,
  createHmac,
  createPublicKey,
  createPrivateKey,
  diffieHellman,
  createCipheriv,
  createDecipheriv,
  sign,
  verify,
} = require('node:crypto');

function sha512(input) {
  return createHash('sha512').update(input).digest('hex');
}

function toBuffer(value) {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  return Buffer.from(String(value));
}

function computeRouteTag(sharedSecret, counter = 0) {
  return createHash('sha512')
    .update(Buffer.concat([toBuffer(sharedSecret), Buffer.from(String(counter))]))
    .digest('hex');
}

function hkdfSha512(ikm, info, length) {
  const salt = Buffer.alloc(64, 0);
  const prk = createHmac('sha512', salt).update(ikm).digest();
  let prev = Buffer.alloc(0);
  const output = [];
  let i = 1;
  while (Buffer.concat(output).length < length) {
    prev = createHmac('sha512', prk)
      .update(Buffer.concat([prev, Buffer.from(info), Buffer.from([i])]))
      .digest();
    output.push(prev);
    i += 1;
  }
  return Buffer.concat(output).subarray(0, length);
}

function encryptAesGcm(plaintextBuffer, key) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintextBuffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('base64'),
    ciphertext: encrypted.toString('base64'),
    tag: tag.toString('base64'),
  };
}

function decryptAesGcm(payload, key) {
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(payload.iv, 'base64'));
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
  const messageKey = hkdfSha512(sharedSecret, 'secure-msg-key', 32);
  const encryptedPayload = encryptAesGcm(payloadBytes, messageKey);

  return {
    encryptedPayload,
  };
}

function decryptPayload(encryptedMessage, recipientDevicePrivateKeyPem, senderDevicePublicKeyPem) {
  const senderPublicKey = createPublicKey(senderDevicePublicKeyPem);
  const recipientPrivateKey = createPrivateKey(recipientDevicePrivateKeyPem);
  const sharedSecret = diffieHellman({ privateKey: recipientPrivateKey, publicKey: senderPublicKey });
  const messageKey = hkdfSha512(sharedSecret, 'secure-msg-key', 32);
  const decryptedPayload = decryptAesGcm(encryptedMessage.encryptedPayload, messageKey);
  return JSON.parse(decryptedPayload.toString('utf8'));
}

function encryptPayloadWithMessageKey(payload, messageKey) {
  const payloadBytes = Buffer.from(JSON.stringify(payload));
  return {
    encryptedPayload: encryptAesGcm(payloadBytes, messageKey),
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
  return createHmac('sha512', toBuffer(chainKey)).update('msg').digest().subarray(0, 32);
}

function deriveNextChainKey(chainKey) {
  return createHmac('sha512', toBuffer(chainKey)).update('chain').digest();
}

function signMessage(identityPrivateKeyPem, messageObject) {
  const payload = Buffer.from(JSON.stringify(messageObject));
  return sign(null, payload, createPrivateKey(identityPrivateKeyPem)).toString('base64');
}

function verifyMessage(identityPublicKeyPem, messageObject, signature) {
  const payload = Buffer.from(JSON.stringify(messageObject));
  return verify(null, payload, createPublicKey(identityPublicKeyPem), Buffer.from(signature, 'base64'));
}

module.exports = {
  sha512,
  computeRouteTag,
  encryptPayload,
  decryptPayload,
  encryptPayloadWithMessageKey,
  decryptPayloadWithMessageKey,
  deriveSharedSecret,
  deriveInitialChainKey,
  deriveMessageKey,
  deriveNextChainKey,
  signMessage,
  verifyMessage,
};
