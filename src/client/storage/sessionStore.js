const {
  createHash,
  createHmac,
  createCipheriv,
  createDecipheriv,
  pbkdf2Sync,
  randomBytes,
} = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const SESSION_SCHEMA_VERSION = 1;
const PBKDF2_ITERATIONS = 600_000;

function toBuffer(value) {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (typeof value === 'string') {
    return Buffer.from(value, 'base64');
  }
  throw new Error('SessionStore expected buffer-compatible value');
}

function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  }
  if (!value || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
}

class SessionStore {
  constructor({
    storageDir,
    deviceSecret,
    ttlMs = 24 * 60 * 60 * 1000,
    maxSkippedMessageKeys = 512,
    filename = 'securechat.sessions.enc',
  }) {
    if (!storageDir) {
      throw new Error('SessionStore requires storageDir');
    }
    if (!deviceSecret) {
      throw new Error('SessionStore requires deviceSecret');
    }
    this.storageDir = storageDir;
    this.filePath = path.join(storageDir, filename);
    const parsedTtl = Number(ttlMs);
    this.ttlMs = Number.isFinite(parsedTtl) && parsedTtl > 0
      ? parsedTtl
      : 24 * 60 * 60 * 1000;
    const parsedSkipped = Number(maxSkippedMessageKeys);
    this.maxSkippedMessageKeys = Number.isFinite(parsedSkipped) && parsedSkipped > 0
      ? Math.floor(parsedSkipped)
      : 512;
    this.deviceSecret = String(deviceSecret);
  }

  deriveKeys(salt) {
    const master = pbkdf2Sync(this.deviceSecret, salt, PBKDF2_ITERATIONS, 64, 'sha256');
    return {
      encKey: master.subarray(0, 32),
      macKey: master.subarray(32, 64),
    };
  }

  serializeSession(sessionId, session) {
    const skippedEntries = [...(session.skippedMessageKeys?.entries?.() || [])]
      .slice(-this.maxSkippedMessageKeys)
      .map(([key, value]) => [key, toBuffer(value).toString('base64')]);

    return {
      sessionId,
      peerDeviceId: session.peerDeviceId || null,
      peerIdentityPublicKey: session.peerIdentityPublicKey || null,
      peerDevicePublicKey: session.peerDevicePublicKey || null,
      routeSecretRef: session.routeSecretRef || null,
      rootKey: toBuffer(session.rootKey).toString('base64'),
      chainKeySend: toBuffer(session.chainKeySend).toString('base64'),
      chainKeyReceive: toBuffer(session.chainKeyReceive).toString('base64'),
      sendCounter: session.sendCounter || 0,
      receiveCounter: session.receiveCounter || 0,
      previousCounter: session.previousCounter || 0,
      lastDHKey: session.lastDHKey || null,
      currentReceiveDhKey: session.currentReceiveDhKey || null,
      selfDHKeyPair: session.selfDHKeyPair || null,
      ratchetPending: Boolean(session.ratchetPending),
      isDecoy: Boolean(session.isDecoy),
      expiresAt: Number(session.expiresAt) || 0,
      skippedMessageKeys: skippedEntries,
      seenMessageIds: [...(session.seenMessageIds?.entries?.() || [])],
      storedAt: Date.now(),
    };
  }

  deserializeSession(record) {
    return {
      peerDeviceId: record.peerDeviceId || undefined,
      peerIdentityPublicKey: record.peerIdentityPublicKey || undefined,
      peerDevicePublicKey: record.peerDevicePublicKey || undefined,
      routeSecretRef: record.routeSecretRef || undefined,
      rootKey: Buffer.from(record.rootKey, 'base64'),
      chainKeySend: Buffer.from(record.chainKeySend, 'base64'),
      chainKeyReceive: Buffer.from(record.chainKeyReceive, 'base64'),
      sendCounter: record.sendCounter,
      receiveCounter: record.receiveCounter,
      previousCounter: record.previousCounter,
      lastDHKey: record.lastDHKey || undefined,
      currentReceiveDhKey: record.currentReceiveDhKey || undefined,
      selfDHKeyPair: record.selfDHKeyPair || undefined,
      ratchetPending: Boolean(record.ratchetPending),
      expiresAt: record.expiresAt,
      isDecoy: Boolean(record.isDecoy),
      skippedMessageKeys: new Map((record.skippedMessageKeys || []).map(([key, value]) => [
        key,
        Buffer.from(value, 'base64'),
      ])),
      seenMessageIds: new Map(record.seenMessageIds || []),
    };
  }

  encryptDocument(doc) {
    const plaintext = Buffer.from(stableStringify(doc));
    const salt = randomBytes(16);
    const { encKey, macKey } = this.deriveKeys(salt);
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', encKey, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const mac = createHmac('sha256', macKey)
      .update(iv)
      .update(tag)
      .update(ciphertext)
      .digest('base64');

    return {
      schemaVersion: SESSION_SCHEMA_VERSION,
      salt: salt.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      mac,
    };
  }

  decryptDocument(blob) {
    if (!blob || blob.schemaVersion !== SESSION_SCHEMA_VERSION) {
      throw new Error('SessionStore unsupported schema version');
    }

    const salt = Buffer.from(blob.salt, 'base64');
    const { encKey, macKey } = this.deriveKeys(salt);
    const iv = Buffer.from(blob.iv, 'base64');
    const tag = Buffer.from(blob.tag, 'base64');
    const ciphertext = Buffer.from(blob.ciphertext, 'base64');
    const expectedMac = createHmac('sha256', macKey)
      .update(iv)
      .update(tag)
      .update(ciphertext)
      .digest('base64');

    if (expectedMac !== blob.mac) {
      throw new Error('SessionStore MAC verification failed');
    }

    const decipher = createDecipheriv('aes-256-gcm', encKey, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(plaintext.toString('utf8'));
  }

  cleanupRecords(records, now = Date.now()) {
    return records.filter((record) => {
      if (typeof record.expiresAt === 'number' && record.expiresAt > 0 && now >= record.expiresAt) {
        return false;
      }
      if (typeof record.storedAt === 'number' && now - record.storedAt > this.ttlMs) {
        return false;
      }
      return true;
    });
  }

  saveSessions(sessions) {
    fs.mkdirSync(this.storageDir, { recursive: true });
    const sessionEntries = sessions instanceof Map ? [...sessions.entries()] : Object.entries(sessions || {});
    const records = sessionEntries.map(([sessionId, session]) => this.serializeSession(sessionId, session));
    const encrypted = this.encryptDocument({
      schemaVersion: SESSION_SCHEMA_VERSION,
      savedAt: Date.now(),
      records,
    });

    const tmpPath = `${this.filePath}.tmp`;
    fs.writeFileSync(tmpPath, `${JSON.stringify(encrypted)}\n`, { mode: 0o600 });
    fs.renameSync(tmpPath, this.filePath);
  }

  loadSessions() {
    if (!fs.existsSync(this.filePath)) {
      return new Map();
    }

    const raw = fs.readFileSync(this.filePath, 'utf8');
    let encryptedBlob;
    try {
      encryptedBlob = JSON.parse(raw);
    } catch (error) {
      throw new Error(`SessionStore file is not valid JSON: ${error.message}`);
    }

    let doc;
    try {
      doc = this.decryptDocument(encryptedBlob);
    } catch (error) {
      throw new Error(`SessionStore decryption failed: ${error.message}`);
    }
    const records = this.cleanupRecords(doc.records || []);
    const sessions = new Map();
    for (const record of records) {
      sessions.set(record.sessionId, this.deserializeSession(record));
    }
    return sessions;
  }
}

module.exports = {
  SessionStore,
  SESSION_SCHEMA_VERSION,
};
