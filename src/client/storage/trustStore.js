const {
  createHmac,
  createCipheriv,
  createDecipheriv,
  pbkdf2Sync,
  randomBytes,
  timingSafeEqual,
} = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const TRUST_SCHEMA_VERSION = 1;
const PBKDF2_ITERATIONS = 600_000;

const TRUST_LEVELS = {
  UNKNOWN: 'UNKNOWN',
  TRUSTED: 'TRUSTED',
  VERIFIED: 'VERIFIED',
  BLOCKED: 'BLOCKED',
};

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

class TrustStore {
  constructor({ storageDir, deviceSecret, filename = 'securechat.trust.enc' }) {
    if (!storageDir) {
      throw new Error('TrustStore requires storageDir');
    }
    if (!deviceSecret) {
      throw new Error('TrustStore requires deviceSecret');
    }
    this.storageDir = storageDir;
    this.filePath = path.join(storageDir, filename);
    this.deviceSecret = String(deviceSecret);
    this.cache = null;
  }

  deriveKeys(salt) {
    const master = pbkdf2Sync(this.deviceSecret, salt, PBKDF2_ITERATIONS, 64, 'sha256');
    return {
      encKey: master.subarray(0, 32),
      macKey: master.subarray(32, 64),
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
      schemaVersion: TRUST_SCHEMA_VERSION,
      salt: salt.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      mac,
    };
  }

  decryptDocument(blob) {
    if (!blob || blob.schemaVersion !== TRUST_SCHEMA_VERSION) {
      throw new Error('TrustStore unsupported schema version');
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

    const expectedMacBuf = Buffer.from(expectedMac, 'base64');
    const actualMacBuf = Buffer.from(blob.mac, 'base64');
    if (
      expectedMacBuf.length !== actualMacBuf.length
      || !timingSafeEqual(expectedMacBuf, actualMacBuf)
    ) {
      throw new Error('TrustStore MAC verification failed');
    }

    const decipher = createDecipheriv('aes-256-gcm', encKey, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(plaintext.toString('utf8'));
  }

  loadTrust() {
    if (!fs.existsSync(this.filePath)) {
      this.cache = new Map();
      return this.cache;
    }

    let raw;
    try {
      raw = fs.readFileSync(this.filePath, 'utf8');
    } catch {
      this.cache = new Map();
      return this.cache;
    }

    let blob;
    try {
      blob = JSON.parse(raw);
    } catch {
      this.cache = new Map();
      return this.cache;
    }

    let doc;
    try {
      doc = this.decryptDocument(blob);
    } catch {
      this.cache = new Map();
      return this.cache;
    }

    const map = new Map();
    for (const entry of doc.entries || []) {
      if (entry && entry.fingerprint) {
        map.set(entry.fingerprint, entry);
      }
    }
    this.cache = map;
    return this.cache;
  }

  saveTrust(map) {
    fs.mkdirSync(this.storageDir, { recursive: true });
    const entries = [...(map instanceof Map ? map.values() : Object.values(map || {}))];
    const encrypted = this.encryptDocument({
      schemaVersion: TRUST_SCHEMA_VERSION,
      savedAt: Date.now(),
      entries,
    });

    const tmpPath = `${this.filePath}.tmp`;
    fs.writeFileSync(tmpPath, `${JSON.stringify(encrypted)}\n`, { mode: 0o600 });
    fs.renameSync(tmpPath, this.filePath);
  }

  ensureLoaded() {
    if (!this.cache) {
      this.loadTrust();
    }
    return this.cache;
  }

  get(fingerprint) {
    return this.ensureLoaded().get(fingerprint) || null;
  }

  set(fingerprint, entry) {
    this.ensureLoaded().set(fingerprint, entry);
    this.saveTrust(this.cache);
  }

  delete(fingerprint) {
    this.ensureLoaded().delete(fingerprint);
    this.saveTrust(this.cache);
  }

  list() {
    return [...this.ensureLoaded().values()];
  }
}

module.exports = {
  TrustStore,
  TRUST_LEVELS,
  TRUST_SCHEMA_VERSION,
};
