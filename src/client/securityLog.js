const {
  createCipheriv,
  createDecipheriv,
  createHmac,
  pbkdf2Sync,
  randomBytes,
} = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const SECURITY_LOG_SCHEMA_VERSION = 1;
const PBKDF2_ITERATIONS = 600_000;

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

class SecurityLog {
  constructor({
    maxEntries = 1_000,
    storageDir,
    deviceSecret,
    filename = 'securechat.securitylog.enc',
    persistenceEnabled = false,
  } = {}) {
    this.maxEntries = Math.max(1, Number(maxEntries) || 1_000);
    this.entries = [];
    this.persistenceEnabled = Boolean(persistenceEnabled && storageDir && deviceSecret);
    this.storageDir = storageDir;
    this.deviceSecret = deviceSecret ? String(deviceSecret) : null;
    this.filePath = storageDir ? path.join(storageDir, filename) : null;
    if (this.persistenceEnabled) {
      this.load();
    }
  }

  append(eventType, details = {}) {
    const entry = {
      id: `${Date.now()}:${this.entries.length}`,
      eventType,
      timestamp: Date.now(),
      details,
    };
    this.entries.push(entry);
    if (this.entries.length > this.maxEntries) {
      this.entries.splice(0, this.entries.length - this.maxEntries);
    }
    if (this.persistenceEnabled) {
      this.save();
    }
    return entry;
  }

  list() {
    return this.entries.map((entry) => ({ ...entry }));
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
      schemaVersion: SECURITY_LOG_SCHEMA_VERSION,
      salt: salt.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      mac,
    };
  }

  decryptDocument(blob) {
    if (!blob || blob.schemaVersion !== SECURITY_LOG_SCHEMA_VERSION) {
      throw new Error('SecurityLog unsupported schema version');
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
      throw new Error('SecurityLog MAC verification failed');
    }
    const decipher = createDecipheriv('aes-256-gcm', encKey, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(plaintext.toString('utf8'));
  }

  save() {
    fs.mkdirSync(this.storageDir, { recursive: true });
    const payload = this.encryptDocument({ entries: this.entries, savedAt: Date.now() });
    const tmp = `${this.filePath}.tmp`;
    fs.writeFileSync(tmp, `${JSON.stringify(payload)}\n`, { mode: 0o600 });
    fs.renameSync(tmp, this.filePath);
  }

  load() {
    if (!this.filePath || !fs.existsSync(this.filePath)) {
      return;
    }
    try {
      const raw = fs.readFileSync(this.filePath, 'utf8');
      const blob = JSON.parse(raw);
      const doc = this.decryptDocument(blob);
      const entries = Array.isArray(doc.entries) ? doc.entries : [];
      this.entries = entries.slice(-this.maxEntries);
    } catch {
      this.entries = [];
    }
  }
}

module.exports = {
  SecurityLog,
  SECURITY_LOG_SCHEMA_VERSION,
};
