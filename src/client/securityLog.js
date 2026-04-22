const {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  pbkdf2Sync,
} = require('node:crypto');
const fs = require('node:fs');

const LOG_SCHEMA_VERSION = 1;
const PBKDF2_ITERATIONS = 300_000;

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
  constructor({ maxEntries = 2_048 } = {}) {
    this.maxEntries = Math.max(64, Number(maxEntries) || 2_048);
    this.entries = [];
  }

  append(eventType, details = {}) {
    const entry = {
      timestamp: Date.now(),
      type: String(eventType || 'unknown'),
      details: details && typeof details === 'object' ? details : { value: details },
    };
    this.entries.push(entry);
    if (this.entries.length > this.maxEntries) {
      this.entries.splice(0, this.entries.length - this.maxEntries);
    }
    return entry;
  }

  getEntries() {
    return this.entries.map((entry) => ({
      timestamp: entry.timestamp,
      type: entry.type,
      details: entry.details,
    }));
  }

  deriveKey(passphrase, salt) {
    return pbkdf2Sync(String(passphrase), salt, PBKDF2_ITERATIONS, 32, 'sha256');
  }

  persistEncrypted(filePath, passphrase) {
    if (!filePath || !passphrase) {
      throw new Error('persistEncrypted requires filePath and passphrase');
    }
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const key = this.deriveKey(passphrase, salt);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const plaintext = Buffer.from(stableStringify({
      schemaVersion: LOG_SCHEMA_VERSION,
      entries: this.entries,
      savedAt: Date.now(),
    }));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const blob = {
      schemaVersion: LOG_SCHEMA_VERSION,
      salt: salt.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
    };
    fs.writeFileSync(filePath, `${JSON.stringify(blob)}\n`, { mode: 0o600 });
  }

  loadEncrypted(filePath, passphrase) {
    if (!filePath || !passphrase || !fs.existsSync(filePath)) {
      return [];
    }
    const raw = fs.readFileSync(filePath, 'utf8');
    const blob = JSON.parse(raw);
    if (blob.schemaVersion !== LOG_SCHEMA_VERSION) {
      throw new Error('Unsupported security log schema version');
    }
    const salt = Buffer.from(blob.salt, 'base64');
    const key = this.deriveKey(passphrase, salt);
    const decipher = createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(blob.iv, 'base64'),
    );
    decipher.setAuthTag(Buffer.from(blob.tag, 'base64'));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(blob.ciphertext, 'base64')),
      decipher.final(),
    ]);
    const parsed = JSON.parse(plaintext.toString('utf8'));
    this.entries = Array.isArray(parsed.entries)
      ? parsed.entries.slice(-this.maxEntries)
      : [];
    return this.getEntries();
  }
}

module.exports = {
  SecurityLog,
  LOG_SCHEMA_VERSION,
};
