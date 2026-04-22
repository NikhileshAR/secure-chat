const {
  randomBytes,
  pbkdf2Sync,
  createCipheriv,
  createDecipheriv,
  createHmac,
  argon2Sync,
} = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const KEY_VAULT_SCHEMA_VERSION = 1;
const PBKDF2_ITERATIONS = 600_000;

function deriveKey(passphrase, salt, options = {}) {
  const normalizedPassphrase = String(passphrase || '');
  const useArgon2 = options.preferArgon2 !== false && typeof argon2Sync === 'function';

  if (useArgon2) {
    return {
      kdf: {
        type: 'argon2id',
        memory: 64 * 1024,
        time: 3,
        parallelism: 1,
        salt: salt.toString('base64'),
      },
      key: argon2Sync('argon2id', {
        message: Buffer.from(normalizedPassphrase),
        nonce: salt,
        parallelism: 1,
        memory: 64 * 1024,
        passes: 3,
        tagLength: 32,
      }),
    };
  }

  const iterations = PBKDF2_ITERATIONS;
  return {
    kdf: {
      type: 'pbkdf2-sha256',
      iterations,
      salt: salt.toString('base64'),
    },
    key: pbkdf2Sync(normalizedPassphrase, salt, iterations, 32, 'sha256'),
  };
}

function deriveKeyFromStoredKdf(passphrase, kdf) {
  const salt = Buffer.from(kdf.salt, 'base64');
  if (kdf.type === 'argon2id' && typeof argon2Sync === 'function') {
    return argon2Sync('argon2id', {
      message: Buffer.from(String(passphrase || '')),
      nonce: salt,
      parallelism: kdf.parallelism || 1,
      memory: kdf.memory || 64 * 1024,
      passes: kdf.time || 3,
      tagLength: 32,
    });
  }
  return pbkdf2Sync(String(passphrase || ''), salt, kdf.iterations || PBKDF2_ITERATIONS, 32, 'sha256');
}

function encryptBlobWithPassphrase(value, passphrase, options = {}) {
  const salt = randomBytes(16);
  const { key, kdf } = deriveKey(passphrase, salt, options);
  const iv = randomBytes(12);
  const plaintext = Buffer.from(JSON.stringify(value));
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const mac = createHmac('sha256', key)
    .update(iv)
    .update(tag)
    .update(ciphertext)
    .digest('base64');

  return {
    schemaVersion: KEY_VAULT_SCHEMA_VERSION,
    kdf,
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    mac,
    updatedAt: Date.now(),
  };
}

function decryptBlobWithPassphrase(blob, passphrase) {
  if (!blob || blob.schemaVersion !== KEY_VAULT_SCHEMA_VERSION) {
    throw new Error('KeyVault unsupported schema version');
  }
  const key = deriveKeyFromStoredKdf(passphrase, blob.kdf);
  const iv = Buffer.from(blob.iv, 'base64');
  const tag = Buffer.from(blob.tag, 'base64');
  const ciphertext = Buffer.from(blob.ciphertext, 'base64');
  const expectedMac = createHmac('sha256', key)
    .update(iv)
    .update(tag)
    .update(ciphertext)
    .digest('base64');
  if (expectedMac !== blob.mac) {
    throw new Error('KeyVault authentication failed');
  }

  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(plaintext.toString('utf8'));
  } catch {
    throw new Error('KeyVault authentication failed');
  }
}

function encryptBlobWithArgon2Passphrase(value, passphrase) {
  if (typeof argon2Sync !== 'function') {
    return encryptBlobWithPassphrase(value, passphrase, { preferArgon2: false });
  }
  const salt = randomBytes(16);
  const key = argon2Sync('argon2id', {
    message: Buffer.from(String(passphrase || '')),
    nonce: salt,
    parallelism: 1,
    memory: 64 * 1024,
    passes: 3,
    tagLength: 32,
  });
  const iv = randomBytes(12);
  const plaintext = Buffer.from(JSON.stringify(value));
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    schemaVersion: KEY_VAULT_SCHEMA_VERSION,
    kdf: {
      type: 'argon2id',
      memory: 64 * 1024,
      time: 3,
      parallelism: 1,
      salt: salt.toString('base64'),
    },
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    updatedAt: Date.now(),
  };
}

function decryptBlobWithArgon2Passphrase(blob, passphrase) {
  if (!blob || blob?.kdf?.type !== 'argon2id') {
    throw new Error('Backup must use argon2id KDF');
  }
  if (typeof argon2Sync !== 'function') {
    throw new Error('Argon2 support is required for backup import');
  }
  const salt = Buffer.from(blob.kdf.salt, 'base64');
  const key = argon2Sync('argon2id', {
    message: Buffer.from(String(passphrase || '')),
    nonce: salt,
    parallelism: blob.kdf.parallelism || 1,
    memory: blob.kdf.memory || 64 * 1024,
    passes: blob.kdf.time || 3,
    tagLength: 32,
  });
  const iv = Buffer.from(blob.iv, 'base64');
  const tag = Buffer.from(blob.tag, 'base64');
  const ciphertext = Buffer.from(blob.ciphertext, 'base64');
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(plaintext.toString('utf8'));
  } catch {
    throw new Error('KeyVault authentication failed');
  }
}

class KeyVault {
  constructor({ storageDir, filename = 'securechat.keys.enc' }) {
    if (!storageDir) {
      throw new Error('KeyVault requires storageDir');
    }
    this.storageDir = storageDir;
    this.filePath = path.join(storageDir, filename);
    this.unlockedKeys = null;
  }

  lockKeys({ identityPrivateKey, devicePrivateKey }, passphrase, options = {}) {
    if (!identityPrivateKey || !devicePrivateKey) {
      throw new Error('KeyVault requires both identityPrivateKey and devicePrivateKey');
    }
    const payload = encryptBlobWithPassphrase({
      identityPrivateKey,
      devicePrivateKey,
    }, passphrase, options);

    fs.mkdirSync(this.storageDir, { recursive: true });
    const tmpPath = `${this.filePath}.tmp`;
    fs.writeFileSync(tmpPath, `${JSON.stringify(payload)}\n`, { mode: 0o600 });
    fs.renameSync(tmpPath, this.filePath);
    this.unlockedKeys = null;
  }

  unlock(passphrase) {
    const raw = fs.readFileSync(this.filePath, 'utf8');
    const payload = JSON.parse(raw);
    const parsed = decryptBlobWithPassphrase(payload, passphrase);

    this.unlockedKeys = {
      identityPrivateKey: parsed.identityPrivateKey,
      devicePrivateKey: parsed.devicePrivateKey,
      unlockedAt: Date.now(),
    };

    return {
      identityPrivateKey: this.unlockedKeys.identityPrivateKey,
      devicePrivateKey: this.unlockedKeys.devicePrivateKey,
    };
  }

  getUnlockedKeys() {
    if (!this.unlockedKeys) {
      throw new Error('KeyVault is locked');
    }
    return {
      identityPrivateKey: this.unlockedKeys.identityPrivateKey,
      devicePrivateKey: this.unlockedKeys.devicePrivateKey,
    };
  }

  isLocked() {
    return !this.unlockedKeys;
  }

  clearUnlockedKeys() {
    this.unlockedKeys = null;
  }
}

module.exports = {
  KeyVault,
  KEY_VAULT_SCHEMA_VERSION,
  encryptBlobWithPassphrase,
  decryptBlobWithPassphrase,
  encryptBlobWithArgon2Passphrase,
  decryptBlobWithArgon2Passphrase,
};
