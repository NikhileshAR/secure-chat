const fs = require('node:fs');
const path = require('node:path');
const {
  randomBytes,
  generateKeyPairSync,
  sign,
  verify,
  createPrivateKey,
  createPublicKey,
} = require('node:crypto');

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

class NetworkIdentityManager {
  constructor({ storageDir, filename = 'securechat.network.identity.json' } = {}) {
    if (!storageDir) {
      throw new Error('NetworkIdentityManager requires storageDir');
    }
    this.storageDir = storageDir;
    this.filePath = path.join(storageDir, filename);
    this.identity = null;
  }

  generateNetworkIdentity() {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    return {
      schemaVersion: 1,
      networkId: randomBytes(16).toString('hex'),
      networkPublicKey: publicKey.export({ type: 'spki', format: 'pem' }),
      networkPrivateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
      createdAt: Date.now(),
    };
  }

  validateIdentity(identity) {
    return Boolean(
      identity
      && identity.schemaVersion === 1
      && typeof identity.networkId === 'string'
      && identity.networkId.length === 32
      && typeof identity.networkPublicKey === 'string'
      && typeof identity.networkPrivateKey === 'string',
    );
  }

  loadOrCreate() {
    if (this.identity) {
      return this.identity;
    }
    if (!fs.existsSync(this.filePath)) {
      this.identity = this.generateNetworkIdentity();
      this.persist();
      return this.identity;
    }
    try {
      const raw = fs.readFileSync(this.filePath, 'utf8');
      const parsed = JSON.parse(raw);
      if (!this.validateIdentity(parsed)) {
        throw new Error('invalid identity file');
      }
      this.identity = parsed;
      return this.identity;
    } catch {
      this.identity = this.generateNetworkIdentity();
      this.persist();
      return this.identity;
    }
  }

  persist() {
    fs.mkdirSync(this.storageDir, { recursive: true });
    const tmpPath = `${this.filePath}.tmp`;
    fs.writeFileSync(tmpPath, `${JSON.stringify(this.identity)}\n`, { mode: 0o600 });
    fs.renameSync(tmpPath, this.filePath);
  }

  getNetworkIdentity() {
    const identity = this.loadOrCreate();
    return {
      networkId: identity.networkId,
      networkPublicKey: identity.networkPublicKey,
      createdAt: identity.createdAt,
    };
  }

  signNetworkMetadata(data) {
    const identity = this.loadOrCreate();
    const payload = Buffer.from(stableStringify(data), 'utf8');
    return sign(null, payload, createPrivateKey(identity.networkPrivateKey)).toString('base64');
  }

  verifyNetworkSignature(data, signature, publicKey) {
    if (!signature || !publicKey) {
      return false;
    }
    const payload = Buffer.from(stableStringify(data), 'utf8');
    try {
      return verify(
        null,
        payload,
        createPublicKey(publicKey),
        Buffer.from(String(signature), 'base64'),
      );
    } catch {
      return false;
    }
  }
}

module.exports = {
  NetworkIdentityManager,
  stableStringify,
};
