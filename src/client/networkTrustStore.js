const fs = require('node:fs');
const path = require('node:path');
const {
  createPublicKey,
  verify,
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

function verifyNetworkSignature(data, signature, publicKey) {
  if (!signature || !publicKey) {
    return false;
  }
  try {
    return verify(
      null,
      Buffer.from(stableStringify(data), 'utf8'),
      createPublicKey(publicKey),
      Buffer.from(String(signature), 'base64'),
    );
  } catch {
    return false;
  }
}

class NetworkTrustStore {
  constructor({ storageDir, filename = 'securechat.network.trust.json' } = {}) {
    if (!storageDir) {
      throw new Error('NetworkTrustStore requires storageDir');
    }
    this.storageDir = storageDir;
    this.filePath = path.join(storageDir, filename);
    this.entries = null;
  }

  ensureLoaded() {
    if (this.entries) {
      return this.entries;
    }
    if (!fs.existsSync(this.filePath)) {
      this.entries = {};
      return this.entries;
    }
    try {
      this.entries = JSON.parse(fs.readFileSync(this.filePath, 'utf8')) || {};
    } catch {
      this.entries = {};
    }
    return this.entries;
  }

  save() {
    fs.mkdirSync(this.storageDir, { recursive: true });
    const tmp = `${this.filePath}.tmp`;
    fs.writeFileSync(tmp, `${JSON.stringify(this.entries)}\n`, { mode: 0o600 });
    fs.renameSync(tmp, this.filePath);
  }

  get(networkId) {
    return this.ensureLoaded()[networkId] || null;
  }

  set(networkId, entry) {
    this.ensureLoaded()[networkId] = entry;
    this.save();
    return entry;
  }

  verifyAndTrust({
    networkId,
    networkPublicKey,
    networkMetadata,
    networkMetadataSignature,
    bundle,
  } = {}) {
    if (!networkId || !networkPublicKey) {
      return { ok: false, reason: 'missing_network_identity' };
    }
    if (!verifyNetworkSignature(networkMetadata || {}, networkMetadataSignature, networkPublicKey)) {
      return { ok: false, reason: 'invalid_network_signature' };
    }
    if (bundle?.networkId && bundle.networkId !== networkId) {
      return { ok: false, reason: 'bundle_network_id_mismatch' };
    }
    if (bundle?.networkPublicKey && bundle.networkPublicKey !== networkPublicKey) {
      return { ok: false, reason: 'bundle_network_key_mismatch' };
    }

    const now = Date.now();
    const existing = this.get(networkId);
    if (!existing) {
      return {
        ok: true,
        entry: this.set(networkId, {
          networkId,
          networkPublicKey,
          firstSeen: now,
          lastSeen: now,
          trustLevel: 'TRUSTED',
        }),
      };
    }
    if (existing.networkPublicKey !== networkPublicKey && existing.trustLevel === 'TRUSTED') {
      return { ok: false, reason: 'network_key_changed' };
    }
    return {
      ok: true,
      entry: this.set(networkId, {
        ...existing,
        lastSeen: now,
      }),
    };
  }
}

module.exports = {
  NetworkTrustStore,
  stableStringify,
  verifyNetworkSignature,
};
