const fs = require('node:fs');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const { stableStringify } = require('./networkIdentity');

function base64UrlEncode(value) {
  return Buffer.from(value)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function base64UrlDecode(value) {
  const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
  return Buffer.from(`${normalized}${padding}`, 'base64').toString('utf8');
}

class InviteManager {
  constructor({
    networkIdentity,
    storageDir,
    usageFilename = 'securechat.invite.usage.json',
  } = {}) {
    if (!networkIdentity) {
      throw new Error('InviteManager requires networkIdentity');
    }
    if (!storageDir) {
      throw new Error('InviteManager requires storageDir');
    }
    this.networkIdentity = networkIdentity;
    this.storageDir = storageDir;
    this.usagePath = path.join(storageDir, usageFilename);
    this.usage = null;
  }

  ensureUsageLoaded() {
    if (this.usage) {
      return this.usage;
    }
    if (!fs.existsSync(this.usagePath)) {
      this.usage = {};
      return this.usage;
    }
    try {
      this.usage = JSON.parse(fs.readFileSync(this.usagePath, 'utf8'));
    } catch {
      this.usage = {};
    }
    return this.usage;
  }

  saveUsage() {
    fs.mkdirSync(this.storageDir, { recursive: true });
    const tmp = `${this.usagePath}.tmp`;
    fs.writeFileSync(tmp, `${JSON.stringify(this.usage)}\n`, { mode: 0o600 });
    fs.renameSync(tmp, this.usagePath);
  }

  generateToken({ expiresAt, usageLimit = 1, label } = {}) {
    const now = Date.now();
    const expiry = Number(expiresAt);
    const payload = {
      tokenId: randomBytes(16).toString('hex'),
      issuedAt: now,
      expiresAt: Number.isFinite(expiry) ? expiry : now + 24 * 60 * 60 * 1000,
      usageLimit: Math.max(1, Number(usageLimit) || 1),
      ...(label ? { label: String(label) } : {}),
    };
    const signature = this.networkIdentity.signNetworkMetadata(payload);
    return `${base64UrlEncode(stableStringify(payload))}.${base64UrlEncode(signature)}`;
  }

  parseToken(token) {
    const parts = String(token || '').split('.');
    if (parts.length !== 2) {
      return null;
    }
    try {
      const payload = JSON.parse(base64UrlDecode(parts[0]));
      const signature = base64UrlDecode(parts[1]);
      return { payload, signature };
    } catch {
      return null;
    }
  }

  verifyToken(token, { consume = false } = {}) {
    const parsed = this.parseToken(token);
    if (!parsed) {
      return { valid: false, reason: 'invalid_format' };
    }
    const { payload, signature } = parsed;
    const { networkPublicKey } = this.networkIdentity.getNetworkIdentity();
    const signatureOk = this.networkIdentity.verifyNetworkSignature(payload, signature, networkPublicKey);
    if (!signatureOk) {
      return { valid: false, reason: 'invalid_signature' };
    }
    if (Date.now() > Number(payload.expiresAt)) {
      return { valid: false, reason: 'expired' };
    }
    this.ensureUsageLoaded();
    const used = Number(this.usage[payload.tokenId] || 0);
    if (used >= Number(payload.usageLimit || 0)) {
      return { valid: false, reason: 'usage_limit_reached' };
    }
    if (consume) {
      this.usage[payload.tokenId] = used + 1;
      this.saveUsage();
    }
    return {
      valid: true,
      payload,
      usage: {
        used,
        usageLimit: Number(payload.usageLimit),
      },
    };
  }
}

module.exports = {
  InviteManager,
};
