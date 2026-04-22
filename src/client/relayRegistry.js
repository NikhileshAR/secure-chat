const fs = require('node:fs');
const path = require('node:path');

class RelayRegistry {
  constructor({ storageDir, filename = 'securechat.relays.json' } = {}) {
    if (!storageDir) {
      throw new Error('RelayRegistry requires storageDir');
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
      this.entries = [];
      return this.entries;
    }
    try {
      this.entries = JSON.parse(fs.readFileSync(this.filePath, 'utf8')) || [];
    } catch {
      this.entries = [];
    }
    return this.entries;
  }

  save() {
    fs.mkdirSync(this.storageDir, { recursive: true });
    const tmpPath = `${this.filePath}.tmp`;
    fs.writeFileSync(tmpPath, `${JSON.stringify(this.entries)}\n`, { mode: 0o600 });
    fs.renameSync(tmpPath, this.filePath);
  }

  upsert({ url, label, trustLevel = 'TRUSTED' }) {
    if (!url) {
      return null;
    }
    const entries = this.ensureLoaded();
    const now = Date.now();
    const idx = entries.findIndex((entry) => entry.url === url);
    const next = {
      url,
      label: label || (idx >= 0 ? entries[idx].label : undefined),
      trustLevel,
      lastSeen: now,
    };
    if (idx >= 0) {
      entries[idx] = { ...entries[idx], ...next };
    } else {
      entries.push(next);
    }
    this.save();
    return next;
  }

  list() {
    return [...this.ensureLoaded()];
  }
}

module.exports = {
  RelayRegistry,
};
