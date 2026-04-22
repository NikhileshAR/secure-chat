class RelayRegistry {
  constructor() {
    this.relays = new Map();
    this.rotationIndex = 0;
  }

  addRelay(url, label = 'relay', trustLevel = 'UNKNOWN') {
    const normalized = String(url || '').trim();
    if (!normalized) {
      throw new Error('Relay URL is required');
    }
    const now = Date.now();
    const existing = this.relays.get(normalized);
    this.relays.set(normalized, {
      url: normalized,
      label: String(label || 'relay'),
      trustLevel: String(trustLevel || 'UNKNOWN').toUpperCase(),
      lastSeen: existing?.lastSeen || 0,
      addedAt: existing?.addedAt || now,
      updatedAt: now,
    });
  }

  removeRelay(url) {
    return this.relays.delete(String(url || '').trim());
  }

  markSeen(url, when = Date.now()) {
    const entry = this.relays.get(String(url || '').trim());
    if (!entry) {
      return false;
    }
    entry.lastSeen = when;
    entry.updatedAt = when;
    this.relays.set(entry.url, entry);
    return true;
  }

  listRelays() {
    return [...this.relays.values()].map((entry) => ({ ...entry }));
  }

  chooseRandomRelay() {
    const relays = this.listRelays();
    if (!relays.length) {
      return null;
    }
    const index = Math.floor(Math.random() * relays.length);
    return relays[index];
  }

  chooseNextRelay() {
    const relays = this.listRelays();
    if (!relays.length) {
      return null;
    }
    const relay = relays[this.rotationIndex % relays.length];
    this.rotationIndex += 1;
    return relay;
  }
}

module.exports = {
  RelayRegistry,
};
