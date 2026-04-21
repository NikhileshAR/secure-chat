const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { KeyVault } = require('../src/client/storage/keyVault');
const { SessionStore } = require('../src/client/storage/sessionStore');

test('key vault encrypts at rest and unlocks in memory only', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'securechat-vault-'));
  const vault = new KeyVault({ storageDir: dir });

  vault.lockKeys({
    identityPrivateKey: 'identity-private-key',
    devicePrivateKey: 'device-private-key',
  }, 'passphrase-1', { preferArgon2: false });

  const stored = fs.readFileSync(path.join(dir, 'securechat.keys.enc'), 'utf8');
  assert.equal(stored.includes('identity-private-key'), false);
  assert.equal(stored.includes('device-private-key'), false);
  assert.throws(() => vault.unlock('wrong-passphrase'), /authentication failed/i);

  const unlocked = vault.unlock('passphrase-1');
  assert.equal(unlocked.identityPrivateKey, 'identity-private-key');
  assert.equal(unlocked.devicePrivateKey, 'device-private-key');

  vault.clearUnlockedKeys();
  assert.equal(vault.isLocked(), true);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('session store persists and loads bounded skipped keys', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'securechat-store-'));
  const store = new SessionStore({
    storageDir: dir,
    deviceSecret: 'device-secret-1',
    maxSkippedMessageKeys: 2,
  });

  const session = {
    rootKey: Buffer.alloc(32, 1),
    chainKeySend: Buffer.alloc(32, 2),
    chainKeyReceive: Buffer.alloc(32, 3),
    sendCounter: 1,
    receiveCounter: 1,
    previousCounter: 0,
    lastDHKey: 'peer-dh',
    currentReceiveDhKey: 'peer-dh',
    selfDHKeyPair: { publicKey: 'pub', privateKey: 'priv' },
    ratchetPending: false,
    expiresAt: Date.now() + 10_000,
    skippedMessageKeys: new Map([
      ['a', Buffer.alloc(32, 7)],
      ['b', Buffer.alloc(32, 8)],
      ['c', Buffer.alloc(32, 9)],
    ]),
    seenMessageIds: new Map([['m1', Date.now() + 1000]]),
  };

  store.saveSessions(new Map([['peer-1', session]]));
  const loaded = store.loadSessions();

  assert.equal(loaded.size, 1);
  const restored = loaded.get('peer-1');
  assert.equal(restored.skippedMessageKeys.size, 2);

  fs.rmSync(dir, { recursive: true, force: true });
});
