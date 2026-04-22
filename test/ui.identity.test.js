const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { randomBytes } = require('node:crypto');

const { InstanceManager } = require('../app/server');
const appHelpers = require('../app/public/app');

function closeAndCleanupContext(context) {
  if (!context) {
    return;
  }
  if (context.reconnectTimer) {
    clearTimeout(context.reconnectTimer);
  }
  if (context.pollTimer) {
    clearTimeout(context.pollTimer);
  }
  if (context.client) {
    context.client.close();
  }
  fs.rmSync(context.paths.baseDir, { recursive: true, force: true });
}

function createTestInstanceId(prefix) {
  return `${prefix}-${randomBytes(6).toString('hex')}`;
}

test('new identity is created per client instance', (t) => {
  const manager = new InstanceManager();
  const contextA = manager.getContext(createTestInstanceId('ui-test-a'));
  const contextB = manager.getContext(createTestInstanceId('ui-test-b'));
  t.after(() => {
    closeAndCleanupContext(contextA);
    closeAndCleanupContext(contextB);
  });

  const stateA = manager.serializeState(contextA);
  const stateB = manager.serializeState(contextB);
  assert.notEqual(stateA.identity.fingerprint, stateB.identity.fingerprint);
});

test('reset identity generates a new fingerprint', (t) => {
  const manager = new InstanceManager();
  const context = manager.getContext(createTestInstanceId('ui-test-reset'));
  t.after(() => {
    closeAndCleanupContext(context);
  });

  const before = manager.serializeState(context).identity.fingerprint;
  manager.resetIdentity(context);
  const after = manager.serializeState(context).identity.fingerprint;
  assert.notEqual(before, after);
});

test('message sender detection uses sender identity public key', () => {
  const myIdentity = 'my-public-key';
  const outbound = { senderIdentityPublicKey: 'my-public-key' };
  const inbound = { senderIdentityPublicKey: 'peer-public-key' };

  assert.equal(appHelpers.detectMessageRole(outbound, myIdentity), 'you');
  assert.equal(appHelpers.detectMessageRole(inbound, myIdentity), 'peer');
});

test('contact add flow auto-trusts and stores contact details', (t) => {
  const manager = new InstanceManager();
  const contextA = manager.getContext(createTestInstanceId('ui-test-contact-a'));
  const contextB = manager.getContext(createTestInstanceId('ui-test-contact-b'));
  t.after(() => {
    closeAndCleanupContext(contextA);
    closeAndCleanupContext(contextB);
  });

  contextB.state.relays = ['ws://relay.example:8080'];
  const shared = manager.getIdentitySharePayload(contextB);
  const added = manager.addContactFromPayload(contextA, shared.text, '');

  assert.equal(added.trustLevel, 'TRUSTED');
  assert.equal(added.fingerprint, shared.payload.fingerprint);
  assert.equal(added.deviceName, shared.payload.deviceName);

  const contacts = manager.listContactsWithTrust(contextA);
  assert.equal(contacts.length, 1);
  assert.equal(contacts[0].trustLevel, 'TRUSTED');
});
