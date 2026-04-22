const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

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

test('new identity is created per client instance', () => {
  const manager = new InstanceManager();
  const contextA = manager.getContext(`ui-test-a-${Date.now()}-${Math.random()}`);
  const contextB = manager.getContext(`ui-test-b-${Date.now()}-${Math.random()}`);

  const stateA = manager.serializeState(contextA);
  const stateB = manager.serializeState(contextB);
  assert.notEqual(stateA.identity.fingerprint, stateB.identity.fingerprint);

  closeAndCleanupContext(contextA);
  closeAndCleanupContext(contextB);
});

test('reset identity generates a new fingerprint', () => {
  const manager = new InstanceManager();
  const context = manager.getContext(`ui-test-reset-${Date.now()}-${Math.random()}`);

  const before = manager.serializeState(context).identity.fingerprint;
  manager.resetIdentity(context);
  const after = manager.serializeState(context).identity.fingerprint;
  assert.notEqual(before, after);

  closeAndCleanupContext(context);
});

test('message sender detection uses sender identity public key', () => {
  const myIdentity = 'my-public-key';
  const outbound = { senderIdentityPublicKey: 'my-public-key' };
  const inbound = { senderIdentityPublicKey: 'peer-public-key' };

  assert.equal(appHelpers.detectMessageRole(outbound, myIdentity), 'you');
  assert.equal(appHelpers.detectMessageRole(inbound, myIdentity), 'peer');
});

test('contact add flow auto-trusts and stores contact details', () => {
  const manager = new InstanceManager();
  const contextA = manager.getContext(`ui-test-contact-a-${Date.now()}-${Math.random()}`);
  const contextB = manager.getContext(`ui-test-contact-b-${Date.now()}-${Math.random()}`);

  contextB.state.relays = ['ws://relay.example:8080'];
  const shared = manager.getIdentitySharePayload(contextB);
  const added = manager.addContactFromPayload(contextA, shared.text, '');

  assert.equal(added.trustLevel, 'TRUSTED');
  assert.equal(added.fingerprint, shared.payload.fingerprint);
  assert.equal(added.deviceName, shared.payload.deviceName);

  const contacts = manager.listContactsWithTrust(contextA);
  assert.equal(contacts.length, 1);
  assert.equal(contacts[0].trustLevel, 'TRUSTED');

  closeAndCleanupContext(contextA);
  closeAndCleanupContext(contextB);
});
