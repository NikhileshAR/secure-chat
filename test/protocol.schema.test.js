const test = require('node:test');
const assert = require('node:assert/strict');

const { validateMessage, canonicalSerialize } = require('../src/protocol/schema');

test('schema validates array item types and object fields', () => {
  assert.throws(() => {
    validateMessage({
      type: 'pull',
      protocolVersion: '1.0',
      senderDeviceId: 'd1',
      encryptedPayload: '',
      timestamp: Date.now(),
      routeTags: ['ok', 2],
    }, { allowLegacy: false });
  }, /invalid item type/i);

  assert.throws(() => {
    validateMessage({
      type: 'handshake',
      protocolVersion: '1.0',
      senderDeviceId: 'd1',
      encryptedPayload: '',
      timestamp: Date.now(),
      publicKeys: 'bad-object',
    }, { allowLegacy: false });
  }, /must be an object/i);
});

test('canonical serialization keeps deterministic key order', () => {
  const first = canonicalSerialize({ b: 1, a: { d: 2, c: 3 } });
  const second = canonicalSerialize({ a: { c: 3, d: 2 }, b: 1 });
  assert.equal(first, second);
});
