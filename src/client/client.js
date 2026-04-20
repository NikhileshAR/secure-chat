const { WebSocket } = require('ws');
const { randomUUID, randomBytes } = require('node:crypto');
const { generateIdentity } = require('./identity');
const { encryptPayload, decryptPayload, computeRouteTag, signMessage, verifyMessage } = require('./crypto');

class SekureClient {
  constructor({ serverUrl, identity = generateIdentity(), postQuantumPublicKey }) {
    this.serverUrl = serverUrl;
    this.identity = identity;
    this.postQuantumPublicKey = postQuantumPublicKey || randomBytes(32).toString('base64');
    this.socket = null;
  }

  async connect() {
    this.socket = new WebSocket(this.serverUrl);

    await new Promise((resolve, reject) => {
      this.socket.once('open', resolve);
      this.socket.once('error', reject);
    });

    this.sendRaw({
      type: 'handshake',
      senderDeviceId: this.identity.deviceId,
      timestamp: Date.now(),
      encryptedPayload: '',
      publicKeys: {
        identity: this.identity.identityKeyPair.publicKey,
        classicalDevice: this.identity.deviceKeyPair.publicKey,
        postQuantumDevice: this.postQuantumPublicKey,
      },
    });
  }

  sendRaw(message) {
    if (!this.socket || this.socket.readyState !== this.socket.OPEN) {
      throw new Error('Client is not connected');
    }
    this.socket.send(`${JSON.stringify(message)}\n`);
  }

  sendChat({ content, recipientDevicePublicKey, routeSecret, attachments }) {
    const payload = {
      messageId: randomUUID(),
      content,
      attachments,
    };

    const encrypted = encryptPayload(
      payload,
      this.identity.deviceKeyPair.privateKey,
      recipientDevicePublicKey,
    );

    const baseMessage = {
      type: 'chat',
      senderDeviceId: this.identity.deviceId,
      routeTag: computeRouteTag(routeSecret),
      encryptedPayload: JSON.stringify(encrypted),
      timestamp: Date.now(),
    };

    const signature = signMessage(this.identity.identityKeyPair.privateKey, baseMessage);
    this.sendRaw({ ...baseMessage, signature });

    return baseMessage;
  }

  decryptChat({ message, senderDevicePublicKey, senderIdentityPublicKey }) {
    if (message.signature) {
      const { signature, ...unsigned } = message;
      if (!verifyMessage(senderIdentityPublicKey, unsigned, signature)) {
        throw new Error('Invalid message signature');
      }
    }

    return decryptPayload(
      JSON.parse(message.encryptedPayload),
      this.identity.deviceKeyPair.privateKey,
      senderDevicePublicKey,
    );
  }

  pull(routeSecrets = []) {
    this.sendRaw({
      type: 'control',
      senderDeviceId: this.identity.deviceId,
      encryptedPayload: '',
      timestamp: Date.now(),
      action: 'pull',
      routeTags: routeSecrets.map((secret) => computeRouteTag(secret)),
    });
  }

  close() {
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
  }
}

module.exports = {
  SekureClient,
};
