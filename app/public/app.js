const APP_HELPERS = (() => {
  const INSTANCE_KEY = 'securechat.clientInstanceId';
  const DEVICE_NAME_KEY = 'securechat.deviceName';

  function randomUuid() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
      return crypto.randomUUID();
    }
    const seed = `${Date.now()}-${Math.random()}-${Math.random()}`;
    return `id-${seed.replace(/[^a-zA-Z0-9]/g, '').slice(0, 24)}`;
  }

  function createClientInstanceId({ sessionStorage, localStorage, uuidFactory = randomUuid }) {
    const existing = sessionStorage.getItem(INSTANCE_KEY);
    if (existing) {
      return existing;
    }
    const created = uuidFactory();
    sessionStorage.setItem(INSTANCE_KEY, created);
    const markerKey = `identity_${created}`;
    if (!localStorage.getItem(markerKey)) {
      localStorage.setItem(markerKey, JSON.stringify({ createdAt: Date.now() }));
    }
    return created;
  }

  function clearIdentityMarker({ localStorage, clientInstanceId }) {
    localStorage.removeItem(`identity_${clientInstanceId}`);
  }

  function createDefaultDeviceName({ localStorage }) {
    const existing = localStorage.getItem(DEVICE_NAME_KEY);
    if (existing && existing.trim()) {
      return existing.trim();
    }
    const suffix = String(Math.floor(Math.random() * 10_000)).padStart(4, '0');
    const created = `Device-${suffix}`;
    localStorage.setItem(DEVICE_NAME_KEY, created);
    return created;
  }

  function saveDeviceName({ localStorage, name }) {
    const normalized = String(name || '').trim();
    if (!normalized) {
      return null;
    }
    localStorage.setItem(DEVICE_NAME_KEY, normalized);
    return normalized;
  }

  function shortIdFromFingerprint(fingerprint) {
    return String(fingerprint || '').replace(/:/g, '').slice(0, 8);
  }

  function detectMessageRole(message, myIdentityPublicKey) {
    if (!message || !myIdentityPublicKey) {
      return 'peer';
    }
    return message.senderIdentityPublicKey === myIdentityPublicKey ? 'you' : 'peer';
  }

  return {
    INSTANCE_KEY,
    DEVICE_NAME_KEY,
    createClientInstanceId,
    clearIdentityMarker,
    createDefaultDeviceName,
    saveDeviceName,
    shortIdFromFingerprint,
    detectMessageRole,
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = APP_HELPERS;
}

if (typeof window !== 'undefined') {
  const state = {
    contacts: [],
    selectedContactId: null,
    messagesByContact: new Map(),
    identityPublicKey: null,
    fingerprint: '',
    connection: null,
    debugVisible: false,
    clientInstanceId: APP_HELPERS.createClientInstanceId({
      sessionStorage: window.sessionStorage,
      localStorage: window.localStorage,
    }),
    deviceName: APP_HELPERS.createDefaultDeviceName({ localStorage: window.localStorage }),
  };

  function byId(id) {
    return document.getElementById(id);
  }

  async function api(path, options = {}) {
    const headers = Object.fromEntries(Object.entries({
      'content-type': 'application/json',
      'x-client-instance-id': state.clientInstanceId,
      'x-device-name': state.deviceName,
      ...(options.headers || {}),
    }).filter(([, value]) => value !== undefined && value !== null));
    const res = await fetch(path, {
      ...options,
      headers,
    });
    const body = await res.json();
    if (!res.ok) {
      throw new Error(body.error || 'Request failed');
    }
    return body;
  }

  function renderConnection(connection) {
    state.connection = connection;
    const dot = connection.status === 'CONNECTED'
      ? '● Connected'
      : connection.status === 'CONNECTING'
        ? '● Connecting...'
        : '● Disconnected';
    byId('connectionStatus').textContent = connection.lastError ? `${dot} - ${connection.lastError}` : dot;

    const relays = Array.isArray(connection.relays) ? connection.relays : [];
    const active = connection.activeRelayUrl || 'n/a';
    const fallback = relays.find((url) => url !== connection.activeRelayUrl) || 'n/a';
    byId('relayStatus').textContent = `Connected to: ${active} (fallback: ${fallback})`;
  }

  function renderContactInfo(contact) {
    const block = byId('contactInfo');
    if (!contact) {
      block.classList.add('hidden');
      return;
    }
    block.classList.remove('hidden');
    byId('contactFingerprint').textContent = contact.fingerprint;
    byId('contactTrust').textContent = contact.trustLevel;
    byId('contactShortId').textContent = contact.shortId || APP_HELPERS.shortIdFromFingerprint(contact.fingerprint);
  }

  function renderContacts(contacts) {
    state.contacts = contacts;
    const list = byId('contactsList');
    list.innerHTML = '';
    for (const contact of contacts) {
      const item = document.createElement('li');
      item.textContent = `${contact.label} • ${contact.trustLevel} • ${contact.shortId}`;
      list.appendChild(item);
    }

    const select = byId('chatContactSelect');
    const previous = state.selectedContactId;
    select.innerHTML = '<option value="">Select contact</option>';
    for (const contact of contacts) {
      const option = document.createElement('option');
      option.value = contact.id;
      option.textContent = `${contact.label} (${contact.trustLevel})`;
      select.appendChild(option);
    }

    if (previous && contacts.some((contact) => contact.id === previous)) {
      select.value = previous;
      renderContactInfo(contacts.find((contact) => contact.id === previous));
    } else {
      renderContactInfo(null);
    }
  }

  function renderMessages(contactId) {
    const container = byId('chatMessages');
    if (!contactId) {
      container.innerHTML = '<p>Select a contact to view chat.</p>';
      return;
    }
    const contact = state.contacts.find((entry) => entry.id === contactId);
    const messages = state.messagesByContact.get(contactId) || [];
    container.innerHTML = '';

    for (const message of messages) {
      const role = APP_HELPERS.detectMessageRole(message, state.identityPublicKey);
      const wrapper = document.createElement('div');
      wrapper.className = `msg ${role}`;

      const meta = document.createElement('div');
      meta.className = 'meta';
      const when = new Date(message.timestamp || Date.now()).toLocaleTimeString();
      const ownLabel = `[${state.deviceName}] You`;
      const peerName = message.senderLabel || contact?.label || 'Peer';
      const peerLabel = `[${peerName}] Peer`;
      meta.textContent = `${role === 'you' ? ownLabel : peerLabel} • ${when} • ${message.status}`;

      const content = document.createElement('div');
      content.textContent = message.content;
      wrapper.appendChild(meta);
      wrapper.appendChild(content);
      container.appendChild(wrapper);
    }

    container.scrollTop = container.scrollHeight;
  }

  function renderDebug(snapshot) {
    byId('debugFingerprint').textContent = snapshot.identity.fingerprint;
    byId('debugRelay').textContent = snapshot.connection.activeRelayUrl || 'n/a';
    byId('debugConnection').textContent = snapshot.connection.status;
    byId('debugSessions').textContent = String(snapshot.debug.sessionCount);
  }

  async function loadState() {
    const snapshot = await api('/api/state', {
      method: 'GET',
      headers: { 'content-type': undefined },
    });

    state.identityPublicKey = snapshot.identity.publicKey;
    state.fingerprint = snapshot.identity.fingerprint;
    state.deviceName = snapshot.identity.deviceName || state.deviceName;

    byId('fingerprint').textContent = snapshot.identity.fingerprint;
    byId('shortId').textContent = APP_HELPERS.shortIdFromFingerprint(snapshot.identity.fingerprint);
    byId('deviceName').value = state.deviceName;

    renderConnection(snapshot.connection);
    renderContacts(snapshot.contacts);
    renderDebug(snapshot);
  }

  async function refreshCurrentMessages() {
    if (!state.selectedContactId) {
      return;
    }
    const response = await api(`/api/messages?contactId=${encodeURIComponent(state.selectedContactId)}`, {
      method: 'GET',
      headers: { 'content-type': undefined },
    });
    state.messagesByContact.set(state.selectedContactId, response.messages || []);
    renderMessages(state.selectedContactId);
  }

  async function handleConnect() {
    const relayInput = byId('relayUrl').value.trim();
    const relayUrls = relayInput
      ? relayInput.split(',').map((entry) => entry.trim()).filter(Boolean)
      : [];
    const configFile = byId('configFile').files[0];
    let clientConfig = null;

    if (configFile) {
      clientConfig = JSON.parse(await configFile.text());
    }

    await api('/api/connection/connect', {
      method: 'POST',
      body: JSON.stringify({ relayUrl: relayUrls[0], relayUrls, clientConfig }),
    });
    await loadState();
  }

  async function handleShareIdentity() {
    const payload = await api('/api/identity/share', {
      method: 'GET',
      headers: { 'content-type': undefined },
    });
    byId('sharePanel').classList.remove('hidden');
    byId('shareQr').src = payload.qrImageUrl;
    byId('shareText').value = payload.text;
  }

  async function handleAddContact() {
    const payloadText = byId('contactPayload').value.trim();
    const label = byId('contactLabel').value.trim();
    if (!payloadText) {
      throw new Error('Contact payload is required');
    }
    await api('/api/contacts/add', {
      method: 'POST',
      body: JSON.stringify({ payloadText, label }),
    });
    byId('contactPayload').value = '';
    byId('contactLabel').value = '';
    byId('scanStatus').textContent = 'Contact added and trusted.';
    await loadState();
  }

  async function handleSend() {
    if (!state.selectedContactId) {
      throw new Error('Select a contact');
    }
    const content = byId('chatInput').value.trim();
    if (!content) {
      return;
    }
    await api('/api/chat/send', {
      method: 'POST',
      body: JSON.stringify({ contactId: state.selectedContactId, content }),
    });
    byId('chatInput').value = '';
    await refreshCurrentMessages();
  }

  async function createNewIdentity() {
    APP_HELPERS.clearIdentityMarker({ localStorage: window.localStorage, clientInstanceId: state.clientInstanceId });
    await api('/api/identity/reset', {
      method: 'POST',
      body: JSON.stringify({}),
    });
  }

  async function decodeQrFromImage() {
    const file = byId('qrImageFile').files[0];
    if (!file) {
      throw new Error('Select a QR image file');
    }
    if (!('BarcodeDetector' in window)) {
      throw new Error('QR image scanning is not supported in this browser. Paste payload text instead.');
    }
    const detector = new BarcodeDetector({ formats: ['qr_code'] });
    const imageBitmap = await createImageBitmap(file);
    const codes = await detector.detect(imageBitmap);
    if (!codes.length || !codes[0].rawValue) {
      throw new Error('No QR code found in image');
    }
    byId('contactPayload').value = codes[0].rawValue;
    byId('scanStatus').textContent = 'QR decoded. You can add the contact now.';
  }

  function wireEvents() {
    byId('connectBtn').addEventListener('click', () => {
      handleConnect().catch((error) => {
        byId('connectionStatus').textContent = `● Disconnected - ${error.message}`;
      });
    });

    byId('saveDeviceNameBtn').addEventListener('click', () => {
      const saved = APP_HELPERS.saveDeviceName({ localStorage: window.localStorage, name: byId('deviceName').value });
      if (!saved) {
        alert('Device name is required');
        return;
      }
      state.deviceName = saved;
      loadState().catch(() => {});
    });

    byId('resetIdentityBtn').addEventListener('click', () => {
      createNewIdentity()
        .then(() => window.location.reload())
        .catch((error) => alert(error.message));
    });

    byId('shareIdentityBtn').addEventListener('click', () => {
      handleShareIdentity().catch((error) => alert(error.message));
    });

    byId('copyIdentityBtn').addEventListener('click', async () => {
      await navigator.clipboard.writeText(byId('shareText').value);
    });

    byId('decodeQrBtn').addEventListener('click', () => {
      decodeQrFromImage().catch((error) => {
        byId('scanStatus').textContent = error.message;
      });
    });

    byId('addContactBtn').addEventListener('click', () => {
      handleAddContact().catch((error) => alert(error.message));
    });

    byId('chatContactSelect').addEventListener('change', () => {
      state.selectedContactId = byId('chatContactSelect').value || null;
      const selected = state.contacts.find((contact) => contact.id === state.selectedContactId) || null;
      renderContactInfo(selected);
      refreshCurrentMessages().catch(() => {
        renderMessages(state.selectedContactId);
      });
    });

    byId('sendBtn').addEventListener('click', () => {
      handleSend().catch((error) => alert(error.message));
    });

    byId('toggleDebugBtn').addEventListener('click', () => {
      state.debugVisible = !state.debugVisible;
      byId('debugPanel').classList.toggle('hidden', !state.debugVisible);
      byId('toggleDebugBtn').textContent = state.debugVisible ? 'Hide Debug Info' : 'Show Debug Info';
    });
  }

  async function startMessageRefreshLoop() {
    while (true) {
      try {
        await loadState();
        await refreshCurrentMessages();
      } catch {
        // keep UI alive during temporary failures
      }
      await new Promise((resolve) => setTimeout(resolve, 1200));
    }
  }

  wireEvents();
  loadState();
  startMessageRefreshLoop();
}
