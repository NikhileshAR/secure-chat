const state = {
  contacts: [],
  selectedContactId: null,
  messagesByContact: new Map(),
};

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'content-type': 'application/json' },
    ...options,
  });
  const body = await res.json();
  if (!res.ok) {
    throw new Error(body.error || 'Request failed');
  }
  return body;
}

function byId(id) {
  return document.getElementById(id);
}

function renderConnection(connection) {
  const extra = connection.activeRelayUrl ? ` (${connection.activeRelayUrl})` : '';
  byId('connectionStatus').textContent = `Status: ${connection.status}${extra}${connection.lastError ? ` - ${connection.lastError}` : ''}`;
}

function renderContacts(contacts) {
  state.contacts = contacts;
  const list = byId('contactsList');
  list.innerHTML = '';
  for (const contact of contacts) {
    const item = document.createElement('li');
    item.textContent = `${contact.label} - ${contact.trustLevel} - ${contact.fingerprint}`;
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
  }
}

function renderMessages(contactId) {
  const container = byId('chatMessages');
  if (!contactId) {
    container.innerHTML = '<p>Select a contact to view chat.</p>';
    return;
  }
  const messages = state.messagesByContact.get(contactId) || [];
  container.innerHTML = '';
  for (const message of messages) {
    const wrapper = document.createElement('div');
    wrapper.className = 'msg';
    const meta = document.createElement('div');
    meta.className = 'meta';
    const when = new Date(message.timestamp || Date.now()).toLocaleTimeString();
    meta.textContent = `${message.direction === 'out' ? 'You' : 'Peer'} • ${when} • ${message.status}`;
    const content = document.createElement('div');
    content.textContent = message.content;
    wrapper.appendChild(meta);
    wrapper.appendChild(content);
    container.appendChild(wrapper);
  }
  container.scrollTop = container.scrollHeight;
}

async function loadState() {
  const snapshot = await api('/api/state');
  byId('fingerprint').textContent = snapshot.identity.fingerprint;
  renderConnection(snapshot.connection);
  renderContacts(snapshot.contacts);
}

async function refreshCurrentMessages() {
  if (!state.selectedContactId) {
    return;
  }
  const response = await api(`/api/messages?contactId=${encodeURIComponent(state.selectedContactId)}`, {
    method: 'GET',
    headers: undefined,
  });
  state.messagesByContact.set(state.selectedContactId, response.messages || []);
  renderMessages(state.selectedContactId);
}

async function handleConnect() {
  const relayUrl = byId('relayUrl').value.trim();
  const configFile = byId('configFile').files[0];
  let clientConfig = null;

  if (configFile) {
    const raw = await configFile.text();
    clientConfig = JSON.parse(raw);
  }

  await api('/api/connection/connect', {
    method: 'POST',
    body: JSON.stringify({ relayUrl, clientConfig }),
  });
  await loadState();
}

async function handleShareIdentity() {
  const payload = await api('/api/identity/share', {
    method: 'GET',
    headers: undefined,
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
      byId('connectionStatus').textContent = `Status: ERROR - ${error.message}`;
    });
  });

  byId('shareIdentityBtn').addEventListener('click', () => {
    handleShareIdentity().catch((error) => {
      alert(error.message);
    });
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
    refreshCurrentMessages().catch(() => {
      renderMessages(state.selectedContactId);
    });
  });

  byId('sendBtn').addEventListener('click', () => {
    handleSend().catch((error) => alert(error.message));
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
