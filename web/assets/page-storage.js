import { api, button, requireSession } from '/assets/admin-common.js';
const $ = (id) => document.getElementById(id);
const value = (id) => $(id).value.trim();
const node = (tag, text, className = '') => { const element = document.createElement(tag); element.textContent = text; element.className = className; return element; };
let connections = [], tenants = [], current = null, autoId = true, editorGeneration = 0;
const session = await requireSession();
const admin = session.role === 'admin' && !session.tenant;
$('storage-new').hidden = !admin; $('storage-access').hidden = admin;

async function guard(action) {
  $('storage-error').hidden = true;
  try { await action(); }
  catch (error) { $('storage-error').textContent = error.message; $('storage-error').hidden = false; $('storage-error').scrollIntoView({ block: 'nearest' }); }
}
function notice(message) { $('storage-notice').textContent = message; $('storage-notice').hidden = false; }
async function refresh() {
  const result = await api('/api/workflows/storage'); connections = result.storage;
  const list = $('storage-list'); list.replaceChildren();
  if (!connections.length) {
    const empty = node('div', '', 'empty-state'); empty.append(node('h3', 'Choose where your files go'), node('p', admin ? 'Connect S3 storage, a shared folder, or another Votport install. Use the same connections for deliveries and receive projects.' : 'Ask your administrator to make a connection available to this tenant.'));
    if (admin) empty.append(button('Add your first storage', '', () => edit()));
    list.append(empty);
  }
  for (const connection of connections) {
    const card = node('article', '', 'card');
    const head = node('div', '', 'section-heading'); head.append(node('h3', connection.label), node('span', connection.enabled ? 'Enabled' : 'Disabled', 'badge'));
    card.append(head, node('p', connection.kind === 'folder' ? 'Shared folder' : connection.kind === 'votport' ? 'Votport destination' : 'S3 storage', 'connection-meta'));
    if (connection.kind === 'folder') card.append(node('p', `${connection.directory}${connection.prefix ? `/${connection.prefix}` : ''}`, 'connection-meta'));
    else if (connection.kind === 'votport') card.append(node('p', connection.endpoint, 'connection-meta'), node('p', 'Saved receive link · Verified file transfer', 'connection-meta'));
    else card.append(node('p', `s3://${connection.bucket}/${connection.prefix}`, 'connection-meta'), node('p', connection.endpoint, 'connection-meta'), node('p', `${connection.region} · ${connection.kms_key_id ? 'KMS encryption' : 'Bucket default encryption'} · ${connection.credential_source === 'saved' ? 'Saved access key' : 'Server credentials'}`, 'connection-meta'));
    if (admin) {
      const actions = node('div', '', 'actions'); actions.append(button('Edit connection', 'ghost', () => edit(connection)), button('Test connection', 'ghost', (element) => guard(async () => {
        element.disabled = true;
        try { const result = await test(connection); notice(`${connection.label}: ${result.message}`); } finally { element.disabled = false; }
      }))); card.append(actions);
    }
    list.append(card);
  }
}
function authentication() {
  const mode = value('ws-auth'); $('ws-credential-fields').hidden = mode !== 'access_key';
  for (const id of ['ws-access-key', 'ws-secret-key', 'ws-session-token']) { $(id).disabled = mode !== 'access_key'; $(id).required = mode === 'access_key' && id !== 'ws-session-token'; }
  $('ws-auth-note').textContent = mode === 'server' ? 'Use credentials or an IAM role already configured on the server. No keys are stored by this connection.' : mode === 'keep' ? 'The saved credentials will stay unchanged. Choose Access key to replace them.' : 'Credentials are stored privately on the server and are never sent back to the browser.';
}
function encryption() { $('ws-kms-field').hidden = value('ws-encryption') !== 'kms'; $('ws-kms').disabled = $('ws-kms-field').hidden; $('ws-kms').required = !$('ws-kms-field').hidden; }
function portAuthentication() {
  const keep = value('ws-port-auth') === 'keep'; $('ws-port-fields').hidden = keep;
  for (const id of ['ws-port-link', 'ws-port-password']) $(id).disabled = keep;
  $('ws-port-note').textContent = keep ? `Using the saved receive link at ${current?.endpoint || ''}. Choose Enter receive link and password to replace it.` : 'The receive link and password stay private after saving. Enter both to replace a saved connection.';
}
function destinationKind() {
  const kind = value('ws-kind');
  for (const name of ['s3', 'folder', 'votport']) { $(`ws-${name}-settings`).hidden = kind !== name; $(`ws-${name}-settings`).disabled = kind !== name; }
  $('ws-prefix-field').hidden = kind === 'votport'; $('ws-prefix').disabled = kind === 'votport';
  for (const name of ['ws-encryption-field', 'ws-path-field']) $(name).hidden = kind !== 's3';
  $('ws-encryption').disabled = kind !== 's3'; $('ws-path').disabled = kind !== 's3';
  encryption(); if (kind !== 's3') { $('ws-kms-field').hidden = true; $('ws-kms').disabled = true; }
  portAuthentication();
}
function provider() {
  const aws = value('ws-provider') === 'aws'; $('ws-endpoint-field').hidden = aws; $('ws-endpoint').readOnly = aws;
  if (aws) { $('ws-endpoint').value = `https://s3.${value('ws-region') || 'us-east-1'}.amazonaws.com`; $('ws-path').checked = false; }
  else $('ws-path').checked = true;
}
function edit(connection) {
  if (!admin || $('workflow-save-storage').inert) return;
  editorGeneration += 1;
  current = connection || null; autoId = !connection;
  $('workflow-save-storage').reset(); $('workflow-save-storage').hidden = false;
  $('storage-editor-title').textContent = connection ? `Edit ${connection.label}` : 'Add storage';
  $('ws-kind').value = connection?.kind || 's3'; $('ws-kind').disabled = !!connection;
  $('ws-directory').value = connection?.directory || '';
  $('ws-port-auth').querySelector('[value=keep]').hidden = !connection;
  $('ws-port-auth').value = connection ? 'keep' : 'replace';
  for (const key of ['id', 'label', 'bucket', 'region', 'prefix']) $(`ws-${key}`).value = connection?.[key] ?? (key === 'region' ? 'us-east-1' : '');
  $('ws-id').readOnly = !!connection;
  $('ws-provider').value = !connection || /^https:\/\/s3\.[a-z0-9-]+\.amazonaws\.com$/.test(connection.endpoint) ? 'aws' : 'custom';
  provider();
  if (connection) { $('ws-endpoint').value = connection.endpoint; $('ws-path').checked = connection.path_style; }
  $('ws-auth').querySelector('[value=keep]').hidden = connection?.credential_source !== 'saved';
  $('ws-auth').value = connection?.credential_source === 'saved' ? 'keep' : connection ? 'server' : 'access_key';
  authentication();
  $('ws-encryption').value = connection?.kms_key_id ? 'kms' : 'default'; $('ws-kms').value = connection?.kms_key_id || ''; encryption();
  $('ws-enabled').checked = connection?.enabled ?? true;
  destinationKind();
  $('ws-tenants').replaceChildren();
  const available = [{ key: '', label: 'Default tenant' }, ...tenants];
  for (const key of connection?.tenants || []) if (!available.some((tenant) => tenant.key === key)) available.push({ key, label: key });
  for (const tenant of available) {
    const label = node('label', '', 'check'), input = document.createElement('input'); input.type = 'checkbox'; input.value = tenant.key; input.checked = (connection?.tenants || ['']).includes(tenant.key);
    label.append(input, document.createTextNode(tenant.label || tenant.key)); $('ws-tenants').append(label);
  }
  $('storage-test').disabled = !connection; $('storage-test-result').textContent = '';
  $('workflow-save-storage').scrollIntoView({ block: 'start' }); $('ws-label').focus();
}
async function test(connection) { return api(`/api/workflows/storage/${encodeURIComponent(connection.id)}/test`, { method: 'POST', body: JSON.stringify({ revision: connection.revision }) }); }
$('workflow-save-storage').addEventListener('submit', (event) => {
  event.preventDefault(); const submit = event.submitter;
  if (submit.disabled) return;
  submit.disabled = true; $('workflow-save-storage').inert = true; $('storage-new').disabled = true;
  guard(async () => {
    const kind = value('ws-kind');
    const storage = Object.fromEntries(['id', 'label', 'endpoint', 'bucket', 'region', 'prefix'].map((key) => [key, value(`ws-${key}`)]));
    Object.assign(storage, { revision: current?.revision || 0, kms_key_id: value('ws-encryption') === 'kms' ? value('ws-kms') : null, tenants: [...$('ws-tenants').querySelectorAll('input:checked')].map((input) => input.value), path_style: $('ws-path').checked, enabled: $('ws-enabled').checked });
    storage.kind = kind; storage.directory = kind === 'folder' ? value('ws-directory') : '';
    if (kind !== 's3') Object.assign(storage, { endpoint: '', bucket: '', region: '', kms_key_id: null, path_style: false });
    if (!storage.tenants.length && storage.enabled) throw new Error('Choose at least one tenant that can use this connection.');
    let credentials = value('ws-auth') === 'keep' ? null : value('ws-auth') === 'server' ? { mode: 'server' } : { mode: 'access_key', access_key_id: value('ws-access-key'), secret_access_key: $('ws-secret-key').value, session_token: $('ws-session-token').value || null };
    if (kind === 'folder') credentials = { mode: 'server' };
    if (kind === 'votport') {
      credentials = value('ws-port-auth') === 'keep' ? null : { mode: 'votport', request_url: value('ws-port-link'), password: $('ws-port-password').value || null };
      storage.endpoint = credentials ? new window.URL(credentials.request_url).origin : current.endpoint;
      storage.prefix = '';
    }
    const saved = await api('/api/workflows/storage', { method: 'PUT', body: JSON.stringify({ storage, credentials }) });
    saved.credential_source = credentials ? credentials.mode === 'server' ? 'server' : 'saved' : current?.credential_source || 'server';
    $('workflow-save-storage').inert = false;
    edit(saved);
    notice(`“${saved.label}” saved. Test the saved connection before using it in a workflow.`);
    await refresh();
  }).finally(() => { submit.disabled = false; $('workflow-save-storage').inert = false; $('storage-new').disabled = false; });
});
$('storage-test').onclick = () => guard(async () => {
  if (!current) return;
  const generation = editorGeneration;
  $('storage-test').disabled = true; $('storage-test-result').textContent = 'Checking connection…';
  try { const result = await test(current); if (generation === editorGeneration) $('storage-test-result').textContent = result.message; }
  catch (error) { if (generation === editorGeneration) { $('storage-test-result').textContent = ''; throw error; } }
  finally { if (generation === editorGeneration) $('storage-test').disabled = false; }
});
$('storage-new').onclick = () => edit(); $('storage-close').onclick = () => { editorGeneration += 1; $('workflow-save-storage').hidden = true; $('storage-new').focus(); };
$('ws-label').oninput = () => { if (!current && autoId) $('ws-id').value = value('ws-label').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '').slice(0, 100); };
$('ws-id').oninput = () => { autoId = false; };
$('ws-provider').onchange = provider; $('ws-region').oninput = () => { if (value('ws-provider') === 'aws') provider(); };
$('ws-auth').onchange = authentication; $('ws-encryption').onchange = encryption;
$('ws-kind').onchange = destinationKind; $('ws-port-auth').onchange = portAuthentication;
for (const event of ['input', 'change']) $('workflow-save-storage').addEventListener(event, () => { editorGeneration += 1; $('storage-test').disabled = true; $('storage-test-result').textContent = 'Save changes before testing.'; });
await guard(async () => { if (admin) tenants = (await api('/api/admin/tenants')).tenants; await refresh(); });
