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
    const empty = node('div', '', 'empty-state'); empty.append(node('h3', 'Bring your storage into the workflow'), node('p', admin ? 'Connect an Amazon S3 bucket or an S3-compatible service. Import source files and export verified deliveries from one place.' : 'Ask your administrator to make a storage connection available to this tenant.'));
    if (admin) empty.append(button('Add your first storage', '', () => edit()));
    list.append(empty);
  }
  for (const connection of connections) {
    const card = node('article', '', 'card');
    const head = node('div', '', 'section-heading'); head.append(node('h3', connection.label), node('span', connection.enabled ? 'Enabled' : 'Disabled', 'badge'));
    card.append(head, node('p', `s3://${connection.bucket}/${connection.prefix}`, 'connection-meta'), node('p', connection.endpoint, 'connection-meta'));
    card.append(node('p', `${connection.region} · ${connection.kms_key_id ? 'KMS encryption' : 'Bucket default encryption'} · ${connection.credential_source === 'saved' ? 'Saved access key' : 'Server credentials'}`, 'connection-meta'));
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
  const generation = editorGeneration;
  guard(async () => {
    const storage = Object.fromEntries(['id', 'label', 'endpoint', 'bucket', 'region', 'prefix'].map((key) => [key, value(`ws-${key}`)]));
    Object.assign(storage, { revision: current?.revision || 0, kms_key_id: value('ws-encryption') === 'kms' ? value('ws-kms') : null, tenants: [...$('ws-tenants').querySelectorAll('input:checked')].map((input) => input.value), path_style: $('ws-path').checked, enabled: $('ws-enabled').checked });
    if (!storage.tenants.length && storage.enabled) throw new Error('Choose at least one tenant that can use this connection.');
    const credentials = value('ws-auth') === 'keep' ? null : value('ws-auth') === 'server' ? { mode: 'server' } : { mode: 'access_key', access_key_id: value('ws-access-key'), secret_access_key: $('ws-secret-key').value, session_token: $('ws-session-token').value || null };
    const saved = await api('/api/workflows/storage', { method: 'PUT', body: JSON.stringify({ storage, credentials }) });
    if (generation === editorGeneration) $('ws-access-key').value = $('ws-secret-key').value = $('ws-session-token').value = '';
    await refresh();
    $('workflow-save-storage').inert = false;
    if (generation === editorGeneration) edit(connections.find((connection) => connection.id === saved.id));
    notice(`“${saved.label}” saved. Test the saved connection before using it in a workflow.`);
  }).finally(() => { submit.disabled = false; $('workflow-save-storage').inert = false; $('storage-new').disabled = false; });
});
$('storage-test').onclick = () => guard(async () => {
  if (!current) return;
  const generation = editorGeneration;
  $('storage-test').disabled = true; $('storage-test-result').textContent = 'Checking bucket access…';
  try { const result = await test(current); if (generation === editorGeneration) $('storage-test-result').textContent = result.message; }
  catch (error) { if (generation === editorGeneration) { $('storage-test-result').textContent = ''; throw error; } }
  finally { if (generation === editorGeneration) $('storage-test').disabled = false; }
});
$('storage-new').onclick = () => edit(); $('storage-close').onclick = () => { editorGeneration += 1; $('workflow-save-storage').hidden = true; $('storage-new').focus(); };
$('ws-label').oninput = () => { if (!current && autoId) $('ws-id').value = value('ws-label').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '').slice(0, 100); };
$('ws-id').oninput = () => { autoId = false; };
$('ws-provider').onchange = provider; $('ws-region').oninput = () => { if (value('ws-provider') === 'aws') provider(); };
$('ws-auth').onchange = authentication; $('ws-encryption').onchange = encryption;
for (const event of ['input', 'change']) $('workflow-save-storage').addEventListener(event, () => { editorGeneration += 1; $('storage-test').disabled = true; $('storage-test-result').textContent = 'Save changes before testing.'; });
await guard(async () => { if (admin) tenants = (await api('/api/admin/tenants')).tenants; await refresh(); });
