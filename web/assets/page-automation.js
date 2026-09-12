import { markFormSaved } from '/assets/form-drafts.js';
import { api, button, confirmModal, copyToClipboard, formatWhen, requireSession } from '/assets/admin-common.js';
const $ = (id) => document.getElementById(id);
const permissionLabels = {
  'library:read': 'browse files',
  'jobs:read': 'read jobs and verification',
  'jobs:create': 'create and retry jobs',
  'jobs:cancel': 'cancel jobs',
  'deliveries:create': 'create deliveries',
  'deliveries:read': 'read delivery activity',
  'deliveries:revoke': 'revoke deliveries',
};

function automationTokenStatus(token) {
  if (token.revoked_at) return 'revoked';
  if (token.expires_at && token.expires_at <= Math.floor(Date.now() / 1000)) return 'expired';
  return 'active';
}

function renderAutomationTokens(tokens) {
  const container = $('automation-tokens');
  container.replaceChildren();
  if (!tokens.length) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'No automation tokens issued.';
    container.append(empty);
    return;
  }
  for (const token of [...tokens].reverse()) {
    const card = document.createElement('div');
    card.className = 'card link-item';
    const head = document.createElement('div');
    head.className = 'head';
    const title = document.createElement('h3');
    title.textContent = token.label || 'Automation token';
    const status = automationTokenStatus(token);
    const badge = document.createElement('span');
    badge.className = `badge ${status === 'active' ? 'on' : 'off'}`;
    badge.textContent = status;
    head.append(title, badge);
    card.append(head);

    const meta = document.createElement('p');
    meta.className = 'muted';
    const parts = [
      `created ${formatWhen(token.created_at)}`,
      `expires ${formatWhen(token.expires_at)}`,
      Number.isFinite(token.last_used_at)
        ? `last used ${formatWhen(token.last_used_at)}`
        : 'never used',
      token.directory ? `folder ${token.directory}` : 'any folder',
      token.permissions.map((permission) => permissionLabels[permission] || permission).join(', '),
    ];
    meta.textContent = parts.join(' · ');
    card.append(meta);

    if (status === 'active') {
      card.append(
        button('Revoke', 'tiny danger', async () => {
          if (
            !(await confirmModal(
              'Revoke automation token',
              `Revoke "${token.label || 'this token'}"? Automation using it will stop working.`,
              'Revoke',
            ))
          )
            return;
          await api(`/api/admin/automation-tokens/${encodeURIComponent(token.id)}`, {
            method: 'DELETE',
          });
          await refreshAutomationTokens();
        }),
      );
    }
    container.append(card);
  }
}

async function refreshAutomationTokens() {
  try {
    const { tokens } = await api('/api/admin/automation-tokens');
    renderAutomationTokens(tokens || []);
  } catch (error) {
    const message = document.createElement('p');
    message.className = 'error';
    message.setAttribute('role', 'alert');
    message.textContent = error.message;
    $('automation-tokens').replaceChildren(message);
  }
}

$('automation-token-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const error = $('automation-token-error');
  error.hidden = true;
  const label = $('automation-token-label').value.trim();
  const expires = Number($('automation-token-expires').value);
  const directory = $('automation-token-directory').value.trim();
  if (!label || label.length > 100) {
    error.textContent = 'Name must be 1 to 100 characters.';
    error.hidden = false;
    return;
  }
  if (!Number.isInteger(expires) || expires < 1 || expires > 365) {
    error.textContent = 'Expiry must be between 1 and 365 days.';
    error.hidden = false;
    return;
  }
  const permissions = [...$('automation-token-permissions').querySelectorAll('input:checked')].map((input) => input.value);
  if (!permissions.length) {
    error.textContent = 'Choose at least one allowed action.';
    error.hidden = false;
    return;
  }
  const submit = $('automation-token-submit');
  submit.disabled = true;
  try {
    const response = await api('/api/admin/automation-tokens', {
      method: 'POST',
      body: JSON.stringify({ label, expires_days: expires, directory: directory || null, permissions }),
    });
    if (!response.token) throw new Error('server did not return the automation token');
    markFormSaved($('automation-token-form')); $('automation-token-form').reset();
    $('automation-token-value').value = response.token;
    $('automation-token-result').hidden = false;
    $('automation-token-copy').onclick = () => copyToClipboard($('automation-token-copy'), response.token);
    const config = JSON.stringify({ mcpServers: { votport: { command: 'votport', args: ['mcp'], env: { VOTPORT_URL: window.location.origin, VOTPORT_AUTOMATION_TOKEN: response.token } } } }, null, 2);
    $('automation-mcp-config').textContent = config;
    $('automation-mcp-copy').onclick = () => copyToClipboard($('automation-mcp-copy'), config);
    await refreshAutomationTokens();
  } catch (requestError) {
    error.textContent = requestError.message;
    error.hidden = false;
  } finally {
    submit.disabled = false;
  }
});

await Promise.all([requireSession(), refreshAutomationTokens()]);
