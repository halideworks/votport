import { markFormSaved } from '/assets/form-drafts.js';
import { api, button, confirmModal, copyToClipboard, formatWhen, requireSession } from '/assets/admin-common.js';
import { $, fieldError } from '/assets/object-card.js';
// Page size follows the server convention (50 default, 100 max); the list
// follows `next` until it runs out, like the workflows page.
const TOKEN_PAGE_SIZE = 50;
let tokenRows = [], tokenNext = null, tokenLoading = false;
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

// One mapped table per class: token badges print labels, never wire values
// (audit item 446).
const tokenStatusNames = { active: 'Active', expired: 'Expired', revoked: 'Revoked' };

function renderAutomationTokens() {
  const container = $('automation-tokens');
  $('automation-token-status').textContent = tokenRows.length
    ? `${tokenRows.length} automation token${tokenRows.length === 1 ? '' : 's'} issued.`
    : 'No automation tokens issued.';
  $('automation-token-more').hidden = !tokenNext;
  $('automation-token-more').disabled = tokenLoading;
  container.replaceChildren();
  if (!tokenRows.length) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'No automation tokens issued.';
    container.append(empty);
    return;
  }
  for (const token of [...tokenRows].reverse()) {
    const card = document.createElement('div');
    card.className = 'card link-item';
    const head = document.createElement('div');
    head.className = 'head';
    const title = document.createElement('h3');
    title.textContent = token.label || 'Automation token';
    const status = automationTokenStatus(token);
    const badge = document.createElement('span');
    badge.className = `badge ${status === 'active' ? 'on' : 'off'}`;
    badge.textContent = tokenStatusNames[status];
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
      token.created_by ? `created by ${token.created_by}` : 'creator unknown',
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
          await refreshAutomationTokens(true);
        }),
      );
    }
    container.append(card);
  }
}

async function refreshAutomationTokens(reset = false) {
  if (tokenLoading) return;
  if (reset) { tokenRows = []; tokenNext = null; }
  tokenLoading = true;
  try {
    // First page is queryless (server default 50); continuations carry the
    // keyset cursor.
    let path = '/api/admin/automation-tokens';
    if (tokenNext) path += `?after=${encodeURIComponent(tokenNext)}&limit=${TOKEN_PAGE_SIZE}`;
    const page = await api(path);
    tokenRows = tokenRows.concat(page.tokens || []);
    tokenNext = page.next || null;
    renderAutomationTokens();
  } catch (error) {
    $('automation-token-status').textContent = 'Automation tokens could not be loaded.';
    const message = document.createElement('p');
    message.className = 'error';
    message.setAttribute('role', 'alert');
    message.textContent = error.message;
    $('automation-tokens').replaceChildren(message);
    $('automation-token-more').hidden = true;
  } finally {
    tokenLoading = false;
    $('automation-token-more').disabled = false;
  }
}

$('automation-token-more').addEventListener('click', () => refreshAutomationTokens());

const tokenError = fieldError($('automation-token-label'), $('automation-token-error'));

$('automation-token-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  tokenError.clear();
  const label = $('automation-token-label').value.trim();
  const expires = Number($('automation-token-expires').value);
  const directory = $('automation-token-directory').value.trim();
  if (!label || label.length > 100) {
    tokenError.show('Name must be 1 to 100 characters.');
    return;
  }
  if (!Number.isInteger(expires) || expires < 1 || expires > 365) {
    tokenError.show('Expiry must be between 1 and 365 days.');
    return;
  }
  const permissions = [...$('automation-token-permissions').querySelectorAll('input:checked')].map((input) => input.value);
  if (!permissions.length) {
    tokenError.show('Choose at least one allowed action.');
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
    await refreshAutomationTokens(true);
  } catch (requestError) {
    tokenError.show(requestError.message);
  } finally {
    submit.disabled = false;
  }
});

await Promise.all([requireSession(), refreshAutomationTokens()]);
