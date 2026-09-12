import { discardForm, markFormSaved } from '/assets/form-drafts.js';
import { api, button, confirmModal, formatWhen, requireSession } from '/assets/admin-common.js';
import { loadNotificationSettings, notificationEditor, notificationServices } from '/assets/notifications.js';

const $ = (id) => document.getElementById(id);
const node = (tag, text, className = '') => { const element = document.createElement(tag); element.textContent = text; element.className = className; return element; };
const session = await requireSession(), admin = session.role === 'admin';
let editing = null, defaultsEditor;
for (const [key, label] of Object.entries(notificationServices)) $('nd-channel').add(new window.Option(label, key));
$('notification-new').hidden = $('notification-defaults-save').hidden = !admin;
const guides = {
  slack: ['Create an incoming webhook for the Slack channel that should receive these messages.', 'https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/'],
  teams: ['Create a Teams Workflows webhook for the channel or chat. Choose Anyone for trigger authentication and assign a co-owner.', 'https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook'],
  google_chat: ['Create a webhook in the destination space’s Apps & integrations settings.', 'https://developers.google.com/workspace/chat/quickstart/webhooks'],
  discord: ['Create a webhook under the channel’s Integrations settings. Add a thread ID when posting to a forum.', 'https://docs.discord.com/developers/resources/webhook'],
  email: ['Send through the SMTP relay configured by the platform administrator. Choose this destination’s recipients below.'],
  webhook: ['Receive a JSON summary at your endpoint. An optional bearer token authenticates requests.'],
  ntfy: ['Enter the full topic URL and, if required, an access token.'],
  pushover: ['Enter your Pushover application token and recipient user or group key.'],
};
async function guard(action) {
  $('notification-error').hidden = true;
  try { await action(); } catch (error) { $('notification-error').textContent = error.message; $('notification-error').hidden = false; }
}
function fields() {
  const channel = $('nd-channel').value;
  const visible = { url: !['email', 'pushover'].includes(channel), token: ['webhook', 'ntfy', 'pushover'].includes(channel), user: channel === 'pushover', recipients: channel === 'email', thread: channel === 'discord', 'clear-token': ['webhook', 'ntfy'].includes(channel) && !!editing?.token_set };
  for (const [field, shown] of Object.entries(visible)) { $(`nd-${field}-field`).hidden = !shown; $(`nd-${field}`).disabled = !shown; }
  $('nd-url').required = visible.url && !editing?.url_set; $('nd-user').required = visible.user && !editing?.user_set; $('nd-token').required = channel === 'pushover' && !editing?.token_set; $('nd-recipients').required = visible.recipients;
  const [help, href] = guides[channel]; $('nd-guide').replaceChildren(document.createTextNode(help));
  if (href) { const link = node('a', ' Setup guide'); link.href = href; link.target = '_blank'; link.rel = 'noopener noreferrer'; $('nd-guide').append(link); }
}
function edit(destination = null) {
  if (!discardForm($('notification-form'))) return;
  editing = destination; $('notification-form').reset(); $('notification-form').hidden = false;
  $('notification-editor-title').textContent = destination ? `Edit ${destination.label}` : 'Add destination';
  $('nd-channel').value = destination?.channel || 'slack'; $('nd-channel').disabled = !!destination;
  $('nd-url').required = !destination && !['email', 'pushover'].includes($('nd-channel').value);
  $('nd-label').value = destination?.label || ''; $('nd-target').value = destination?.target || '';
  $('nd-recipients').value = (destination?.recipients || []).join('\n'); $('nd-thread').value = destination?.thread_id || '';
  $('nd-enabled').checked = destination?.enabled ?? true;
  for (const field of ['url', 'token', 'user']) { $(`nd-${field}`).value = ''; $(`nd-${field}`).placeholder = destination?.[`${field}_set`] ? 'Saved; leave blank to keep' : ''; }
  fields(); $('notification-form').scrollIntoView({ block: 'nearest' }); $('nd-label').focus();
}
function write(destination, overrides = {}) {
  return { id: destination.id, revision: destination.revision, label: destination.label, channel: destination.channel, target: destination.target,
    enabled: destination.enabled, recipients: destination.recipients, thread_id: destination.thread_id, ...overrides };
}
async function refresh() {
  const data = await loadNotificationSettings(true);
  $('notification-destinations').replaceChildren();
  for (const destination of data.destinations) {
    const card = node('div', '', 'card'), head = node('div', '', 'section-heading');
    head.append(node('h3', destination.label), node('span', destination.enabled ? 'Enabled' : 'Disabled', 'badge')); card.append(head);
    card.append(node('p', `${notificationServices[destination.channel]} · ${destination.target}`, 'connection-meta'));
    const outcome = data.outcomes[destination.id];
    if (outcome) card.append(node('p', `Last attempt ${formatWhen(outcome.at)} · ${outcome.delivered ? 'Accepted by destination' : 'Failed; check connection settings'}`, outcome.delivered ? 'field-help' : 'error'));
    else card.append(node('p', 'No delivery attempted yet. Send a test to check the destination.', 'field-help'));
    if (admin) {
      const actions = node('div', '', 'actions');
      actions.append(button('Edit', 'ghost', () => edit(destination)));
      const test = button('Send test', 'ghost', () => guard(async () => {
        test.disabled = true;
        try { await api(`/api/notifications/${destination.id}/test`, { method: 'POST' }); $('notification-notice').textContent = `Test accepted for ${destination.label}. Check that it appeared in ${destination.target}.`; }
        finally { test.disabled = false; await refresh(); }
      })); test.disabled = !destination.enabled; actions.append(test);
      actions.append(button(destination.enabled ? 'Disable' : 'Enable', 'ghost', () => guard(async () => {
        await api('/api/notifications', { method: 'POST', body: JSON.stringify(write(destination, { enabled: !destination.enabled })) }); await refresh();
      })));
      actions.append(button('Delete', 'ghost', () => guard(async () => {
        if (!await confirmModal('Delete notification destination', `Remove ${destination.label}? Subscriptions to it will stop sending. Other destinations are unaffected.`, 'Delete destination')) return;
        await api(`/api/notifications/${destination.id}`, { method: 'DELETE', body: JSON.stringify({ revision: destination.revision }) }); await refresh();
      })));
      card.append(actions);
    }
    $('notification-destinations').append(card);
  }
  if (!data.destinations.length) $('notification-destinations').append(node('p', 'Add your first destination, then select it on a request, delivery, or workflow.', 'card field-help'));
  if (!$('notification-defaults-form').dataset.dirty) { defaultsEditor = notificationEditor({ policy: data.defaults, defaults: true, readOnly: !admin, settings: data }); $('notification-defaults').replaceChildren(defaultsEditor.element); }
}
$('nd-channel').addEventListener('change', fields);
$('notification-new').onclick = () => edit();
$('notification-cancel').onclick = () => { if (!discardForm($('notification-form'))) return; $('notification-form').hidden = true; $('notification-new').focus(); };
$('notification-refresh').onclick = () => guard(refresh);
$('notification-form').addEventListener('submit', (event) => {
  event.preventDefault(); const form = event.currentTarget; if (form.inert) return; form.inert = true;
  guard(async () => {
    const channel = $('nd-channel').value;
    const value = { id: editing?.id || '', revision: editing?.revision || 0, channel, label: $('nd-label').value.trim(), target: $('nd-target').value.trim(), enabled: $('nd-enabled').checked };
    for (const field of ['url', 'token', 'user']) value[field] = $(`nd-${field}`).disabled ? '' : $(`nd-${field}`).value.trim();
    value.clear_token = !$('nd-clear-token').disabled && $('nd-clear-token').checked;
    value.recipients = channel === 'email' ? $('nd-recipients').value.split('\n').map((line) => line.trim()).filter(Boolean) : [];
    value.thread_id = channel === 'discord' ? $('nd-thread').value.trim() : '';
    await api('/api/notifications', { method: 'POST', body: JSON.stringify(value) });
    markFormSaved(form); form.reset(); form.hidden = true; editing = null; $('notification-notice').textContent = 'Destination saved. Choose it on a transfer or add it to tenant defaults.'; await refresh();
  }).finally(() => { form.inert = false; });
});
$('notification-defaults-form').addEventListener('change', () => { $('notification-defaults-form').dataset.dirty = 'true'; });
$('notification-defaults-form').addEventListener('submit', (event) => {
  event.preventDefault(); const form = event.currentTarget; if (form.inert || !defaultsEditor) return;
  guard(async () => {
    const policy = defaultsEditor.read();
    if (!await confirmModal('Update notification defaults', 'Requests and deliveries using tenant defaults will use these destinations and events immediately.', 'Save defaults')) return;
    form.inert = true;
    try { await api('/api/notifications/defaults', { method: 'PUT', body: JSON.stringify(policy) }); markFormSaved(form); delete form.dataset.dirty; $('notification-defaults-status').textContent = 'Tenant defaults saved.'; await refresh(); }
    finally { form.inert = false; }
  });
});
await guard(refresh);
