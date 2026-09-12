import { markFormSaved } from '/assets/form-drafts.js';
import { api, button } from '/assets/admin-common.js';

export const notificationEvents = {
  route_approval_requested: 'Route approval requested', route_approved: 'Route approved', route_identity_changed: 'Port identity changed', route_failed: 'Route failed or unreachable', route_recovered: 'Route recovered', route_received: 'Route received and verified',
  upload_complete: 'Upload completed', upload_failed: 'Upload failed',
  outbound_download_started: 'First download started', outbound_delivery_complete: 'Delivery completed',
  workflow_retry_scheduled: 'Workflow retry scheduled', workflow_failed: 'Workflow failed',
};
export const tradeEvents = ['route_approval_requested', 'route_approved', 'route_identity_changed', 'route_failed', 'route_recovered', 'route_received'];
export const uploadEvents = ['upload_complete', 'upload_failed'];
export const downloadEvents = ['outbound_download_started', 'outbound_delivery_complete'];
export const workflowEvents = [...downloadEvents, 'workflow_retry_scheduled', 'workflow_failed'];
export const notificationServices = { slack: 'Slack', teams: 'Microsoft Teams', google_chat: 'Google Chat', discord: 'Discord', email: 'Email', webhook: 'JSON webhook', ntfy: 'ntfy', pushover: 'Pushover' };
let pending;
export function loadNotificationSettings(refresh = false) {
  if (!pending || refresh) pending = api('/api/notifications').catch((error) => { pending = null; throw error; });
  return pending;
}
const node = (tag, text = '', className = '') => { const element = document.createElement(tag); element.textContent = text; element.className = className; return element; };

export function notificationEditor({ policy = null, events = Object.keys(notificationEvents), inherit, inheritLabel = 'Use project settings', defaults = false, readOnly = false, settings } = {}) {
  const element = node('fieldset', '', 'notification-editor'), legend = node('legend', 'Notifications');
  const modeLabel = node('label', 'Send notifications'), mode = document.createElement('select');
  for (const [value, label] of [['off', 'Off'], ...(!defaults ? [['default', 'Use tenant defaults']] : []), ['custom', 'Choose destinations and events'], ...(inherit !== undefined ? [['inherit', inheritLabel]] : [])]) mode.add(new window.Option(label, value));
  mode.className = 'notification-mode'; modeLabel.append(mode);
  const summary = node('div', '', 'field-help'), rules = node('div', '', 'notification-rules'), status = node('p', 'Loading notification destinations…', 'field-help');
  status.setAttribute('role', 'status');
  const manage = node('a', 'Add or manage destinations ↗', 'text-link'); manage.href = '/notifications'; manage.target = '_blank'; manage.rel = 'noopener noreferrer'; manage.hidden = defaults;
  const picker = document.createElement('select'); picker.setAttribute('aria-label', 'Destination to add');
  const add = button('Add destination', 'ghost', () => {
    const destination = catalog.destinations.find((item) => item.id === picker.value);
    if (!destination) return;
    addDestination(destination, [], true); updatePicker(); renderMode(); element.dispatchEvent(new window.Event('change', { bubbles: true }));
  });
  const addRow = node('div', '', 'notification-add'); addRow.append(picker, add);
  const reload = button('Refresh destinations', 'ghost tiny', () => load(true)); reload.hidden = defaults || readOnly;
  element.append(legend, modeLabel, summary, addRow, rules, status, manage, reload); element.disabled = true;
  let catalog, selected;
  function readRules() {
    return [...rules.querySelectorAll('.notification-destination')].map((group) => ({ destination_id: group.dataset.destination, events: [...group.querySelectorAll('input:checked')].map((input) => input.dataset.event) }));
  }
  function updatePicker() {
    const current = new Set(readRules().map((rule) => rule.destination_id));
    picker.replaceChildren(new window.Option('Choose a destination', ''));
    for (const destination of catalog.destinations) if (destination.enabled && !current.has(destination.id)) picker.add(new window.Option(`${destination.label} · ${destination.target}`, destination.id));
    picker.disabled = picker.options.length === 1 || current.size >= 32; add.disabled = picker.disabled || !picker.value;
  }
  function addDestination(destination, selectedEvents, open = false) {
    const group = node('fieldset', '', 'notification-destination'); group.dataset.destination = destination.id;
    group.append(node('legend', `${destination.label}${destination.enabled ? '' : ' · disabled'}`), node('p', `${notificationServices[destination.channel] || ''} · ${destination.target}`, 'field-help'));
    const detail = node('details', '', 'notification-events'), caption = node('summary'), choices = node('div', '', 'permission-grid'); detail.open = open;
    for (const event of events) {
      const label = node('label', '', 'check'), input = document.createElement('input'); input.type = 'checkbox'; input.dataset.event = event;
      input.checked = selectedEvents.includes(event); input.disabled = !destination.enabled && !input.checked;
      label.append(input, document.createTextNode(notificationEvents[event])); choices.append(label);
    }
    const describeEvents = () => { const chosen = [...choices.querySelectorAll('input:checked')].map((input) => notificationEvents[input.dataset.event]); caption.textContent = chosen.length ? `Notify when: ${chosen.join(', ')}` : 'Choose events'; };
    choices.addEventListener('change', describeEvents); describeEvents(); detail.append(caption, choices); group.append(detail);
    const remove = button('Remove destination', 'ghost tiny', () => { group.remove(); updatePicker(); renderMode(); picker.focus(); element.dispatchEvent(new window.Event('change', { bubbles: true })); });
    remove.hidden = readOnly; group.append(remove); rules.append(group);
    if (open) detail.querySelector('input')?.focus();
  }
  picker.addEventListener('change', () => { add.disabled = !picker.value; });
  function describe(policy) {
    const resolved = policy?.mode === 'default' ? catalog.defaults : policy;
    const active = resolved?.mode === 'custom' ? resolved.rules.filter((rule) => rule.events.some((event) => events.includes(event))) : [];
    summary.replaceChildren();
    for (const rule of active) {
      const destination = catalog.destinations.find((d) => d.id === rule.destination_id);
      summary.append(node('p', `${destination?.label || 'Unavailable destination'} · ${destination?.target || rule.destination_id}${destination?.enabled ? '' : ' · disabled'}: ${rule.events.filter((event) => events.includes(event)).map((event) => notificationEvents[event]).join(', ')}`));
    }
    if (!active.length) summary.append(node('p', 'No notifications will be sent for these events.'));
  }
  function renderMode() {
    rules.hidden = mode.value !== 'custom'; addRow.hidden = rules.hidden || readOnly; summary.hidden = mode.value === 'custom' || mode.value === 'off';
    if (mode.value === 'default') describe(catalog.defaults);
    if (mode.value === 'inherit') describe(inherit || { mode: 'off', rules: [] });
    if (mode.value === 'custom') {
      const chosen = readRules();
      status.textContent = chosen.length ? `${chosen.length} ${chosen.length === 1 ? 'destination selected' : 'destinations selected'}. Only checked events will be sent.` : 'Add a destination, then choose when it should hear from this port.';
    } else status.textContent = mode.value === 'off' ? 'Notifications are off for this item.' : '';
  }
  let loadTicket = 0;
  async function load(refresh = false) {
    const ticket = ++loadTicket;
    if (refresh && catalog) selected = { mode: mode.value, rules: readRules() };
    element.disabled = true; status.textContent = 'Loading notification destinations…';
    try {
      const loaded = settings || await loadNotificationSettings(refresh);
      if (ticket !== loadTicket) return;
      catalog = loaded;
      selected ||= policy || (inherit !== undefined ? { mode: 'inherit', rules: [] } : { mode: 'off', rules: [] });
      mode.value = selected.mode;
      const available = new Map(catalog.destinations.map((destination) => [destination.id, destination]));
      for (const rule of selected.rules || []) if (!available.has(rule.destination_id)) available.set(rule.destination_id, { id: rule.destination_id, label: 'Unavailable destination', target: rule.destination_id, enabled: false });
      rules.replaceChildren();
      for (const rule of selected.rules || []) addDestination(available.get(rule.destination_id), rule.events);
      updatePicker();
      element.disabled = readOnly; mode.disabled = false; status.textContent = ''; renderMode();
    } catch (error) {
      status.textContent = error.message; status.append(button('Retry loading destinations', 'link', () => load(true)));
      element.disabled = false; mode.disabled = true;
    }
  }
  mode.addEventListener('change', renderMode);
  rules.addEventListener('change', renderMode);
  const ready = load();
  return { element, ready, reset() { mode.value = 'default'; rules.replaceChildren(); if (catalog) { updatePicker(); renderMode(); } }, read() {
    if (!catalog) throw new Error('Notification destinations could not be loaded. Retry before saving.');
    if (mode.value === 'inherit') return null;
    const policy = { mode: mode.value, rules: [] };
    if (mode.value === 'custom') {
      policy.rules = readRules();
      if (policy.rules.some((rule) => !rule.events.length)) throw new Error('Choose at least one event for each destination, or remove destinations you do not need.');
      if (!policy.rules.length) throw new Error('Choose at least one notification event and destination, or turn notifications off.');
      if (policy.rules.length > 32) throw new Error('Choose at most 32 notification destinations.');
    }
    return policy;
  } };
}

export function notificationDetails({ policy, events, save, readOnly = false, inherit, inheritLabel }) {
  const enabled = ['default', 'custom'].includes((policy || inherit)?.mode);
  const details = node('details', '', 'notification-details'), summary = node('summary', enabled ? 'Notifications enabled · configure' : 'Notifications off · configure');
  details.setAttribute('data-unsaved', '');
  const editor = notificationEditor({ policy, events, readOnly, inherit, inheritLabel }), status = node('p', '', 'field-help'); status.setAttribute('role', 'status');
  const apply = button('Save notifications', 'ghost', async () => {
    let policy;
    try { policy = editor.read(); } catch (error) { status.textContent = error.message; return; }
    apply.disabled = true; editor.element.disabled = true; status.textContent = 'Saving…';
    try { await save(policy); markFormSaved(details); delete details.dataset.dirty; status.textContent = 'Notification settings saved.'; summary.textContent = ['default', 'custom'].includes((policy || inherit)?.mode) ? 'Notifications enabled · configure' : 'Notifications off · configure'; }
    catch (error) { status.textContent = error.message; }
    finally { apply.disabled = false; editor.element.disabled = false; }
  });
  editor.element.addEventListener('change', () => { details.dataset.dirty = 'true'; });
  apply.hidden = readOnly; details.append(summary, editor.element, apply, status); return details;
}
