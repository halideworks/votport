import { isFormDirty, markFormSaved } from '/assets/form-drafts.js';
import { api, requireSession, button, copyToClipboard, confirmModal, formatWhen } from '/assets/admin-common.js';
import { notificationEditor, tradeEvents } from '/assets/notifications.js';

const $ = (id) => document.getElementById(id);
const session = await requireSession(), admin = session.role === 'admin';
let catalog, preview = null, previewRevision = 0, setup = null;
const returnRequest = new URLSearchParams(window.location.search).get('receive');
function node(tag, text = '', className = '') { const el = document.createElement(tag); el.textContent = text; el.className = className; return el; }
async function guard(action) { $('trade-error').hidden = true; try { await action(); } catch (error) { $('trade-error').textContent = error.message; $('trade-error').hidden = false; $('trade-error').focus(); } }
function field(text, input) { input.setAttribute('aria-label', text); const label = node('label', text); label.append(input); return label; }
function input(type, value = '') { const el = document.createElement('input'); el.type = type; el.value = value; return el; }
function select(options, current) { const el = document.createElement('select'); for (const [value, label] of options) { const opt = node('option', label); opt.value = value; el.append(opt); } if (current) el.value = current; return el; }
function resetForm(form) { form.reset(); for (const mode of form.querySelectorAll('.notification-mode')) { mode.value = 'default'; mode.dispatchEvent(new window.Event('change')); } markFormSaved(form); }
function link(text, href) { const el = node('a', text); el.href = href; return el; }
const statusNames = { active: 'Active', pending_approval: 'Pending approval', paused: 'Paused', revoked: 'Revoked', unreachable: 'Unreachable', identity_mismatch: 'Identity mismatch', enrolling: 'Enrollment incomplete' };
function routeState(route) { return route.direction === 'incoming' || ['paused', 'revoked'].includes(route.state) ? route.state : route.remote_state || route.state; }
function showSetup(direction, focus = true) {
  setup = direction;
  $('trade-accept-form').hidden = direction !== 'send'; $('trade-receive-setup').hidden = direction !== 'receive';
  for (const value of ['send', 'receive']) $(`trade-start-${value}`).setAttribute('aria-expanded', String(value === direction));
  if (direction === 'receive') { $('trade-endpoints-section').hidden = false; $('trade-endpoints-section').open = true; }
  if (focus && direction) $(`trade-${direction}-title`).focus();
}
function requestSelected() {
  const chosen = $('trade-request').selectedOptions[0];
  $('trade-endpoint-details').hidden = $('trade-endpoint-details').disabled = !chosen?.value;
  if (chosen?.value && !$('trade-endpoint-name').value) $('trade-endpoint-name').value = chosen.dataset.label;
}
function clearPreview() {
  preview = null; previewRevision++;
  $('trade-accept-details').hidden = $('trade-accept-details').disabled = true;
  $('trade-preview').replaceChildren(); $('trade-accept').disabled = true; $('trade-confirm').checked = false;
}
$('trade-setup').hidden = !admin; $('port-save').hidden = !admin || !!session.tenant;
$('port-name').disabled = $('port-address').disabled = !admin || !!session.tenant;
const acceptNotifications = notificationEditor({ events: tradeEvents, policy: { mode: 'default', rules: [] } });
const endpointNotifications = notificationEditor({ events: tradeEvents, policy: { mode: 'default', rules: [] } });
$('trade-accept-notifications').append(acceptNotifications.element); $('trade-endpoint-notifications').append(endpointNotifications.element);

async function refresh() {
  const [data, requests] = await Promise.all([api('/api/trade-routes'), api('/api/admin/links')]);
  catalog = data;
  if (!isFormDirty($('port-form'))) { $('port-name').value = catalog.port.name; $('port-address').value = catalog.port.address; }
  $('port-display-name').textContent = catalog.port.name; $('port-display-address').textContent = catalog.port.address; $('port-key').textContent = catalog.port.key;
  const routeEdits = new Map([...$('trade-connections').querySelectorAll('.trade-route form[data-unsaved]')].filter(isFormDirty).map((form) => [form.closest('.trade-route').id, form.closest('details')]));
  const peerEdits = new Map([...$('trade-connections').querySelectorAll('details[data-peer]')].filter((details) => isFormDirty(details.querySelector('form'))).map((details) => [details.dataset.peer, details]));
  const invitationEdits = new Map([...$('trade-endpoints').querySelectorAll('form')].filter(isFormDirty).map((form) => [form.parentElement.id, form]));
  $('trade-endpoints').replaceChildren(); $('trade-connections').replaceChildren();
  const chosen = $('trade-request').value || (!catalog.endpoints.some((e) => e.id === returnRequest) ? returnRequest : '');
  $('trade-request').replaceChildren();
  const placeholder = node('option', 'Choose a receive request'); placeholder.value = ''; $('trade-request').append(placeholder);
  for (const request of requests.links || []) {
    if (request.has_password || !request.active || (request.expires_at && request.expires_at <= Date.now() / 1000) || request.uploads?.length || catalog.endpoints.some((e) => e.id === request.id)) continue;
    const option = node('option', `${request.label} · ${request.dest || 'Receive root'}`); option.value = request.id; option.dataset.label = request.label; $('trade-request').append(option);
  }
  $('trade-request').value = chosen || '';
  $('trade-request-help').textContent = $('trade-request').options.length === 1 ? 'No eligible requests yet. Create one below, then we will bring you back to set permissions.' : 'Only active requests with no password or previous uploads can be used.';
  requestSelected();
  $('trade-endpoints-section').hidden = !catalog.endpoints.length && setup !== 'receive';
  for (const endpoint of catalog.endpoints) {
    const row = node('div', '', 'card'); row.id = `endpoint-${endpoint.id}`; row.tabIndex = -1;
    row.append(node('h3', endpoint.name), node('p', `${endpoint.category === 'internal' ? 'Internal site' : 'External partner'} · ${endpoint.forwarding ? 'Forwarding allowed' : 'Forwarding prohibited'}`, 'field-help'), link('Receiving folder, limits and workflow →', `/receive#link-${endpoint.id}`));
    if (admin) {
      const form = node('form'), key = input('text'); form.setAttribute('data-unsaved', ''); key.maxLength = 64; key.placeholder = 'Optional: exact sending port fingerprint';
      const expiry = select([['3600', '1 hour'], ['86400', '24 hours'], ['604800', '7 days']], '86400');
      const advanced = node('details', '', 'trade-advanced'); advanced.append(node('summary', 'Invitation expiry and preapproval'), field('Invitation expiry', expiry), field('Preapproved sender fingerprint', key), node('p', 'Leave the fingerprint blank to review and approve the sender after they connect. Enter a verified fingerprint only if you want that port approved automatically.', 'field-help'));
      form.append(node('p', 'The sender will need your approval after accepting this invitation.', 'field-help'), advanced);
      const submit = node('button', 'Create invitation'); submit.type = 'submit'; form.append(submit);
      form.addEventListener('submit', (event) => { event.preventDefault(); if (form.inert) return; form.inert = true;
        guard(async () => {
          const result = await api('/api/trade-routes/invitations', { method: 'POST', body: JSON.stringify({ endpoint: endpoint.id, expected_key: key.value.trim(), expires_in: Number(expiry.value) }) });
          markFormSaved(form);
          $('trade-issued-invitation').value = JSON.stringify(result.invitation); $('trade-invitation-result').hidden = false;
          $('trade-invitation-next').textContent = `For ${endpoint.name}. Expires ${formatWhen(result.invitation.document.expires_at)}. Ask the sender to open Trade routes, choose “Send to another port” and paste this invitation. ${key.value.trim() ? 'The specified sender is preapproved.' : 'Then refresh this page and approve their incoming route under Connected ports.'}`;
          $('trade-invitation-title').focus();
        }).finally(() => { form.inert = false; });
      }); row.append(invitationEdits.get(row.id) || form);
    } $('trade-endpoints').append(row);
  }
  if (!catalog.endpoints.length) $('trade-endpoints').append(node('p', 'No receiving endpoints yet.', 'field-help'));
  const peers = new Map();
  for (const route of catalog.routes) { if (!peers.has(route.peer_key)) peers.set(route.peer_key, []); peers.get(route.peer_key).push(route); }
  const pending = catalog.routes.filter((r) => r.direction === 'incoming' && r.state === 'pending_approval').length;
  $('trade-connection-count').textContent = pending ? `${pending} incoming ${pending === 1 ? 'route needs' : 'routes need'} approval` : `${peers.size} connected ${peers.size === 1 ? 'port' : 'ports'}`;
  for (const [key, routes] of peers) {
    const group = node('section', '', 'card'); group.append(node('h3', routes[0].peer_name));
    const identity = node('details', '', 'trade-advanced'); identity.open = routes.some((r) => r.direction === 'incoming' && r.state === 'pending_approval'); identity.append(node('summary', 'Verify port identity'), node('code', key, 'trade-key'), button('Copy peer fingerprint', 'ghost tiny', (element) => copyToClipboard(key, element))); group.append(identity);
    const outgoing = routes.find((r) => r.direction === 'outgoing');
    if (outgoing) {
      group.append(node('p', outgoing.address, 'trade-key'));
      if (admin) { const edit = node('details'), form = node('form'), address = input('url', outgoing.address); edit.dataset.peer = key; form.setAttribute('data-unsaved', ''); address.required = true; edit.append(node('summary', 'Change peer address')); form.append(field('New port address', address), node('p', 'The new address must prove the same pinned identity. Updates all outgoing routes to this peer in this tenant. Finish active deliveries first.', 'field-help'));
        const save = node('button', 'Verify and save address'); save.type = 'submit'; form.append(save); form.addEventListener('submit', (event) => { event.preventDefault(); if (form.inert) return; form.inert = true; guard(async () => { await api(`/api/trade-routes/${outgoing.id}/address`, { method: 'PUT', body: JSON.stringify({ address: address.value, revision: outgoing.revision }) }); markFormSaved(form); await refresh(); }).finally(() => { form.inert = false; }); }); edit.append(form); group.append(peerEdits.get(key) || edit); }
    }
    if (!outgoing) group.append(node('p', routes[0].address || 'The sender connects to this port; no inbound address is required on the sender.', 'field-help trade-key'));
    const cards = node('div', '', 'connection-grid');
    for (const route of routes) cards.append(routeCard(route, routeEdits.get(`route-${route.id}`))); group.append(cards); $('trade-connections').append(group);
  }
  if (!peers.size) {
    const empty = node('div', '', 'empty-state'); empty.append(node('h3', 'Your first route starts with an invitation'), node('p', admin ? 'Choose a direction above. The receiving team creates the invitation, and the sending team accepts it.' : 'Ask a port administrator to create or accept an invitation. Connected routes will appear here.')); $('trade-connections').append(empty);
  }
}
function routeCard(route, savedEditor) {
  const card = node('article', '', 'card trade-route'), head = node('div', '', 'section-heading');
  card.id = `route-${route.id}`; card.tabIndex = -1;
  const current = routeState(route);
  head.append(node('h4', route.name), node('span', statusNames[current] || 'Status unavailable', `badge ${current === 'active' ? 'on' : 'off'}`)); card.append(head);
  card.append(node('p', `${route.direction === 'incoming' ? 'Incoming → this port' : 'Outgoing → partner'} · ${route.category === 'internal' ? 'Internal site' : 'External partner'}`, 'field-help'));
  card.append(node('p', `Receiving endpoint: ${route.endpoint_name}`), node('p', `Managed forwarding: ${route.forwarding ? 'allowed' : 'prohibited'}`, 'field-help'));
  const next = {
    pending_approval: route.direction === 'incoming' ? (admin ? 'Your approval is needed. Check the sending port’s fingerprint above, then approve this route.' : 'A port administrator needs to approve this sender.') : 'Waiting for the receiving team. Ask them to approve your route on their Trade routes page, then check the connection.',
    active: route.direction === 'incoming' ? 'Ready to receive. New files follow this endpoint’s receiving settings.' : `Ready to send. Choose “${route.name}” in a workflow project’s destinations.`,
    paused: route.state === 'paused' ? 'Paused on this port. Set permission to Active to allow new transfers again.' : 'Paused by the receiving team. Ask them to restore permission.',
    revoked: 'This permission has ended. Ask the receiving team for a new invitation to reconnect.',
    unreachable: 'The other port could not be reached. Check its address and network access, then try Check connection.',
    identity_mismatch: 'The address answered with a different identity. Contact the other administrator before changing this connection.',
    enrolling: 'Setup was interrupted. Retry enrollment to finish connecting with the same invitation.',
  };
  if (next[current]) card.append(node('p', next[current], 'info-banner'));
  if (route.direction === 'outgoing') {
    if (current === 'active') card.append(link('Choose this route in a workflow →', '/workflows#projects'));
    const local = node('details', '', 'trade-advanced'); local.append(node('summary', 'Local connection ID for scripts and agents'), node('p', 'This ID selects the saved route on this port. It is not the other port’s address. In the UI, choose the route by name.', 'field-help'), node('code', route.id, 'trade-key'), button('Copy local connection ID', 'ghost tiny', (element) => copyToClipboard(route.id, element))); card.append(local);
  }
  card.append(node('p', route.last_contact ? `Last contact ${formatWhen(route.last_contact)}` : 'No successful contact yet.', 'field-help'));
  if (route.error) card.append(node('p', route.error, 'error'));
  const deliveries = catalog.deliveries[route.id] || [];
  const failures = deliveries.filter((d) => ['failed', 'retrying'].includes(d.state)).length;
  if (failures) card.append(node('p', `${failures} failed or retrying recent deliveries`, 'error'));
  if (deliveries.length) {
    const detail = node('details'); detail.append(node('summary', 'Recent deliveries'));
    for (const delivery of deliveries) {
      const remote = delivery.remote || delivery;
      let text = remote.received ? 'Received and verified' : 'Awaiting verified receipt';
      if (remote.revoked) text += ' · Delivery revoked';
      else if (remote.released) text += ' · Released';
      else if (typeof remote.workflow === 'string' && remote.workflow) text += remote.workflow === 'awaiting_approval' ? ' · Held for approval' : ` · Processing (${remote.workflow.replaceAll('_', ' ')})`;
      else if (remote.received) text += ' · No workflow release reported';
      const row = node('p', `${delivery.label || 'Incoming delivery'} · ${text}`, 'field-help'); detail.append(row);
    } card.append(detail);
  }
  if (admin) {
    const actions = node('div', '', 'actions');
    if (route.direction === 'incoming' && route.state === 'pending_approval') {
      actions.append(button('Approve incoming route', '', (element) => guard(async () => {
        if (!await confirmModal('Approve incoming route', `Allow ${route.peer_name} to send files to ${route.endpoint_name}? Confirm this fingerprint with the sending team: ${route.peer_key}`, 'Approve route')) return;
        element.disabled = true;
        try { await api(`/api/trade-routes/${route.id}`, { method: 'PUT', body: JSON.stringify({ revision: route.revision, state: 'active', cancel_active: false, notifications: route.notifications }) }); $('trade-notice').textContent = 'Route approved. The sender can now check the connection and start sending.'; await refresh(); $(`route-${route.id}`).focus(); }
        finally { element.disabled = false; }
      })));
    }
    if (route.direction === 'outgoing' && route.state !== 'revoked') {
      actions.append(button(route.remote_grant ? 'Check connection' : 'Retry enrollment', 'ghost', (element) => guard(async () => {
        element.disabled = true;
        try { await api(`/api/trade-routes/${route.id}/test`, { method: 'POST' }); await refresh(); $(`route-${route.id}`).focus(); }
        finally { element.disabled = false; }
      })));
    } card.append(actions);
    const details = node('details'), form = node('form'); details.append(node('summary', 'Permissions and notifications'));
    const policy = notificationEditor({ events: tradeEvents, policy: route.notifications });
    const state = select([...(route.state === 'pending_approval' ? [['pending_approval', 'Keep pending approval']] : []), ...(route.state !== 'revoked' ? [['active', route.state === 'pending_approval' && route.direction === 'incoming' ? 'Approve route' : 'Active'], ['paused', 'Paused']] : []), ['revoked', 'Revoked']], route.state);
    const active = select([['finish', 'Let admitted transfers finish'], ['cancel', 'Cancel admitted transfers']], route.cancel_active ? 'cancel' : 'finish');
    const inFlight = field('When pausing or revoking', active); inFlight.hidden = !['paused', 'revoked'].includes(state.value);
    state.onchange = () => { inFlight.hidden = !['paused', 'revoked'].includes(state.value); };
    form.setAttribute('data-unsaved', '');
    form.append(field('Permission on this port', state), inFlight, policy.element);
    const save = node('button', 'Save route settings'); save.type = 'submit'; form.append(save);
    form.addEventListener('submit', (event) => { event.preventDefault(); if (form.inert) return;
      guard(async () => {
        if (state.value === 'revoked' && !await confirmModal('Revoke this route', 'New deliveries will be denied. Restoring permission requires a new invitation. Previously received files remain on the destination.', 'Revoke route')) return;
        form.inert = true;
        try { await api(`/api/trade-routes/${route.id}`, { method: 'PUT', body: JSON.stringify({ revision: route.revision, state: state.value, cancel_active: active.value === 'cancel', notifications: policy.read() }) }); markFormSaved(form); $('trade-notice').textContent = 'Route settings saved.'; await refresh(); $(`route-${route.id}`).focus(); } finally { form.inert = false; }
      });
    }); details.append(form); card.append(savedEditor || details);
    if (route.direction === 'outgoing' && route.remote_grant && route.state !== 'revoked') {
      const credential = node('details', '', 'trade-advanced'); credential.append(node('summary', 'Connection security'), node('p', 'Replace this route’s private access credential. The port’s identity and route permission stay the same.', 'field-help'), button('Rotate credential', 'ghost', (element) => guard(async () => {
        element.disabled = true;
        try { await api(`/api/trade-routes/${route.id}/rotate`, { method: 'POST' }); $('trade-notice').textContent = 'Route credential rotated.'; await refresh(); $(`route-${route.id}`).focus(); }
        finally { element.disabled = false; }
      }))); card.append(credential);
    }
  }
  return card;
}
$('port-form').addEventListener('submit', (event) => { event.preventDefault(); const form = event.currentTarget; if (form.inert) return; form.inert = true; guard(async () => { await api('/api/trade-routes/port', { method: 'PUT', body: JSON.stringify({ name: $('port-name').value.trim(), address: $('port-address').value.trim() }) }); markFormSaved(form); $('trade-notice').textContent = 'Port details saved.'; await refresh(); }).finally(() => { form.inert = false; }); });
$('trade-start-send').onclick = () => showSetup('send'); $('trade-start-receive').onclick = () => showSetup('receive');
for (const close of document.querySelectorAll('[data-close-setup]')) close.onclick = () => { const previous = setup; showSetup(null); $(`trade-start-${previous}`).focus(); };
$('trade-request').onchange = requestSelected;
$('port-copy-key').onclick = (event) => copyToClipboard(catalog.port.key, event.currentTarget);
$('port-copy-address').onclick = (event) => copyToClipboard(catalog.port.address, event.currentTarget);
$('trade-copy-invitation').onclick = (event) => copyToClipboard($('trade-issued-invitation').value, event.currentTarget);
$('trade-dismiss-invitation').onclick = () => { $('trade-issued-invitation').value = ''; $('trade-invitation-result').hidden = true; $('trade-start-receive').focus(); };
$('trade-refresh').onclick = () => guard(refresh);
$('trade-category').onchange = () => { $('trade-forwarding').checked = $('trade-category').value === 'internal'; };
$('trade-invitation').addEventListener('input', clearPreview);
$('trade-inspect').onclick = () => guard(async () => {
  clearPreview();
  let invitation;
  try { invitation = JSON.parse($('trade-invitation').value); } catch { throw new Error('Paste the complete route invitation from the receiving team. A port address or connection ID cannot be used here.'); }
  const ticket = previewRevision;
  $('trade-inspect').disabled = true; $('trade-inspect').textContent = 'Checking destination…';
  try {
    const result = await api('/api/trade-routes/inspect', { method: 'POST', body: JSON.stringify({ invitation }) });
    if (ticket !== previewRevision) return;
    preview = invitation; const endpoint = invitation.document.body.endpoint;
    $('trade-preview').replaceChildren(node('h3', result.document.body.name), node('p', invitation.document.body.address, 'trade-key'), node('p', 'Port identity fingerprint', 'field-help'), node('code', result.document.issuer, 'trade-key'), node('p', `Files arrive at: ${endpoint.name}`), node('p', `${endpoint.category === 'internal' ? 'Internal site' : 'External partner'} · Forwarding ${endpoint.forwarding ? 'allowed' : 'prohibited'}`, 'field-help'), node('p', `Accepted metadata fields: ${endpoint.metadata_keys.join(', ') || 'none'}`, 'field-help'), node('p', `Invitation expires ${formatWhen(invitation.document.expires_at)}`, 'field-help'));
    $('trade-accept-details').hidden = $('trade-accept-details').disabled = false; $('trade-accept').disabled = false;
    if (!$('trade-name').value) $('trade-name').value = endpoint.name;
    $('trade-review-title').focus();
  } catch (error) { if (ticket === previewRevision) throw error; }
  finally { $('trade-inspect').disabled = false; $('trade-inspect').textContent = 'Preview invitation'; }
});
$('trade-discover').onclick = () => guard(async () => { const result = await api('/api/trade-routes/inspect', { method: 'POST', body: JSON.stringify({ address: $('trade-discovery-address').value }) }); $('trade-discovery-result').textContent = `${result.document.body.name} · ${result.document.issuer}`; });
$('trade-accept-form').addEventListener('submit', (event) => { event.preventDefault(); const form = event.currentTarget; if (!preview || form.inert) return; form.inert = true;
  guard(async () => { const route = await api('/api/trade-routes', { method: 'POST', body: JSON.stringify({ invitation: preview, name: $('trade-name').value.trim(), notifications: acceptNotifications.read() }) }); resetForm(form); clearPreview(); showSetup(null); $('trade-notice').textContent = route.state === 'active' ? 'Route active. Choose its name in a workflow’s destinations.' : 'Route saved. Follow the next step on its card below.'; await refresh(); $(`route-${route.id}`).focus(); }).finally(() => { form.inert = false; });
});
$('trade-endpoint-form').addEventListener('submit', (event) => { event.preventDefault(); const form = event.currentTarget; if (form.inert) return;
  guard(async () => { if (!await confirmModal('Require enrolled routes', 'This receive request will accept uploads only through approved trade routes. Ordinary receive-link uploads will be denied.', 'Create endpoint')) return;
    const id = $('trade-request').value;
    form.inert = true; try { await api('/api/trade-routes/endpoints', { method: 'POST', body: JSON.stringify({ id, name: $('trade-endpoint-name').value.trim(), category: $('trade-category').value, forwarding: $('trade-forwarding').checked, metadata_keys: $('trade-metadata').value.split(',').map((v) => v.trim()).filter(Boolean), notifications: endpointNotifications.read() }) }); resetForm(form); $('trade-notice').textContent = 'Receiving endpoint created. Next, create an invitation below and send it to the other team.'; await refresh(); $('trade-endpoints-section').open = true; $(`endpoint-${id}`).focus(); } finally { form.inert = false; }
  });
});
await guard(refresh);
if (admin && (returnRequest || window.location.hash === '#receive')) showSetup('receive');
else if (admin && window.location.hash === '#send') showSetup('send');
