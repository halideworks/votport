/* global URL, Blob, Option, sessionStorage, crypto */
import { api, button, confirmModal, copyToClipboard, formatBytes, formatWhen, requireSession, revealHash } from '/assets/admin-common.js';

const $ = (id) => document.getElementById(id);
const value = (id) => $(id).value.trim();
const optionalNumber = (id) => value(id) ? Number(value(id)) : null;
const localTime = (id) => value(id) ? Math.floor(new Date(value(id)).getTime() / 1000) : null;
const node = (tag, content, className = '') => { const element = document.createElement(tag); element.textContent = content; element.className = className; return element; };
const stateNames = { queued: 'Scheduled', preparing: 'Preparing files', awaiting_approval: 'Needs approval', exporting: 'Delivering copies', retrying: 'Retry scheduled', ready: 'Ready to share', failed: 'Needs attention', cancelled: 'Cancelled', retiring: 'Cleaning up', retired: 'Archived' };
let projects = [], storage = [], jobs = [], cursor = null, eventCursor = 0, attemptCursor = 0, jobsRevision = 0;
const eventPage = [];
let projectRevision = 0, hookRevision = 0, editingProject = null, autoProjectId = true, appendedJobs = false, loadingEvents = false, poll;
const loaded = new Set();
const session = await requireSession();
const admin = session.role === 'admin';
const draftKey = `votport-workflow-draft:${session.tenant || ''}`;

function notice(message) { $('workflow-notice').textContent = message; $('workflow-notice').hidden = false; }
async function guard(action) {
  $('workflow-error').hidden = true;
  try { await action(); }
  catch (error) { $('workflow-error').textContent = error.message; $('workflow-error').hidden = false; $('workflow-error').scrollIntoView({ block: 'nearest' }); }
}
function options(select, entries, first) {
  const previous = select.value;
  select.replaceChildren();
  if (first !== undefined) select.add(new Option(first, ''));
  for (const item of entries) select.add(new Option(item.label, item.id));
  if ([...select.options].some((option) => option.value === previous)) select.value = previous;
}
function download(name, content) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(content, null, 2)], { type: 'application/json' }));
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = name; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function empty(title, detail, action) {
  const element = node('div', '', 'empty-state'); element.append(node('h3', title), node('p', detail));
  if (action) element.append(action);
  return element;
}
function form(id, action) {
  $(id).addEventListener('submit', (event) => {
    event.preventDefault(); const submit = event.submitter;
    if (submit?.disabled) return;
    if (submit) submit.disabled = true;
    $(id).inert = true;
    guard(action).finally(() => { $(id).inert = false; if (submit) submit.disabled = false; });
  });
}

function projectFields() {
  const project = projects.find((item) => item.id === value('workflow-project'));
  $('workflow-metadata').replaceChildren();
  $('workflow-recipients').replaceChildren(node('legend', 'Recipients'));
  $('workflow-rules').textContent = project
    ? `${project.directory} · ${project.require_approval ? 'Approval required' : 'Released after preparation'}${project.scan_required ? ' · Malware scan' : ''}${project.media ? ' · Video checks' : ''}${project.sequence ? ' · Sequence check' : ''}`
    : 'Choose a project to see its delivery requirements.';
  for (const key of project?.required_metadata || []) {
    const label = node('label', key), input = document.createElement('input'); input.dataset.key = key; input.required = true; input.maxLength = 4096;
    label.append(input); $('workflow-metadata').append(label);
  }
  for (const recipient of project?.recipients || []) {
    const label = node('label', '', 'check'), input = document.createElement('input'); input.type = 'checkbox'; input.value = recipient.holder;
    label.append(input, document.createTextNode(recipient.email)); $('workflow-recipients').append(label);
  }
  if (!project?.recipients?.length) $('workflow-recipients').append(node('p', 'Anyone with the download link can receive this delivery.', 'field-help'));
}
async function refreshProjects() {
  const [projectResponse, storageResponse] = await Promise.all([api('/api/workflows/projects'), api('/api/workflows/storage')]);
  projects = projectResponse.projects; storage = storageResponse.storage;
  options($('workflow-project'), projects, 'Choose a project');
  options($('workflow-import'), storage.filter((item) => item.enabled && item.kind === 's3'), 'Project library folder');

  projectFields(); renderProjects();
}
async function newDelivery(id) {
  if ($('workflow-create').inert) return;
  await refreshProjects();
  if (!projects.length) {
    window.location.hash = '#projects';
    if (admin) editProject();
    else notice('Ask an administrator to create a project and give you sender access.');
    return;
  }
  window.location.hash = '#jobs';
  $('workflow-create').hidden = false;
  if (id) $('workflow-project').value = id;
  else if (projects.length === 1) $('workflow-project').value = projects[0].id;
  const saved = JSON.parse(sessionStorage.getItem(draftKey) || 'null');
  if (saved) {
    $('workflow-project').value = saved.project_id; $('workflow-label').value = saved.label; $('workflow-days').value = saved.expires_days;
    for (const [field, timestamp] of [['start', saved.not_before], ['deadline', saved.deadline]]) {
      const date = timestamp ? new Date(timestamp * 1000) : null;
      $(`workflow-${field}`).value = date ? new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16) : '';
    }
    $('workflow-import').value = saved.import?.storage_id || ''; $('workflow-prefix').value = saved.import?.prefix || '';
    $('workflow-result').textContent = 'Restored your pending request. Retry to recover the same delivery.';
  }
  projectFields();
  if (saved) {
    for (const input of $('workflow-metadata').querySelectorAll('input')) input.value = saved.metadata[input.dataset.key] || '';
    for (const input of $('workflow-recipients').querySelectorAll('input')) input.checked = saved.recipients.includes(input.value);
  }
  $('workflow-new-operation').hidden = !saved; $('workflow-prefix-field').hidden = !value('workflow-import');
  $('workflow-create').scrollIntoView({ block: 'start' }); $('workflow-label').focus();
}
function renderProjects() {
  const list = $('workflow-project-list'); list.replaceChildren();
  if (!projects.length) {
    list.append(empty('Create your first project', 'A project brings a folder, its team, and delivery requirements together. Set it up once and reuse it.', admin ? button('Create project', '', () => editProject()) : null));
  }
  for (const project of projects) {
    const card = node('article', '', 'card'); card.append(node('h3', project.label), node('p', project.directory, 'connection-meta'));
    const rules = [project.require_approval ? 'Approval required' : 'No approval step', `${project.recipients.length} enrolled recipients`, `${project.required_metadata.length} required fields`];
    if (project.receive) rules.push('Incoming and outgoing files');
    for (const id of project.destinations) rules.push(`Copy to ${storage.find((item) => item.id === id)?.label || id}`);
    if (project.scan_required) rules.push('Malware scan');
    if (project.sequence) rules.push('Sequence check');
    if (project.media) rules.push('Video checks');
    card.append(node('p', rules.join(' · '), 'connection-meta'));
    const actions = node('div', '', 'actions');
    actions.append(button('New delivery', 'ghost', () => guard(() => newDelivery(project.id))));
    if (admin) actions.append(button('Edit project', 'ghost', () => editProject(project)));
    card.append(actions); list.append(card);
  }
}

const fields = {
  members: [{ key: 'subject', label: 'Email or agent ID', list: 'wp-agent-subjects', max: 500 }, { key: 'role', label: 'Role', options: ['sender', 'approver', 'viewer'] }],
  recipients: [{ key: 'email', label: 'Email', type: 'email', max: 254 }, { key: 'holder', label: 'Device public key', pattern: '[0-9a-fA-F]{64}', max: 64 }],
  metadata: [{ key: 'key', label: 'Field name', max: 100 }],
};
function addRow(kind, values = {}) {
  const row = node('div', '', `form-row${fields[kind].length === 1 ? ' single' : ''}`);
  for (const field of fields[kind]) {
    const label = node('label', field.label), input = document.createElement(field.options ? 'select' : 'input');
    input.dataset.key = field.key; input.required = true;
    if (field.options) for (const option of field.options) input.add(new Option(option[0].toUpperCase() + option.slice(1), option));
    else { input.type = field.type || 'text'; input.maxLength = field.max; if (field.pattern) input.pattern = field.pattern; if (field.list) input.setAttribute('list', field.list); }
    input.value = values[field.key] || (field.options ? field.options[0] : ''); label.append(input); row.append(label);
  }
  const remove = button('Remove', 'ghost', () => { row.remove(); $(`wp-add-${kind === 'members' ? 'member' : kind === 'recipients' ? 'recipient' : 'metadata'}`).focus(); });
  remove.setAttribute('aria-label', `Remove ${kind === 'metadata' ? 'required field' : kind === 'members' ? 'team member' : 'recipient'}`);
  row.append(remove); $(`wp-${kind}`).append(row); return row;
}
const rows = (kind) => [...$(`wp-${kind}`).children].map((row) => Object.fromEntries([...row.querySelectorAll('input,select')].map((input) => [input.dataset.key, input.value.trim()])));
function editProject(project) {
  if (!admin || $('workflow-save-project').inert) return;
  editingProject = project || null; projectRevision = project?.revision || 0; autoProjectId = !project;
  $('workflow-save-project').reset(); $('workflow-save-project').hidden = false;
  $('project-editor-title').textContent = project ? `Edit ${project.label}` : 'New project';
  for (const key of ['id', 'label', 'directory']) { $(`wp-${key}`).value = project?.[key] || ''; }
  $('wp-id').readOnly = $('wp-directory').readOnly = !!project;
  for (const kind of Object.keys(fields)) $(`wp-${kind}`).replaceChildren();
  for (const [subject, role] of Object.entries(project?.members || {})) addRow('members', { subject, role });
  for (const recipient of project?.recipients || []) addRow('recipients', recipient);
  for (const key of project?.required_metadata || []) addRow('metadata', { key });
  $('wp-domains').value = (project?.allowed_domains || []).join('\n');
  $('wp-approval').checked = project?.require_approval || false; $('wp-scan').checked = project?.scan_required || false;
  $('wp-release').value = project?.release || 'all_destinations';
  $('wp-receive').checked = project?.receive || false;
  $('wp-destinations').replaceChildren();
  const destinations = new Map(storage.map((item) => [item.id, item]));
  for (const id of project?.destinations || []) if (!destinations.has(id)) destinations.set(id, { id, label: `${id} (unavailable)`, enabled: false });
  for (const connection of destinations.values()) {
    const label = node('label', '', 'check'), input = document.createElement('input');
    input.type = 'checkbox'; input.value = connection.id; input.checked = project?.destinations?.includes(connection.id) || false;
    input.disabled = !connection.enabled && !input.checked;
    label.append(input, document.createTextNode(`${connection.label}${connection.enabled ? '' : ' · disabled'}`)); $('wp-destinations').append(label);
  }
  if (!destinations.size) $('wp-destinations').append(node('p', 'Add an S3 bucket, shared folder or Votport connection to send copies automatically.', 'muted'));
  $('wp-sequence-enabled').checked = !!project?.sequence; $('wp-media-enabled').checked = !!project?.media;
  for (const [id, key] of [['sequence-prefix', 'prefix'], ['sequence-suffix', 'suffix'], ['first', 'first'], ['last', 'last'], ['padding', 'padding']]) $(`wp-${id}`).value = project?.sequence?.[key] ?? (key === 'padding' ? 4 : '');
  for (const [id, key] of [['codec', 'video_codec'], ['width', 'width'], ['height', 'height'], ['rate', 'frame_rate']]) $(`wp-${id}`).value = project?.media?.[key] ?? '';
  checkFields(); $('workflow-save-project').scrollIntoView({ block: 'start' }); $('wp-label').focus();
}
function checkFields() {
  for (const kind of ['sequence', 'media']) {
    const enabled = $(`wp-${kind}-enabled`).checked; $(`wp-${kind}-fields`).hidden = !enabled;
    for (const input of $(`wp-${kind}-fields`).querySelectorAll('input')) input.disabled = !enabled;
  }
  $('wp-first').required = $('wp-last').required = $('wp-sequence-enabled').checked;
}

async function refreshJobs(more = false) {
  const revision = ++jobsRevision;
  const requested = /^#job-([a-f0-9]{32})$/.exec(window.location.hash)?.[1];
  const page = await api(`/api/workflows/jobs?limit=50&after=${encodeURIComponent(more ? cursor || '' : '')}`);
  if (!more && requested && !page.jobs.some(({ job }) => job.id === requested)) {
    page.jobs.unshift(await api(`/api/workflows/jobs/${requested}`));
  }
  if (revision !== jobsRevision) return false;
  if (!more) appendedJobs = false;
  else if (page.jobs.length) appendedJobs = true;
  jobs = [...new Map((more ? jobs.concat(page.jobs) : page.jobs).map((entry) => [entry.job.id, entry])).values()]; cursor = page.next; $('workflow-more').hidden = !cursor;
  const list = $('workflow-jobs'); list.replaceChildren();
  if (!jobs.length) list.append(empty('Every delivery, in one place', 'Create a delivery to follow preparation, approvals, storage exports, and recipient acceptance.', button('Create delivery', '', () => guard(() => newDelivery()))));
  for (const { job, url } of jobs) {
    const card = node('article', '', 'card job-card'); card.id = `job-${job.id}`;
    const head = node('div', '', 'head'); head.append(node('h3', job.request.label), node('span', stateNames[job.state] || job.state, 'badge'));
    card.append(head, node('p', `${job.project.label} · ${formatWhen(job.created_at)}`, 'connection-meta'));
    if (job.request.not_before) card.append(node('p', `Scheduled ${formatWhen(job.request.not_before)}`, 'muted'));
    if (job.request.deadline) card.append(node('p', `Acceptance due ${formatWhen(job.request.deadline)}`, 'muted'));
    if (url && job.state !== 'ready') card.append(node('p', 'Local download link is released. Destination copies are still pending.', 'info-banner'));
    if (job.received) {
      const source = node('a', 'View incoming request →', 'text-link'); source.href = `/receive?search=${encodeURIComponent(job.received.link_id)}#link-${job.received.link_id}`; card.append(source);
      if (job.state !== 'retired') card.append(node('p', 'This delivery uses the original received files. Keep them unchanged until the delivery is archived. Automatic archival occurs seven days after cancellation, failure, or link expiry or revocation.', 'field-help'));
    }
    for (const id of job.project.destinations) {
      const result = job.checks.destinations?.[id], receipt = job.checks.route_receipts?.[id], revoked = job.checks.route_revocations?.[id];
      const leg = node('div', '', 'destination-status'), name = storage.find((item) => item.id === id)?.label || id;
      const status = result?.state === 'complete' ? (receipt ? 'Destination signed its receipt' : 'Verified copy complete') : result?.state === 'sending' ? `${formatBytes(result.transferred)} transferred this attempt` : result?.error || 'Pending';
      leg.append(node('p', `${name}: ${status}`, result?.error ? 'error' : 'connection-meta'));
      if (revoked || (receipt && ['cancelled', 'retiring', 'retired'].includes(job.state))) {
        leg.append(node('p', revoked?.state === 'acknowledged' ? 'Revocation acknowledged by the destination port.' : `Revocation awaiting destination acknowledgment.${revoked?.retry_at ? ` Next attempt ${formatWhen(revoked.retry_at)}.` : ''}`, 'field-help'));
      }
      if (receipt) leg.append(button('Download custody evidence', 'tiny ghost', () => download(`trade-route-${job.id}-${id}.json`, {
        format: 'votport-route-evidence-v1', receipt, ancestors: [...(job.checks.source_ancestry || []), ...(job.checks.source_receipt ? [job.checks.source_receipt] : [])], revocation: revoked?.acknowledgement || null,
      })));
      card.append(leg);
    }
    if (job.state === 'retrying') card.append(node('p', `Next attempt ${formatWhen(job.checks.retry_at)}`, 'muted'));
    if (job.error) card.append(node('p', job.error, 'error'));
    const detail = document.createElement('details'); detail.append(node('summary', 'Package and recipient verification'));
    detail.append(node('p', job.manifest ? `Manifest: ${job.manifest}` : 'The manifest will be available after preparation.', 'mono'));
    const evidence = node('div', '', 'evidence-records'); let after = 0;
    const load = button('Load recipient evidence', 'ghost', () => guard(async () => {
      load.disabled = true;
      try {
        const result = await api(`/api/workflows/jobs/${job.id}/evidence?after=${after}&limit=100`);
        if (!result.evidence.length) { evidence.append(node('p', after ? 'All available records loaded.' : 'No recipient verification recorded yet.', 'muted')); return; }
        for (const record of result.evidence) {
          const statement = record.evidence, holder = statement.authorization.challenge.holder;
          const who = job.project.recipients.find((recipient) => recipient.holder === holder)?.email || holder;
          evidence.append(node('p', `${who}: ${statement.kind === 'accepted' ? 'Accepted' : 'Files verified'} · ${formatWhen(record.received_at)}`));
        }
        after = result.next; load.textContent = 'Load more evidence';
        evidence.append(button('Export signed evidence', 'ghost', () => download(`delivery-${job.id}-evidence-${after}.json`, result)));
      } finally { load.disabled = false; }
    }));
    detail.append(load, evidence); card.append(detail);
    const actions = node('div', '', 'actions');
    if (url) actions.append(button('Copy download link', '', (element) => copyToClipboard(element, url)));
    if (job.state === 'awaiting_approval') actions.append(button('Approve delivery', '', () => guard(async () => {
      if (await confirmModal('Approve delivery', `Release “${job.request.label}” with manifest ${job.manifest}?`, 'Approve delivery')) {
        await api(`/api/workflows/jobs/${job.id}`, { method: 'POST', body: JSON.stringify({ action: 'approve', manifest: job.manifest }) }); await refreshJobs();
      }
    })));
    if (['failed', 'retrying'].includes(job.state)) actions.append(button('Retry', 'ghost', () => guard(async () => { await api(`/api/workflows/jobs/${job.id}`, { method: 'POST', body: JSON.stringify({ action: 'retry' }) }); await refreshJobs(); })));
    if (!['cancelled', 'retired', 'retiring'].includes(job.state)) actions.append(button('Cancel delivery', 'danger', () => guard(async () => {
      if (await confirmModal('Cancel delivery', 'Stop downloads here and request revocation at connected ports? Each port will stop route-managed sharing and forwarding. Downloaded files and independent copies remain.', 'Cancel delivery')) {
        await api(`/api/workflows/jobs/${job.id}`, { method: 'POST', body: JSON.stringify({ action: 'cancel' }) }); await refreshJobs();
      }
    })));
    card.append(actions); list.append(card);
  }
  revealHash({ scroll: false });
  schedulePoll();
  return true;
}
function schedulePoll() {
  clearTimeout(poll);
  if (!document.hidden && section() === 'jobs' && $('workflow-create').hidden && jobs.some(({ job }) => (['queued', 'preparing', 'exporting', 'retrying'].includes(job.state) || Object.values(job.checks.route_revocations || {}).some((route) => route.state === 'pending'))) && !appendedJobs) {
    poll = setTimeout(() => { if (!$('workflow-jobs').contains(document.activeElement) && !$('workflow-jobs').querySelector('details[open]')) guard(() => refreshJobs()); else schedulePoll(); }, 10000);
  }
}

form('workflow-create', async () => {
  const project = projects.find((item) => item.id === value('workflow-project'));
  const recipients = [...$('workflow-recipients').querySelectorAll('input:checked')].map((input) => input.value);
  if (project?.recipients.length && !recipients.length) throw new Error('Choose at least one recipient.');
  const request = { project_id: value('workflow-project'), label: value('workflow-label'), expires_days: Number(value('workflow-days')),
    metadata: Object.fromEntries([...$('workflow-metadata').querySelectorAll('input')].map((input) => [input.dataset.key, input.value])), recipients,
    not_before: localTime('workflow-start'), deadline: localTime('workflow-deadline'), import: value('workflow-import') ? { storage_id: value('workflow-import'), prefix: value('workflow-prefix') } : null };
  const saved = JSON.parse(sessionStorage.getItem(draftKey) || 'null'); request.operation_id = saved?.operation_id || crypto.randomUUID();
  if (saved && JSON.stringify(request) !== JSON.stringify(saved)) { $('workflow-new-operation').hidden = false; throw new Error('A previous request is still pending. Retry its original fields, or discard the pending draft before changing this delivery.'); }
  sessionStorage.setItem(draftKey, JSON.stringify(request));
  $('workflow-result').textContent = 'Creating delivery…';
  let issued;
  try { issued = await api('/api/workflows/jobs', { method: 'POST', body: JSON.stringify(request) }); }
  catch (error) {
    if (!saved && error.status >= 400 && error.status < 500) sessionStorage.removeItem(draftKey);
    $('workflow-new-operation').hidden = !sessionStorage.getItem(draftKey); $('workflow-result').textContent = '';
    throw error;
  }
  sessionStorage.removeItem(draftKey); $('workflow-create').hidden = true; $('workflow-create').reset(); $('workflow-result').textContent = '';
  notice(`“${issued.job.request.label}” was created. Follow its progress below.`); await refreshJobs();
});
form('workflow-save-project', async () => {
  const memberRows = rows('members'), recipientRows = rows('recipients');
  if (new Set(memberRows.map((row) => row.subject)).size !== memberRows.length) throw new Error('Each team member can appear only once.');
  const media = { video_codec: value('wp-codec') || null, width: optionalNumber('wp-width'), height: optionalNumber('wp-height'), frame_rate: value('wp-rate') || null };
  if ($('wp-media-enabled').checked && Object.values(media).every((entry) => entry === null)) throw new Error('Choose at least one video format requirement.');
  const project = { id: value('wp-id'), revision: projectRevision, label: value('wp-label'), directory: value('wp-directory'),
    members: Object.fromEntries(memberRows.map(({ subject, role }) => [subject, role])), recipients: recipientRows.map(({ email, holder }) => ({ email, holder: holder.toLowerCase() })),
    allowed_domains: value('wp-domains').split('\n').map((line) => line.trim().toLowerCase()).filter(Boolean), required_metadata: rows('metadata').map((row) => row.key),
    require_approval: $('wp-approval').checked, scan_required: $('wp-scan').checked, destinations: [...$('wp-destinations').querySelectorAll('input:checked')].map((input) => input.value), receive: $('wp-receive').checked, release: value('wp-release'),
    sequence: $('wp-sequence-enabled').checked ? { prefix: value('wp-sequence-prefix'), suffix: value('wp-sequence-suffix'), first: Number(value('wp-first')), last: optionalNumber('wp-last'), padding: Number(value('wp-padding')) } : null,
    media: $('wp-media-enabled').checked ? media : null };
  if (!(await confirmModal('Save project rules', 'These rules protect the entire folder, including existing links. Existing deliveries need the current policy before further downloads.', 'Save rules'))) return;
  const saved = await api('/api/workflows/projects', { method: 'PUT', body: JSON.stringify(project) });
  $('workflow-save-project').hidden = true; editingProject = null; loaded.delete('jobs');
  $('workflow-jobs').replaceChildren(node('p', 'Loading deliveries…', 'muted'));
  notice(`Project “${saved.label}” saved.`); await refreshProjects();
});

async function loadAttempts(more = false) {
  if (!more) attemptCursor = 0;
  const page = await api(`/api/workflows/webhook/attempts?after=${attemptCursor}&limit=100`);
  if (!more) $('workflow-webhook-attempts').replaceChildren();
  if (!page.attempts.length && !more) $('workflow-webhook-attempts').append(empty('No webhook attempts yet', 'Enable a receiver to start sending delivery events. Failed attempts retry automatically.'));
  for (const attempt of page.attempts) {
    const row = node('div', '', 'event-row'), content = node('div', '');
    content.append(node('strong', `Event ${attempt.event_id} · ${attempt.status}`), node('p', `${attempt.attempts} attempts${attempt.error ? ` · ${attempt.error}` : ''}`, 'muted')); row.append(content);
    row.append(button('Replay event', 'ghost', () => guard(async () => { await api(`/api/workflows/webhook/replay/${attempt.event_id}`, { method: 'POST' }); notice(`Event ${attempt.event_id} queued for replay.`); await loadAttempts(); })));
    $('workflow-webhook-attempts').append(row);
  }
  attemptCursor = page.attempts.at(-1)?.id || attemptCursor; $('workflow-webhook-more').hidden = page.attempts.length < 100;
}
async function loadEvents() {
  if (loadingEvents) return;
  loadingEvents = true; $('workflow-events-next').disabled = true;
  try {
    const page = await api(`/api/workflows/events?after=${eventCursor}&limit=100`);
    if (!eventCursor) $('workflow-events').replaceChildren();
    eventPage.push(...page.events); eventCursor = page.next;
    for (const event of page.events) {
      const row = node('div', '', 'event-row'), content = node('div', '');
      content.append(node('strong', event.kind.replaceAll('_', ' ')), node('p', `${formatWhen(event.created_at)}${event.grant_id ? ` · Delivery ${event.grant_id}` : ''}`, 'muted'));
      row.append(content, node('span', `#${event.id}`, 'mono')); $('workflow-events').append(row);
    }
    if (!$('workflow-events').children.length) $('workflow-events').append(empty('No activity yet', 'Delivery actions and recipient acknowledgments will appear here.'));
    $('workflow-events-export').disabled = !eventPage.length;
    $('workflow-events-next').textContent = page.events.length ? 'Load more activity' : 'Check for new activity';
  } finally { loadingEvents = false; $('workflow-events-next').disabled = false; }
}
form('workflow-save-webhook', async () => {
  const result = await api('/api/workflows/webhook', { method: 'PUT', body: JSON.stringify({ url: value('wh-url'), enabled: $('wh-enabled').checked, revision: hookRevision }) });
  hookRevision = result.webhook.revision; const secret = $('workflow-webhook-secret'); secret.replaceChildren(node('strong', 'Update your receiver with this signing secret'), node('p', result.signing_secret, 'mono'));
  secret.append(button('Copy signing secret', 'ghost', (element) => copyToClipboard(element, result.signing_secret))); secret.hidden = false; notice('Webhook saved.'); await loadAttempts();
});

function section() { return ['jobs', 'projects', 'webhooks', 'activity'].includes(window.location.hash.slice(1)) ? window.location.hash.slice(1) : 'jobs'; }
async function showSection() {
  jobsRevision++;
  const selected = section();
  const requested = /^#job-([a-f0-9]{32})$/.exec(window.location.hash)?.[1];
  for (const panel of document.querySelectorAll('[data-workflow-panel]')) panel.hidden = panel.dataset.workflowPanel !== selected;
  for (const link of document.querySelectorAll('.page-tabs a')) { if (link.hash === `#${selected}`) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current'); }
  clearTimeout(poll);
  if (!loaded.has(selected) || (requested && !jobs.some(({ job }) => job.id === requested))) {
    if (selected === 'jobs' && !await refreshJobs()) return;
    if (selected === 'projects') {
      await refreshProjects();
      if (admin) {
        const [library, tokens] = await Promise.all([api('/api/admin/outbound-files?directory='), api('/api/admin/automation-tokens')]);
        $('wp-folders').replaceChildren(...(library.directories || []).map((folder) => new Option(folder, folder)));
        let suggestions = $('wp-agent-subjects');
        if (!suggestions) { suggestions = document.createElement('datalist'); suggestions.id = 'wp-agent-subjects'; $('workflow-save-project').append(suggestions); }
        suggestions.replaceChildren(...tokens.tokens.map((token) => new Option(token.label, `automation:${token.id}`)));
      }
    }
    if (selected === 'activity') await loadEvents();
    if (selected === 'webhooks' && admin) {
      const result = await api('/api/workflows/webhook'); hookRevision = result.webhook?.revision || 0; $('wh-url').value = result.webhook?.url || ''; $('wh-enabled').checked = result.webhook?.enabled || false; await loadAttempts();
    }
    loaded.add(selected);
  }
  if (requested) revealHash();
  schedulePoll();
}
$('workflow-new').onclick = () => guard(() => newDelivery());
$('workflow-close-create').onclick = () => { $('workflow-create').hidden = true; $('workflow-new').focus(); schedulePoll(); };
$('workflow-close-project').onclick = () => { $('workflow-save-project').hidden = true; $('workflow-new-project').focus(); };
$('workflow-new-project').onclick = () => editProject(); $('workflow-new-project').hidden = !admin;
$('workflow-project').onchange = projectFields;
$('workflow-import').onchange = () => { $('workflow-prefix-field').hidden = !value('workflow-import'); };
$('workflow-new-operation').onclick = () => { sessionStorage.removeItem(draftKey); $('workflow-new-operation').hidden = true; $('workflow-result').textContent = 'Ready to create a new delivery.'; };
$('workflow-refresh').onclick = () => guard(() => refreshJobs()); $('workflow-more').onclick = () => guard(() => refreshJobs(true));
$('wp-label').oninput = () => { if (!editingProject && autoProjectId) $('wp-id').value = value('wp-label').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 100); };
$('wp-id').oninput = () => { autoProjectId = false; };
for (const [kind, name] of [['members', 'member'], ['recipients', 'recipient'], ['metadata', 'metadata']]) $(`wp-add-${name}`).onclick = () => addRow(kind).querySelector('input').focus();
$('wp-sequence-enabled').onchange = $('wp-media-enabled').onchange = checkFields;
$('workflow-save-webhook').hidden = $('workflow-webhook-refresh').hidden = !admin; $('workflow-webhook-access').hidden = admin;
$('workflow-webhook-refresh').onclick = () => guard(() => loadAttempts()); $('workflow-webhook-more').onclick = () => guard(() => loadAttempts(true));
$('workflow-events-next').onclick = () => guard(loadEvents); $('workflow-events-export').onclick = () => download(`delivery-events-${eventCursor}.json`, eventPage);
window.addEventListener('hashchange', () => guard(showSection)); document.addEventListener('visibilitychange', schedulePoll); window.addEventListener('pagehide', () => clearTimeout(poll));
await guard(showSection);
