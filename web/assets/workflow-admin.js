/* global URL, Blob, Option, sessionStorage, crypto */
import { api, button, confirmModal, copyToClipboard, formatWhen } from '/assets/admin-common.js';

const $ = (id) => document.getElementById(id);
const value = (id) => $(id).value.trim();
const lines = (id) => value(id).split('\n').map((line) => line.trim()).filter(Boolean);
const optionalNumber = (id) => value(id) ? Number(value(id)) : null;
const localTime = (id) => value(id) ? Math.floor(new Date(value(id)).getTime() / 1000) : null;
const text = (tag, content) => { const node = document.createElement(tag); node.textContent = content; return node; };

function download(name, content) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(content, null, 2)], { type: 'application/json' }));
  const anchor = document.createElement('a');
  anchor.href = url; anchor.download = name; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function initWorkflows() {
  let projects = [], storage = [], jobs = [], cursor = null, eventCursor = 0, eventPage = [];
  let initialized = false, projectRevision = 0, storageRevision = 0, hookRevision = 0, draftKey = '';

  async function guard(action) {
    $('workflow-error').hidden = true;
    try { await action(); }
    catch (error) { $('workflow-error').textContent = error.message; $('workflow-error').hidden = false; }
  }

  function options(select, entries, first) {
    const previous = select.value;
    select.replaceChildren();
    if (first !== undefined) select.add(new Option(first, ''));
    for (const item of entries) select.add(new Option(item.label, item.id));
    if ([...select.options].some((option) => option.value === previous)) select.value = previous;
  }

  function projectFields() {
    const project = projects.find((item) => item.id === value('workflow-project'));
    $('workflow-metadata').replaceChildren();
    $('workflow-recipients').replaceChildren(text('legend', 'Recipients'));
    $('workflow-rules').textContent = project
      ? `${project.directory} · ${project.require_approval ? 'Approval required' : 'No approval required'} · ${project.scan_required ? 'Malware scan required' : 'No malware scan'}${project.media ? ' · Media checks required' : ''}${project.sequence ? ' · Complete sequence required' : ''}`
      : 'Create a project or ask an administrator to grant you project access.';
    for (const key of project?.required_metadata || []) {
      const label = text('label', key), input = document.createElement('input');
      input.dataset.key = key; input.required = true; input.maxLength = 4096;
      label.append(input); $('workflow-metadata').append(label);
    }
    for (const recipient of project?.recipients || []) {
      const label = document.createElement('label'), input = document.createElement('input');
      input.type = 'checkbox'; input.value = recipient.holder;
      label.append(input, document.createTextNode(` ${recipient.email} (${recipient.holder.slice(0, 12)}…)`));
      $('workflow-recipients').append(label);
    }
  }

  function editProject() {
    const project = projects.find((item) => item.id === value('workflow-edit-project'));
    projectRevision = project?.revision || 0;
    for (const key of ['id', 'label', 'directory']) { $(`wp-${key}`).value = project?.[key] || ''; }
    $('wp-id').readOnly = $('wp-directory').readOnly = !!project;
    $('wp-metadata').value = (project?.required_metadata || []).join('\n');
    $('wp-domains').value = (project?.allowed_domains || []).join('\n');
    $('wp-members').value = Object.entries(project?.members || {}).map(([subject, role]) => `${subject} ${role}`).join('\n');
    $('wp-recipients').value = (project?.recipients || []).map((recipient) => `${recipient.email} ${recipient.holder}`).join('\n');
    $('wp-approval').checked = project?.require_approval || false;
    $('wp-scan').checked = project?.scan_required || false;
    $('wp-export').value = project?.export_storage || '';
    for (const [id, key] of [['sequence-prefix', 'prefix'], ['sequence-suffix', 'suffix'], ['first', 'first'], ['last', 'last'], ['padding', 'padding']]) {
      $(`wp-${id}`).value = project?.sequence?.[key] ?? (key === 'padding' ? 4 : '');
    }
    for (const [id, key] of [['codec', 'video_codec'], ['width', 'width'], ['height', 'height'], ['rate', 'frame_rate']]) { $(`wp-${id}`).value = project?.media?.[key] ?? ''; }
  }

  function editStorage() {
    const item = storage.find((entry) => entry.id === value('workflow-edit-storage'));
    storageRevision = item?.revision || 0;
    for (const key of ['id', 'label', 'endpoint', 'bucket', 'region', 'prefix']) { $(`ws-${key}`).value = item?.[key] ?? (key === 'region' ? 'us-east-1' : ''); }
    $('ws-id').readOnly = !!item;
    $('ws-kms').value = item?.kms_key_id || '';
    $('ws-tenants').value = (item?.tenants || ['']).map((tenant) => tenant || '*').join('\n');
    $('ws-path').checked = item?.path_style ?? true;
    $('ws-enabled').checked = item?.enabled ?? true;
  }

  async function refreshProjects() {
    projects = (await api('/api/workflows/projects')).projects;
    storage = (await api('/api/workflows/storage')).storage;
    options($('workflow-project'), projects);
    options($('workflow-edit-project'), projects, 'New project');
    options($('workflow-edit-storage'), storage, 'New storage');
    options($('workflow-import'), storage.filter((item) => item.enabled), 'Use library files');
    options($('wp-export'), storage.filter((item) => item.enabled), 'No export');
    projectFields();
  }

  async function refreshJobs(more = false) {
    const page = await api(`/api/workflows/jobs?limit=50&after=${encodeURIComponent(more ? cursor || '' : '')}`);
    jobs = more ? jobs.concat(page.jobs) : page.jobs;
    cursor = page.next;
    $('workflow-more').hidden = !cursor;
    $('workflow-jobs').replaceChildren();
    if (!jobs.length) $('workflow-jobs').append(text('p', 'No delivery jobs yet.'));
    for (const { job, url } of jobs) {
      const card = document.createElement('article'); card.className = 'card';
      card.append(text('h3', job.request.label), text('p', `${job.project.label} · ${job.state.replaceAll('_', ' ')} · ${formatWhen(job.created_at)}`));
      if (job.error) card.append(text('p', job.error));
      if (job.manifest) {
        const manifest = text('p', `Manifest: ${job.manifest}`); manifest.className = 'mono'; card.append(manifest);
      }
      if (url) card.append(button('Copy download link', 'tiny', (element) => copyToClipboard(element, url)));
      if (job.state === 'awaiting_approval') card.append(button('Approve this manifest', 'tiny', () => guard(async () => {
        if (await confirmModal('Approve delivery', `Release “${job.request.label}” with manifest ${job.manifest}?`, 'Approve')) {
          await api(`/api/workflows/jobs/${job.id}`, { method: 'POST', body: JSON.stringify({ action: 'approve', manifest: job.manifest }) });
          await refreshJobs();
        }
      })));
      if (job.state === 'failed') card.append(button('Retry', 'tiny', () => guard(async () => {
        await api(`/api/workflows/jobs/${job.id}`, { method: 'POST', body: JSON.stringify({ action: 'retry' }) }); await refreshJobs();
      })));
      if (!['cancelled', 'retired', 'retiring'].includes(job.state)) card.append(button('Cancel job', 'tiny danger', () => guard(async () => {
        if (await confirmModal('Cancel delivery', 'Stop subsequent downloads for this job?', 'Cancel job')) {
          await api(`/api/workflows/jobs/${job.id}`, { method: 'POST', body: JSON.stringify({ action: 'cancel' }) }); await refreshJobs();
        }
      })));
      const evidence = document.createElement('div');
      let after = 0;
      card.append(button('Load recipient evidence', 'tiny ghost', () => guard(async () => {
        const page = await api(`/api/workflows/jobs/${job.id}/evidence?after=${after}&limit=100`);
        if (!page.evidence.length) evidence.append(text('p', after ? 'No further records.' : 'No recipient verification recorded.'));
        for (const record of page.evidence) {
          const statement = record.evidence, holder = statement.authorization.challenge.holder;
          const who = job.project.recipients.find((recipient) => recipient.holder === holder)?.email || holder;
          evidence.append(text('p', `${who}: ${statement.kind} · ${formatWhen(record.received_at)}`));
        }
        after = page.next;
        if (page.evidence.length) evidence.append(button('Download signed evidence page', 'tiny', () => download(`delivery-${job.id}-evidence-${after}.json`, page)));
      })), evidence);
      $('workflow-jobs').append(card);
    }
  }

  function form(id, action) {
    $(id).addEventListener('submit', (event) => {
      event.preventDefault();
      const submit = event.submitter;
      if (submit?.disabled) return;
      if (submit) submit.disabled = true;
      guard(action).finally(() => { if (submit) submit.disabled = false; });
    });
  }

  form('workflow-create', async () => {
    const request = { project_id: value('workflow-project'), label: value('workflow-label'), expires_days: Number(value('workflow-days')),
      metadata: Object.fromEntries([...$('workflow-metadata').querySelectorAll('input')].map((input) => [input.dataset.key, input.value])),
      recipients: [...$('workflow-recipients').querySelectorAll('input:checked')].map((input) => input.value),
      not_before: localTime('workflow-start'), deadline: localTime('workflow-deadline'),
      import: value('workflow-import') ? { storage_id: value('workflow-import'), prefix: value('workflow-prefix') } : null };
    const saved = JSON.parse(sessionStorage.getItem(draftKey) || 'null');
    request.operation_id = saved?.operation_id || crypto.randomUUID();
    if (saved && JSON.stringify(request) !== JSON.stringify(saved)) throw new Error('Retry with the same fields, or select “Start a separate delivery.”');
    sessionStorage.setItem(draftKey, JSON.stringify(request));
    const issued = await api('/api/workflows/jobs', { method: 'POST', body: JSON.stringify(request) });
    $('workflow-result').textContent = `Job ${issued.job.id}: ${issued.job.state.replaceAll('_', ' ')}. Refresh to follow its progress.`;
    await refreshJobs();
  });
  $('workflow-new-operation').onclick = () => { sessionStorage.removeItem(draftKey); $('workflow-result').textContent = 'Ready to create a separate delivery.'; };
  $('workflow-project').onchange = projectFields;
  $('workflow-edit-project').onchange = editProject;
  $('workflow-edit-storage').onchange = editStorage;
  $('workflow-refresh').onclick = () => guard(refreshJobs);
  $('workflow-more').onclick = () => guard(() => refreshJobs(true));

  form('workflow-save-project', async () => {
    const pairs = (id) => lines(id).map((line) => { const pair = line.split(/\s+/); if (pair.length !== 2) throw new Error('Use two space-separated values per line.'); return pair; });
    const media = { video_codec: value('wp-codec') || null, width: optionalNumber('wp-width'), height: optionalNumber('wp-height'), frame_rate: value('wp-rate') || null };
    const project = { id: value('wp-id'), revision: projectRevision, label: value('wp-label'), directory: value('wp-directory'),
      members: Object.fromEntries(pairs('wp-members')), recipients: pairs('wp-recipients').map(([email, holder]) => ({ email, holder })),
      allowed_domains: lines('wp-domains'), required_metadata: lines('wp-metadata'), require_approval: $('wp-approval').checked,
      scan_required: $('wp-scan').checked, export_storage: value('wp-export') || null,
      sequence: value('wp-first') ? { prefix: value('wp-sequence-prefix'), suffix: value('wp-sequence-suffix'), first: Number(value('wp-first')), last: optionalNumber('wp-last'), padding: Number(value('wp-padding')) } : null,
      media: Object.values(media).some((item) => item !== null) ? media : null };
    if (!(await confirmModal('Save project rules', 'These rules protect the whole directory. Existing jobs require the current policy before further downloads.', 'Save rules'))) return;
    const saved = await api('/api/workflows/projects', { method: 'PUT', body: JSON.stringify(project) });
    projectRevision = saved.revision;
    await refreshProjects(); $('workflow-edit-project').value = saved.id; editProject(); await refreshJobs();
  });

  form('workflow-save-storage', async () => {
    const item = Object.fromEntries(['id', 'label', 'endpoint', 'bucket', 'region', 'prefix'].map((key) => [key, value(`ws-${key}`)]));
    Object.assign(item, { revision: storageRevision, kms_key_id: value('ws-kms') || null, tenants: lines('ws-tenants').map((tenant) => tenant === '*' ? '' : tenant), path_style: $('ws-path').checked, enabled: $('ws-enabled').checked });
    const saved = await api('/api/workflows/storage', { method: 'PUT', body: JSON.stringify(item) });
    await refreshProjects(); $('workflow-edit-storage').value = saved.id; editStorage();
  });

  form('workflow-save-webhook', async () => {
    const result = await api('/api/workflows/webhook', { method: 'PUT', body: JSON.stringify({ url: value('wh-url'), enabled: $('wh-enabled').checked, revision: hookRevision }) });
    hookRevision = result.webhook.revision;
    $('workflow-webhook-secret').textContent = `Signing secret: ${result.signing_secret}. Store it in your receiver's secret manager.`;
  });
  let attemptCursor = 0;
  $('workflow-webhook-refresh').onclick = () => guard(async () => {
    const page = await api(`/api/workflows/webhook/attempts?after=${attemptCursor}&limit=100`);
    if (!page.attempts.length) { $('workflow-webhook-attempts').append(text('p', 'End of attempts. Refresh again to start from the beginning.')); attemptCursor = 0; return; }
    if (!attemptCursor) $('workflow-webhook-attempts').replaceChildren();
    for (const attempt of page.attempts) {
      const row = text('p', `Event ${attempt.event_id}: ${attempt.status} · ${attempt.attempts} attempts${attempt.error ? ` · ${attempt.error}` : ''}`);
      row.append(button('Replay', 'tiny', () => guard(async () => {
        await api(`/api/workflows/webhook/replay/${attempt.event_id}`, { method: 'POST' }); row.append(document.createTextNode(' · Replay queued'));
      })));
      $('workflow-webhook-attempts').append(row);
    }
    attemptCursor = page.attempts.at(-1).id;
  });
  $('workflow-events-next').onclick = () => guard(async () => {
    const page = await api(`/api/workflows/events?after=${eventCursor}&limit=100`);
    eventPage = page.events; eventCursor = page.next;
    $('workflow-events').replaceChildren(...eventPage.map((event) => text('p', `${event.id} · ${event.kind.replaceAll('_', ' ')} · ${formatWhen(event.created_at)} · ${event.grant_id}`)));
    if (!eventPage.length) $('workflow-events').append(text('p', 'No more visible events.'));
    $('workflow-events-export').disabled = !eventPage.length;
  });
  $('workflow-events-export').onclick = () => download(`delivery-events-${eventCursor}.json`, eventPage);

  $('workflows').addEventListener('toggle', () => {
    if (!$('workflows').open || initialized) return;
    initialized = true;
    guard(async () => {
      const session = await api('/api/admin/session');
      draftKey = `votport-workflow-draft:${session.tenant || ''}`;
      const admin = session.role === 'admin';
      $('workflow-project-panel').hidden = $('workflow-webhook-panel').hidden = !admin;
      $('workflow-storage-panel').hidden = !admin || !!session.tenant;
      await refreshProjects(); await refreshJobs();
      if (admin) {
        const result = await api('/api/workflows/webhook');
        hookRevision = result.webhook?.revision || 0;
        $('wh-url').value = result.webhook?.url || '';
        $('wh-enabled').checked = result.webhook?.enabled || false;
      }
    }).catch(() => {}).finally(() => { if (!$('workflow-error').hidden) initialized = false; });
  });
  if (window.location.hash === '#workflows') $('workflows').open = true;
}
