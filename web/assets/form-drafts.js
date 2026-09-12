const dirty = new Set(), keys = new WeakMap();
let mounted = false;
const fields = (root) => [...root.querySelectorAll('[data-draft-field]')].filter((field) => !['password', 'file', 'hidden'].includes(field.type));
function persist(root) {
  const key = keys.get(root);
  if (key) try { window.sessionStorage.setItem(key, JSON.stringify(Object.fromEntries(fields(root).map((field) => [field.id, field.value])))); } catch { /* Browser storage may be disabled. */ }
}
export function isFormDirty(root) { return dirty.has(root); }
export function markFormChanged(root) {
  if (!root) return;
  dirty.add(root); persist(root);
}
export function markFormSaved(root) {
  if (!root) return;
  dirty.delete(root);
  if (keys.has(root)) try { window.sessionStorage.removeItem(keys.get(root)); } catch { /* Browser storage may be disabled. */ }
  root.querySelector('.draft-note')?.remove();
}
export function discardForm(root) {
  if (dirty.has(root) && !window.confirm('Discard your unsaved changes?')) return false;
  markFormSaved(root); return true;
}
export async function confirmLeave(action) {
  if ([...dirty].some((root) => root.isConnected) && !window.confirm('Leave with unsaved changes? Saved settings will stay unchanged.')) return false;
  await action();
  dirty.clear(); return true;
}
export function mountDrafts(session) {
  if (mounted) return;
  mounted = true;
  for (const root of document.querySelectorAll('[data-draft]')) {
    const key = `votport-form:${JSON.stringify([session.subject, session.tenant, window.location.pathname, window.location.search, root.id])}`;
    keys.set(root, key);
    try {
      const saved = JSON.parse(window.sessionStorage.getItem(key) || 'null');
      if (saved && fields(root).some((field) => typeof saved[field.id] === 'string' && saved[field.id] !== field.value)) {
        for (const field of fields(root)) if (typeof saved[field.id] === 'string') field.value = saved[field.id];
        const note = document.createElement('p'); note.className = 'draft-note field-help'; note.setAttribute('role', 'status');
        note.textContent = 'Restored your name and basic options in this tab. Recheck files, access and notification settings before saving.';
        root.prepend(note); dirty.add(root);
      }
    } catch { /* A damaged or unavailable draft must not prevent editing. */ }
  }
  for (const event of ['input', 'change']) document.addEventListener(event, (event) => {
    const root = event.target.closest('[data-unsaved]');
    if (root) markFormChanged(root);
  });
  document.addEventListener('invalid', (event) => {
    for (let parent = event.target.parentElement; parent; parent = parent.parentElement) if (parent.tagName === 'DETAILS') parent.open = true;
  }, true);
  window.addEventListener('beforeunload', (event) => {
    if ([...dirty].some((root) => root.isConnected)) { event.preventDefault(); event.returnValue = ''; }
  });
}
