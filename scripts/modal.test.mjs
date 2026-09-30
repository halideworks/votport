import assert from 'node:assert/strict';
import { test } from 'node:test';
import { confirmModal, alertModal } from '../web/assets/object-card.js';

test('each overlapping modal waits for its own answer', async () => {
  const elements = new Map();
  const dialog = new EventTarget();
  dialog.showModal = () => { dialog.open = true; };
  dialog.close = (value) => {
    dialog.returnValue = value;
    dialog.open = false;
    dialog.dispatchEvent(new Event('close'));
  };
  elements.set('confirm', dialog);
  globalThis.document = { getElementById(id) {
    if (!elements.has(id)) elements.set(id, {});
    return elements.get(id);
  } };
  try {
    const first = confirmModal('Delete first', 'First file', 'Delete');
    const second = confirmModal('Delete second', 'Second file', 'Delete');
    const warning = alertModal('Connection failed');
    await new Promise(setImmediate);
    assert.equal(elements.get('confirm-title').textContent, 'Delete first');
    dialog.close('ok');
    assert.equal(await first, true);
    await new Promise(setImmediate);
    assert.equal(elements.get('confirm-detail').textContent, 'Second file');
    dialog.close('cancel');
    assert.equal(await second, false);
    await new Promise(setImmediate);
    assert.equal(elements.get('confirm-detail').textContent, 'Connection failed');
    assert.equal(elements.get('confirm-ok').hidden, true);
    dialog.close('cancel');
    await warning;
  } finally { delete globalThis.document; }
});
