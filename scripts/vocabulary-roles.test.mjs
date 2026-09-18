// Finding 445: session roles are admin, operator, viewer and auditor, but
// "auditor" and "tenant admin" showed up in zero user-visible strings. A
// principal's grants now read as words and the audit nav hint names the
// auditor role.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const read = (p) => readFile(new URL(p, import.meta.url), 'utf8');

test('principal grants render as role words, never the wire form tenant/role', async () => {
  const script = await read('../web/assets/page-tenants.js');
  // One word builder per grant: "acme auditor", "acme tenant admin", "auditor".
  assert.match(script, /grant\.role === 'admin' && grant\.tenant !== '' \? 'tenant admin' : grant\.role/);
  assert.match(script, /grant\.tenant === '' \? role : `\$\{grant\.tenant\} \$\{role\}`/);
  assert.doesNotMatch(script, /\/\$\{grant\.role\}/);
});

test('the audit nav hint names the auditor role', async () => {
  const script = await read('../web/assets/admin-common.js');
  assert.match(
    script,
    /\['audit', '\/audit', 'Audit', 'Review who did what on this port\. An auditor session sees only this page\.'\]/,
  );
});
