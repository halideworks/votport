// Shared object card: one row per delivered file on the sender done list,
// the operator listing, and the verify page. The identity line carries the
// full suite:root; clicking it copies the pasteable form. AGPL-3.0-only.

export function identityLine(file) {
  return `${file.suite}:${file.root}`;
}

// file: { name, suite, root } — bytes/receipt are the caller's status string.
// options.tag: 'li' (sender, verify) or 'div' (operator listing).
// options.rowClass: extra classes besides 'object-card'.
// options.status: preformatted status text.
// options.extras: Node[] inserted after the status (badges, buttons).
export function appendObjectCard(parent, file, options = {}) {
  const row = document.createElement(options.tag === 'div' ? 'div' : 'li');
  row.className = options.rowClass
    ? `object-card ${options.rowClass}`
    : 'object-card';

  const name = document.createElement('span');
  name.textContent = file.name;
  row.append(name);

  if (options.status) {
    const status = document.createElement('span');
    status.className = 'status';
    status.textContent = options.status;
    row.append(status);
  }

  for (const extra of options.extras ?? []) row.append(extra);

  const id = document.createElement('div');
  id.className = 'mono muted file-id';
  id.title = 'Copy identity';
  id.setAttribute('role', 'button');
  id.tabIndex = 0;
  id.textContent = identityLine(file);
  const copy = () => navigator.clipboard.writeText(identityLine(file));
  id.addEventListener('click', copy);
  id.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      copy();
    }
  });
  row.append(id);

  parent.append(row);
  return row;
}
