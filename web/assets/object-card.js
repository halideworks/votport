// Shared object card: one row per delivered file on the sender done list,
// the operator listing, and the verify page. The identity line carries the
// full suite:root; clicking it copies the pasteable form. AGPL-3.0-only.

// Byte size for status lines; shared home so public pages (verify) do not
// import the admin module for one helper.
export function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  const exponent = Math.min(Math.floor(Math.log2(bytes) / 10), units.length - 1);
  const value = bytes / 2 ** (10 * exponent);
  return `${value >= 100 || exponent === 0 ? Math.round(value) : value.toFixed(1)} ${units[exponent]}`;
}

export function identityLine(file) {
  return `${file.suite}:${file.root}`;
}

// file: { name, suite, root } — bytes/receipt are the caller's status string.
// options.tag: 'li' (sender, verify) or 'div' (operator listing).
// options.rowClass: extra classes besides 'object-card'.
// options.status: preformatted status text.
// options.extras: Node[] inserted after the status (badges, buttons).
export function appendObjectCard(parent, file, options = {}) {
  const row = document.createElement(options.tag === "div" ? "div" : "li");
  row.className = options.rowClass
    ? `object-card ${options.rowClass}`
    : "object-card";

  const name = document.createElement("span");
  name.textContent = file.name;
  row.append(name);

  if (options.status) {
    const status = document.createElement("span");
    status.className = "status";
    status.textContent = options.status;
    row.append(status);
  }

  for (const extra of options.extras ?? []) row.append(extra);

  const id = document.createElement("div");
  id.className = "mono muted file-id";
  id.title = "Copy identity";
  id.setAttribute("role", "button");
  id.tabIndex = 0;
  id.textContent = identityLine(file);
  const copy = () => navigator.clipboard.writeText(identityLine(file));
  id.addEventListener("click", copy);
  id.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      copy();
    }
  });
  row.append(id);

  parent.append(row);
  return row;
}
