// Shared object card: one row per delivered file on the sender done list,
// the operator listing, and the verify page. The identity line carries the
// full suite:root; clicking it copies the pasteable form. VOTPORT PROPRIETARY LICENSE.

// Byte size for status lines; shared home so public pages (verify) do not
// import the admin module for one helper. Decimal units, one vocabulary with
// the desktops' Rust human_bytes: transfer limits are created in decimal GB
// and rates are quoted the same way, so sizes read the same everywhere.
export function formatBytes(bytes) {
  if (bytes === 0) return '0 bytes';
  if (bytes === 1) return '1 byte';
  const units = ['bytes', 'KB', 'MB', 'GB', 'TB'];
  let amount = bytes;
  let unit = 0;
  while (amount >= 1000 && unit < units.length - 1) {
    amount /= 1000;
    unit += 1;
  }
  // One decimal below 100, none at or above, and a carry when rounding
  // reaches the next unit (999.5 KB reads 1.0 MB).
  if (unit < units.length - 1 && amount >= 999.5) {
    amount /= 1000;
    unit += 1;
  }
  if (unit === 0) return `${bytes} bytes`;
  return `${amount >= 99.95 ? Math.round(amount) : amount.toFixed(1)} ${units[unit]}`;
}

/// Copies text and flips the button label to Copied for a moment.
export async function copyToClipboard(element, text) {
  await navigator.clipboard.writeText(text);
  element.dataset.label ??= element.textContent;
  if (element.getAttribute('aria-label')) {
    element.dataset.ariaLabel ??= element.getAttribute('aria-label');
    element.setAttribute('aria-label', 'Copied');
  }
  element.textContent = 'Copied';
  setTimeout(() => {
    element.textContent = element.dataset.label;
    if (element.dataset.ariaLabel) element.setAttribute('aria-label', element.dataset.ariaLabel);
  }, 1500);
}

/// The votport: app link for one transfer kind and token, carrying the
/// current origin so the desktop app can prefill the server address.
export function appLink(kind, token) {
  return `votport://${kind}/${encodeURIComponent(token)}?base=${encodeURIComponent(window.location.origin)}`;
}

/// Binds an error alert to the field that must change: the field's
/// aria-describedby names the alert and aria-invalid holds while it shows.
/// Alerts with no owning field stay standalone role=alerts.
export function fieldError(field, alert) {
  const described = new Set((field.getAttribute('aria-describedby') ?? '').split(/\s+/).filter(Boolean));
  described.add(alert.id);
  field.setAttribute('aria-describedby', [...described].join(' '));
  return {
    show(message) {
      alert.textContent = message;
      alert.hidden = false;
      field.setAttribute('aria-invalid', 'true');
    },
    clear() {
      alert.hidden = true;
      field.removeAttribute('aria-invalid');
    },
  };
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
  const copyLabel = `Copy file hash: ${file.name}`;
  id.setAttribute("aria-label", copyLabel);
  id.setAttribute("aria-live", "polite");
  id.setAttribute("aria-atomic", "true");
  id.tabIndex = 0;
  const identity = identityLine(file);
  id.textContent = identity;
  let copyStatusTimer;
  let copyPending = false;
  const copy = async () => {
    if (copyPending) return;
    copyPending = true;
    clearTimeout(copyStatusTimer);
    try {
      await navigator.clipboard.writeText(identity);
      id.textContent = "Copied";
      id.setAttribute("aria-label", `Copied file hash: ${file.name}`);
    } catch {
      id.textContent = "Copy failed";
      id.setAttribute("aria-label", `Copy failed: ${file.name}`);
    } finally {
      copyPending = false;
      copyStatusTimer = setTimeout(() => {
        id.textContent = identity;
        id.setAttribute("aria-label", copyLabel);
      }, 1500);
    }
  };
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

/// Whole seconds as a short duration: 45s, 2m 40s, 1h 5m. Fractional
/// estimates from live rates round to the shown second.
export function formatDuration(seconds) {
  const total = Math.round(seconds);
  if (total < 60) return `${total}s`;
  if (total < 3600) return `${Math.floor(total / 60)}m ${total % 60}s`;
  return `${Math.floor(total / 3600)}h ${Math.floor((total % 3600) / 60)}m`;
}

/// Relative age for an activity stamp: "just now", "3 min ago", "2 d ago";
/// a future moment reads "in 5 min". Pair it with formatWhen in a title so
/// the exact moment stays one hover away (audit finding 462).
export function formatAgo(unixSeconds, now = Math.round(Date.now() / 1000)) {
  const delta = now - unixSeconds;
  // Cutoff, divisor, unit: pick the largest unit that fits the distance.
  const steps = [
    [60, 1, 'just now'],
    [3600, 60, 'min'],
    [86400, 3600, 'h'],
    [604800, 86400, 'd'],
    [2629800, 604800, 'w'],
    [31557600, 2629800, 'mo'],
    [Infinity, 31557600, 'y'],
  ];
  const [, divisor, unit] = steps.find(([limit]) => Math.abs(delta) < limit);
  if (unit === 'just now') return unit;
  const value = Math.max(1, Math.floor(Math.abs(delta) / divisor));
  return delta > 0 ? `${value} ${unit} ago` : `in ${value} ${unit}`;
}
