// Browser end-to-end check: signs in to the admin UI, creates a link,
// uploads files through the real uploader (vot-wasm), and
// verifies the bytes on disk. VOTPORT PROPRIETARY LICENSE.
//
// Requires: `npm ci`, the Playwright browser selected by BROWSER_ENGINE, a
// running votport, and:
//   BASE_URL        e.g. http://127.0.0.1:8080
//   ADMIN_PASSWORD  the admin password of that instance
//   RECEIVE_DIR     the instance's receive root, from this process's view
//
//   BROWSER_ENGINE=firefox node scripts/browser-e2e.mjs

import { chromium, firefox, webkit } from "playwright";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const base = process.env.BASE_URL || "http://127.0.0.1:8080";
const adminPassword = process.env.ADMIN_PASSWORD;
const receiveDir = process.env.RECEIVE_DIR;
const browserEngine = process.env.BROWSER_ENGINE || "chromium";
const browserType = { chromium, firefox, webkit }[browserEngine];
if (!adminPassword || !receiveDir) {
  console.error("set BASE_URL, ADMIN_PASSWORD and RECEIVE_DIR");
  process.exit(2);
}
if (!browserType) {
  console.error("BROWSER_ENGINE must be chromium, firefox, or webkit");
  process.exit(2);
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "votport-e2e-"));
process.once("exit", () => fs.rmSync(dir, { recursive: true, force: true }));
fs.writeFileSync(path.join(dir, "Résumé Draft.pdf"), "unicode names travel\n");
const outboundFiles = Array.from({ length: 12 }, (_, index) => ({
  name: `deliver-${String(index + 1).padStart(2, "0")}.txt`,
  content: `deliverable ${index + 1}\n`,
}));
for (const file of outboundFiles) fs.writeFileSync(path.join(dir, file.name), file.content);
const folder = path.join(dir, "folder-pick");
fs.mkdirSync(path.join(folder, "nested"), { recursive: true });
fs.writeFileSync(path.join(folder, "nested", "folder-nested.txt"), "nested folder deliverable\n");
// Multiple server-sized ranges exercise the bounded parallel upload path, and
// a file over 64 MiB is hashed as segments across the worker pool on a runner
// with three or more cores, so the server verifies ranges proved from an
// assembled tree.
const big = Buffer.alloc(96 * 1024 * 1024 + 99);
const pattern = Buffer.alloc(253);
for (let i = 0; i < pattern.length; i += 1) pattern[i] = (i * 7) % 253;
for (let at = 0; at < big.length; at += pattern.length) pattern.copy(big, at, 0, Math.min(pattern.length, big.length - at));
fs.writeFileSync(path.join(dir, "archive.tar"), big);

// A UTF-8 locale is required for all engines to accept non-ASCII file names.
const browser = await browserType.launch({
  env: { ...process.env, LANG: "C.UTF-8", LC_ALL: "C.UTF-8" },
});
const page = await browser.newPage();
page.on("dialog", (dialog) => dialog.accept());
const errors = [];
page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
await page.addInitScript(() => {
  Object.defineProperty(window, "__clipboardFailure", { value: false, writable: true });
  Object.defineProperty(window, "__clipboardHold", { value: false, writable: true });
  Object.defineProperty(window, "__releaseClipboard", { value: null, writable: true });
  Object.defineProperty(window, "__copiedText", { value: "", writable: true });
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: async (text) => {
      if (window.__clipboardHold) await new Promise((resolve) => { window.__releaseClipboard = resolve; });
      if (window.__clipboardFailure) throw new Error("Clipboard unavailable");
      window.__copiedText = String(text);
    }, readText: async () => window.__copiedText },
  });
});

async function collectDownloads(action, count) {
  const downloads = [];
  let timer;
  let resolveDownloads;
  let rejectDownloads;
  const complete = new Promise((resolve, reject) => {
    resolveDownloads = resolve;
    rejectDownloads = reject;
  });
  const onDownload = (download) => {
    downloads.push(download);
    if (downloads.length === count) resolveDownloads(downloads);
  };
  page.on("download", onDownload);
  timer = setTimeout(() => rejectDownloads(new Error(`expected ${count} downloads, got ${downloads.length}`)), 30000);
  try {
    await action();
    return await complete;
  } finally {
    clearTimeout(timer);
    page.off("download", onDownload);
  }
}

// Headless Chromium does not provide a deterministic folder chooser. Force
// the supported anchor-download fallback so this path is exercised in CI.
await page.addInitScript(() => {
  Object.defineProperty(window, "showDirectoryPicker", { value: undefined });
});

const genericSsoError = "SSO sign-in failed. Try again or contact your administrator.";
for (const [code, expected] of [
  [Buffer.from("Contact attacker.invalid to unlock this account").toString("hex"), genericSsoError],
  ["Contact attacker.invalid", genericSsoError],
  ["constructor", genericSsoError],
  ["__proto__", genericSsoError],
  ["account_blocked", "This account is blocked. Contact your administrator."],
  ["not_provisioned", "This account has not been provisioned. Contact your administrator."],
  ["state_invalid", "This sign-in has expired or is invalid. Start sign-in again."],
  ["", null],
]) {
  await page.goto(`${base}/?sso_error=${encodeURIComponent(code)}`);
  await page.waitForSelector("#login:not([hidden])");
  await page.waitForFunction(() => window.location.search === "");
  const banner = page.locator("#login-error");
  if (expected === null) {
    if (await banner.isVisible()) throw new Error("empty SSO error displayed a banner");
  } else if (!(await banner.isVisible()) || (await banner.textContent()) !== expected) {
    throw new Error(`SSO error ${code} displayed unexpected text: ${await banner.textContent()}`);
  }
}
console.log("SSO errors use fixed messages and remove the URL parameter: ok");

await page.goto(base);
await page.waitForSelector("#login:not([hidden])");
await page.fill("#login-password", adminPassword);
await page.click("#login-form button[type=submit]");
// Signed-in users land on /receive; the create form is the first element.
await page.waitForSelector("#create-form:not([hidden])", { timeout: 15000 });
await page.locator("#create-notification-options").evaluate((node) => { node.open = true; });
await page.locator(".notification-editor > p.field-help").first().waitFor();
if (await page.locator(".notification-editor > p.field-help").evaluateAll((nodes) => nodes.some((node) => node.getAttribute("role") === "status"))) {
  throw new Error("embedded notification guidance must stay quiet while editors rerender");
}
await page.route("**/api/notifications*", (route) => route.fulfill({ status: 503, json: { error: "Notification catalog unavailable." } }), { times: 1 });
await page.reload();
await page.locator("#create-notification-options").evaluate((node) => { node.open = true; });
const notificationStatus = page.locator("#create-notifications .notification-editor > p.field-help");
await notificationStatus.waitFor();
await page.getByRole("button", { name: "Retry loading destinations", exact: true }).waitFor();
if (await notificationStatus.getAttribute("role") !== "alert") {
  throw new Error("notification catalog failures must be announced");
}
await page.getByRole("button", { name: "Retry loading destinations", exact: true }).click();
await page.waitForFunction(() => {
  const node = document.querySelector("#create-notifications .notification-editor > p.field-help");
  return node && !node.hasAttribute("role") && node.textContent === "Notifications are off for this item.";
});

const run = Date.now().toString(36);
const dest = `e2e-${run}`;
// Unique per run so the script can be re-run against the same instance.
const PROJECT = `browser-project-${run}`;
const FOLDER_PROJECT = `browser-folder-project-${run}`;
await page.fill("#create-label", "browser e2e");
await page.fill("#create-dest", dest);
let receivePostSeen = false;
let receiveListFailed = false;
let releaseReceiveList;
const heldReceiveList = new Promise((resolve) => { releaseReceiveList = resolve; });
await page.route("**/api/admin/links*", async (route) => {
  if (route.request().method() === "POST") {
    const response = await route.fetch();
    receivePostSeen = true;
    return route.fulfill({ response });
  }
  if (receivePostSeen && !receiveListFailed) {
    receiveListFailed = true;
    await heldReceiveList;
    return route.fulfill({ status: 503, json: { error: "Created link list refresh unavailable." } });
  }
  return route.continue();
});
const createdResponse = page.waitForResponse((response) => response.url().includes("/api/admin/links")
  && response.request().method() === "POST");
await page.click("#create-form button[type=submit]");
const createdLinkId = (await (await createdResponse).json()).link.id;
await page.waitForSelector("#new-link:not([hidden])");
const linkUrl = (await page.textContent("#new-link-url")).trim();
try {
  await page.waitForFunction(() => document.activeElement.id === "new-link-url"
    && !document.getElementById("create-form").inert
    && !document.querySelector("#create-form button[type=submit]").disabled);
} finally {
  releaseReceiveList();
}
await page.locator("#links-error").filter({ hasText: "Created link list refresh unavailable." }).waitFor({ state: "visible" });
if (await page.getAttribute("#new-link-url", "role") !== "status"
  || await page.evaluate(() => document.activeElement === document.getElementById("new-link-url"))
  !== true
  || await page.textContent("#links-action-status") !== "Receive link created.") {
  throw new Error("created receive links must announce and focus their address");
}
if (!receiveListFailed || await page.locator("#create-error").isVisible()) {
  throw new Error("a list refresh failure must not hide or fail a successfully created receive link");
}
await page.click("#new-link-copy");
await page.waitForFunction((url) => window.__copiedText === url
  && document.getElementById("links-action-status").textContent === "Receive link copied.", linkUrl);
await page.evaluate(() => { window.__clipboardFailure = true; window.__clipboardHold = true; window.__releaseClipboard = null; });
await page.click("#new-link-copy");
await page.waitForFunction(() => typeof window.__releaseClipboard === "function");
await page.locator("#links-query").focus();
await page.evaluate(() => { window.__clipboardHold = false; window.__releaseClipboard(); });
await page.waitForFunction(() => document.activeElement === document.getElementById("links-query")
  && document.getElementById("links-action-status").textContent === "Could not copy the receive address. Use Copy address below to retry.");
await page.evaluate(() => { window.__clipboardHold = false; });
await page.click("#new-link-copy");
await page.waitForFunction(() => document.activeElement === document.getElementById("new-link-url")
  && document.getElementById("links-action-status").textContent === "Your receive address is selected below. Copy it to share.");
await page.evaluate(() => { window.__clipboardFailure = false; });
await page.reload();
await page.locator("#links [data-link-id]").first().waitFor();
const embeddedNotificationStatuses = page.locator(".notification-editor > p.field-help");
if (await embeddedNotificationStatuses.count() < 2
  || await embeddedNotificationStatuses.evaluateAll((nodes) => nodes.some((node) => node.getAttribute("role") === "status"))
  || await page.getAttribute("#links-action-status", "role") !== "status") {
  throw new Error("repeated embedded notification editors must stay quiet while action status remains live");
}

const mastheadSearchRoute = "**/api/admin/search?*";
let searchUnavailable = false;
const searchNow = Math.floor(Date.now() / 1000);
await page.route(mastheadSearchRoute, (route) => searchUnavailable
  ? route.fulfill({ status: 503, json: { error: "Search fixture unavailable." } })
  : route.fulfill({ json: {
    requests: [
      { id: "unselected-request", label: "unselected request", active: true, dest, created_at: searchNow },
      { id: createdLinkId, label: "browser search request", active: true, dest, created_at: searchNow },
    ],
    files: [{ link_id: createdLinkId, path: "search.txt", bytes: 42, link_label: "browser search request", completed_at: searchNow }],
    downloads: [{ id: "search-grant", label: "browser search download", name: "search.txt", revoked: false, created_at: searchNow }],
  } }));
const searchInput = page.locator("#global-search-input");
const searchResults = page.locator("#global-search-results");
const searchStatus = page.locator("#global-search-status");
await searchInput.focus();
if (await searchInput.getAttribute("autocomplete") !== "off"
  || await searchInput.getAttribute("role") !== "combobox"
  || await searchInput.getAttribute("aria-controls") !== "global-search-results"
  || await searchInput.getAttribute("aria-expanded") !== "false"
  || await searchInput.getAttribute("aria-autocomplete") !== "list"
  || await searchInput.getAttribute("aria-haspopup") !== "listbox"
  || await searchResults.getAttribute("role") !== "listbox"
  || await searchStatus.getAttribute("role") !== "status") {
  throw new Error("masthead search must expose its combobox and listbox semantics");
}
await searchInput.fill("ac");
const options = searchResults.locator('[role="option"]');
await options.first().waitFor();
await page.waitForFunction(() => document.getElementById("global-search-status").textContent === "5 search results.");
if (await options.count() !== 5 || await searchResults.locator('[role="option"][aria-selected="false"]').count() !== 5
  || await options.evaluateAll((rows) => rows.some((row) => row.tabIndex !== -1))) {
  throw new Error("masthead search must expose every result as an unselected option");
}
const auditOption = options.filter({ hasText: "Search audit log" });
if (await auditOption.count() !== 1
  || !(await auditOption.getAttribute("href")).includes("/audit?q=ac")) {
  throw new Error("entitled masthead search must link the phrase to the audit page");
}
await searchInput.focus();
await searchInput.press("Tab");
if (await page.evaluate(() => document.activeElement?.getAttribute("role") === "option")
  || !(await searchResults.isHidden())
  || await searchInput.getAttribute("aria-expanded") !== "false") {
  throw new Error("Tab must skip input-owned search options");
}
await searchInput.focus();
await searchInput.fill("ac");
await page.waitForFunction(() => document.getElementById("global-search-status").textContent === "5 search results.");
await options.first().waitFor();
await searchInput.press("ArrowDown");
const firstOptionId = await options.nth(0).getAttribute("id");
if (await searchInput.getAttribute("aria-activedescendant") !== firstOptionId
  || await options.nth(0).getAttribute("aria-selected") !== "true"
  || !(await options.nth(0).evaluate((node) => getComputedStyle(node).outlineStyle !== "none"))) {
  throw new Error("ArrowDown must select and visibly mark the first search result");
}
await searchInput.fill("new");
if (await searchInput.getAttribute("aria-activedescendant") !== null) {
  throw new Error("new search input must clear the old active result");
}
const refreshedSearch = page.waitForResponse((response) => response.url().includes("/api/admin/search")
  && response.status() === 200);
await searchInput.fill("ac");
await refreshedSearch;
await page.waitForFunction(() => document.getElementById("global-search-status").textContent === "5 search results.");
await options.first().waitFor();
await searchInput.press("ArrowDown");
await searchInput.press("ArrowDown");
const secondOptionId = await options.nth(1).getAttribute("id");
if (await searchInput.getAttribute("aria-activedescendant") !== secondOptionId
  || await options.nth(0).getAttribute("aria-selected") !== "false"
  || await options.nth(1).getAttribute("aria-selected") !== "true") {
  throw new Error("ArrowDown must advance the active search result");
}
await searchInput.press("ArrowUp");
if (await searchInput.getAttribute("aria-activedescendant") !== firstOptionId) {
  throw new Error("ArrowUp must return to the previous search result");
}
await searchInput.press("Home");
if (!(await searchInput.evaluate((node) => node.selectionStart === 0 && node.selectionEnd === 0))
  || await searchInput.getAttribute("aria-activedescendant") !== firstOptionId) {
  throw new Error("Home must move the input cursor without clearing the active result");
}
await searchInput.press("End");
if (!(await searchInput.evaluate((node) => node.selectionStart === node.value.length && node.selectionEnd === node.value.length))
  || await searchInput.getAttribute("aria-activedescendant") !== firstOptionId) {
  throw new Error("End must move the input cursor without clearing the active result");
}
await searchInput.press("Escape");
if (!(await searchResults.isHidden())
  || await searchInput.getAttribute("aria-expanded") !== "false"
  || await searchInput.getAttribute("aria-activedescendant") !== null
  || !(await searchInput.evaluate((node) => node === document.activeElement))) {
  throw new Error("Escape must close and reset masthead search state");
}
searchUnavailable = true;
await searchInput.fill("zz");
await page.waitForFunction(() => document.getElementById("global-search-status").textContent === "Search failed: Search fixture unavailable.");
if (await searchResults.isHidden() || !(await searchResults.textContent()).includes("Search failed: Search fixture unavailable.")) {
  throw new Error("masthead search failures must remain visible and announced");
}
searchUnavailable = false;
await searchInput.fill("ac");
await options.first().waitFor();
await searchInput.press("ArrowDown");
await searchInput.press("ArrowDown");
await searchInput.press("Enter");
await page.waitForURL((url) => url.pathname === "/receive"
  && url.searchParams.get("search") === createdLinkId
  && url.hash === `#link-${createdLinkId}`);
const searchedCard = page.locator(`#link-${createdLinkId}`);
await searchedCard.locator("details[open]").waitFor();
await page.waitForFunction((id) => document.activeElement?.id === id, `link-${createdLinkId}`);
if (!(await searchedCard.evaluate((node) => getComputedStyle(node).outlineStyle !== "none"))) {
  throw new Error("hash navigation must leave a visibly focused destination card");
}
await page.unroute(mastheadSearchRoute);

const workflowJobId = "a".repeat(32);
const workflowJob = {
  id: workflowJobId,
  state: "ready",
  created_at: searchNow,
  request: { label: "Search workflow", notifications: null, not_before: null, deadline: null },
  project: { id: "search-project", label: "Search project", recipients: [], notifications: null, destinations: [] },
  received: null,
  checks: {},
  manifest: null,
  error: null,
};
await page.route("**/api/workflows/projects", (route) => route.fulfill({ json: { projects: [] } }));
await page.route("**/api/workflows/storage", (route) => route.fulfill({ json: { storage: [] } }));
const workflowJobsRoute = (route) => {
  const url = new URL(route.request().url());
  return url.pathname.endsWith(`/jobs/${workflowJobId}`)
    ? route.fulfill({ json: { job: workflowJob } })
    : route.fulfill({ json: { jobs: [], next: null } });
};
await page.route("**/api/workflows/jobs?*", workflowJobsRoute);
await page.route("**/api/workflows/jobs/*", workflowJobsRoute);
await page.goto(`${base}/workflows#job-${workflowJobId}`);
const workflowCard = page.locator(`#job-${workflowJobId}`);
await workflowCard.waitFor();
await workflowCard.locator("details[open]").waitFor();
await page.waitForFunction((id) => document.activeElement?.id === id, `job-${workflowJobId}`);
if (!(await workflowCard.evaluate((node) => getComputedStyle(node).outlineStyle !== "none"))) {
  throw new Error("workflow hash navigation must leave a visibly focused job card");
}
await page.unroute("**/api/workflows/projects");
await page.unroute("**/api/workflows/storage");
await page.unroute("**/api/workflows/jobs?*");
await page.unroute("**/api/workflows/jobs/*");
await page.unroute("**/api/admin/links*");
console.log("link:", linkUrl);

const senderSource = fs.readFileSync(new URL("../web/assets/upload.js", import.meta.url), "utf8");
const senderTestSource = senderSource.replace(
  "  showResumeNote();\n})();",
  "  showResumeNote();\n  window.__votportPreviewTest = { renderNote, setStatus, showDone };\n})();",
);
if (senderTestSource === senderSource) throw new Error("could not instrument sender preview test");
await page.route("**/assets/upload.js", (route) => route.fulfill({
  status: 200,
  contentType: "text/javascript",
  body: senderTestSource,
}));
const linkToken = new URL(linkUrl).pathname.split("/").filter(Boolean).pop();
const previewInfo = {
  usable: true,
  label: "large-selection-test",
  needs_password: false,
  authorized: true,
  max_entries: 1_000_000,
  max_bytes: 1_000_000_000,
  allow_hidden: true,
  chunk_bytes: 8 * 1024 * 1024,
  push: false,
};
const previewInfoRoute = (route) => {
  if (new URL(route.request().url()).pathname === `/api/r/${linkToken}`) {
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(previewInfo) });
  }
  return route.continue();
};
await page.route("**/api/r/*", previewInfoRoute);
await page.goto(linkUrl);
await page.waitForSelector("#uploader:not([hidden])", { timeout: 15000 });

for (const name of ["report.pdf.vot-receipt", "report.VOT-RECEIPT", "report.vot-receI\u0307pt", ".vot-receipt"]) {
  await page.setInputFiles("#file-input", { name, mimeType: "application/octet-stream", buffer: Buffer.from("x") });
  const error = page.locator("#upload-error");
  if (!(await error.isVisible()) || !(await error.textContent()).includes("reserved for signed receipts")) {
    throw new Error(`receipt filename was not refused: ${name}`);
  }
  if (await page.locator("#file-list > li").count() !== 0 || !(await page.locator("#send").isDisabled())) {
    throw new Error("a refused receipt filename changed the selection");
  }
}
console.log("Receipt filenames are refused before browser selection: ok");

for (const name of ["a".repeat(244), "ア".repeat(81) + "a"]) {
  await page.setInputFiles("#file-input", { name, mimeType: "application/octet-stream", buffer: Buffer.from("x") });
  const error = page.locator("#upload-error");
  if (!(await error.isVisible()) || !(await error.textContent()).includes("243 UTF-8 bytes; shorten")) {
    throw new Error(`oversized payload filename was not refused: ${name}`);
  }
  if (await page.locator("#file-list > li").count() !== 0 || !(await page.locator("#send").isDisabled())) {
    throw new Error("an oversized filename changed the selection");
  }
}
for (const name of ["a".repeat(243), "ア".repeat(81)]) {
  await page.setInputFiles("#file-input", { name, mimeType: "application/octet-stream", buffer: Buffer.from("x") });
  if (await page.locator("#upload-error").isVisible() || await page.locator("#file-list > li").count() !== 1 || await page.locator("#send").isDisabled()) {
    throw new Error(`243-byte payload filename was not admitted: ${name}`);
  }
  await page.click("#clear-files");
}

const previewFiles = Array.from({ length: 100_000 }, (_, index) => ({
  name: `preview-${String(index).padStart(6, "0")}.exr`,
  mimeType: "application/octet-stream",
  buffer: Buffer.from("x"),
}));
await page.setInputFiles("#file-input", previewFiles, { timeout: 180000 });
const pickedPreview = await page.evaluate(() => ({
  totals: document.getElementById("totals").textContent,
  rows: document.querySelectorAll("#file-list > li").length,
  fileRows: document.querySelectorAll("#file-list > li[data-path]").length,
  sendDisabled: document.getElementById("send").disabled,
}));
if (!pickedPreview.totals.replaceAll(",", "").includes("100000 file(s)")
  || !pickedPreview.totals.replaceAll(",", "").includes("Showing first 200 of 100000 selected files")
  || pickedPreview.rows !== 200 || pickedPreview.fileRows !== 200 || pickedPreview.sendDisabled) {
  throw new Error(`large picked preview failed: ${JSON.stringify(pickedPreview)}`);
}
console.log("100,000-file picked preview retains the full selection and 200 rows: ok");
await page.click("#clear-files");

await page.setInputFiles("#file-input", Array.from({ length: 201 }, (_, index) => ({
  name: `count-${String(index).padStart(3, "0")}.exr`,
  mimeType: "application/octet-stream",
  buffer: Buffer.from("x"),
})));
const countPreview = await page.evaluate(() => {
  window.__votportPreviewTest.setStatus("count-200.exr", "delivered ✓", true);
  window.__votportPreviewTest.renderNote();
  const progressNote = document.getElementById("progress-note").textContent;
  document.getElementById("cancel").click();
  const cancelDetail = document.getElementById("confirm-cancel-detail").textContent;
  window.__votportPreviewTest.setStatus("count-200.exr", "Preparing");
  window.__votportPreviewTest.renderNote();
  const retryNote = document.getElementById("progress-note").textContent;
  const files = Array.from({ length: 201 }, (_, index) => ({
    path: `count-${String(index).padStart(3, "0")}.exr`, bytes: 1,
    suite: "sha256", root: "a".repeat(64), receipt: false,
  }));
  let copiedProof = "";
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: async (text) => { copiedProof = text; }, readText: async () => window.__copiedText },
  });
  window.__votportPreviewTest.showDone({ files });
  document.getElementById("copy-proof").click();
  return {
    copiedProof,
    progressNote,
    retryNote,
    cancelDetail,
    doneSummary: document.getElementById("done-summary").textContent,
    doneRows: document.querySelectorAll("#done-list > li").length,
  };
});
if (!countPreview.progressNote.includes("1 of 201 files verified")
  || !countPreview.retryNote.includes("0 of 201 files verified")
  || !countPreview.cancelDetail.includes("The one already delivered is kept.")
  || !countPreview.doneSummary.includes("201 files")
  || !countPreview.doneSummary.includes("Showing first 200 of 201 delivered files below.")
  || !countPreview.copiedProof.includes("count-200.exr")
  || countPreview.doneRows !== 200) {
  throw new Error(`large count state failed: ${JSON.stringify(countPreview)}`);
}
console.log("hidden progress/cancel counts and 200-row completed preview: ok");
await page.unroute("**/assets/upload.js");
await page.unroute("**/api/r/*", previewInfoRoute);
await page.reload();
await page.waitForSelector("#uploader:not([hidden])", { timeout: 15000 });
await page.route("**/api/r/*/session", (route) => route.fulfill({ status: 503 }));
await page.setInputFiles("#file-input", path.join(dir, "Résumé Draft.pdf"));
await page.focus("#send");
await Promise.all([
  page.waitForResponse((response) => response.url().endsWith("/session") && response.status() === 503),
  page.keyboard.press("Enter"),
]);
if (await page.evaluate(() => document.activeElement.id) !== "cancel") {
  throw new Error("keyboard upload did not focus Cancel transfer");
}
await page.keyboard.press("Enter");
await page.getByRole("dialog", { name: "Cancel transfer", exact: true }).waitFor();
await page.keyboard.press("Tab");
await page.keyboard.press("Enter");
await page.waitForFunction(() =>
  document.getElementById("progress-card").hidden
  && document.getElementById("upload-error").textContent === "Transfer cancelled."
  && document.activeElement === document.getElementById("send"),
);
await Promise.all([
  page.waitForResponse((response) => response.url().endsWith("/session") && response.status() === 503),
  page.keyboard.press("Enter"),
]);
if (await page.evaluate(() => document.activeElement.id) !== "cancel") {
  throw new Error("keyboard upload did not focus Cancel transfer");
}
await page.keyboard.press("Enter");
await page.keyboard.press("Escape");
await page.waitForFunction(() =>
  !document.getElementById("confirm-cancel").open
  && document.getElementById("confirm-cancel").returnValue !== "cancel"
  && !document.getElementById("progress-card").hidden,
);
await page.keyboard.press("Enter");
await page.keyboard.press("Tab");
await page.keyboard.press("Enter");
await page.waitForFunction(() =>
  document.getElementById("progress-card").hidden
  && document.activeElement === document.getElementById("send"),
);
await page.unroute("**/api/r/*/session");
console.log("cancel restores focus and Escape preserves the retried transfer: ok");
await page.route("**/api/r/*/session", (route) => route.fulfill({ status: 403 }));
await page.reload();
await page.waitForSelector("#uploader:not([hidden])", { timeout: 15000 });
await page.setInputFiles("#file-input", path.join(dir, "Résumé Draft.pdf"));
await page.focus("#pick");
await page.evaluate(() => document.getElementById("upload-form").requestSubmit());
await page.waitForFunction(() =>
  document.getElementById("progress-card").hidden
  && !document.getElementById("upload-error").hidden
  && document.activeElement === document.getElementById("pick"),
);
console.log("failed upload preserves external focus: ok");
await page.unroute("**/api/r/*/session");
await page.route("**/api/r/*/session", async (route) => {
  await page.click("#cancel");
  await route.fulfill({ status: 403 });
});
await page.click("#send");
await page.waitForFunction(() =>
  document.getElementById("progress-card").hidden
  && !document.getElementById("upload-error").hidden
  && !document.getElementById("confirm-cancel").open
  && document.activeElement === document.getElementById("send"),
);
console.log("failed upload dismisses cancellation and restores focus: ok");
await page.unroute("**/api/r/*/session");
await page.reload();
await page.waitForSelector("#uploader:not([hidden])", { timeout: 15000 });
await page.setInputFiles("#file-input", [
  path.join(dir, "Résumé Draft.pdf"),
  path.join(dir, "archive.tar"),
]);
await page.route("**/api/r/*/session", async (route) => {
  await page.click("#cancel");
  await route.continue();
});
await page.click("#send");
await page.waitForSelector("#done-card:not([hidden])", { timeout: 120000 });
await page.waitForFunction(() =>
  !document.getElementById("confirm-cancel").open
  && document.activeElement === document.getElementById("copy-proof")
  && document.getElementById("upload-status").textContent === "2 files shipped and verified.",
);
await page.unroute("**/api/r/*/session");
console.log("completion announces both files, dismisses cancellation and focuses proof: ok");
console.log(
  "uploaded:",
  (await page.textContent("#done-list")).trim().replace(/\s+/g, " "),
);
// Done cards come back in manifest order (folded path key), not selection
// order, so look the small file's identity up by name.
const cards = await page.$$eval("#done-list li", (els) =>
  els.map((el) => ({
    name: el.querySelector("span")?.textContent ?? "",
    id: el.querySelector(".file-id").textContent,
  })),
);
const ids = cards.map((card) => card.id);
const pdfId = cards.find((card) => card.name.includes("Résumé Draft.pdf"))?.id;
if (
  ids.length !== 2 ||
  ids.some((id) => !/^[a-z0-9]+:[0-9a-f]{64}$/.test(id))
) {
  throw new Error(`object card identity malformed: ${JSON.stringify(ids)}`);
}
const statuses = await page.$$eval("#done-list .status", (els) =>
  els.map((el) => el.textContent),
);
if (!statuses.every((s) => s.includes("receipt ✓"))) {
  throw new Error(`receipt mark missing: ${JSON.stringify(statuses)}`);
}
const links = await (await page.request.get(`${base}/api/admin/links`)).json();
const receivedLink = links.links.find((link) => link.url === linkUrl);
const receivedHeaders = await (await page.request.get(`${base}/api/admin/links/${receivedLink.id}/uploads`)).json();
const receivedUpload = receivedHeaders.uploads[0];
if (browserEngine === "chromium") {
  await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
}
await page.click("#done-list li:first-child .file-id");
if (browserEngine === "chromium") {
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  if (copied !== ids[0]) {
    throw new Error(`copy mismatch: ${copied}`);
  }
}

for (const focus of ["send", "cancel", "pick", "external-focus"]) {
  await page.goto(linkUrl);
  await page.waitForSelector("#uploader:not([hidden])");
  await page.setInputFiles("#file-input", {
    name: `${focus}.txt`, mimeType: "text/plain", buffer: Buffer.from("focus check\n"),
  });
  await page.route("**/api/r/*/session", async (route) => {
    if (focus !== "send") await page.evaluate((id) => {
      if (id === "external-focus") {
        const button = document.createElement("button");
        button.id = id;
        button.textContent = "External focus";
        document.body.append(button);
      }
      document.getElementById(id).focus();
    }, focus);
    await route.continue();
  });
  await page.focus("#send");
  await page.keyboard.press("Enter");
  await page.waitForSelector("#done-card:not([hidden])", { timeout: 30000 });
  const announcement = page.locator("#upload-status");
  if (await announcement.getAttribute("role") !== "status"
    || await announcement.textContent() !== "1 file shipped and verified.") {
    throw new Error("completion status was not announced");
  }
  const expected = focus === "external-focus" ? focus : "copy-proof";
  if (await page.evaluate(() => document.activeElement.id) !== expected) {
    throw new Error(`completion did not preserve focus from ${focus}`);
  }
  await page.unroute("**/api/r/*/session");
}
console.log("completion moves hidden focus and preserves external focus: ok");

await page.goto(linkUrl);
await page.waitForSelector("#uploader:not([hidden])");
const sequenceFiles = Array.from({ length: 17 }, (_, index) => ({
  name: `sequence-${String(index).padStart(2, "0")}.bin`,
  mimeType: "application/octet-stream",
  buffer: Buffer.alloc(1024 + index, index),
}));
let smallActive = 0;
let smallPeak = 0;
const observeSmallChunks = async (route) => {
  smallActive += 1;
  smallPeak = Math.max(smallPeak, smallActive);
  try {
    await new Promise((resolve) => setTimeout(resolve, 25));
    const response = await route.fetch();
    await route.fulfill({ response });
  } finally {
    smallActive -= 1;
  }
};
await page.route("**/api/session/*/chunk?*", observeSmallChunks);
await page.setInputFiles("#file-input", sequenceFiles);
await page.click("#send");
await page.waitForSelector("#done-card:not([hidden])", { timeout: 30000 });
await page.unroute("**/api/session/*/chunk?*", observeSmallChunks);
if (smallPeak <= 1 || smallPeak > 8 || smallActive !== 0) {
  throw new Error(`small-file upload window: peak=${smallPeak}, active=${smallActive}`);
}
for (const file of sequenceFiles) {
  const received = path.join(receiveDir, dest, file.name);
  if (!fs.readFileSync(received).equals(file.buffer) || !fs.existsSync(`${received}.vot-receipt`)) {
    throw new Error(`small-file delivery or receipt mismatch: ${file.name}`);
  }
}
console.log("small files overlap within eight requests and finish with matching bytes and receipts: ok");

for (const mode of browserEngine === "chromium" ? ["unreadable", "short", "short-busy"] : ["short", "short-busy"]) {
  const keptName = `source-${mode}-a-kept.txt`;
  const changedName = `source-${mode}-z-changed.bin`;
  const keptPath = path.join(dir, keptName);
  const changedPath = path.join(dir, changedName);
  const keptBytes = `verified before ${mode} source failure\n`;
  fs.writeFileSync(keptPath, keptBytes);
  fs.writeFileSync(changedPath, Buffer.alloc(9 * 1024 * 1024, 0x37));
  await page.goto(linkUrl);
  await page.waitForSelector("#uploader:not([hidden])");
  let changed = false;
  let aborts = 0;
  let busy = 0;
  let buildChecks = 0;
  const observeBuildCheck = (request) => {
    if (new URL(request.url()).pathname === `/api/r/${linkToken}`) buildChecks += 1;
  };
  page.on("request", observeBuildCheck);
  const changeSource = async (route) => {
    if (mode === "short-busy" && new URL(route.request().url()).searchParams.get("entry") === "1") {
      busy += 1;
      await route.fulfill({ status: 503, body: "busy" });
      await page.waitForFunction(() => document.getElementById("phase").textContent === "Paused");
      await page.waitForFunction(() => typeof window.releaseShortRead === "function");
      await page.evaluate(() => window.releaseShortRead());
      return;
    }
    const response = await route.fetch();
    if (!changed) {
      if (new URL(route.request().url()).searchParams.get("entry") !== "0" || response.status() !== 200
        || fs.readFileSync(path.join(receiveDir, dest, keptName), "utf8") !== keptBytes) {
        throw new Error("source mutation did not follow the first verified file");
      }
      if (mode === "unreadable") {
        const fd = fs.openSync(changedPath, "r+");
        try { fs.writeSync(fd, Buffer.from([0x99]), 0, 1, 0); } finally { fs.closeSync(fd); }
        const later = new Date(Date.now() + 2000);
        fs.utimesSync(changedPath, later, later);
      } else {
        await page.evaluate((hold) => {
          const read = Blob.prototype.arrayBuffer;
          Blob.prototype.arrayBuffer = function () {
            if (hold && this.size === 1024 * 1024) {
              return new Promise((resolve) => { window.releaseShortRead = () => resolve(new ArrayBuffer(1)); });
            }
            return !hold && this.size > 1024 ? Promise.resolve(new ArrayBuffer(1)) : read.call(this);
          };
        }, mode === "short-busy");
      }
      changed = true;
    }
    await route.fulfill({ response });
  };
  const observeAbort = async (route) => { aborts += 1; await route.continue(); };
  await page.route("**/api/session/*/chunk?*", changeSource);
  await page.route("**/api/session/*/abort", observeAbort);
  await page.setInputFiles("#file-input", [keptPath, changedPath]);
  await page.click("#send");
  await page.waitForSelector("#upload-error:not([hidden])", { timeout: 10000 });
  const message = await page.textContent("#upload-error");
  if (!changed || aborts !== 1 || buildChecks === 0 || (mode === "short-busy" && busy === 0)
    || message !== `"${changedName}" changed while uploading; pick it again. The one already delivered is kept. Fix the rest and send them again.`
    || await page.locator("#resume-note").isVisible()
    || await page.evaluate((key) => localStorage.getItem(key), `votport-resume-${linkToken}`) !== null
    || fs.readFileSync(path.join(receiveDir, dest, keptName), "utf8") !== keptBytes
    || !fs.existsSync(path.join(receiveDir, dest, `${keptName}.vot-receipt`))
    || fs.existsSync(path.join(receiveDir, dest, changedName))) {
    throw new Error(`source ${mode} did not abort with verified files preserved: ${message}`);
  }
  await page.unroute("**/api/session/*/chunk?*", changeSource);
  await page.unroute("**/api/session/*/abort", observeAbort);
  page.off("request", observeBuildCheck);
}
console.log("failed and short source reads discard resume state and preserve verified files: ok");

for (const mode of ["retry", "cancel"]) {
  const name = `snapshot-${mode}.bin`;
  const sourcePath = path.join(dir, name);
  const original = Buffer.alloc(1024 * 1024, mode === "retry" ? 0x51 : 0x52);
  fs.writeFileSync(sourcePath, original);
  await page.goto(linkUrl);
  await page.waitForSelector("#uploader:not([hidden])");
  let attempts = 0;
  const busyOnce = async (route) => {
    attempts += 1;
    if (attempts === 1 || mode === "cancel") {
      fs.writeFileSync(sourcePath, Buffer.alloc(original.length, 0x99));
      await route.fulfill({ status: 503, body: "busy" });
    } else {
      await route.continue();
    }
  };
  await page.route("**/api/session/*/chunk?*", busyOnce);
  await page.setInputFiles("#file-input", sourcePath);
  await page.click("#send");
  if (mode === "retry") {
    await page.waitForSelector("#done-card:not([hidden])", { timeout: 30000 });
    if (attempts !== 2 || !fs.readFileSync(path.join(receiveDir, dest, name)).equals(original)
      || !fs.existsSync(path.join(receiveDir, dest, `${name}.vot-receipt`))) {
      throw new Error("retry did not reuse the verified source snapshot");
    }
  } else {
    await page.waitForFunction(() => document.getElementById("phase").textContent === "Paused");
    await page.click("#cancel");
    await page.locator('#confirm-cancel button[value="cancel"]').click();
    await page.waitForFunction(() => !document.getElementById("upload-error").hidden
      && document.getElementById("upload-error").textContent === "Transfer cancelled.");
    if (fs.existsSync(path.join(receiveDir, dest, name)) || await page.locator("#resume-note").isVisible()
      || await page.evaluate((key) => localStorage.getItem(key), `votport-resume-${linkToken}`) !== null) {
      throw new Error("cancelled snapshot retry left a delivery or resume record");
    }
  }
  await page.unroute("**/api/session/*/chunk?*", busyOnce);
}
console.log("retries preserve the original source snapshot and remain cancellable: ok");

for (const status of [409, 422]) {
  await page.goto(linkUrl);
  await page.waitForSelector("#uploader:not([hidden])");
  let busy = 0;
  let releaseRefusal;
  const busyStarted = new Promise((resolve) => { releaseRefusal = resolve; });
  const refuseWithBusySibling = async (route) => {
    if (new URL(route.request().url()).searchParams.get("entry") === "0") {
      await busyStarted;
      await route.fulfill({ status, contentType: "application/json", body: JSON.stringify({ error: "range refused" }) });
    } else {
      busy += 1;
      await route.fulfill({ status: 503, body: "busy" });
      await page.waitForFunction(() => document.getElementById("phase").textContent === "Paused");
      releaseRefusal();
    }
  };
  await page.route("**/api/session/*/chunk?*", refuseWithBusySibling);
  await page.setInputFiles("#file-input", ["a", "b"].map((name) => ({
    name: `refused-${status}-${name}.bin`, mimeType: "application/octet-stream", buffer: Buffer.from(`${status}-${name}`),
  })));
  await page.click("#send");
  await page.waitForSelector("#upload-error:not([hidden])", { timeout: 10000 });
  if (!busy || await page.textContent("#upload-error") !== "range refused. Any files already delivered are kept. Fix the selection and send again."
    || await page.locator("#resume-note").isVisible()
    || await page.evaluate((key) => localStorage.getItem(key), `votport-resume-${linkToken}`) !== null) {
    throw new Error(`${status} refusal did not stop the busy sibling`);
  }
  await page.unroute("**/api/session/*/chunk?*", refuseWithBusySibling);
}
console.log("permanent range refusals stop retries across parallel files: ok");

await page.goto(linkUrl);
await page.waitForSelector("#uploader:not([hidden])");
let rebeginAborts = 0;
const rebeginThenRefuse = async (route) => {
  if (new URL(route.request().url()).searchParams.get("entry") === "0") {
    const response = await route.fetch();
    const body = await response.json();
    await route.fulfill({ response, json: { ...body, rebegin: true } });
  } else {
    await page.waitForFunction(() => document.getElementById("meter").getAttribute("aria-valuenow") === "50");
    await route.fulfill({ status: 422, contentType: "application/json", body: JSON.stringify({ error: "range refused after restart" }) });
  }
};
const observeRebeginAbort = async (route) => { rebeginAborts += 1; await route.continue(); };
await page.route("**/api/session/*/chunk?*", rebeginThenRefuse);
await page.route("**/api/session/*/abort", observeRebeginAbort);
await page.setInputFiles("#file-input", ["a", "b"].map((name) => ({
  name: `rebegin-${name}.bin`, mimeType: "application/octet-stream", buffer: Buffer.from(`rebegin-${name}`),
})));
await page.click("#send");
await page.waitForSelector("#upload-error:not([hidden])", { timeout: 10000 });
if (rebeginAborts !== 1 || !(await page.textContent("#upload-error")).startsWith("range refused after restart.")
  || await page.locator("#resume-note").isVisible()
  || await page.evaluate((key) => localStorage.getItem(key), `votport-resume-${linkToken}`) !== null
  || fs.readFileSync(path.join(receiveDir, dest, "rebegin-a.bin"), "utf8") !== "rebegin-a"
  || !fs.existsSync(path.join(receiveDir, dest, "rebegin-a.bin.vot-receipt"))) {
  throw new Error(`earlier rebegin hid the terminal refusal: aborts=${rebeginAborts}`);
}
await page.unroute("**/api/session/*/chunk?*", rebeginThenRefuse);
await page.unroute("**/api/session/*/abort", observeRebeginAbort);
console.log("terminal refusal takes precedence over an earlier rebegin and preserves published bytes: ok");

await page.goto(linkUrl);
await page.waitForSelector("#uploader:not([hidden])");
let releaseHeldReply;
let published;
const heldReply = new Promise((resolve) => { releaseHeldReply = resolve; });
const publication = new Promise((resolve) => { published = resolve; });
const holdPublishedReply = async (route) => {
  if (new URL(route.request().url()).searchParams.get("entry") === "0") {
    const response = await route.fetch();
    if (response.status() !== 200) throw new Error("held reply did not follow publication");
    published();
    await heldReply;
  } else {
    await publication;
    await route.fulfill({ status: 422, contentType: "application/json", body: JSON.stringify({ error: "range refused with a held reply" }) });
  }
};
await page.route("**/api/session/*/chunk?*", holdPublishedReply);
try {
  await page.setInputFiles("#file-input", ["a", "b"].map((name) => ({
    name: `held-${name}.bin`, mimeType: "application/octet-stream", buffer: Buffer.from(`held-${name}`),
  })));
  await page.click("#send");
  await page.waitForSelector("#upload-error:not([hidden])", { timeout: 10000 });
  const message = await page.textContent("#upload-error");
  const kept = fs.readFileSync(path.join(receiveDir, dest, "held-a.bin"), "utf8") === "held-a"
    && fs.existsSync(path.join(receiveDir, dest, "held-a.bin.vot-receipt"));
  if (!kept || message !== "range refused with a held reply. Any files already delivered are kept. Fix the selection and send again."
    || await page.locator("#resume-note").isVisible()
    || await page.evaluate((key) => localStorage.getItem(key), `votport-resume-${linkToken}`) !== null) {
    throw new Error(`held publication feedback was wrong: kept=${kept}, message=${message}`);
  }
} finally {
  releaseHeldReply();
  await page.unroute("**/api/session/*/chunk?*", holdPublishedReply);
}
console.log("a lost success reply does not claim that no file was delivered: ok");

// Public receipt check against the same deployment: key GET is public, and
// the sidecar on disk must verify with a root matching the done-list card.
const sidecarName = "Résumé Draft.pdf.vot-receipt";
const key = await page.evaluate(async () => {
  const response = await fetch("/api/receipt-key");
  if (!response.ok) throw new Error(`receipt-key ${response.status}`);
  return (await response.json()).receipt_key;
});
if (!/^[0-9a-f]{64}$/.test(key)) {
  throw new Error(`receipt key malformed: ${key}`);
}
const check = await fetch(`${base}/api/verify`, {
  method: "POST",
  headers: { "Content-Type": "application/octet-stream" },
  body: fs.readFileSync(path.join(receiveDir, dest, sidecarName)),
});
const verdict = await check.json();
if (!check.ok || !verdict.ok) {
  throw new Error(`verify failed: ${check.status} ${JSON.stringify(verdict)}`);
}
if (!pdfId || `${verdict.suite}:${verdict.root}` !== pdfId) {
  throw new Error(`verify root mismatch: ${JSON.stringify({ verdict, cards })}`);
}
console.log("verified:", pdfId);

const receivedFiles = await (await page.request.get(`${base}/api/admin/links/${receivedLink.id}/uploads/${receivedUpload.id}/files`)).json();
const receivedFile = receivedFiles.files.find((file) => file.path === "Résumé Draft.pdf");
if (!receivedFile) throw new Error("received-file page omitted the published PDF");
const receiptShare = await page.request.post(`${base}/api/admin/outbound-grants`, {
  headers: { "X-Votport": "1" },
  data: { link_id: receivedLink.id, upload_id: receivedUpload.id, file_index: receivedFile.file_index },
});
if (!receiptShare.ok()) throw new Error(`received-file share: ${receiptShare.status()} ${await receiptShare.text()}`);
await page.goto((await receiptShare.json()).url);
await page.getByRole("button", { name: "Download file: Résumé Draft.pdf", exact: true }).waitFor();
const [fileDownload] = await collectDownloads(
  () => page.getByRole("button", { name: "Download file: Résumé Draft.pdf", exact: true }).click(), 1,
);
if (fileDownload.suggestedFilename() !== "Résumé Draft.pdf" ||
    fs.readFileSync(await fileDownload.path(), "utf8") !== "unicode names travel\n") {
  throw new Error("individual download changed the Unicode filename or file bytes");
}
const [receiptDownload] = await collectDownloads(
  () => page.getByRole("button", { name: "Download receipt: Résumé Draft.pdf", exact: true }).click(), 1,
);
if (receiptDownload.suggestedFilename() !== sidecarName ||
    !fs.readFileSync(await receiptDownload.path()).equals(fs.readFileSync(path.join(receiveDir, dest, sidecarName)))) {
  throw new Error("receipt download changed the Unicode filename or evidence");
}
console.log("received-file and receipt buttons preserve Unicode filenames and bytes: ok");

// The /verify page itself: slot UI, sidecar-only, full match, mismatch.
const stored = path.join(receiveDir, dest);
const payloadPath = path.join(stored, "Résumé Draft.pdf");
const sidecarPath = path.join(stored, sidecarName);
await page.goto(`${base}/verify`);
await page.waitForSelector("#verify-drop", { timeout: 15000 });
const shownKey = await page.textContent("#receipt-key");
if (shownKey.trim() !== key) {
  throw new Error("verify page shows a different receipt key");
}
await page.setInputFiles("#sidecar-input", sidecarPath);
await page.click("#check");
await page.waitForSelector("#verify-result:not([hidden])", {
  timeout: 15000,
});
let title = await page.textContent("#verify-title");
if (title !== "Genuine receipt") {
  throw new Error(`sidecar-only verdict: ${title}`);
}
let okClass = await page.$eval("#verify-result", (el) => el.classList.contains("ok"));
if (okClass) throw new Error("sidecar-only check must not be .ok");

await page.click("#reset");
await page.setInputFiles("#payload-input", payloadPath);
await page.setInputFiles("#sidecar-input", sidecarPath);
await page.click("#check");
await page.waitForFunction(
  () => !document.getElementById("verify-result").hidden &&
    document.getElementById("verify-title").textContent !== "",
  { timeout: 60000 },
);
title = await page.textContent("#verify-title");
okClass = await page.$eval("#verify-result", (el) => el.classList.contains("ok"));
if (title !== "Verified" || !okClass) {
  throw new Error(`full-match verdict: ${title} ok=${okClass}`);
}

await page.click("#reset");
await page.setInputFiles("#payload-input", path.join(dir, "archive.tar"));
await page.setInputFiles("#sidecar-input", sidecarPath);
await page.click("#check");
await page.waitForFunction(
  () => document.getElementById("verify-title").textContent === "Does not match",
  { timeout: 60000 },
);
console.log("verify page flow ok");

// Deliver an outbound multi-file link through the admin UI.
await page.goto(`${base}/deliver`);
try {
  await page.waitForSelector("#library-input", { state: "attached", timeout: 15000 });
} catch (error) {
  console.error(`deliver page did not load at ${page.url()}: ${await page.locator("body").innerText()}`);
  throw error;
}
await page.fill("#deliver-project", PROJECT);
await page.setInputFiles("#library-input", outboundFiles.map((file) => path.join(dir, file.name)));
await page.waitForFunction(
  () => document.getElementById("library-status").textContent.includes("12 files added"),
  { timeout: 30000 },
);
const rootFolder = page.locator(
  `#library-files input[aria-label="Select folder ${PROJECT}"]`,
);
await rootFolder.waitFor();
// Earlier runs leave their own project folders behind; only this run's must be a folder row.
const rootFiles = await page.locator("#library-files .library-file:not(.library-folder)").allTextContents();
if (await rootFolder.count() !== 1 || rootFiles.some((row) => outboundFiles.some((file) => row.includes(file.name)))) {
  throw new Error(`scoped library root did not show ${PROJECT} as a folder`);
}
await page.getByRole("button", { name: `Open folder ${PROJECT}` }).focus();
await page.keyboard.press("Enter");
await page.waitForFunction(
  (project) => document.querySelector('#library-breadcrumbs [aria-current="page"]')?.textContent === project &&
    document.querySelectorAll("#library-files input[type=checkbox]").length === 12,
  PROJECT,
  { timeout: 15000 },
);
if (!await page.evaluate(() => document.activeElement.matches('#library-breadcrumbs [aria-current="page"]'))) {
  throw new Error("folder navigation lost keyboard focus");
}
const currentDirectory = await page.textContent('#library-breadcrumbs [aria-current="page"]');
if (currentDirectory !== PROJECT) {
  throw new Error(`scoped library breadcrumb: ${currentDirectory}`);
}

await page.locator("#nav .nav-more > summary").click();
await page.getByRole("link", { name: "Automation", exact: true }).click();
await page.fill("#automation-token-label", `browser agent ${run}`);
await page.fill("#automation-token-directory", PROJECT);
await page.uncheck('#automation-token-permissions input[value="deliveries:create"]');
await page.uncheck('#automation-token-permissions input[value="deliveries:read"]');
await page.click("#automation-token-submit");
await page.waitForSelector("#automation-token-result:not([hidden])");
const agentToken = await page.inputValue("#automation-token-value");
const agentConfig = JSON.parse(await page.textContent("#automation-mcp-config"));
if (agentConfig.mcpServers.votport.env.VOTPORT_AUTOMATION_TOKEN !== agentToken ||
    agentConfig.mcpServers.votport.env.VOTPORT_URL !== base ||
    agentConfig.mcpServers.votport.args[0] !== "mcp") {
  throw new Error("agent MCP configuration does not match the issued token and server");
}
const agentHeaders = { Authorization: `Bearer ${agentToken}` };
const access = await (await page.request.get(`${base}/api/automation/session`, { headers: agentHeaders })).json();
if (access.automation_token.directory !== PROJECT ||
    JSON.stringify(access.automation_token.permissions) !== '["library:read"]') {
  throw new Error("agent token does not have the selected folder and permissions");
}
const agentFiles = await (await page.request.get(`${base}/api/automation/files?limit=1`, { headers: agentHeaders })).json();
if (agentFiles.files.length !== 1 || !agentFiles.has_more) throw new Error("agent file pagination failed");
const refusedShare = await page.request.post(`${base}/api/automation/share`, {
  headers: agentHeaders, data: { directory: PROJECT, expires_days: 7, operation_id: `browser-${run}` },
});
if (refusedShare.status() !== 403) throw new Error("browse-only token created a delivery");
const agentCard = page.locator("#automation-tokens .card").filter({ has: page.getByRole("heading", { name: `browser agent ${run}`, exact: true }) });
await agentCard.getByRole("button", { name: "Revoke", exact: true }).click();
await page.click("#confirm-ok");
await agentCard.locator(".badge").filter({ hasText: "revoked" }).waitFor();
const revokedAccess = await page.request.get(`${base}/api/automation/session`, { headers: agentHeaders });
if (revokedAccess.status() !== 401) throw new Error("revoked agent token still authenticates");
await page.getByRole("link", { name: "Deliver", exact: true }).click();
await page.getByRole("button", { name: `Open folder ${PROJECT}` }).click();
await page.waitForFunction(() => document.querySelectorAll("#library-files input[type=checkbox]").length === 12);
console.log("agent access: selected permissions, MCP config, pagination, and revocation ok");

const projectFiles = await page.$$eval("#library-files .library-file:not(.library-folder) .mono", (els) =>
  els.map((el) => el.textContent).sort(),
);
if (JSON.stringify(projectFiles) !== JSON.stringify(outboundFiles.map((file) => file.name))) {
  throw new Error(`scoped library files: ${JSON.stringify(projectFiles)}`);
}
await page.getByRole("button", { name: "Library", exact: true }).click();
await page.waitForSelector(`#library-files input[aria-label="Select folder ${PROJECT}"]`, {
  state: "visible",
  timeout: 15000,
});
if (!await page.evaluate(() => document.activeElement.matches('#library-breadcrumbs [aria-current="page"]'))) {
  throw new Error("breadcrumb navigation lost keyboard focus");
}
await page.route("**/api/admin/outbound-files?directory=*", (route) => route.fulfill({ status: 503 }), { times: 1 });
await page.getByRole("button", { name: `Open folder ${PROJECT}` }).focus();
await page.keyboard.press("Enter");
await page.locator("#library-files [role=alert]").waitFor();
if (!await page.evaluate(() => document.activeElement.matches('#library-breadcrumbs [aria-current="page"]'))) {
  throw new Error("failed folder navigation lost keyboard focus");
}
await page.keyboard.press("Enter");
await page.waitForSelector(`#library-files input[aria-label="Select folder ${PROJECT}"]`);
await page.route("**/api/admin/outbound-files?directory=*", async (route) => {
  await page.focus("#library-search");
  await route.fulfill({ status: 503 });
}, { times: 1 });
await page.getByRole("button", { name: `Open folder ${PROJECT}` }).click();
await page.locator("#library-files [role=alert]").waitFor();
if (await page.evaluate(() => document.activeElement.id) !== "library-search") {
  throw new Error("failed folder navigation stole external focus");
}
await page.getByRole("button", { name: "Library", exact: true }).click();
await page.waitForSelector(`#library-files input[aria-label="Select folder ${PROJECT}"]`);
console.log("library navigation preserves keyboard focus on success and failure: ok");
let releaseFolderSelection;
const heldFolderSelection = new Promise((resolve) => { releaseFolderSelection = resolve; });
await page.route("**/api/admin/outbound-files?selection=*", async (route) => {
  await heldFolderSelection;
  await route.continue();
}, { times: 1 });
try {
  await page.locator(`#library-files input[aria-label="Select folder ${PROJECT}"]`).click();
  await page.fill("#deliver-label", "Pending folder selection");
  await page.click("#deliver-submit");
  await page.locator("#deliver-error").waitFor({ state: "visible" });
  if (await page.textContent("#deliver-error") !== "Wait for the folder selection to finish before creating a link.") {
    throw new Error("link creation must wait for the full folder selection");
  }
} finally {
  releaseFolderSelection();
}

await page.waitForFunction(
  () => document.getElementById("library-selection-status").textContent.startsWith("12 files selected"),
  { timeout: 15000 },
);
await page.route("**/api/admin/outbound-files?directory=*", async (route) => {
  await page.focus("#library-search");
  await route.continue();
}, { times: 1 });
await page.getByRole("button", { name: `Open folder ${PROJECT}` }).click();
await page.waitForFunction(
  (project) => document.querySelector('#library-breadcrumbs [aria-current="page"]')?.textContent === project &&
    document.querySelectorAll("#library-files input[type=checkbox]").length === 12 &&
    [...document.querySelectorAll("#library-files input[type=checkbox]")].every((checkbox) => checkbox.checked) &&
    document.getElementById("library-selection-status").textContent.startsWith("12 files selected"),
  PROJECT,
  { timeout: 15000 },
);
if (await page.evaluate(() => document.activeElement.id) !== "library-search") {
  throw new Error("folder navigation stole external focus");
}
console.log("library navigation preserves focus moved during a request: ok");
const selectedProjectFiles = await page.$$eval(
  "#library-files input[type=checkbox]",
  (checkboxes) => checkboxes.map((checkbox) => checkbox.checked),
);
if (selectedProjectFiles.length !== 12 || !selectedProjectFiles.every(Boolean)) {
  throw new Error(`scoped library selection: ${JSON.stringify(selectedProjectFiles)}`);
}
if (!(await page.textContent("#library-selection-status")).startsWith("12 files selected")) {
  throw new Error("scoped library selection status changed");
}
await page.getByRole("button", { name: "Library", exact: true }).click();
const selectedFolder = page.locator(
  `#library-files input[aria-label="Select folder ${PROJECT}"]`,
);
await selectedFolder.waitFor({ state: "visible", timeout: 15000 });
if (!(await selectedFolder.isChecked())) {
  throw new Error("scoped library folder selection was lost");
}
if (!(await page.textContent("#library-selection-status")).startsWith(`${outboundFiles.length} files selected`)) {
  throw new Error("scoped library root selection status changed");
}
await selectedFolder.click();
await page.getByRole("button", { name: `Open folder ${PROJECT}` }).click();
await page.waitForFunction(
  () => document.querySelectorAll("#library-files input[type=checkbox]").length === 12 &&
    ![...document.querySelectorAll("#library-files input[type=checkbox]")].some((checkbox) => checkbox.checked) &&
    document.getElementById("library-selection-status").textContent.startsWith("0 files selected"),
  undefined,
  { timeout: 15000 },
);
await page.locator("#library-files input[type=checkbox]").first().check();
await page.getByRole("button", { name: "Library", exact: true }).click();
await page.waitForSelector(`#library-files input[aria-label="Select folder ${PROJECT}"]`);
const selectionError = "library selection is too large; choose a narrower folder or select individual files";
await page.route("**/api/admin/outbound-files?selection=*", (route) => route.fulfill({
  status: 422,
  contentType: "application/json",
  body: JSON.stringify({ error: selectionError }),
}), { times: 1 });
await selectedFolder.click();
await page.locator("#library-selection-error").waitFor({ state: "visible" });
if (await selectedFolder.isChecked() ||
    !(await page.textContent("#library-selection-status")).startsWith("1 file selected") ||
    await page.textContent("#library-selection-error") !== selectionError) {
  throw new Error("an oversized folder refusal changed the existing selection");
}
await page.unroute("**/api/admin/outbound-files?selection=*");
await selectedFolder.click();
await page.waitForFunction(
  () => document.getElementById("library-selection-status").textContent.startsWith("12 files selected") &&
    document.querySelector('#library-files input[aria-label^="Select folder "]').checked,
  undefined,
  { timeout: 15000 },
);
console.log("oversized library selection refusal keeps existing files and remains retryable: ok");

await page.fill("#deliver-project", FOLDER_PROJECT);
await page.setInputFiles("#library-folder-input", folder);
await page.waitForFunction(
  () => document.getElementById("library-status").textContent.includes("1 file added"),
  { timeout: 30000 },
);
await page.getByRole("button", { name: "Library", exact: true }).click();
await page.waitForSelector(
  `#library-files input[aria-label="Select folder ${FOLDER_PROJECT}"]`,
  { state: "visible", timeout: 15000 },
);
await page.fill("#library-search", "folder-nested.txt");
await page.waitForFunction(
  (expected) => [...document.querySelectorAll("#library-files .mono")].some((el) => el.textContent === expected),
  `${FOLDER_PROJECT}/folder-pick/nested/folder-nested.txt`,
  { timeout: 15000 },
);
await page.fill("#library-search", "");
await page.waitForFunction(
  () => document.querySelector('#library-breadcrumbs [aria-current="page"]')?.textContent === "Library",
  { timeout: 15000 },
);

const incompleteSearchText = "Search incomplete. Refine your search or browse folders.";
const noMatchSearchText = "No matching library files.";
const searchFixturePath = `${FOLDER_PROJECT}/folder-pick/nested/folder-nested.txt`;
const searchResponses = [
  { files: [], truncated: true },
  { files: [{ path: searchFixturePath, bytes: 25 }], truncated: true },
  { files: [], truncated: false },
];
const searchRoute = "**/api/admin/outbound-files?q=*";
await page.route(searchRoute, async (route) => {
  const response = searchResponses.shift();
  if (!response) throw new Error("unexpected extra library search request");
  await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(response) });
});
try {
  await page.fill("#library-search", "budget-zero");
  await page.waitForFunction(
    (text) => document.querySelector("#library-files")?.innerText === text,
    incompleteSearchText,
  );
  if (await page.locator("#library-files").getByText(noMatchSearchText, { exact: true }).count()) {
    throw new Error("truncated empty search claimed no matching files");
  }

  await page.fill("#library-search", "budget-one");
  await page.waitForFunction(
    ([expected, incomplete]) => document.querySelector("#library-files")?.innerText.includes(expected)
      && document.querySelector("#library-files")?.innerText.includes(incomplete),
    [searchFixturePath, incompleteSearchText],
  );
  const oneMatchText = await page.locator("#library-files").innerText();
  if (oneMatchText.includes(noMatchSearchText)) throw new Error("truncated partial search claimed no matching files");

  await page.fill("#library-search", "budget-done");
  await page.getByText(noMatchSearchText, { exact: true }).waitFor();
  if (await page.getByText(incompleteSearchText, { exact: true }).count()) {
    throw new Error("completed empty search reported incomplete");
  }
} finally {
  await page.unroute(searchRoute);
}
if (searchResponses.length) throw new Error(`library search fixtures unused: ${searchResponses.length}`);
console.log("library search reports incomplete zero and partial results and completed no-match results: ok");
await page.fill("#library-search", "");
await page.waitForSelector(
  `#library-files input[aria-label="Select folder ${FOLDER_PROJECT}"]`,
  { state: "visible", timeout: 15000 },
);

if (await page.getByRole("button", { name: /^Share folder / }).count()) {
  throw new Error("folder sharing must use the selection checkboxes and access form");
}
await page.fill("#deliver-label", "browser outbound e2e");
let releasePreparation;
const heldPreparation = new Promise((resolve) => { releasePreparation = resolve; });
let preparationRequests = 0;
await page.route("**/api/admin/outbound-grants", async (route) => {
  if (route.request().method() !== "POST") return route.continue();
  preparationRequests += 1;
  await heldPreparation;
  await route.fulfill({ status: 503, json: { error: "Preparation failed; try again." } });
});
try {
  await page.click("#deliver-submit");
  await page.locator("#deliver-progress").waitFor({ state: "visible" });
  if (!(await page.textContent("#deliver-progress")).includes("Verifying selected files") ||
      await page.textContent("#deliver-submit") !== "Preparing link…" ||
      !(await page.locator("#deliver-label").isDisabled()) ||
      !(await page.locator("#library-files input[type=checkbox]").first().isDisabled()) ||
      !(await page.locator("#library-search").isEnabled())) {
    throw new Error("preparation must show progress, protect submitted settings and leave the library usable");
  }
  await page.locator("#deliver-form").evaluate((form) => form.dispatchEvent(new Event("submit", { cancelable: true })));
  releasePreparation();
  await page.locator("#deliver-error").waitFor({ state: "visible" });
  if (preparationRequests !== 1 ||
      await page.inputValue("#deliver-label") !== "browser outbound e2e" ||
      !(await page.locator("#deliver-submit").isEnabled()) ||
      !(await page.locator("#library-files input[type=checkbox]").first().isEnabled()) ||
      !(await page.locator("#deliver-progress").isHidden())) {
    throw new Error("failed preparation must preserve settings and selection and allow retry without a duplicate request");
  }
} finally {
  releasePreparation();
  await page.unroute("**/api/admin/outbound-grants");
}
let releaseGrant;
const heldGrant = new Promise((resolve) => { releaseGrant = resolve; });
await page.route("**/api/admin/outbound-grants", async (route) => {
  if (route.request().method() === "POST") {
    await heldGrant;
    return route.continue();
  }
  return route.continue();
}, { times: 1 });
await page.click("#deliver-submit");
await page.locator("#deliver-progress").waitFor({ state: "visible" });
await page.locator("#library-search").focus();
releaseGrant();
await page.waitForSelector("#outbound-result:not([hidden])", { timeout: 30000 });
const outboundUrl = await page.inputValue("#outbound-url");
if (!/^https?:\/\//.test(outboundUrl)) {
  throw new Error(`outbound URL malformed: ${outboundUrl}`);
}
if (await page.evaluate(() => document.activeElement.id) !== "library-search") {
  throw new Error("a delayed download result must preserve focus moved by the operator");
}
await page.unroute("**/api/admin/outbound-grants");
await page.reload();
const savedGrant = page.locator('#outbound-grants .card').filter({ has: page.getByRole('heading', { name: 'browser outbound e2e', exact: true }) });
await savedGrant.getByRole('button', { name: 'Copy link', exact: true }).click();
await page.locator('#outbound-result').waitFor({ state: 'visible' });
if (await page.inputValue('#outbound-url') !== outboundUrl) {
  throw new Error('reopening a saved download must preserve the original address');
}
await page.waitForFunction((url) => window.__copiedText === url
  && document.getElementById('outbound-grants-status').textContent === 'Download link copied.'
  && document.activeElement === document.getElementById('outbound-url'), outboundUrl);
await page.evaluate(() => { window.__clipboardFailure = true; window.__clipboardHold = true; window.__releaseClipboard = null; });
await page.click('#outbound-copy');
await page.waitForFunction(() => typeof window.__releaseClipboard === 'function');
await page.locator('#library-search').focus();
await page.evaluate(() => { window.__clipboardHold = false; window.__releaseClipboard(); });
await page.waitForFunction(() => {
  return document.activeElement === document.getElementById('library-search')
    && document.getElementById('outbound-grants-status').textContent === 'Could not copy the download address. Use Copy address below to retry.';
});
await page.evaluate(() => { window.__clipboardFailure = true; window.__clipboardHold = false; });
await page.click('#outbound-copy');
await page.waitForFunction(() => {
  const output = document.getElementById('outbound-url');
  return document.activeElement === output
    && output.selectionStart === 0
    && output.selectionEnd === output.value.length
    && document.getElementById('outbound-grants-status').textContent === 'Your download address is selected below. Copy it to share.';
});
await page.evaluate(() => { window.__clipboardFailure = false; });
console.log("download link remains available after reload: ok");

await page.goto(outboundUrl);
await page.waitForSelector("#download-content:not([hidden])", { timeout: 30000 });
if (await page.getAttribute("#download-content", "aria-live") !== null
  || await page.getAttribute("#download-error", "aria-live") !== null
  || await page.getAttribute("#download-error", "role") !== "alert"
  || await page.getAttribute("#separate-download-status", "aria-live") !== "polite") {
  throw new Error("download shell must stay quiet while specific download feedback remains live");
}
for (const file of outboundFiles) {
  await page.getByRole("button", { name: `Download file: ${PROJECT}/${file.name}`, exact: true }).waitFor();
}
if (await page.$eval("#bundle-download", (el) => el.hidden)) {
  throw new Error("bundle download action is missing");
}
if (await page.$eval("#separate-download", (el) => el.hidden)) {
  throw new Error("separate download action is missing");
}
if ((await page.evaluate(() => typeof window.showDirectoryPicker)) !== "undefined") {
  throw new Error("browser fallback was not selected");
}
if (!(await page.textContent("#separate-download-note")).includes("multiple downloads")) {
  throw new Error("separate download fallback note is missing");
}

const streamedBatch = await page.evaluate(async (names) => {
  const token = location.pathname.split("/").filter(Boolean).pop();
  const metadata = await fetch(`/api/s/${encodeURIComponent(token)}?offset=0&limit=100`, {
    credentials: "same-origin",
  }).then((response) => response.json());
  const { saveBatchFiles } = await import("/assets/outbound-download.js");
  const root = await navigator.storage.getDirectory();
  const folder = `download-collisions-${Date.now()}`;
  const directory = await root.getDirectoryHandle(folder, { create: true });
  try {
    const existing = await directory.getFileHandle(names[0], { create: true });
    const writable = await existing.createWritable();
    await writable.write("keep original");
    await writable.close();
    await directory.getDirectoryHandle(names[1], { create: true });
    await saveBatchFiles(
      await fetch(metadata.batch_url, { credentials: "same-origin" }),
      directory,
      metadata.files,
      names,
    );
    if (await (await existing.getFile()).text() !== "keep original") throw new Error("batch replaced an existing file");
    await directory.getDirectoryHandle(names[1]);
    const files = {};
    for (const [index, name] of names.entries()) {
      const storedName = index < 2 ? name.replace(/(\.[^.]*)?$/, " (2)$1") : name;
      files[name] = await (await (await directory.getFileHandle(storedName)).getFile()).text();
    }
    return files;
  } finally {
    await root.removeEntry(folder, { recursive: true });
  }
}, outboundFiles.map((file) => file.name));
if (Object.keys(streamedBatch).length !== outboundFiles.length ||
    outboundFiles.some((file) => streamedBatch[file.name] !== file.content)) {
  throw new Error(`streamed batch payload mismatch: ${JSON.stringify(streamedBatch)}`);
}
console.log("streamed individual batch: ok");
if (fs.readdirSync(dir).some((name) => name.endsWith(".zip"))) {
  throw new Error("streamed individual batch created a ZIP artifact");
}

const [bundleDownload] = await collectDownloads(
  () => page.click("#bundle-download-button"),
  1,
);
const bundlePath = path.join(dir, "deliverables.zip");
await bundleDownload.saveAs(bundlePath);
try {
  const bundleNames = execFileSync("unzip", ["-Z1", bundlePath], { encoding: "utf8" })
    .trim()
    .split("\n")
    .filter(Boolean);
  if (
    bundleNames.length !== outboundFiles.length ||
    !outboundFiles.every((file) => bundleNames.includes(`${PROJECT}/${file.name}`)) ||
    bundleNames.some((name) => name.endsWith(".vot-receipt"))
  ) {
    throw new Error(`bundle payload names: ${JSON.stringify(bundleNames)}`);
  }
  const bundledOne = execFileSync("unzip", ["-p", bundlePath, `${PROJECT}/${outboundFiles[0].name}`], {
    encoding: "utf8",
  });
  if (bundledOne !== outboundFiles[0].content) throw new Error("bundle payload mismatch");
  console.log("bundle payload-only: ok");
} catch (error) {
  if (error.code !== "ENOENT") throw error;
  if (fs.statSync(bundlePath).size < 22) throw new Error("bundle download is empty");
  console.log("bundle download: basic check (unzip unavailable)");
}

const expectedSeparateFiles = browserEngine === "chromium"
  ? outboundFiles.slice(0, 10)
  : outboundFiles;
const separateDownloads = await collectDownloads(
  async () => {
    await page.click("#separate-download-button");
    await page.waitForSelector("#separate-download-confirm[open]");
    const detail = await page.textContent("#separate-download-confirm-detail");
    if (!detail.includes("12 payload files") || !detail.includes("No ZIP or receipt files")) {
      throw new Error(`separate preflight detail: ${detail}`);
    }
    await page.click("#separate-download-start");
  },
  expectedSeparateFiles.length,
);
const separateNames = separateDownloads.map((download) => download.suggestedFilename());
if (separateNames.length !== expectedSeparateFiles.length ||
    !expectedSeparateFiles.every((file) => separateNames.includes(file.name))) {
  throw new Error(`separate download names: ${JSON.stringify(separateNames)}`);
}
for (const download of separateDownloads) {
  const downloadedPath = await download.path();
  if (!downloadedPath) throw new Error("separate download has no path");
  const expected = outboundFiles.find((file) => file.name === download.suggestedFilename())?.content;
  if (expected === undefined || fs.readFileSync(downloadedPath, "utf8") !== expected) {
    throw new Error(`separate payload mismatch: ${download.suggestedFilename()}`);
  }
}
console.log("separate fallback downloads: ok");
await browser.close();

if (
  fs.readFileSync(path.join(stored, "Résumé Draft.pdf"), "utf8") !==
  "unicode names travel\n"
) {
  throw new Error("unicode-named file mismatch");
}
if (!fs.readFileSync(path.join(stored, "archive.tar")).equals(big)) {
  throw new Error("archive.tar mismatch");
}
if (errors.length) {
  console.error(errors.join("\n"));
  process.exit(1);
}
console.log("ok: files verified on disk");
