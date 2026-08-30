// Browser end-to-end check: signs in to the admin UI, creates a link,
// uploads files through the real uploader (vot-wasm in Chromium), and
// verifies the bytes on disk. VOTPORT PROPRIETARY LICENSE.
//
// Requires: `npm ci`, `npx --no-install playwright install chromium`, a
// running votport, and:
//   BASE_URL        e.g. http://127.0.0.1:8080
//   ADMIN_PASSWORD  the admin password of that instance
//   RECEIVE_DIR     the instance's receive root, from this process's view
//
//   node scripts/browser-e2e.mjs

import { chromium } from "playwright";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const base = process.env.BASE_URL || "http://127.0.0.1:8080";
const adminPassword = process.env.ADMIN_PASSWORD;
const receiveDir = process.env.RECEIVE_DIR;
if (!adminPassword || !receiveDir) {
  console.error("set BASE_URL, ADMIN_PASSWORD and RECEIVE_DIR");
  process.exit(2);
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "votport-e2e-"));
process.once("exit", () => fs.rmSync(dir, { recursive: true, force: true }));
fs.writeFileSync(path.join(dir, "Résumé Draft.pdf"), "unicode names travel\n");
fs.writeFileSync(path.join(dir, "deliver-one.txt"), "first deliverable\n");
fs.writeFileSync(path.join(dir, "deliver-two.txt"), "second deliverable\n");
// Multiple server-sized ranges exercise the bounded parallel upload path.
const big = Buffer.alloc(40 * 1024 * 1024 + 99);
for (let i = 0; i < big.length; i += 1) big[i] = (i * 7) % 253;
fs.writeFileSync(path.join(dir, "archive.tar"), big);

// A UTF-8 locale is required for Chromium to accept non-ASCII file names.
const browser = await chromium.launch({
  env: { ...process.env, LANG: "C.UTF-8", LC_ALL: "C.UTF-8" },
});
const page = await browser.newPage();
const errors = [];
page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));

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

await page.goto(base);
await page.waitForSelector("#login:not([hidden])");
await page.fill("#login-password", adminPassword);
await page.click("#login-form button[type=submit]");
// Signed-in users land on /receive; the create form is the first element.
await page.waitForSelector("#create-form:not([hidden])", { timeout: 15000 });

const dest = `e2e-${Date.now().toString(36)}`;
await page.fill("#create-label", "browser e2e");
await page.fill("#create-dest", dest);
await page.click("#create-form button[type=submit]");
await page.waitForSelector("#new-link:not([hidden])");
const linkUrl = (await page.textContent("#new-link-url")).trim();
console.log("link:", linkUrl);

await page.goto(linkUrl);
await page.waitForSelector("#uploader:not([hidden])", { timeout: 15000 });
await page.setInputFiles("#file-input", [
  path.join(dir, "Résumé Draft.pdf"),
  path.join(dir, "archive.tar"),
]);
await page.click("#send");
await page.waitForSelector("#done-card:not([hidden])", { timeout: 120000 });
console.log(
  "uploaded:",
  (await page.textContent("#done-list")).trim().replace(/\s+/g, " "),
);
const ids = await page.$$eval("#done-list .file-id", (els) =>
  els.map((el) => el.textContent),
);
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
await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
await page.click("#done-list li:first-child .file-id");
const copied = await page.evaluate(() => navigator.clipboard.readText());
if (copied !== ids[0]) {
  throw new Error(`copy mismatch: ${copied}`);
}

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
if (`${verdict.suite}:${verdict.root}` !== ids[0]) {
  throw new Error(`verify root mismatch: ${JSON.stringify(verdict)}`);
}
console.log("verified:", ids[0]);

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
  await page.waitForSelector("#library-input", { timeout: 15000 });
} catch (error) {
  console.error(`deliver page did not load at ${page.url()}: ${await page.locator("body").innerText()}`);
  throw error;
}
await page.setInputFiles("#library-input", [
  path.join(dir, "deliver-one.txt"),
  path.join(dir, "deliver-two.txt"),
]);
await page.waitForFunction(
  () => document.getElementById("library-status").textContent.includes("2 files added"),
  { timeout: 30000 },
);
const libraryFiles = page.locator("#library-files input[type=checkbox]");
const libraryFileCount = await libraryFiles.count();
if (libraryFileCount !== 2) {
  throw new Error(`outbound library count: ${libraryFileCount}`);
}
for (let index = 0; index < libraryFileCount; index += 1) {
  await page.locator("#library-files input[type=checkbox]").nth(index).click();
}
await page.fill("#deliver-label", "browser outbound e2e");
await page.click("#deliver-submit");
await page.waitForSelector("#outbound-result:not([hidden])", { timeout: 30000 });
const outboundUrl = await page.inputValue("#outbound-url");
if (!/^https?:\/\//.test(outboundUrl)) {
  throw new Error(`outbound URL malformed: ${outboundUrl}`);
}
console.log("outbound link:", outboundUrl);

await page.goto(outboundUrl);
await page.waitForSelector("#download-content:not([hidden])", { timeout: 30000 });
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

const [bundleDownload] = await collectDownloads(
  () => page.click("#bundle-download-button"),
  1,
);
const bundlePath = path.join(dir, "deliverables.zip");
await bundleDownload.saveAs(bundlePath);
const bundleNames = execFileSync("unzip", ["-Z1", bundlePath], { encoding: "utf8" })
  .trim()
  .split("\n")
  .filter(Boolean);
if (
  bundleNames.length !== 2 ||
  !bundleNames.includes("deliver-one.txt") ||
  !bundleNames.includes("deliver-two.txt") ||
  bundleNames.some((name) => name.endsWith(".vot-receipt"))
) {
  throw new Error(`bundle payload names: ${JSON.stringify(bundleNames)}`);
}
const bundledOne = execFileSync("unzip", ["-p", bundlePath, "deliver-one.txt"], {
  encoding: "utf8",
});
if (bundledOne !== "first deliverable\n") {
  throw new Error("bundle payload mismatch");
}
console.log("bundle payload-only: ok");

const separateDownloads = await collectDownloads(
  () => page.click("#separate-download-button"),
  2,
);
const separateNames = separateDownloads.map((download) => download.suggestedFilename());
if (!separateNames.includes("deliver-one.txt") || !separateNames.includes("deliver-two.txt")) {
  throw new Error(`separate download names: ${JSON.stringify(separateNames)}`);
}
for (const download of separateDownloads) {
  const downloadedPath = await download.path();
  if (!downloadedPath) throw new Error("separate download has no path");
  const expected = download.suggestedFilename() === "deliver-one.txt"
    ? "first deliverable\n"
    : "second deliverable\n";
  if (fs.readFileSync(downloadedPath, "utf8") !== expected) {
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
