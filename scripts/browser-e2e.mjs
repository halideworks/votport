// Browser end-to-end check: signs in to the admin UI, creates a link,
// uploads files through the real uploader (vot-wasm in Chromium), and
// verifies the bytes on disk. AGPL-3.0-only.
//
// Requires: `npm i playwright` (with its Chromium), a running votport, and:
//   BASE_URL        e.g. http://127.0.0.1:8080
//   ADMIN_PASSWORD  the admin password of that instance
//   RECEIVE_DIR     the instance's receive root, from this process's view
//
//   node scripts/browser-e2e.mjs

import { chromium } from "playwright";
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
fs.writeFileSync(path.join(dir, "Résumé Draft.pdf"), "unicode names travel\n");
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

await page.goto(base);
await page.waitForSelector("#login:not([hidden])");
await page.fill("#login-password", adminPassword);
await page.click("#login-form button[type=submit]");
// Signed-in users land on /links; the create form is the first element.
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
await browser.close();

const stored = path.join(receiveDir, dest);
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
