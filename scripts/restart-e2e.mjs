// Restart end-to-end check: runs a real votport process, uploads one large
// file through the browser uploader, stops the server with SIGTERM while the
// transfer is in flight, starts it again over the same directories, and
// verifies the same upload finishes with byte-identical output.
// VOTPORT PROPRIETARY LICENSE.
//
// Requires: `npm ci`, Playwright chromium, and a built server binary:
//   VOTPORT_BIN=server/target/release/votport node scripts/restart-e2e.mjs
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const bin = process.env.VOTPORT_BIN || "server/target/release/votport";
const port = Number(process.env.PORT || 18080);
const base = `http://127.0.0.1:${port}`;
const adminPassword = "restart-e2e-password";
const sizeMib = Number(process.env.SIZE_MIB || 1536);

const root = fs.mkdtempSync(path.join(os.tmpdir(), "votport-restart-"));
const data = path.join(root, "data");
const received = path.join(root, "received");
const outbound = path.join(root, "outbound");
for (const dir of [data, received, outbound]) fs.mkdirSync(dir);
const source = path.join(root, "big.bin");
{
  const out = fs.openSync(source, "w");
  const block = Buffer.alloc(1024 * 1024);
  for (let i = 0; i < sizeMib; i += 1) {
    crypto.randomFillSync(block);
    fs.writeSync(out, block);
  }
  fs.closeSync(out);
}
const sha256 = (file) => {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(file));
  return hash.digest("hex");
};
const expected = sha256(source);

const logs = [];
function startServer() {
  const child = spawn(bin, [], {
    env: {
      ...process.env,
      VOTPORT_BIND: `127.0.0.1:${port}`,
      VOTPORT_DATA_DIR: data,
      VOTPORT_RECEIVE_DIR: received,
      VOTPORT_OUTBOUND_DIR: outbound,
      VOTPORT_WEB_ROOT: "./web",
      VOTPORT_ADMIN_PASSWORD: adminPassword,
      VOTPORT_MAX_UPLOAD_BYTES: String(4 * 1024 * 1024 * 1024),
      RUST_LOG: "info",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (chunk) => logs.push(String(chunk)));
  child.stderr.on("data", (chunk) => logs.push(String(chunk)));
  return child;
}
async function waitForServer(timeoutMs = 20000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const response = await fetch(`${base}/`);
      if (response.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error("server did not come up");
}
function stopServer(child) {
  return new Promise((resolve) => {
    child.once("exit", (code, signal) => resolve({ code, signal }));
    child.kill("SIGTERM");
  });
}

let server = startServer();
await waitForServer();
const browser = await chromium.launch();
const page = await browser.newPage();
const errors = [];
page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
try {
  await page.goto(base);
  await page.waitForSelector("#login:not([hidden])");
  await page.fill("#login-password", adminPassword);
  await page.click("#login-form button[type=submit]");
  await page.waitForSelector("#create-form:not([hidden])", { timeout: 15000 });
  await page.fill("#create-label", "restart e2e");
  await page.fill("#create-dest", "restart");
  await page.click("#create-form button[type=submit]");
  await page.waitForSelector("#new-link:not([hidden])");
  const linkUrl = (await page.textContent("#new-link-url")).trim();

  console.log("link:", linkUrl);
  await page.goto(linkUrl);
  try {
    await page.waitForSelector("#uploader:not([hidden])", { timeout: 15000 });
  } catch (error) {
    console.log("page text:", (await page.textContent("body")).replace(/\s+/g, " ").slice(0, 600));
    console.log("server log tail:", logs.slice(-5).join(""));
    throw error;
  }
  await page.setInputFiles("#file-input", [source]);
  const uploadStarted = Date.now();
  await page.click("#send");
  // Wait until ranges are moving, then a little longer so the restart lands
  // mid-file rather than at the start.
  await page.waitForFunction(
    () => document.querySelector("#phase")?.textContent === "Sending",
    null,
    { timeout: 120000 },
  );
  await page.waitForFunction(
    () => Number(document.querySelector("#meter")?.getAttribute("aria-valuenow")) > 20,
    null,
    { timeout: 120000 },
  );
  const beforeStop = await page.textContent("#progress-note");
  console.log("stopping server at:", beforeStop.trim());
  const exit = await stopServer(server);
  console.log("server exited:", exit);
  const suspended = logs.some((line) => line.includes("suspended upload sessions"));
  if (!suspended) throw new Error("server did not log the suspend");
  const staging = fs.readdirSync(path.join(received, "restart")).filter((name) => name.startsWith(".vot-"));
  if (staging.length < 2) throw new Error(`staging missing after stop: ${JSON.stringify(staging)}`);
  await page.waitForFunction(
    () => document.querySelector("#phase")?.textContent === "Paused",
    null,
    { timeout: 30000 },
  );
  console.log("client paused; restarting server");
  server = startServer();
  await waitForServer();
  const resumed = logs.some((line) => line.includes("re-attached upload session after restart"));
  if (!resumed) throw new Error("server did not log the re-attach");
  await page.waitForSelector("#done-card:not([hidden])", { timeout: 600000 });
  const statuses = await page.$$eval("#done-list .status", (els) => els.map((el) => el.textContent));
  console.log("done:", statuses, `${((Date.now() - uploadStarted) / 1000).toFixed(1)}s`);
  const published = path.join(received, "restart", "big.bin");
  const actual = sha256(published);
  if (actual !== expected) throw new Error(`published bytes differ: ${actual} != ${expected}`);
  if (!fs.existsSync(`${published}.vot-receipt`)) throw new Error("receipt missing");
  const leftovers = fs.readdirSync(path.join(received, "restart")).filter((name) => name.startsWith(".vot-"));
  if (leftovers.length) throw new Error(`staging left behind: ${JSON.stringify(leftovers)}`);
  if (errors.length) throw new Error(errors.join("\n"));
  console.log("restart e2e passed: byte-identical after SIGTERM mid-upload");
} finally {
  await browser.close();
  if (server.exitCode === null) await stopServer(server);
  fs.rmSync(root, { recursive: true, force: true });
}
