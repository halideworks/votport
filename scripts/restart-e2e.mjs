// Restart end-to-end check: runs a real votport process, uploads one large
// file through the browser uploader, stops the server with SIGTERM while the
// transfer is in flight, starts it again over the same directories, and
// verifies the same upload finishes with byte-identical output.
// VOTPORT PROPRIETARY LICENSE.
//
// Requires: `npm ci`, Playwright chromium, the wasm bundle in
// web/assets/vendor (`scripts/build-wasm.sh /path/to/VOT`), and a built
// server binary, run from the repo root:
//   VOTPORT_BIN=server/target/release/votport node scripts/restart-e2e.mjs
//
// MODE=shared (default) restarts the same process over the same three
// directories: the shared-volume failover, where the standby mounts the live
// data directory. MODE=replica runs a `votport standby` beside the live
// process pulling replicas into its own data directory, stops the live one
// mid-upload, and promotes the standby by starting a normal votport over the
// standby's data directory with the same receive root: the replicated
// failover. Both verify the lease handoff and a byte-identical publish.
// SIZE_MIB must keep the upload in flight when the stop lands: on a fast
// disk 128 MiB finishes first and the run fails on "did not log the
// suspend"; 512 or more is safe, the default is 1536.
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
const mode = process.env.MODE || "shared";
if (!["shared", "replica"].includes(mode)) throw new Error(`MODE must be shared or replica, not ${mode}`);
const replicaToken = "restart-e2e-replica-token";
const standbyPort = port + 1;
const standbyBase = `http://127.0.0.1:${standbyPort}`;

const root = fs.mkdtempSync(path.join(os.tmpdir(), "votport-restart-"));
const data = path.join(root, "data");
const standbyData = path.join(root, "standby-data");
const received = path.join(root, "received");
const outbound = path.join(root, "outbound");
for (const dir of [data, standbyData, received, outbound]) fs.mkdirSync(dir);
const leaseFile = path.join(received, ".votport-lease");
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
function startServer(dataDir = data) {
  const child = spawn(bin, [], {
    env: {
      ...process.env,
      VOTPORT_BIND: `127.0.0.1:${port}`,
      VOTPORT_DATA_DIR: dataDir,
      VOTPORT_RECEIVE_DIR: received,
      VOTPORT_OUTBOUND_DIR: outbound,
      VOTPORT_WEB_ROOT: "./web",
      VOTPORT_ADMIN_PASSWORD: adminPassword,
      VOTPORT_MAX_UPLOAD_BYTES: String(4 * 1024 * 1024 * 1024),
      VOTPORT_REPLICA_TOKEN: replicaToken,
      RUST_LOG: "info",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (chunk) => logs.push(String(chunk)));
  child.stderr.on("data", (chunk) => logs.push(String(chunk)));
  return child;
}
const standbyLogs = [];
function startStandby() {
  const child = spawn(bin, ["standby"], {
    env: {
      ...process.env,
      VOTPORT_BIND: `127.0.0.1:${standbyPort}`,
      VOTPORT_DATA_DIR: standbyData,
      VOTPORT_STANDBY_SOURCE: base,
      VOTPORT_REPLICA_TOKEN: replicaToken,
      VOTPORT_STANDBY_INTERVAL_SECS: "5",
      RUST_LOG: "info",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (chunk) => standbyLogs.push(String(chunk)));
  child.stderr.on("data", (chunk) => standbyLogs.push(String(chunk)));
  return child;
}
async function readyz(url) {
  const response = await fetch(`${url}/readyz`);
  return { status: response.status, body: await response.json() };
}
// Waits until the standby has staged a copy whose archive the live instance
// built in a later second than `afterMs`, so a session that had begun by
// then is in the copy. The archive time, not the pull time, is what proves
// that: a pull can finish after a moment while its snapshot predates it.
async function waitForReplica(afterMs, timeoutMs = 60000) {
  const afterSecond = Math.floor(afterMs / 1000);
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const { body } = await readyz(standbyBase);
      if (body.archive_created_at && body.archive_created_at > afterSecond && !body.last_error) return body;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`standby never staged a copy built after ${afterSecond}: ${standbyLogs.slice(-5).join("")}`);
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
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve({ code: child.exitCode, signal: child.signalCode });
      return;
    }
    child.once("exit", (code, signal) => resolve({ code, signal }));
    child.kill("SIGTERM");
  });
}

let server = null;
let standby = null;
let browser = null;
const errors = [];
try {
  server = startServer();
  await waitForServer();
  // An orphan from an earlier run would answer on the port while this
  // child had already died on bind.
  if (server.exitCode !== null) throw new Error(`server exited on start: ${logs.slice(-5).join("")}`);
  if (mode === "replica") standby = startStandby();
  {
    const { status, body } = await readyz(base);
    if (status !== 200 || body.lease?.mine !== true) throw new Error(`live instance does not hold the lease: ${JSON.stringify(body)}`);
  }
  browser = await chromium.launch();
  const page = await browser.newPage();
  page.on("pageerror", (error) => errors.push(`pageerror: ${error.message}`));
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
  // Bytes are moving, so begin has happened; a copy built after this
  // instant holds the session record with whatever prefix was checkpointed.
  const pastBegin = Date.now();
  const beforeStop = await page.textContent("#progress-note");
  if (mode === "replica") {
    const copy = await waitForReplica(pastBegin);
    console.log("standby staged a copy:", JSON.stringify(copy));
  }
  console.log("stopping server at:", beforeStop.trim());
  const exit = await stopServer(server);
  console.log("server exited:", exit);
  const suspended = logs.some((line) => line.includes("suspended upload sessions"));
  if (!suspended) throw new Error("server did not log the suspend");
  if (fs.existsSync(leaseFile)) throw new Error("a clean stop left the lease behind");
  if (standby) {
    const stopped = await stopServer(standby);
    console.log("standby exited:", stopped);
    standby = null;
  }
  const staging = fs.readdirSync(path.join(received, "restart")).filter((name) => name.startsWith(".vot-"));
  if (staging.length < 2) throw new Error(`staging missing after stop: ${JSON.stringify(staging)}`);
  await page.waitForFunction(
    () => document.querySelector("#phase")?.textContent === "Paused",
    null,
    { timeout: 30000 },
  );
  console.log(mode === "replica" ? "client paused; promoting the standby" : "client paused; restarting server");
  server = startServer(mode === "replica" ? standbyData : data);
  await waitForServer();
  const resumed = logs.some((line) => line.includes("re-attached upload session after restart"));
  if (!resumed) throw new Error("server did not log the re-attach");
  {
    const { status, body } = await readyz(base);
    if (status !== 200 || body.lease?.mine !== true) throw new Error(`the new instance does not hold the lease: ${JSON.stringify(body)}`);
  }
  if (mode === "replica") {
    // The boot consumed the staged copy: the marker is gone and the
    // pre-restore files were moved into a rollback directory.
    const names = fs.readdirSync(standbyData);
    if (names.includes(".votport-restore-pending.json")) throw new Error("pending restore was not applied");
    if (!names.some((name) => name.startsWith(".votport-restore-rollback-"))) throw new Error("no restore rollback directory after promotion");
    console.log("pending restore applied on promotion");
  }
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
  console.log(`restart e2e passed (${mode}): byte-identical after SIGTERM mid-upload`);
} finally {
  if (browser) await browser.close();
  if (server) await stopServer(server);
  if (standby) await stopServer(standby);
  fs.rmSync(root, { recursive: true, force: true });
}
