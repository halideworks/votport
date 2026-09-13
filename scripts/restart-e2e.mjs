// Restart end-to-end check: runs a real votport process, uploads one
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
// A browser request barrier holds later chunks until the live process stops.
// SIZE_MIB defaults to 16; progress does not depend on file size or disk speed.
import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
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
const sizeMib = Number(process.env.SIZE_MIB || 16);
assert.ok(Number.isInteger(sizeMib) && sizeMib >= 16 && sizeMib <= 4096, "SIZE_MIB must be 16..4096");
assert.ok(Number.isInteger(port) && port > 0 && port < 65535, "PORT must be 1..65534");
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
for (const dir of [data, standbyData, received, outbound]) fs.mkdirSync(dir, { mode: 0o700 });
const leaseFile = path.join(received, ".vot-stage", ".votport-lease");
const leaseLock = path.join(received, ".vot-stage", "writer.lock");
const stagingDir = path.join(received, "restart", ".vot-stage");
const identity = (file) => { const { dev, ino } = fs.statSync(file, { bigint: true }); return `${dev}:${ino}`; };
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
const sha256 = async (file) => {
  const hash = crypto.createHash("sha256");
  for await (const chunk of fs.createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
};
const expected = await sha256(source);

const logs = [];
const standbyLogs = [];
const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("VOTPORT_")));
function startServer(dataDir = data, pulling = false) {
  const output = pulling ? standbyLogs : logs;
  output.length = 0;
  const child = spawn(bin, pulling ? ["standby"] : [], {
    env: {
      ...environment,
      VOTPORT_BIND: `127.0.0.1:${pulling ? standbyPort : port}`,
      VOTPORT_PUBLIC_URL: base,
      VOTPORT_DATA_DIR: dataDir,
      VOTPORT_RECEIVE_DIR: received,
      VOTPORT_OUTBOUND_DIR: outbound,
      VOTPORT_WEB_ROOT: process.env.VOTPORT_WEB_ROOT || "./web",
      VOTPORT_ADMIN_PASSWORD: adminPassword,
      VOTPORT_MAX_UPLOAD_BYTES: String(4 * 1024 * 1024 * 1024),
      VOTPORT_REPLICA_TOKEN: replicaToken,
      VOTPORT_STANDBY_SOURCE: base,
      VOTPORT_STANDBY_INTERVAL_SECS: "5",
      RUST_LOG: "info",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (chunk) => output.push(String(chunk)));
  child.stderr.on("data", (chunk) => output.push(String(chunk)));
  child.once("error", (error) => { child.startError = error; });
  return child;
}
async function readyz(url) {
  const response = await fetch(`${url}/readyz`, { signal: AbortSignal.timeout(2000) });
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
    if (standby.startError || standby.exitCode !== null || standby.signalCode !== null) throw new Error(`standby exited: ${standbyLogs.slice(-5).join("")}`);
    try {
      const { body } = await readyz(standbyBase);
      if (body.archive_created_at && body.archive_created_at > afterSecond && !body.last_error && standbyLogs.join("").includes(`standby pulling replicas into ${standbyData}`)) return body;
    } catch {}
    await delay(200);
  }
  throw new Error(`standby never staged a copy built after ${afterSecond}: ${standbyLogs.slice(-5).join("")}`);
}
async function waitForServer(timeoutMs = 20000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (server.startError || server.exitCode !== null || server.signalCode !== null) throw new Error(`server exited: ${server.startError || logs.slice(-5).join("")}`);
    try {
      const response = await fetch(`${base}/`, { signal: AbortSignal.timeout(2000) });
      if (response.ok && logs.join("").includes(`votport listening on 127.0.0.1:${port};`)) return;
    } catch {}
    await delay(200);
  }
  throw new Error("server did not come up");
}
async function stopServer(child) {
  if (!child || child.startError || child.exitCode !== null || child.signalCode !== null) {
    return { code: child?.exitCode, signal: child?.signalCode };
  }
  let killTimer, deadline;
  try {
    return await new Promise((resolve, reject) => {
      child.once("exit", (code, signal) => {
        if (signal === "SIGKILL") reject(new Error("process required SIGKILL after SIGTERM"));
        else resolve({ code, signal });
      });
      killTimer = setTimeout(() => child.kill("SIGKILL"), 40000);
      deadline = setTimeout(() => reject(new Error("process did not exit after SIGKILL")), 45000);
      child.kill("SIGTERM");
    });
  } finally {
    clearTimeout(killTimer);
    clearTimeout(deadline);
  }
}

let server = null;
let standby = null;
let browser = null;
const errors = [];
let releaseChunks;
const chunksReleased = new Promise((resolve) => { releaseChunks = resolve; });
try {
  server = startServer();
  await waitForServer();
  // An orphan from an earlier run would answer on the port while this
  // child had already died on bind.
  if (server.exitCode !== null) throw new Error(`server exited on start: ${logs.slice(-5).join("")}`);
  if (mode === "replica") standby = startServer(standbyData, true);
  {
    const { status, body } = await readyz(base);
    if (status !== 200 || body.lease?.mine !== true) throw new Error(`live instance does not hold the lease: ${JSON.stringify(body)}`);
  }
  const originalLock = identity(leaseLock);
  const originalHolder = (await readyz(base)).body.lease.holder;
  const receiptKey = await (await fetch(`${base}/api/receipt-key`, { signal: AbortSignal.timeout(2000) })).json();
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
  const sessionIds = new Set();
  const replies = [];
  const begins = [];
  let interrupted = false, report;
  let markHeld;
  const held = new Promise((resolve) => { markHeld = resolve; });
  await page.route("**/api/session/*/chunk?*", async (route) => {
    const url = new URL(route.request().url());
    sessionIds.add(url.pathname.split("/")[3]);
    if (!interrupted && Number(url.searchParams.get("offset")) === 0 && mode === "replica") {
      // The first accepted range must cross the five-second checkpoint interval.
      await delay(6000);
    } else if (!interrupted && Number(url.searchParams.get("offset")) > 0) {
      markHeld();
      await chunksReleased;
    }
    await route.continue();
  });
  page.on("response", (response) => {
    if (/\/api\/session\/[^/]+\/begin$/.test(new URL(response.url()).pathname) && response.ok()) {
      replies.push(response.json().then((reply) => begins.push(reply)).catch((error) => errors.push(error.message)));
    }
    if (/\/api\/session\/[^/]+\/finish$/.test(new URL(response.url()).pathname) && response.ok()) {
      replies.push(response.json().then((reply) => { report = reply; }).catch((error) => errors.push(error.message)));
    }
  });
  await page.setInputFiles("#file-input", [source]);
  const uploadStarted = Date.now();
  await page.click("#send");
  // Only the first chunk reaches the server until shutdown completes.
  await page.waitForFunction(
    () => document.querySelector("#phase")?.textContent === "Sending",
    null,
    { timeout: 120000 },
  );
  await page.waitForFunction(
    () => Number(document.querySelector("#meter")?.getAttribute("aria-valuenow")) > 0,
    null,
    { timeout: 120000 },
  );
  // Bytes are moving, so begin has happened; a copy built after this
  // instant holds the session record with whatever prefix was checkpointed.
  await Promise.race([held, delay(30000, null, { ref: false }).then(() => { throw new Error("no later chunk reached the request barrier"); })]);
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
  assert.equal(exit.code, 0, "live process must stop cleanly");
  assert.ok(!fs.existsSync(leaseFile), "clean stop must remove its heartbeat");
  assert.equal(identity(leaseLock), originalLock, "clean stop must retain the lock inode");
  if (standby) {
    const stopped = await stopServer(standby);
    console.log("standby exited:", stopped);
    standby = null;
  }
  const staging = fs.readdirSync(stagingDir);
  const stagedFiles = staging.filter((name) => name.endsWith(".stage"));
  assert.equal(stagedFiles.length, 1, `expected one staged payload: ${staging}`);
  assert.deepEqual(staging.sort(), [stagedFiles[0], stagedFiles[0].replace(/\.stage$/, ".journal")].sort(), "suspended upload must retain its exact payload and journal pair");
  const stagedIdentity = identity(path.join(stagingDir, stagedFiles[0]));
  assert.ok(!fs.existsSync(path.join(received, "restart", "big.bin")), "unfinished file was published");
  interrupted = true;
  releaseChunks();
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
  assert.equal(identity(leaseLock), originalLock, "promotion must use the retained lock inode");
  assert.notEqual((await readyz(base)).body.lease.holder, originalHolder, "promotion must acquire a new lease");
  assert.deepEqual(await (await fetch(`${base}/api/receipt-key`, { signal: AbortSignal.timeout(2000) })).json(), receiptKey, "receipt identity must survive restart");
  if (mode === "replica") {
    // The boot consumed the staged copy: the marker is gone and the
    // pre-restore files were moved into a rollback directory.
    const names = fs.readdirSync(standbyData);
    if (names.includes(".votport-restore-pending.json")) throw new Error("pending restore was not applied");
    if (!names.some((name) => name.startsWith(".votport-restore-rollback-"))) throw new Error("no restore rollback directory after promotion");
    console.log("pending restore applied on promotion");
  }
  await page.waitForSelector("#done-card:not([hidden])", { timeout: 120000 });
  const statuses = await page.$$eval("#done-list .status", (els) => els.map((el) => el.textContent));
  console.log("done:", statuses, `${((Date.now() - uploadStarted) / 1000).toFixed(1)}s`);
  const published = path.join(received, "restart", "big.bin");
  const actual = await sha256(published);
  assert.equal(identity(published), stagedIdentity, "resume must publish the retained payload inode");
  await Promise.all(replies);
  assert.equal(sessionIds.size, 1, "restart must resume the same session");
  assert.ok(begins.length >= 2, "client must reconcile the restored session through begin");
  assert.ok(begins.slice(1).some((reply) => reply.entries[0].covered_bytes > 0), "resume must retain verified progress");
  if (actual !== expected) throw new Error(`published bytes differ: ${actual} != ${expected}`);
  if (!fs.existsSync(`${published}.vot-receipt`)) throw new Error("receipt missing");
  const leftovers = fs.readdirSync(stagingDir);
  assert.deepEqual(leftovers, [], "completed upload must leave no staging files or journals");
  const check = await fetch(`${base}/api/verify`, {
    method: "POST", headers: { "Content-Type": "application/octet-stream" },
    body: fs.readFileSync(`${published}.vot-receipt`), signal: AbortSignal.timeout(5000),
  });
  const receipt = await check.json();
  assert.ok(check.ok && receipt.ok, `receipt verification failed: ${JSON.stringify(receipt)}`);
  assert.equal(receipt.root, report.files[0].root);
  assert.equal(receipt.suite, report.files[0].suite);
  assert.equal(receipt.length, fs.statSync(source).size);
  if (errors.length) throw new Error(errors.join("\n"));
  console.log(`restart e2e passed (${mode}): byte-identical after SIGTERM mid-upload`);
} catch (error) {
  console.error("server log:", logs.join(""), "standby log:", standbyLogs.join(""));
  throw error;
} finally {
  releaseChunks();
  const cleanup = await Promise.allSettled([browser?.close(), stopServer(server), stopServer(standby)]);
  const failed = cleanup.find((result) => result.status === "rejected");
  if (failed) throw failed.reason;
  fs.rmSync(root, { recursive: true, force: true });
}
