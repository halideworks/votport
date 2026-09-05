# The desktop client: native apps on one Rust core

Status: in progress, 2026-09-05. The VOT seams in "VOT changes" landed in
vot-cli at pin `0a129ea` (`build_manifest`, `build_manifest_from`,
`push_from`, `fetch_bundle_with`, `probe_serve`, the proof-cache accessors,
and the wire build on the platform-native CI job); the listener session cap
is a separate follow-on. The core and CLI now move bytes end to end: C1 send
over HTTP and QUIC push (#183, #184), C2 receive over HTTP and QUIC fetch
(#185, #186), and C7 within-object resume over HTTP (#187) and over a QUIC
bundle refetch (#189) have landed. The UniFFI surface in `client/core/src/ffi.rs`
(proc-macros, no `.udl`: `send`, `receive`, a `ProgressListener` foreign
trait, and the transfer records) is generated to Swift by the `client` CI job
through the workspace's own `uniffi-bindgen` crate, pinned with the core's
UniFFI 0.31 so the C# generator can share it. The first macOS slice is in
`client/macos`: an xcodegen project and a local Swift package wrapping the
core's XCFramework (both produced by `build-core.sh`, neither committed), and
one Receive screen that takes a delivery link, a password, and a folder,
lists the files the core planned, and draws their progress and verification.
It received a 300 MB delivery on the Mac Studio byte-identical in under
three seconds. Two findings from that run: macOS 15+ holds a GUI app's
connections to LAN addresses until the user answers the Local Network
prompt (the CLI is not asked), so a headless test reaches the server over
an ssh reverse tunnel on loopback; and `Votport --receive <link> <dir>
--snapshot <png>` drives a receive from the command line and writes the
window's own rendering, since screen capture over ssh needs a permission
grant at the Mac. The FFI now hands a shell a `TransferView` computed in
Rust (phase, transport, per-file rows and states, bytes, a rate over a
five-second window, an ETA once the rate has held ten seconds) through a
`TransferListener`, with a `Transfer` handle for cancel; the QUIC paths
report carrier bytes through vot-cli's progress callback. A cancel takes
effect per chunk and per file over HTTP; over QUIC it is honoured only
before the push preflight or the fetch ticket, since vot-cli drops the
resume store once a bundle is whole and a stop after that would discard a
complete download (threading vot-cli's `CancellationHandle` through its
options is the VOT change that makes a mid-carrier cancel possible). A
one-second ticker re-measures the rate while nothing arrives, so a stall
reads as a rate falling to zero. The macOS app now has the four sections
of Decision 6 (Send with the Finder drop target and clipboard paste,
Receive, Transfers with per-transfer cancel and an expanding row, Settings
with a default receive folder), a menu bar item listing the active
transfers and their rates, done and failed notifications, and the
`votport://` scheme (`votport://r/<token>?base=<origin>` and
`votport://s/<token>?base=<origin>`; any page can emit one, so the link is
only prefilled with its origin visible and nothing moves until the user
presses Send or Receive). Launch-time
work runs from the app delegate, since a locked screen never shows a
window. `scripts/design-tokens.mjs` generates `client/design/tokens.json`
from the web stylesheet. Next: the "Open in the app" links on the web
pages, the Windows shell (C5), and the core follow-ons: the client journal
with `votport status` (which also gives multi-file resume) and watch
folders.

| Field | Value |
| --- | --- |
| Status | Proposed |
| Date | 2026-09-04 |
| Continues | `docs/native-push.md` (send direction), `docs/deliver-over-quic.md` (receive direction and the agent) |
| Audience | David |

## Overview

votport moves bytes two ways today: a browser sender over HTTP chunk
sessions, and a native push over VOT QUIC that only the `vot` CLI speaks.
Deliver is HTTP for browsers and VOT QUIC for `vot fetch` and `vot pull`.
The QUIC paths are the fast ones (2.10 Gbit/s Helsinki to Singapore at
191 ms RTT, 9.21 Gbit/s on 10 GbE, both in `docs/deliver-over-quic.md`)
and nobody at a facility will run them from a terminal.

This design adds the client the facility pitch needs: a native macOS app, a
native Windows app, and a CLI, all over one Rust core that owns every state
machine, so each shell is layout and platform integration only. The core
sends by native push, receives by native fetch, falls back to the HTTP
session API when UDP is blocked, hashes source files in place without
copying them, resumes across restarts, and reports honest rates. The same
core is the base of the replication agent in `docs/deliver-over-quic.md`
and, later, of votdock's fleet.

## Goals

- Send: drop files or a folder, paste a request link, watch it land. Over
  QUIC by default, at the rates VOT measures, with every object proven on
  the receiver before publication. A 500 GB sequence is never copied on the
  sending machine.
- Receive: paste a deliver link, pick a destination, get every file
  published atomically with a receipt, verified against the package root.
- Resume: a transfer survives an app quit, a sleep, a network change, and
  a reboot, and picks up where the persisted state says it left off. Over
  push this needs the receiver work in phase C3; decision 4 states what
  version one resumes on each path.
- Native: SwiftUI on macOS, WinUI 3 on Windows. Drag and drop from Finder
  and Explorer, system notifications, dark and light following the OS,
  the app store's idea of a well-behaved app on each platform.
- Fast to use: one primary action per screen, no wizard, no account for a
  sender or recipient holding a link.
- Beautiful: the web pages' design language (the tokens in
  `web/assets/style.css`, Plus Jakarta Sans, JetBrains Mono, the Libre
  Caslon wordmark, the nautical vocabulary kept subtle), rendered by the
  platform toolkit.
- Headless: the CLI runs the same core on Linux, macOS, and Windows for
  watch folders and scripted sends, and is the agent's base.

## Non-goals

- Operator features (creating request links, issuing grants, browsing the
  library) before the transfer paths ship. Version one is for the two
  people holding a link; operator mode is phase C8, behind the same
  sign-in the admin pages use, so the app is a full votport client and
  not only a transfer tool.
- A web view of any kind. No Electron, no Tauri, no embedded browser for
  chrome or content.
- Mobile. iOS Safari is the phone story and stays on the web sender.
- Rendezvous, relay, or hole punching. votport is the fixed end; the app
  dials it. A facility whose firewall blocks UDP gets the HTTP fallback,
  not a relay.
- A plugin API, MAM integration, or an SDK. The CLI's JSON output is the
  integration surface until a customer asks for more.

## What exists today, verified in code

Server, the contract the client speaks (route table in `server/src/app.rs`):

| Route | Role for the client |
| --- | --- |
| `GET /api/r/{token}` | Link info: `needs_password`, `usable`, `max_bytes`, `chunk_bytes`, `allow_hidden`, `max_entries`, `push` (true when the push listener is bound), `branding`. |
| `POST /api/r/{token}/verify` | Password gate; sets the link cookie. |
| `POST /api/r/{token}/push` | Preflight: `{password, holder_key, package{suite, root, length, entries}}` returns `{session, capability, address, certificate_digest, expires_at}` (`api::create_push_session`). |
| `POST /api/r/{token}/session`, `/api/session/{sid}/{seal,page,begin,chunk,finish,abort}` | The HTTP chunk session the browser speaks. `web/assets/upload.js` is the reference implementation, including rebegin on `ChunkProgress.rebegin` and the 422 finish path. |
| `GET /api/push-identity` | Push listener address, certificate digest, issuer public key. |
| `GET /api/s/{token}` | Grant metadata: files, `total_bytes`, and a `fetch` object (`address`, `certificate_digest`, `mint_url`) present only when the serve listener is bound. |
| `POST /api/s/{token}/verify` | Password gate for a grant. |
| `POST /api/s/{token}/fetch` | Mint: `{holder_key}` returns `{capability, address, certificate_digest, package_root, expires_at}` (`api::serve::mint_fetch`). |
| `GET /api/s/{token}/{file,batch,bundle,receipt}` | HTTP delivery and receipts, the fallback. |
| `GET /api/receipt-key`, `POST /api/verify` | Public receipt verification. |

VOT at the pinned revision (`0a129ea`), the functions the core builds on:

- `push_bundle(bundle_dir, address, capability_path, key_source, identity)`
  dials `rails` sessions, each `ServeSession::begin_push_session` over a
  `BundleServer`, and drives to `ServeStatus::Completed` (ADR-0050). It
  takes a bundle directory and opens it with `BundleServer::open`, which
  reads `objects/<root>`; it prints nothing and exposes no progress.
- `build_bundle(source, bundle)` packs files of 256 KiB and under
  (`CANDIDATE_MAX`) into pack objects and copies every larger file into
  `objects/<root>` (`emit_direct`, one read that names the object). For
  the client the copy is the problem: a sequence is read twice and written
  once before the first byte moves. The packs are a second problem:
  votport refuses packed entries on both the HTTP begin and the push
  manifest hook (`session.rs`, "packed entries are not supported"), so
  the client's package must be direct objects only.
- `BundleServer::assemble(manifest_root, sources)` (ADR-0049) serves
  objects from wherever they are, given `ServedSource { path, leaves }` per
  root, and with leaves supplied it samples instead of re-reading. This is
  the no-copy path, but nothing public drives a push from an assembled
  server, and nothing public builds a manifest without also building the
  bundle.
- `fetch_bundle(address, bundle_dir, pin)` and `receive_bundle(bundle,
  destination, receipt, key, observed_at)` are `vot fetch` and the publish
  half of `vot pull`: fetch into a bundle directory, then publish through
  `NativeFile` with a receipt. Every knob is a process environment variable
  (`VOT_FETCH_CAPABILITY`, `VOT_FETCH_HOLDER_KEY`, `VOT_FETCH_SERVE_IDENTITY`,
  `VOT_FETCH_RAILS`, `VOT_FETCH_STATS`), which a long-lived app with two
  transfers in flight cannot use. The fetch already has a placed-bytes
  callback (`BundleFetcher::report_placed`, which the CLI uses to print a
  line every 256 MiB); the push has none, and neither is reachable
  without the environment variables.
- Platform support: `vot-platform-fs`, `vot-platform-net`, and
  `vot-sdk-file` carry Linux, macOS, and Windows code; CI tests the
  platform crates on `windows-2025` and `macos-15` and compiles
  `vot-sdk-file` there through `cargo check -p vot-cli`. The wire feature (quiche plus
  BoringSSL through cmake and nasm) is compiled only on Linux in CI. The
  `nix` dependency of the live transport is a Linux-only target dependency
  and the send and receive paths carry `cfg(not(target_os = "linux"))`
  arms, so the code is written for the other two platforms; whether it
  builds there is measured below.
- Resume granularity. A push session publishes nothing until every
  object has completed (`docs/native-push.md` step 4); when the
  connection drops, the receiver removes its staging, the session, and
  the ticket once every rail thread has returned, which for a vanished
  peer is the transport's 30 s idle timeout; until then the ticket still
  admits joining rails and the session holds its link slot. After that a
  re-dial with the same capability is refused as spent.
  The sink factory's skip (`find_delivered`) covers only files from
  earlier fully recorded uploads. A cut push therefore restarts the
  package. The HTTP session resumes per file at the checkpointed prefix
  and survives a server restart (PR #132). A fetch resumes per range
  within an object through `vot-resume`, within its capability's one-hour
  lifetime (`CAPABILITY_TTL_SECS` in `api/serve.rs`); every unexpired
  undelivered ticket counts against `max_downloads`, so a re-mint is a
  second reservation.

Reference sender behaviour the core must match, from `upload.js` and
`upload-entries.js`: dotfiles refused unless `allow_hidden`, `~` and
reserved names refused, fold-collision paths refused at pick time, 20,000
entries cap, one package per drop, all files hashed before any send.

## Decisions

### 1. One Rust core, two native shells, one CLI

The core is a Rust crate, `votport-core`, exposed through UniFFI. macOS
gets a SwiftUI app that links the core as a Swift package. Windows gets a
WinUI 3 app in C# that links the core through `uniffi-bindgen-cs`. The CLI
is a Rust binary on the same crate. Every view model (the transfer list,
per-file states, the rate and ETA, the error copy) is computed in Rust and
handed to the shell as plain records over a change stream, so the shells
contain no transfer logic, no rate math, and no copy strings. A shell is a
few screens of layout plus the platform integrations a Rust crate cannot
own: drag and drop, notifications, the menu bar item and the tray icon,
the URL scheme registration, code signing, and updates.

Alternatives, and why they lose:

- One GPU-rendered Rust UI (gpui, Slint, iced, egui). One codebase, fast,
  and it looks the same everywhere, which is the problem: "native" in the
  brief means the platform's own controls, text rendering, accessibility
  tree, and window behaviour. A facility Mac user notices a non-native
  file dialog and a non-native menu bar in the first minute. Slint also
  needs a commercial licence decision for a proprietary app. If a third
  platform ever matters (Linux desktops in a facility), Slint is the
  candidate for that shell alone.
- Tauri or any web view. Excluded by the brief. It would also carry the
  web sender's per-file session model and wasm hashing, which are the
  ceilings the native app exists to remove.
- C or C++ core with native shells. Everything the core needs (VOT, the
  receipt crates, SQLite, rustls) is Rust already; a second language for
  the core would be a port, not a saving.

### 2. QUIC first, HTTP fallback, decided per transfer by a probe

Every transfer starts over HTTPS (the link info and the password gate
are HTTP either way). When the link reports `push`, the core reads the
push address and certificate digest from `GET /api/push-identity`; when
the grant carries a `fetch` object, it reads them from there. Before any
preflight or mint, it probes that UDP address with one QUIC handshake
against the digest, budget 2 s. A handshake that completes selects the
VOT path and only then does the core preflight or mint. A timeout or a
refused handshake selects HTTP for that transfer and records
`transport: http` with the reason in the transfer log, so the operator
sees "UDP blocked" rather than "slow". The order matters: a push
preflight registers a session that holds a per-link slot and reserved
bytes until its idle expiry and then records an interrupted event, and a
fetch mint reserves a delivery against `max_downloads`, so neither is
spent on a path the probe has not proven. If the push cannot open after
a successful preflight, the core sends `POST /api/session/{sid}/abort`
before it opens the HTTP session. The choice is per transfer and re-probed on the next
one; there is no sticky setting, only an override in Settings for a
facility that knows its firewall.

The HTTP fallback is the exact session API `upload.js` speaks and the
`/api/s/{token}/batch` and per-file routes for receive. It is not a second
protocol; the web client already proves it against every server change.

### 3. Send without copying: hash in place, manifest only

The core never runs `build_bundle`. It walks the drop, hashes every file
in place with the same leaf-aligned segmentation the web sender uses for
files of 64 MiB and more (proof leaves per 64 KiB group, segments across a
pool of `min(8, cores - 1)` workers), and keeps the leaves. From the roots
it builds the manifest pages and seal into a small manifest directory
under the app's state directory and assembles a `BundleServer` from
`ServedSource { path: <original file>, leaves }` for every entry. Every
entry is a direct object; there are no packs, because votport refuses
packed entries on both receive paths. The push then serves the original
files where they sit. The only bytes written on the sender are the
manifest and a leaves cache next to the state, never a copy of the
payload.

The leaves cache is keyed by path, length, and mtime, so a re-send of the
same sequence (a corrected shot in a folder that was already sent) hashes
only the changed files and the receiver's dedupe skips the rest at the
manifest hook, exactly as the browser's `find_delivered` path does.

Hashing runs before the transfer opens, as the web sender does since
#166, because the preflight binds the package root. Hashing at wire speed
is the budget: BLAKE3 on the pool is bounded by the source disk, so on a
NAS the hash pass costs about one read of the payload. Overlapping hash and
send (announce entries as their roots settle) is a VOT manifest change and
is not in version one; the doc notes it as the upgrade if a facility's
first complaint is the hash pass.

### 4. Resume, stated per transport

| Path | Unit of resume | Survives |
| --- | --- | --- |
| Push (QUIC), version one | Package. A cut push restarts from the first object; only files from earlier fully recorded uploads dedupe. | A brief stall within QUIC's own loss recovery. Not an app quit, not a reboot, not a network change, not a server restart. |
| Push (QUIC), after phase C3 | Object. Staging is keyed by link, package root, and holder key and survives a disconnect; once the old session is gone, a re-preflight for the same three adopts it and the sink factory skips objects whose staged bytes are complete and verified. | App quit, reboot, network change, and the ticket's expiry (the re-preflight mints a new one). Server restart still ends the session; the boot sweep keeps staging a live link can adopt and the next preflight adopts it. |
| HTTP session | File, at the checkpointed prefix. | App quit, reboot, server restart (PR #132). |
| Fetch (QUIC) | Range within an object, through `vot-resume`, within the capability's hour. After the hour a re-mint is a new reservation against `max_downloads`. | App quit, reboot, and a server restart within the hour (the ticket is warmed at boot). |
| HTTP receive | Byte range per file. | Everything; it is a GET with `Range`. |

Version one's push therefore resumes nothing across a disconnect, and
the transfer log says so ("connection lost, package restarted"). The
capability's expiry (`VOTPORT_SESSION_IDLE_SECS`, 1800 s by default,
returned as `expires_at`) is checked at admission only, so a push that
stays connected completes however long it runs; the exposure is a
disconnect, and version one restarts the package rather than routing
large drops over HTTP, because the HTTP path is the browser's speed and
the point of the app is the other one. Phase C3 lands before the shells
ship and is receiver work in votport. Today the receive's drop removes
the staging directory and the ticket, and staging is keyed by session
id, so nothing outlives a disconnect. C3 keys staging by link, package
root, and holder key, keeps it across a disconnect and a server restart
(the boot sweep in `paths::clean_staging` keeps push staging a live
link can still adopt and removes the rest; the reserved-name guard
moves to the new key's shape), and lets a new preflight for the same
three adopt it, so the ticket's lifetime is not the load-bearing part:
the capability expiry is fixed at mint as the idle window and cannot be
refreshed while bytes move, so a 500 GB push that reboots after forty
minutes re-preflights, receives a fresh capability, and re-dials into
the same staging. Two constraints come from the code. The old session
must be gone first: VOT keys its shared plan by the staging directory,
so rails of a new preflight into a directory whose session is still
draining would join the dying plan and be abandoned with it; the core
therefore aborts the cut session (`POST /api/session/{sid}/abort`) and
C3 refuses a preflight whose staging still has a live session. And a
skipped object never reaches the completion hook, so the C3 sink
factory runs the destination open and the staged re-prove itself
before answering skip, and the kept staging includes VOT's `resume.vot`
marker, without which the engine refuses the directory. And VOT opens
whatever already sits at `objects/<root>` before it calls the factory
and unlinks that file by handle after the factory answers, so a re-sent
incomplete object is staged under a fresh name, and a skipped object's
bytes survive only in the destination staging the re-prove filled,
until publish; a second disconnect after that drops the unpublished
destinations and the object is sent again. The factory then skips
every object whose staged bytes are complete and verified, and the
core sends the rest. Within-object resume is the
later VOT item: the receiver's `HAVE` frame already describes verified
64 KiB group coverage within one object (`spec/object.md` section 10) and
has no implementation outside the codec; implementing it on the push
receiver lets a re-dialled push skip covered groups.

The core persists every transfer in a SQLite journal in the state
directory: the drop (paths, lengths, mtimes, roots, leaves file), the
link, the transport chosen, the session or capability, per-object state,
and the log. On launch the core resumes every transfer that was in flight
without asking; the shell shows them as "resuming".

### 5. Identity and credentials

- A device key: one Ed25519 holder key per install, generated at first
  launch, stored in the macOS Keychain, the Windows Credential Manager, or
  a mode 600 file under the state directory on Linux. Its public half is
  the `holder_key` in every preflight and mint. It is not an account and
  names nothing; it is what binds a capability to this machine.
- Per transfer, a capability minted by the server for that package root
  (push) or that grant (fetch), held in memory and in the journal only
  until the transfer ends. Expiry is the server's: the link's idle window
  for a push, one hour for a fetch.
- Link passwords are asked once per link and kept in the platform keychain
  keyed by link token, so a second send to the same request does not ask
  again. The core never writes a password to the journal.
- The server's push and serve certificate digests are pinned per transfer
  from the preflight response, as the CLI pins `VOT_FETCH_SERVE_IDENTITY`.
- Receipts are a receive-side artefact: they arrive with every received
  package, are stored beside the files as the web recipient page does,
  and the app verifies them against `/api/receipt-key` and shows the
  result on the done card. A sender gets no receipt. Over HTTP the
  finish report carries the upload id, each file's object root, and a
  per-file flag saying a sidecar was written; over push the sender gets
  only the receiver's final cursor. The send done card shows the package
  root the core computed, and the upload id and per-file flags when the
  HTTP path supplied them.

### 6. Design language

The shells use the platform toolkit and the votport tokens. Colours,
spacing, and type come from one file, `client/design/tokens.json`,
generated from the `:root` and light blocks of `web/assets/style.css` by a
script under `scripts/`, so the web and the apps cannot drift: the same
`--bg`, `--progress` (#38bdf8), `--ok`, `--danger`, the same light values,
the same accent override from tenant branding. Type is Plus Jakarta Sans
for text, JetBrains Mono for hashes and paths, Libre Caslon Display for
the wordmark only; the fonts ship in the app bundle under the OFL. Every
screen has one primary action. The sender screen is the drop target, the
recipient screen is the destination picker, and the transfer list is the
whole rest of the app. Per-file states are the web sender's (hashing,
sending, landed, verified, skipped as already delivered, failed with the
human copy from `docs/sender-identity.md`). Rates are honest: a moving window
over placed bytes, the ETA hidden until the rate is stable for ten
seconds, the hash phase and the send phase shown as two rates, never one
blended number. Motion follows the platform's reduce-motion setting. No
highlight borders anywhere; a selected transfer expands.

## Architecture

### Repository layout

```
client/
  core/            votport-core: the Rust crate, its own workspace like server/
    Cargo.toml     [workspace] empty, VOT git deps at the server's pin
    src/
      api.rs       HTTPS client for the routes above (reqwest, rustls)
      identity.rs  device key, keychain adapters, link password store
      hash.rs      in-place leaf hashing pool, leaves cache
      package.rs   drop walk, entry rules, manifest builder
      transfer.rs  the transfer state machine and observer
      send.rs      push path and HTTP session path
      receive.rs   fetch path, HTTP path, publish with receipt
      probe.rs     the UDP handshake probe
      journal.rs   SQLite persistence and resume at launch
      watch.rs     watch folders (notify crate), debounce, one drop per settle
      verify.rs    receipt verification
      ffi.rs       the UniFFI surface: commands in, change stream out
    votport_core.udl
  cli/             votport: send, receive, verify, watch, status; JSON lines
  macos/           Xcode project, SwiftUI, the generated Swift package
  windows/         Visual Studio solution, WinUI 3, C#, the generated bindings
  design/          tokens.json (generated), app icons, fonts
```

`client/core` mirrors `server/Cargo.toml`: an empty `[workspace]` so it
never joins a surrounding workspace, the quiche patch, and the VOT git
dependencies at the same revision as the server. The repin procedure
gains one sync point, `client/core/Cargo.toml` and its lock. Cargo target
directories under `client/` follow the `target-*` naming and go into
`.dockerignore` with the server's, so an image build never ships them.

### The transfer state machine

One `Transfer` per drop or per grant, driven by a core thread pool, never
by the shell's main thread:

```
Queued -> Hashing -> Probing -> Preflight -> Sending{Push | Http}
       -> Completing -> Done
any    -> Paused (user) | Failed(reason) | Cancelled
Paused -> Hashing | Sending (resume from journal)
```

Receive is the same shape with `Fetching{Quic | Http}` and `Publishing`
in place of the send states. Every state change and every progress tick
(placed bytes, per-object completion, rail count, FEC counts) goes through
one observer trait implemented once by the journal writer and once by the
FFI change stream; the CLI's JSON lines are the same stream printed. Ticks
are coalesced to ten per second before they cross the FFI.

### Send, step by step

1. The shell hands the core a list of dropped paths and a link URL. The
   core resolves the token from the URL (`/r/{token}`), fetches
   `GET /api/r/{token}`, and applies the entry rules; a refused entry is
   reported before anything else happens, as the web sender does.
2. Password gate if `needs_password` and no keychain entry:
   `POST /api/r/{token}/verify`.
3. Hash in place on the pool; leaves cached; manifest written to the
   state directory; package root and length known.
4. If `push` is true: the probe against the address and digest from
   `GET /api/push-identity`. If it completes, `POST /api/r/{token}/push`
   with the holder key and the package descriptor, then
   `push_from(assembled server, options)` with rails `min(cores, 4)` and
   the observer (four, because the push listener admits eight sessions
   in total and a rail is a session; VOT change 6 lifts this). If the probe fails, or `push` is false, the HTTP
   session:
   `POST /api/r/{token}/session`, seal, pages, begin, chunks with the
   server's `chunk_bytes` and parallel ranges, finish. The HTTP finish
   report and the push's completed cursor both end the transfer; the core
   records the package root it computed and, on the HTTP path, the upload
   id and the per-file receipt flags in the journal, and shows them on
   the done card.
5. On a cut connection over HTTP the core retries the same session with
   backoff and resumes per file. Over push the receiver keeps the cut
   session until its rails time out (30 s) and the ticket admits joiners
   until then, so the core first sends `POST /api/session/{sid}/abort`
   for the cut session, then re-preflights. In version one that restarts
   the package; after C3 the re-preflight adopts the surviving staging
   and only the incomplete objects move.

### Receive, step by step

1. The shell hands the core a grant URL and a destination directory.
   `GET /api/s/{token}`; password gate; the core checks the destination
   for the free space the grant's `total_bytes` needs and refuses early.
2. If the `fetch` object is present: the probe against `fetch.address`
   and `fetch.certificate_digest`, then `POST /api/s/{token}/fetch` with
   the holder key, then `fetch_bundle_with(FetchOptions)` into a staging
   directory beside the destination on the same filesystem (so publish is
   a rename), then `receive_bundle`-equivalent publication through
   `NativeFile` with the receipt and the observed time. The final-cursor
   acknowledgement is sent by the fetch path, so the delivery counts
   against `max_downloads` (ADR-0050).
3. Otherwise HTTP: `/api/s/{token}/batch` for many small files, per-file
   GETs with `Range` for large ones, four in flight, each verified against
   its root as it lands, then the same publication.
4. Receipt verification against `/api/receipt-key`; the done card shows
   the package root, the receipt, and a Reveal in Finder or Show in
   Explorer action.

### Speed budget

- Hash: BLAKE3 on `min(8, cores - 1)` workers reading 16 MiB segments,
  bounded by the source disk; native on an M-series or a desktop Ryzen
  should read at the disk's rate (2 to 7 GB/s on NVMe, the NAS's rate on
  a NAS). Measure on the Studio and the Windows desktop in C1.
- Push: four rails in version one (eight after VOT change 6), sixteen
  objects in flight (ADR-0051), FEC automatic,
  the sender's per-byte cost is the read plus AES-GCM. The single-transfer
  ceiling is a per-byte copy cost inside quiche and BLAKE3, the same one
  the server's fetch path has; 40 GbE per transfer is not on the table
  for version one. The loopback and LAN numbers for the client are
  measured in C1 on the two target machines against erebus.
- Memory: no whole-object buffers anywhere; the core's resident set is the
  rails' windows plus the hash segments, under 512 MiB at eight rails.
- UI: the change stream is coalesced, the transfer list is virtualised,
  and a 20,000-entry drop renders in the shell as one row per top-level
  folder with per-file detail on expand.

### The shells

macOS (`client/macos`): SwiftUI, one window with a sidebar (Send, Receive,
Transfers, Settings), a drop target that accepts files and folders from
Finder and the clipboard, a menu bar item with the active transfers and
their rates, `UNUserNotificationCenter` for done and failed, a `votport://`
URL scheme so the web pages can offer "Open in the app" for a request or
deliver link, Sparkle for updates in a later phase, Developer ID signing
and notarization in CI. Minimum macOS 14. The core ships as an XCFramework
with the generated Swift package.

Windows (`client/windows`): WinUI 3 on the Windows App SDK, C#, Mica
backdrop, the same four sections, drop from Explorer, a tray icon with
the active transfers, toast notifications, the `votport:` protocol
registered by the MSIX manifest, MSIX packaging with a code-signing
certificate. Minimum Windows 10 22H2. The core ships as a DLL with the
generated C# bindings.

CLI (`client/cli`): `votport send <link> <path>...`, `votport receive
<link> <dest>`, `votport verify <receipt> <file>`, `votport watch <dir>
<link>`, `votport status`. Every command prints JSON lines on `--json`
(the change stream verbatim) and a human progress line otherwise. The
Linux build is the agent's base and the facility's headless watch folder.

Operator mode (phase C8, every shell and the CLI): sign in to a votport
with the admin password (`POST /api/admin/login`, the same session
cookie the browser holds) and then use the Receive, Deliver, and library
screens the admin pages have, over the same JSON routes, so the
password path needs no new server surface: create a request link and
send it, issue a deliver grant from the library or from a folder the app
uploads, watch transfers land. Mutating admin routes also require the
`X-Votport` header, which the core sends. SSO needs a small server
addition, because the OIDC callback (`/api/admin/callback`) reads the
state cookie set by `/api/admin/sso/start`, so it must land in the
browser that started it: three touches, a flag on the start route
carried in the signed state, a branch in the callback that redirects to
`votport://signin/<one-time code>` instead of the admin page, and an
exchange route that turns the code into the admin cookie within a
minute. The CLI signs in with the password; an automation token serves
only scripted grant creation on `/api/automation/share`. Tenant
switching follows the admin session's tenant.

### votport server changes

- The recipient page and the sender page get an "Open in the votport app"
  link (`votport://r/{token}`, `votport://s/{token}`) shown when the page
  detects a desktop platform; nothing else on the server changes for
  version one. Push and serve are already there; erebus needs the UDP
  ports mapped and advertised for either QUIC path to be live (both
  listeners are unbound in production today).
- Phase C8, operator mode: the admin routes over the cookie session plus
  the SSO handoff above. Automation tokens stay the scripted path
  (`share` today, `fetch` for scripted pulls once the agent design lands).

## VOT changes (phase C0)

Each is an upstream PR gated on mutants and the public API snapshot, then
one votport repin across the server, the client, and the docs.

1. `build_manifest(source, manifest_root, suite) -> (PackageSummary,
   BTreeMap<[u8; 32], ServedSource>)`: the walk and entry rules of
   `build_bundle`, no packs (every entry a direct object, which is what
   votport accepts), every file hashed in place with its leaves written
   to a cache the caller names, and returned as a `ServedSource` instead
   of being copied. `build_bundle` stays for the CLI. The proof cache
   writer (`package/proof_cache.rs`) becomes public for the leaves cache.
2. `push_from(server: &BundleServer, options: PushOptions) ->
   Result<PackageSummary, Error>` with `PushOptions { address, holder:
   Arc<authz::Holder>, identity: [u8; 32], rails, extensions, progress:
   Option<(u64, Progress)> }`, where `Progress` is a boxed `FnMut(u64,
   Option<u64>)`. `push_bundle` becomes `open` plus this. Push progress is
   the sum over rails of the bytes the carriers have taken, framing
   included, with no total, because a sender does not know how much of what
   it offers the receiver will ask for. Object completions on the sender
   are a later seam.
3. `fetch_bundle_with(options: FetchOptions, bundle: &Path) ->
   Result<PackageSummary, Error>` with `FetchOptions { address, holder:
   Option<Arc<authz::Holder>>, serve_identity, pin, rails, provers,
   extensions, progress }`, replacing the environment variables for library
   callers (item 5 of `docs/deliver-over-quic.md`). The existing
   `BundleFetcher::report_placed` callback feeds the progress observer,
   which reports placed bytes and the package length once known.
4. The `platform-native` CI job compiles `vot-cli` with the wire feature
   on `windows-2025` and `macos-15` (cmake and nasm on both, LLVM for
   bindgen on Windows), and runs the live loopback tests there with the
   65507-byte datagram assertion gated to Linux, where loopback carries
   it. Today the wire feature is built only on Linux in CI; the table
   below is the first off-Linux evidence.
5. Second wave, after the client moves bytes: push resume within an
   object through `HAVE` coverage on the push receiver (decision 4). The
   session-level half of push resume (staging keyed by link, root, and
   holder, kept across a disconnect, adopted by a new preflight, skip of
   complete staged objects) is votport work in phase C3 and needs no VOT
   change.
6. The push listener's concurrent-session cap (`CONCURRENT_SESSIONS`,
   eight, in the accept loop) counts rails, so one client at eight rails
   fills the listener; a second transfer's or a second machine's rails
   then wait in the listener's eight-deep accept backlog and a ninth is
   dropped. The probe cannot see this, because its handshake completes
   before accept. The cap becomes a per-peer cap plus
   a larger global one that the receiver sets (mirroring item 6 of the
   serve seam in `docs/deliver-over-quic.md`), so a client can use eight
   rails without starving the next. Until it lands the client uses four.

## Platform build status

The wire feature was built at the pinned revision on the two target
machines on 2026-09-04, `cargo +1.97.1 build -p vot-cli --features wire
--release --locked`:

| Machine | Result |
| --- | --- |
| Mac Studio, macOS 26.6, Apple silicon, Xcode 26.6, rustup 1.97.1, cmake from pip | Builds: 67 s clean release build of `vot-cli` with BoringSSL. `vot-transport-quiche --features live` tests: 103 of 104 pass. The failure is `a_pair_carries_records_at_a_datagram_size_the_path_allows`, which asserts discovery reaches a 65507-byte datagram on loopback; macOS `lo0` has MTU 16384 and discovery settled at 16356, so the transport is right and the test assumes Linux loopback. The pump also warns that the UDP receive buffer is 8 MiB against the 16 MiB it asks for (`kern.ipc.maxsockbuf`), an operator sysctl for the tuning doc. |
| Windows 11 desktop (26200), MSVC from Visual Studio 2022, cmake 4.2, nasm and LLVM 22 via winget, rustup 1.97.1 | Builds: BoringSSL through the Visual Studio generator, bindgen through `LIBCLANG_PATH`, `vot-cli.exe` in 32 s after the BoringSSL step. `vot-transport-quiche --features live` tests: 104 of 104 pass. |

## CI and distribution

- A `client` job on `ubuntu-24.04` runs fmt, clippy at deny warnings, and
  the core's tests including an e2e that starts a votport from the same
  checkout and sends and receives over both paths on loopback. It is
  path-filtered to `client/**` and the VOT pin, so a server-only PR never
  runs it, and the server jobs are path-filtered away from `client/**`.
- The shells build on `macos-15` and `windows-2025` runners only on tags
  and on PRs that touch their directories. GitHub bills macOS minutes at
  ten times Linux and Windows at two; the Mac Studio and the Windows
  desktop can be self-hosted runners for the shells, as VOT already uses
  a self-hosted storage runner. David's call.
- Releases: a tag builds the CLI for Linux x86_64 and aarch64, macOS
  universal, and Windows x86_64; the macOS app as a notarized DMG; the
  Windows app as a signed MSIX. Versions follow the server's.

## Open questions David owns

1. Apple Developer ID and a Windows code-signing certificate; without
   them the builds run but users see the unsigned-app warnings.
2. Whether erebus maps the push and serve UDP ports (both listeners are
   unbound in production), which decides whether the pilot's app runs
   QUIC or the HTTP fallback against the live box.
3. Self-hosted runners on the Studio and the Windows desktop, or paid
   GitHub minutes for the shells.
4. Minimum OS versions (macOS 14, Windows 10 22H2 proposed).
5. Whether the sender app keeps link passwords in the keychain (proposed
   yes, per link) or asks every time.

## PR plan

| Phase | Repo | Content | Done when |
| --- | --- | --- | --- |
| C0 | VOT | `build_manifest`, `build_manifest_from`, `push_from`, `fetch_bundle_with`, `probe_serve`, progress observers, wire on the platform-native job (the listener session cap is a follow-on) | Loopback push from an assembled server and fetch with options pass on Linux, macOS, and Windows in CI (landed, pin `0a129ea`) |
| C1 | votport | `client/core` and `client/cli`: api, identity, hash, package, transfer, send over push and HTTP, journal, e2e on loopback | `votport send` moves a 20,000-entry drop and a 4 GiB file over both paths on all three platforms; the HTTP path resumes after a kill; hash and transfer rates recorded on the two target machines |
| C2 | votport | Receive over fetch and HTTP, publish with receipt, verify | `votport receive` publishes a grant with a verified receipt and the delivery counts on the server |
| C3 | votport | Push resume on the receiver: staging keyed by link, package root, and holder key, kept across a disconnect and by the boot sweep, adopted by a new preflight once the old session is gone, sink factory re-proves and skips complete staged objects; the core aborts the cut session, re-preflights, and re-dials | A push killed at 90% of a 20,000-entry drop, resumed after the ticket expired and after a server restart, finishes by sending only the objects that were not complete |
| C4 | votport | macOS app | Send and receive from Finder drops, notarized DMG from CI, the design review against the web pages |
| C5 | votport | Windows app | Same, signed MSIX |
| C6 | votport | Watch folders, "Open in the app" links, updates | A facility watch folder sends every settled drop unattended for a week on the soak rig |
| C7 | VOT then votport | Push resume within an object | A killed 200 GB single-file push resumes at the last verified group |
| C8 | votport | Operator mode: sign in (password and SSO), request links, deliver grants, library, transfers landing live | An operator runs a facility day from the app without opening the web admin |

Measurements before and after each phase run on erebus and between the
Studio and erebus over the wired LAN.

## Risks

- BoringSSL through cmake on Windows and macOS had never been built off
  Linux here before 2026-09-04. It builds on both, with the runner
  prerequisites the table names (cmake and nasm everywhere, LLVM for
  bindgen on Windows). The CI job in VOT change 4 pins those installs so
  the result stays true; msquic (`vot-transport-msquic`) stays the
  fallback carrier if a future quiche bump breaks a platform.
- UniFFI's C# generator is third party (`uniffi-bindgen-cs`, maintained by
  NordSecurity). If it lags a UniFFI release, the Windows shell pins the
  older UniFFI; the core's surface is small enough to hand-write a C ABI
  if it ever has to.
- Two shells is two places to break. The mitigation is the rule that a
  shell holds no logic: a behaviour bug is a core bug with one fix.
- The hash pass before the first byte is visible on a NAS at 1 GbE (a
  100 GB sequence hashes for fifteen minutes before sending). The upgrade
  is the overlapped manifest in decision 3; it needs a VOT change and is
  not promised for version one.
- Facility firewalls that block UDP make every transfer HTTP, which is the
  browser's speed. The probe makes that visible in the transfer log and
  the operator doc gets a one-line firewall rule for the push and serve
  ports.
