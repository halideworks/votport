import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

// Source-level assertions on the two shells and their build scripts, in the
// style of notification-sound.test.mjs: the surfaces cannot be built on the
// CI runner, so the pins hold the shape the findings asked for. The Rust
// side carries the functional coverage (e2e_ffi's re-asked-folder scenario,
// journal's set_dest test).

const read = (path) => readFile(new URL(`../${path}`, import.meta.url), 'utf8');

test('transfer notifications show banner and sound while the app is frontmost, with permission asked at launch', async () => {
  const notifier = await read('client/macos/Votport/Notifier.swift');
  assert.match(notifier, /UNUserNotificationCenterDelegate/);
  const willPresent = notifier.match(
    /willPresent notification[\s\S]*?withCompletionHandler completionHandler[\s\S]*?\{[\s\S]*?\n        \}/,
  );
  assert.ok(willPresent, 'the delegate implements willPresent');
  assert.match(willPresent[0], /completionHandler\(\[\.banner, \.sound\]\)/);
  // Permission belongs to launch, not to the first transfer's end.
  assert.match(notifier, /static func start\(\)[\s\S]*?requestAuthorization/);
  const transferEnded = notifier.match(/static func transferEnded[\s\S]*?\n    \}/)[0];
  assert.ok(transferEnded, 'transferEnded exists');
  assert.doesNotMatch(transferEnded, /requestAuthorization/);
  const app = await read('client/macos/Votport/VotportApp.swift');
  assert.match(
    app,
    /applicationDidFinishLaunching[\s\S]*?Notifier\.start\(\)/,
    'launch installs the notification delegate and asks once',
  );
});

test('retrying a journalled receive re-asks for the folder instead of re-running the refusal', async () => {
  // macOS: the card opens a folder picker seeded with the journalled folder
  // and the chosen folder crosses the FFI as dest.
  const card = await read('client/macos/Votport/TransfersView.swift');
  assert.match(card, /item\.kind == \.receive[\s\S]*?NSOpenPanel\(\)/);
  assert.match(card, /canChooseDirectories = true/);
  assert.match(card, /directoryURL = URL\(fileURLWithPath: item\.subject\)/);
  assert.match(card, /destination: folder/);
  const macStore = await read('client/macos/Votport/TransferStore.swift');
  assert.match(
    macStore,
    /func resume\(_ id: UUID, password: String\?, destination: URL\?\)[\s\S]*?VotportCore\.resume\(\s*id: journalId, password: password, dest: destination\?\.path,/,
  );
  // Windows: the card opens a FolderPicker for a receive; the tray resume
  // keeps the journalled folder.
  const page = await read('client/windows/Votport/TransfersPage.xaml.cs');
  assert.match(page, /item\.Kind == TransferItem\.Kinds\.Receive[\s\S]*?new FolderPicker\(\)/);
  assert.match(page, /PickSingleFolderAsync/);
  const winStore = await read('client/windows/Votport/TransferStore.cs');
  assert.match(winStore, /Resume\(TransferItem item, string\? password, string\? destination = null\)/);
  assert.match(winStore, /VotportClientCoreMethods\.Resume\(id, password, destination, transfer, listener\)/);
  const tray = await read('client/windows/Votport/TrayPanel.xaml.cs');
  assert.match(tray, /Resume\(item, null\)/);
  // The core keeps the answer: the words stay honest and the run journals
  // the folder it was given.
  const error = await read('client/core/src/error.rs');
  assert.match(error, /is already in that folder\. Choose an empty one\./);
  const ffi = await read('client/core/src/ffi.rs');
  assert.match(ffi, /pub fn resume\(\s*id: String,\s*password: Option<String>,\s*dest: Option<String>,/);
  assert.match(ffi, /journal::set_dest\(&entry\.id, &dest\)/);
});

test('one version rules the core, the XcodeGen project, and the Windows manifests', async () => {
  const core = await read('client/core/Cargo.toml');
  const version = core.match(/^version = "(.+)"$/m)[1];
  const fourPart = `${version}.0`;
  const project = await read('client/macos/project.yml');
  assert.match(project, /MARKETING_VERSION: "(.+)"/);
  assert.equal(project.match(/MARKETING_VERSION: "(.+)"/)[1], version, 'project.yml drifts from the core');
  const manifest = await read('client/windows/Votport/app.manifest');
  assert.equal(
    manifest.match(/assemblyIdentity version="([\d.]+)"/)[1],
    fourPart,
    'app.manifest drifts from the core',
  );
  const appx = await read('client/windows/Votport/Package.appxmanifest');
  assert.equal(appx.match(/Identity [^>]*Version="([\d.]+)"/)[1], fourPart, 'Package.appxmanifest drifts from the core');
  // The build scripts are the writers, so a future version moves all three.
  const macScript = await read('client/macos/build-core.sh');
  assert.match(macScript, /version=\$\(sed -n 's\/\^version = ".*\$\/\\1\/p' core\/Cargo\.toml \| head -1\)/);
  assert.match(macScript, /MARKETING_VERSION/);
  const winScript = await read('client/windows/build-core.ps1');
  assert.match(winScript, /core\\Cargo\.toml/);
  assert.match(winScript, /app\.manifest/);
  assert.match(winScript, /Package\.appxmanifest/);
});

test('the macOS core ships both Apple architectures and Windows knows its ARM64 target', async () => {
  const macScript = await read('client/macos/build-core.sh');
  assert.match(macScript, /--target aarch64-apple-darwin/);
  assert.match(macScript, /--target x86_64-apple-darwin/);
  assert.match(macScript, /lipo -create -output "\$universal\/libvotport_client_core\.a"/);
  assert.match(macScript, /lipo -create -output "\$universal\/votport"/);
  assert.doesNotMatch(macScript, /release concern, later/);
  const winScript = await read('client/windows/build-core.ps1');
  assert.match(winScript, /\[ValidateSet\("x64", "arm64"\)\]\[string\]\$Arch = "x64"/);
  assert.match(winScript, /aarch64-pc-windows-msvc/);
  const project = await read('client/windows/Votport/Votport.csproj');
  assert.match(project, /<RuntimeIdentifiers>win-x64;win-arm64<\/RuntimeIdentifiers>/);
  assert.match(project, /Generated\\arm64\\votport_client_core\.dll/);
  // The release step that produces the ARM64 package is written down.
  const doc = await read('docs/desktop-client.md');
  assert.match(doc, /build-core\.ps1 -Arch arm64/);
  assert.match(doc, /win-arm64/);
});

test('the unpackaged uninstall removes the protocol command, the Run entry and the toast AUMID', async () => {
  const protocol = await read('client/windows/Votport/Protocol.cs');
  const unregister = protocol.match(/public static void UnregisterIfUnpackaged\(\)[\s\S]*?\n    \}/)[0];
  assert.ok(unregister, 'the uninstall entry point exists');
  assert.match(unregister, /DeleteValue\("Votport", throwOnMissingValue: false\)/);
  assert.match(unregister, /UnregisterForProtocolActivation\("votport"/);
  assert.match(unregister, /DeleteSubKeyTree\(\@"Software\\Classes\\votport"/);
  assert.match(unregister, /DeleteSubKeyTree\(\$\@"Software\\Classes\\AppUserModelId\\/);
  // Wired as a destructive control with a confirm, beside Remove local data.
  const page = await read('client/windows/Votport/SettingsPage.xaml.cs');
  assert.match(page, /Uninstall_Click[\s\S]*?ContentDialog \{[\s\S]*?CloseButtonText = "Cancel"/);
  assert.match(page, /ContentDialogResult\.Primary\) Protocol\.UnregisterIfUnpackaged\(\)/);
  assert.match(await read('client/windows/Votport/SettingsPage.xaml'), /x:Name="UninstallButton"/);
});

test('the tray indicators separate failure from idle and show moved over total', async () => {
  // macOS: the menu bar glyph carries the last outcome and the Dock the fraction.
  const macStore = await read('client/macos/Votport/TransferStore.swift');
  const symbol = macStore.match(/var menuBarSymbol: String \{[\s\S]*?\n    \}/)[0];
  assert.ok(symbol, 'menuBarSymbol exists');
  assert.match(symbol, /active\.isEmpty \{ return "sailboat\.fill"/);
  assert.match(symbol, /last\.interrupted \|\| last\.view\?\.phase == \.failed \? "exclamationmark\.triangle" : "sailboat"/);
  const dock = macStore.match(/private func updateDockTile\(\)[\s\S]*?\n    \}/)[0];
  assert.ok(dock, 'the Dock progress update exists');
  assert.match(dock, /moved \+= item\.view\?\.movedBytes \?\? 0/);
  assert.match(dock, /total \+= item\.view\?\.totalBytes \?\? 0/);
  // The Dock fraction itself uses an API newer than the SDKs the shell
  // builds against; the badge draw is what every SDK carries.
  assert.match(dock, /NSApp\.dockTile\.display\(\)/);
  assert.match(macStore, /items\[index\]\.view = view\n        updateDockTile\(\)/);
  assert.match(macStore, /handles\[id\] = nil\n        updateDockTile\(\)/);
  const app = await read('client/macos/Votport/VotportApp.swift');
  assert.match(app, /Image\(systemName: store\.menuBarSymbol\)/);
  assert.doesNotMatch(app, /store\.active\.isEmpty \? "sailboat" : "sailboat\.fill"/);
  // Windows: the tray tip carries the last outcome, the taskbar bar the fraction.
  const win = await read('client/windows/Votport/MainWindow.xaml.cs');
  const indicate = win.match(/private void Indicate\(\)[\s\S]*?\n    \}/)[0];
  assert.ok(indicate, 'the tray and taskbar update exists');
  assert.match(indicate, /FirstOrDefault\(item => !item\.Running\)/);
  assert.match(indicate, /Format\.StatusLine\(last\)/);
  assert.match(indicate, /moved \+= item\.View\?\.MovedBytes \?\? 0/);
  assert.match(indicate, /total \+= item\.View\?\.TotalBytes \?\? 0/);
  assert.match(indicate, /Taskbar\.SetProgressValue\(hwnd, moved, total\)/);
  assert.match(indicate, /TaskbarState\.NoProgress/);
});

test('every link entry path admits only a bare http or https origin (audit finding 511)', async () => {
  // The macOS and Windows shells parse votport:// links with their platform
  // URL parser; the core's split_link must hold the same line for hand
  // entered and stored links, because the base is what the transfer talks to.
  const mac = await read('client/macos/Votport/VotportApp.swift');
  assert.match(mac, /scheme == "https" \|\| scheme == "http", origin\.host != nil,/);
  assert.match(mac, /origin\.path\.isEmpty \|\| origin\.path == "\/", origin\.query == nil,/);
  assert.match(mac, /origin\.fragment == nil, origin\.user == nil, origin\.password == nil/);
  const win = await read('client/windows/Votport/WebLink.cs');
  assert.match(win, /parsed\.Scheme != "https" && parsed\.Scheme != "http"/);
  assert.match(win, /parsed\.AbsolutePath != "" && parsed\.AbsolutePath != "\/"\)/);
  assert.match(win, /parsed\.Query\.Length != 0 \|\| parsed\.Fragment\.Length != 0 \|\| parsed\.UserInfo\.Length != 0/);
  const core = await read('client/core/src/api.rs');
  assert.match(core, /fn bare_origin\(base: &str\) -> bool \{[\s\S]*reqwest::Url::parse\(base\)/);
  assert.match(core, /matches!\(url\.scheme\(\), "http" \| "https"\)[\s\S]*url\.query\(\)\.is_none\(\)[\s\S]*url\.fragment\(\)\.is_none\(\)/);
  assert.match(core, /!bare_origin\(base\)/);
});

test('editing a desktop link clears the previous preview before checking the replacement', async () => {
  const mac = await read('client/macos/Votport/LinkPreviewer.swift');
  const windows = await read('client/windows/Votport/LinkPreviewer.cs');
  assert.match(mac, /current = trimmed\s+preview = nil\s+guard !trimmed\.isEmpty/);
  assert.match(windows, /timer\.Stop\(\);\s+Preview = null;\s+if \(current\.Length == 0\)/);
});
