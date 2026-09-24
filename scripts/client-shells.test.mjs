import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

// The shells cannot be built on the CI runner, so this checks that the core,
// the XcodeGen project, the Windows manifests and both build scripts carry
// one version.

const read = (path) => readFile(new URL(`../${path}`, import.meta.url), 'utf8');

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

