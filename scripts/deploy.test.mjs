import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

test('deploy builds the requested commit even when the checkout is dirty', () => {
  const root = mkdtempSync(join(tmpdir(), 'votport-deploy-test-'));
  try {
    mkdirSync(join(root, 'server'));
    mkdirSync(join(root, 'bin'));
    const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
    git('init', '-q');
    git('config', 'user.name', 'Test');
    git('config', 'user.email', 'test@example.invalid');
    writeFileSync(join(root, 'server/Cargo.toml'), 'version = "1.2.3"\n');
    writeFileSync(join(root, 'payload'), 'committed\n');
    git('add', 'server/Cargo.toml', 'payload');
    git('commit', '-qm', 'Fixture');
    const sha = git('rev-parse', 'HEAD');
    git('update-ref', 'refs/remotes/origin/main', sha);
    writeFileSync(join(root, 'server/Cargo.toml'), 'version = "9.9.9"\n');
    writeFileSync(join(root, 'payload'), 'dirty\n');
    writeFileSync(join(root, 'untracked'), 'must not ship\n');
    writeFileSync(join(root, 'docker-compose.override.yml'), '# Deployed main fixture\nservices:\n  votport:\n    image: votport-local:fixture\n');
    writeFileSync(join(root, 'bin/docker'), `#!/bin/sh
case "$1" in
  port) echo '8080/tcp -> 127.0.0.1:8103';;
  build) printf '%s\\n' "$@" > "$TEST_ROOT/build-args"; cat > "$TEST_ROOT/context.tar"; exit 77;;
  *) exit 99;;
esac
`, { mode: 0o700 });
    const result = spawnSync('bash', [new URL('./deploy.sh', import.meta.url).pathname, sha], {
      env: { ...process.env, PATH: `${join(root, 'bin')}:${process.env.PATH}`, VOTPORT_DEPLOY_REPO: root, TEST_ROOT: root, TMPDIR: root },
      encoding: 'utf8',
    });
    assert.equal(result.status, 77, result.stderr);
    const args = readFileSync(join(root, 'build-args'), 'utf8');
    assert.match(args, /VOTPORT_VERSION=1\.2\.3/);
    assert.ok(args.includes(`VOTPORT_REVISION=${sha}`));
    assert.ok(args.endsWith('-\n'));
    const archive = join(root, 'context.tar');
    assert.equal(execFileSync('tar', ['-xOf', archive, 'payload'], { encoding: 'utf8' }), 'committed\n');
    assert.doesNotMatch(execFileSync('tar', ['-tf', archive], { encoding: 'utf8' }), /untracked/);
    assert.match(readFileSync(join(root, 'docker-compose.override.yml'), 'utf8'), /image: votport-local:fixture/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// A repository whose first commit is the deployed revision and whose second
// is the one being deployed, with fake docker and curl on PATH.
function rollbackFixture(root, schemas, { publicFails = false } = {}) {
  mkdirSync(join(root, 'server/src'), { recursive: true });
  mkdirSync(join(root, 'bin'));
  const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
  git('init', '-q');
  git('config', 'user.name', 'Test');
  git('config', 'user.email', 'test@example.invalid');
  writeFileSync(join(root, 'server/Cargo.toml'), 'version = "1.2.3"\n');
  const shas = schemas.map((schema, index) => {
    writeFileSync(join(root, 'server/src/store.rs'), `pub(crate) const SCHEMA_VERSION: u64 = ${schema};\n`);
    git('add', 'server');
    git('commit', '-q', '--allow-empty', '-m', `Fixture ${index}`);
    return git('rev-parse', 'HEAD');
  });
  const sha = shas.at(-1);
  git('update-ref', 'refs/remotes/origin/main', sha);
  const before = `# Deployed main ${shas[0].slice(0, 7)} (from ${shas[0]}). Previous image: older.\nservices:\n  votport:\n    image: votport-local:audit-previous\n`;
  writeFileSync(join(root, 'docker-compose.override.yml'), before);
  writeFileSync(join(root, 'docker-compose.yml'), '      VOTPORT_PUBLIC_URL: "https://drop.example.com"\n');
  writeFileSync(join(root, 'bin/docker'), `#!/bin/sh
case "$1" in
  port) echo '8080/tcp -> 127.0.0.1:8103';;
  build) cat > /dev/null;;
  image) echo sha256:fixture;;
  compose) grep '^    image: ' "$TEST_ROOT/docker-compose.override.yml" >> "$TEST_ROOT/compose-up";;
  inspect) case "$*" in *Config.Image*) echo votport-local:audit-previous;; *) echo running;; esac;;
  exec) echo "votport 1.2.3 ($FAKE_BUILD)";;
  *) exit 99;;
esac
`, { mode: 0o700 });
  writeFileSync(join(root, 'bin/curl'), `#!/bin/sh
case "$*" in
  *https*) exit 60;;
  *readyz*) echo '{"healthy":true,"lease":{"mine":true}}';;
esac
exit 0
`, { mode: 0o700 });
  const result = spawnSync('bash', [new URL('./deploy.sh', import.meta.url).pathname, sha], {
    env: {
      ...process.env, PATH: `${join(root, 'bin')}:${process.env.PATH}`, VOTPORT_DEPLOY_REPO: root, TEST_ROOT: root, TMPDIR: root,
      FAKE_BUILD: publicFails ? sha : 'a-different-build',
    },
    encoding: 'utf8',
  });
  const images = readFileSync(join(root, 'compose-up'), 'utf8').trim().split('\n').map((line) => line.trim());
  return { result, sha, before, images };
}

test('a failed verification restores the previous image', () => {
  const root = mkdtempSync(join(tmpdir(), 'votport-deploy-test-'));
  try {
    const { result, sha, before, images } = rollbackFixture(root, [48, 48]);
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /VERIFY FAILED: binary version/);
    assert.match(result.stderr, /restoring votport-local:audit-previous/);
    assert.doesNotMatch(result.stderr, /ROLLBACK FAILED/);
    assert.equal(readFileSync(join(root, 'docker-compose.override.yml'), 'utf8'), before);
    assert.deepEqual(images, [`image: votport-local:audit-${sha.slice(0, 7)}`, 'image: votport-local:audit-previous']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a failed verification after a schema change keeps the new image and says why', () => {
  const root = mkdtempSync(join(tmpdir(), 'votport-deploy-test-'));
  try {
    const { result, sha, images } = rollbackFixture(root, [47, 48]);
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /NOT ROLLED BACK: .* from schema 47 to 48/);
    assert.doesNotMatch(result.stderr, /ROLLBACK FAILED/);
    assert.match(readFileSync(join(root, 'docker-compose.override.yml'), 'utf8'), new RegExp(`image: votport-local:audit-${sha.slice(0, 7)}`));
    assert.deepEqual(images, [`image: votport-local:audit-${sha.slice(0, 7)}`]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('an unreachable public path rolls back instead of exiting with the new image pinned', () => {
  const root = mkdtempSync(join(tmpdir(), 'votport-deploy-test-'));
  try {
    const { result, before, images } = rollbackFixture(root, [48, 48], { publicFails: true });
    assert.equal(result.status, 1, result.stderr);
    const script = readFileSync(new URL('./deploy.sh', import.meta.url), 'utf8').split('\n');
    const line = script.findIndex((text) => text.startsWith('code=$(curl')) + 1;
    assert.match(result.stderr, new RegExp(`VERIFY FAILED: command failed at line ${line}\\b`));
    assert.equal(readFileSync(join(root, 'docker-compose.override.yml'), 'utf8'), before);
    assert.equal(images.at(-1), 'image: votport-local:audit-previous');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
