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
