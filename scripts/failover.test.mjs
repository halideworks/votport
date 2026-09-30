import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

function fixture(script, overrides = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'votport-failover-'));
  const events = join(directory, 'events');
  writeFileSync(events, '');
  writeFileSync(join(directory, 'curl'), `#!/bin/sh
case "$*" in
  *healthz*)
    if [ -f "$PROBE_FILE" ]; then exit 1; fi
    touch "$PROBE_FILE"; exit 0 ;;
  *readyz*) printf '%s' '{"sessions_active":0,"lease":{"mine":true},"archive_created_at":null,"last_error":null}' ;;
  *) printf '%s\\n' "api:$*" >> "$EVENT_LOG"; cat >/dev/null ;;
esac
`, { mode: 0o700 });
  const action = (name, status = 0) => `printf '%s\\n' ${name} >> "$EVENT_LOG"; exit ${status}`;
  try {
    const result = spawnSync('bash', [`ops/failover/${script}.sh`], {
      env: { ...process.env, PATH: `${directory}:${process.env.PATH}`,
        EVENT_LOG: events, PROBE_FILE: join(directory, 'probe'),
        LIVE_HOST_URL: 'http://old', NEW_LIVE_HOST_URL: 'http://new',
        LIVE_URL: 'https://old', NEW_LIVE_URL: 'https://new', VOTPORT_ADMIN_PASSWORD: 'fixture',
        TOPOLOGY: 'shared', INTERVAL: '0', FAILURES: '1', READY_TIMEOUT: '0', DRAIN_TIMEOUT: '0',
        FENCE_CMD: action('fence'), UNFENCE_CMD: action('restart-old'),
        LIVE_STOP_CMD: action('stop-old'), LIVE_RESTART_CMD: action('restart-old'),
        PROMOTE_CMD: action('promote', 1), PROMOTION_STOP_CMD: action('stop-new'),
        REPOINT_CMD: action('repoint'), ...overrides,
      }, encoding: 'utf8', timeout: 5000,
    });
    assert.equal(result.error, undefined);
    return { ...result, events: readFileSync(events, 'utf8').trim().split('\n') };
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

test('failed fencing stops promotion', () => {
  const result = fixture('watch', { FENCE_CMD: 'printf "%s\\n" fence >> "$EVENT_LOG"; exit 1' });
  assert.equal(result.status, 1);
  assert.deepEqual(result.events, ['fence']);
});

test('failed or missing new-writer stop prevents rollback in both scripts', () => {
  for (const script of ['watch', 'planned']) {
    for (const stop of ['', 'printf "%s\\n" stop-new >> "$EVENT_LOG"; exit 1']) {
      const result = fixture(script, { PROMOTION_STOP_CMD: stop });
      assert.equal(result.status, 1);
      assert.ok(result.events.includes('promote'));
      assert.ok(!result.events.includes('restart-old'));
      assert.ok(!result.events.includes('repoint'));
    }
    const result = fixture(script);
    assert.equal(result.status, 1);
    assert.ok(result.events.indexOf('stop-new') < result.events.indexOf('restart-old'));
    assert.ok(!result.events.includes('repoint'));
  }
});

test('replicated planned failover requires a fresh reachable archive', () => {
  const result = fixture('planned', { TOPOLOGY: 'replica' });
  assert.equal(result.status, 1);
  assert.ok(!result.events.includes('stop-old'));
  assert.ok(!result.events.includes('promote'));
  assert.ok(result.events.some((event) => event.includes('draining') && event.includes('false')));
});
