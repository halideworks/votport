# Scalability and native-state follow-up, 2026-09-30

This follows the completed [application audit](audit-2026-09-30.md).
Native signing remains deferred. The application is prerelease software;
clients sharing local state must be updated together. No compatibility
machinery is added for clients predating the shared state lease.

## Changes

- Store reads use four reusable read-only SQLite connections and one committed
  snapshot per call. Mutations, atomic authorization changes, and settings
  map/generation reads retain the serialized writer. Health rejects writer
  poisoning. The database remains at schema version 48.
- Stored-file claim checks use a partial covering index on live files, installed
  transactionally at startup. No dependency or pool configuration is added.
- Independent catalog publishers share a read lock; cache cleanup owns its
  write lock. Build locks remain registered while builders or waiters own them.
- Root-cache persistence releases its lookup lock before encoding and disk I/O.
  A generation comparison retains dirty state when a newer root arrives during
  persistence. A separate persistence lock prevents older snapshots overwriting
  newer ones.
- Abandoned browser sign-in expires after ten minutes and releases its state
  lease. Cancellation and successful completion wake the expiry worker.
- Watch sidecar cleanup takes exclusive ownership of the existing stable state
  lease, which excludes active flights and already-open waiters. Probes do not
  create sidecars. Completed flights attempt immediate cleanup; the periodic
  pass handles at most 1,024 entries per minute. Cleanup does not recreate an
  erased state directory. Claim errors fail closed and retry on the next scan.
- Windows browser sign-in and cancellation invalidate queued account callbacks.
  Both native shells reconcile the displayed port with the committed core
  session after cancellation, including completion committed before its UI
  callback. Stale failures cannot clear a replacement session or its problem.

The Store and catalog decisions are recorded in
[ADR-0002](adr/0002-concurrent-store-reads-and-catalog-publication.md).
Local-state ownership is recorded in
[ADR-0001](adr/0001-principal-identity-and-local-state.md).

## Measurements

All measurements used an isolated, generated 100,000-file database on the same
host. No production database or media was opened or copied. These measurements
are repeatable fixture results, not production latency predictions.

The selected-name claim check used seven samples per mode against the same
Store. Median latency was **14.884 ms without the index** and **0.028 ms with
the index** (approximately 541 times faster).

The mixed workload used eight reader threads, 128 full-table count queries and
20 durable metadata writes. Three trials per mode alternated the old writer
mutex and the read pool. Values below are the median across the three trials;
p95 values were computed separately within each trial.

| Measurement | Old writer mutex | Four concurrent readers |
| --- | ---: | ---: |
| Total wall time | 588.0 ms | 158.4 ms |
| Read p95 | 89.52 ms | 8.63 ms |
| Write p95 | 356.91 ms | 4.42 ms |

The benchmark is an ignored Rust test, explicitly runnable with:

```sh
cargo test --manifest-path server/Cargo.toml --locked --lib \
  store::readers::tests::stored_claim_lookup_benchmark -- --ignored --nocapture
```

This change removes avoidable application serialization. SQLite WAL still has
one writer. Long snapshots can delay checkpoint progress. Readers are bounded
at four and have an 8 MB page-cache budget each. The index adds storage and write
work. Existing restore safety ceilings remain intentional resource limits.
Large uncached media must still be read to calculate its content hash; prior
background hashing and validated cache reuse address delivery creation delay.

## Verification

Local validation passed 975 server checks, 188 native workspace checks
(including 139 core tests), and 84 JavaScript checks with zero skips. Format,
deny-warning lints, release validation, and dependency advisory/license/source
checks passed. CI rejected the existing transitive `yoke-derive 0.8.3` as
yanked; the client lockfile now selects compatible patch `0.8.4` and the native
workspace was revalidated. Direct dependencies are unchanged. Core checks
exercise active locks, open waiters, erased state,
abandoned sign-in expiry, and stale completion.

Native shell checks run on their respective CI platforms: macOS XCTest and the
Windows production-model dispatcher harness. They cover stale success/failure,
signed-out failures, overlapping busy ownership, browser sign-in generation,
and cancellation reconciliation, including a committed session whose displayed
port fields match the previous account. Seven hand-applied mutations of read-only
access, snapshot ownership, the claim index, concurrent publication, cache dirty
generation, state cleanup ownership and SSO lease release each failed a bounded
regression test. Sources were restored before final validation. No installed
desktop was controlled.
