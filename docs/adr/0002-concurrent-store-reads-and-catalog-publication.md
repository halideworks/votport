# ADR-0002: Concurrent Store reads and catalog publication

Status: Accepted

Date: 2026-09-30

## Context

The Store uses SQLite WAL with durable commits, but its single application
mutex serialized administrative reads, timeline exports and serving checks
with mutations. Stored-file claim checks also scanned a tenant's live rows.
Independent catalog publications and cache lookups could wait for unrelated
catalog writes or a cache-sidecar fsync.

## Decision

Keep the existing serialized writer and its transaction boundaries. Add four
reusable read-only SQLite connections. A short pool mutex and condition
variable reserve an available connection; a guard returns it on success,
error or unwind. Each read call starts and ends one deferred transaction so
its related queries see one committed WAL snapshot. Mutating authorization
checks and settings map/generation reads remain on the writer. Health checks
also reject a poisoned writer.

Each reader has an 8 MB page-cache budget, a 64-statement cache, and the
existing mmap and memory-temp settings. Reads wait when all four connections
are reserved. No pool dependency or additional configuration is introduced.
The bundled SQLite is 3.53.2, which includes the WAL-reset race fix.

Create a partial covering index on `files(tenant, stored_as, suite, root)` for
`deleted=0`. Startup installs it transactionally for existing databases; no
schema-version change is required. The index trades additional storage and
mutation work for indexed probes of selected stored names.

Catalog publishers share a read guard; cleanup owns the write guard while
collecting references and pruning. Publishers register roots in the cache
before releasing their guard. Per-object build locks remain registered while
any builder or waiter owns them, including failed builds. Cache persistence
serializes snapshots under a separate persistence mutex, releases the lookup
mutex before disk I/O, and clears dirty state only if the saved generation
still owns the current entries.

## Consequences and verification

SQLite still permits one writer at a time. The application removes its extra
read/write serialization without changing atomic mutation or authorization
semantics. A long read snapshot can delay checkpoint progress; exports use a
reader instead of the writer and release their snapshot on every exit.
Writer durability and existing checkpoint bounds remain in place.

Regression checks exercise reads during an uncommitted write, snapshot
consistency across a concurrent commit, read-only enforcement, reader return
after errors and panics, indexed query plans, concurrent catalog publication,
and changes arriving during cache persistence. The isolated benchmark compares
the same 100,000-file database with and without the claim index and compares
the old writer mutex with the read pool under eight reader threads and durable
writes. Measurements are recorded in the [follow-up report](../scalability-2026-09-30.md).

SQLite's [WAL documentation](https://sqlite.org/wal.html) and
[isolation documentation](https://sqlite.org/isolation.html) describe the
underlying concurrency and snapshot guarantees.
