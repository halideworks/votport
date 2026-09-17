# Offline schema 35 conversion

`votport convert-schema35` converts schema 35 to schema 46. It does not start
HTTP listeners, process jobs, send notifications or copy payload files. Normal
startup still refuses an incompatible database. Other source and target schema
versions are refused.

1. Drain admission, finish or explicitly resolve retained uploads using the
   matching source release, and stop every writer, standby and replica. Zero
   active network transfers does not mean zero persisted admissions.
2. Make and verify a new private cold backup of the complete data directory,
   including its existing keys and surviving SQLite journals. Preserve a
   coherent rollback point for receiving and outbound payloads too. Keep the
   original and backup unchanged; create a separate disposable working copy.
3. Run the target binary against that copy, supplying the public origin used by
   recipients:

   ```sh
   votport convert-schema35 \
     --data-copy /srv/votport-upgrade/working-copy \
     --public-url https://drop.example.com
   ```

   The path must be absolute and canonical, with no symlinks. The command takes
   the data-directory ownership lock and requires existing 32-byte `secret`
   and `receipt.key` files. It refuses pending restore/standby markers, retained
   upload admissions, inconsistent file projections and invalid signed-event
   chains. It never guesses upload completion or repairs historical evidence.
4. Require a successful exit and a final `committed` record in the private
   `schema35-conversion.jsonl` output. Review replacement workflow links before
   distributing them. A missing, truncated or otherwise uncertain result means
   discarding the working copy and starting again from the retained cold backup.
   Reusing an already-converted copy is refused.
5. Verify the converted install set and exact target image before installing
   them together. Keep ingress and workers stopped during installation. Preserve
   the old data, matching journals, payload rollback point and image as one
   coherent set. Upgrade replicas together and make new backups after acceptance.

The converter preserves existing receipt and cookie keys, uploads and file
ordering, tombstones, unsigned sizes, job policy, approvals, grant expiry and
revocation, download counters and historical signed events. It replaces workflow
bearers and their matching grant hashes together, increments matched jobs'
rotation generations, and appends a signed rotation event. Undelivered fetch
tickets for rotated grants are invalidated, releasing their reserved download
slots; delivered history and counters remain unchanged. Existing workflow
URLs stop authorizing access. Only currently released, unexpired, unrevoked
workflow grants receive replacement URLs in the output. The command sends none.
Named-tenant SSO users must sign in again for their new tenant identities.

One source upload-history JSON document is decoded at a time, with a 64 MiB
encoded-document limit. Larger histories require a separately reviewed
conversion. Decoded metadata and SQLite use additional memory: one Linux debug
run with 100,000 file records (17.9 MiB of source JSON) peaked at 162 MiB RSS.
This is a sample, not an upper bound. Memory never contains complete payload
files. The private output contains replacement credentials; keep it out of logs,
tickets and source control.

Automatic rollback is safe only **before the first production application
start**. Workers can resume jobs and send data even while ingress remains
closed. After that boundary, preserve new data and use a forward fix or an
explicit reconciliation instead of restoring a stale snapshot.
