# Direct receiving to NAS

Votport receives directly onto the selected destination filesystem. It does not
require an operator-provisioned staging volume, double payload capacity, or a
final copy. HTTP uploads and native QUIC pushes use the same verified receiver.

## Enable a share

Mount the share on the Linux server and expose that mount at the configured
`VOTPORT_RECEIVE_DIR`, including inside the container. Keep `VOTPORT_DATA_DIR`
on local storage for SQLite, signing keys and upload checkpoints.

Open **Storage > Receiving storage** as a platform administrator. Votport shows
the path, filesystem, source, receiving status and any failed check. For a new
NAS, confirm both server configuration requirements and select **Check and
enable receiving**. These confirmations apply to that exact share, mount root,
receiving directory identity and service UID. Replaced or missing storage stops
receiving instead of falling back to an empty local folder.

Qualification requires:

- Linux NFSv4 with a hard mount and server-coordinated locks, or SMB3/CIFS with
  server inode identity and server ACL or POSIX support.
- Stable server acknowledgments for data and namespace changes. SMB FLUSH or NFS
  COMMIT must wait for the server's stable-storage contract. Server settings that
  acknowledge volatile writes do not satisfy this requirement.
- A private receiving namespace protected by server permissions from creation.
  On both NFS and CIFS, its ancestors must also be protected against replacement
  by another user. Programs sharing Votport's service identity must not modify its private
  files. Client `uid`, `gid` and mode display are not proof of server ACLs.
- Hard links, stable inode identity, namespace synchronization and coordinated
  file locks. Options such as `nostrictsync`, `nobrl`, NFS soft mounts or
  client-local flock emulation are refused.

The operation probe creates a small private file, flushes it, checks an exclusive
hard link and inode identity, synchronizes directories, and removes only its own
probe files. It does not simulate a storage appliance losing power. Qualify the
server configuration with the storage administrator; this release does not claim
power-loss certification for a particular NAS appliance.

The upstream storage contract and rationale are in
[VOT ADR-0054](https://github.com/halideworks/VOT/blob/main/adr/0054-direct-receiving-on-shared-storage.md).
Strict NAS receipts and macOS/Windows NAS receiving are not supported by this
Linux implementation. Desktop senders can use either transfer path to a qualified
Linux Votport server.

## Verification and publication

Each file starts in a private `.vot-stage` directory on its final filesystem.
The incoming proof authorizes the write; native transport passes its verification
witness into the receiver without hashing or copying the same range again.
Completed files publish individually by an exclusive hard link to the same inode,
then removal of the private name. An existing destination is never overwritten.
The two names briefly reference one allocation, not two payloads.

Files appear under their final names only after verification and publication.
A failed transfer may therefore leave already completed files alongside retained
partial files. Signed receipts identify the announced content and publication
observation. Qualified NAS uses Balanced with provider `POSIX_NAS` (`0x0005`),
which records server-acknowledged durability. It does not claim an independent
readback from the storage server's physical media.

The receiver keeps publication journals until its database checkpoint commits.
If publication succeeds but that checkpoint fails, retry reconciles the same
published inode. It does not delete a completed shared file to roll back the
transfer. A restart or uncertain file identity triggers verification before
publication. Corrupt retained bytes are refused and must be sent again.

Reception workflows pin their original files until retirement. S3, shared-folder
and peer exports read and verify these files directly; no reception snapshot is
required. Source changes fail verification. Ordinary local receiving does not
add an unconditional second payload read.

## Ownership and recovery

`.vot-stage/writer.lock` is a permanent inode with an exclusive kernel lock.
Heartbeat JSON is diagnostic and never authorizes takeover based on elapsed time.
Each renewal writes and synchronizes one byte through the retained lock handle.
An I/O failure stops receiving; a cached read or inode check cannot detect a lost
NFS lock. Votport refuses Linux `nfs.recover_lost_locks` when enabled; it must
report loss instead of silently reacquiring ownership. Do not change this kernel
setting while receiving. Ownership renewal also runs during startup and
administrator-triggered recovery.
Native push control directories also retain their writer-lock inode after
cleanup; only transfer metadata is removed.
A local receiving root must be owned by the service account and prevent other
users from renaming its private control folder. Remove group/other write access,
or use the sticky bit when other users need to create files in that folder.
Votport creates a missing local root with mode 0700 and never changes permissions
on an existing receiving folder.
The NAS must coordinate the lock between clients. Stop or fence the old writer
before failover and allow the filesystem to recover its locks. Never remove the
lock file to force another writer in.

Detected ownership loss stops new receiving operations. An already-running
hard-NFS syscall can remain blocked in the kernel; fence the old host before
another host takes over. Unresolved journals, partial files and
database records remain for recovery; startup logs the problem and records an
interrupted transfer event. Published files are retained. The server keeps its
administration interface available when initial NAS qualification is missing.
Retained partial admissions remain charged against tenant quotas after their
connections expire. Resuming the same admission reuses its reservation.

Automatic deletion and retention require destination folders and their ancestors
to prevent other filesystem users from replacing entries. Votport refuses cleanup
where those permissions cannot be established. Receiving into a shared folder
still works; storage administrators can manage deletion there. Reception jobs
release their source-file pins when archived, including tenants that never use
an outbound library.

## SMB small-file performance

Use the Linux CIFS `tcpnodelay` mount option when metadata latency affects EXR
sequences. On the disposable Samba fixture, alternating three runs per mount
with the same three frames gave median component completion times of 1.177739 s
without it and 0.039422 s with it. All SHA-256 hashes matched. Network RTT was
0.245 ms; the original mount repeatedly paused about 40 ms on metadata and flush
operations. No durability, permission or cache-coherency setting changed.

A separate `nosharesock` test mount isolated the comparison from the existing
connection. This is a small component result, not a general application speedup.
Measure the actual workload before changing a deployed mount. See the
[Linux SMB mount options presentation](https://www.snia.org/sites/default/files/2025-05/SNIA-SDC2024-Prasad-Demystyfiying-Linux-Mount-Options.pdf)
and [mount.cifs](https://man7.org/linux/man-pages/man8/mount.cifs.8.html).

## Reproduce the media sanity checks

Use disposable storage and an explicitly selected local scratch directory. On a
workstation, put source files, build targets, caches and `TMPDIR` on the test
volume. Do not use its OS drive. Source and received payload capacity must be on
separate fixture volumes when checking the single-copy receive requirement.

```sh
mkdir -p /test/control
python3 scripts/nas-fixtures.py /test/source-exr --case exr --frames 100000
python3 scripts/nas-fixtures.py /test/source-large --case large --gib 32
TMPDIR=/test/control cargo +1.97.1 test --release --manifest-path server/Cargo.toml --test e2e --no-run
VOTPORT_NAS_TEST_MOUNT=/mnt/nfs VOTPORT_NAS_TEST_SOURCE=/test/source-exr VOTPORT_NAS_TEST_TRANSPORT=push TMPDIR=/test/control cargo +1.97.1 test --release --manifest-path server/Cargo.toml --test e2e mounted_nas_media_campaign -- --ignored --nocapture
```

Repeat with `http`, the SMB mount, and `/test/source-large`. The EXRs are valid
uncompressed RGB half-float frames with unique frame metadata. The large file is
fully written random data. Both generators produce SHA-256 manifests; compare
every received file independently after the timed transfer. The harness retains
its paths and reports elapsed time from client collection through publication,
transport, count, bytes and success. It also checks writer-lock exclusion from a
second process before and after transfer, runs the production ownership renewal
task throughout the transfer, and checks reacquisition after release.

Measure physical allocation on the storage server. CIFS client `st_blocks` can be
stale across writes and publication. Use inode continuity plus server allocation
to check that receiving has one payload. Report component measurements separately
from application transfers and use the same fixture and rig for comparisons.

The ignored `mounted_nas_lock_loss_stops_receiving` and
`mounted_nas_recovery_lock_loss_stops_receiving` tests require a separate
storage-administration process to revoke the disposable client's locks after
`lock-ready` is printed. On an isolated Linux NFS server, write `expire` to the
matching `/proc/fs/nfsd/clients/<id>/ctl`. Run each test separately and target only
its fixture client. The tests require ownership loss within 60 seconds, refusal
of new receiving operations, and no automatic reacquisition.
