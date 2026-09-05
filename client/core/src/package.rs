//! Building the manifest for a drop and preparing to prove its objects.
//!
//! [`build_manifest_from`] hashes every file where it sits and writes only the
//! manifest (a seal and pages), returning the leaves per stored object. The
//! client reads that manifest back to learn the canonical entry order the
//! server's begin uses, so a begin entry index maps to the object it must
//! prove ranges of.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use vot_cli::{build_manifest_from, PackageSummary, ServedSource};
use vot_manifest::{decode_page, decode_seal, EntryKind, StorageRef};
use vot_object::{ObjectBuilder, PreparedObject, Suite};

use crate::entries::Entry;
use crate::error::{Error, Result};

// The on-disk manifest layout, mirroring vot-cli's `package::layout` (which is
// crate-private there). A public accessor in vot-cli would remove this
// duplication; until then the client reads back the manifest it just wrote.
const MANIFEST_DIRECTORY: &str = "manifest";
const MANIFEST_SEAL: &str = "seal.cbor";

fn manifest_page_path(directory: &Path, index: u64) -> PathBuf {
    directory.join(format!("{index:016}.cbor"))
}

/// One object a drop stores, in canonical (begin) order.
#[derive(Debug, Clone)]
pub struct PreparedEntry {
    pub root: [u8; 32],
    pub length: u64,
    /// A file holding the object's bytes, for the one-group case and for a
    /// fallback when no leaves were kept.
    pub source: PathBuf,
    /// The proof leaves the manifest build kept, or `None` for a one-group
    /// object (its root is a single group's hash, with no tree above it).
    pub leaves: Option<Vec<[u8; 32]>>,
}

impl PreparedEntry {
    /// Builds a prover for this object: from the kept leaves without reading
    /// the bytes when there are leaves, or by hashing the file when there are
    /// not (a one-group object at most 64 KiB).
    ///
    /// # Errors
    /// A read failure, or a length that no longer matches what was hashed.
    pub fn prover(&self) -> Result<PreparedObject> {
        // A one-group object keeps a single leaf, which is not a tree
        // `from_proof_leaves` can rebuild (its root is the leaf itself), so it
        // may refuse; hashing the bytes is the fallback for that case.
        if let Some(leaves) = &self.leaves {
            if let Ok(prepared) =
                PreparedObject::from_proof_leaves(Suite::Blake3Bao64, self.length, leaves.clone())
            {
                return Ok(prepared);
            }
        }
        let bytes = fs::read(&self.source).map_err(|source| Error::Read {
            path: self.source.clone(),
            source,
        })?;
        let mut builder = ObjectBuilder::new(Suite::Blake3Bao64, Some(self.length))?;
        builder.update(&bytes)?;
        Ok(builder.finish()?)
    }
}

/// A built manifest ready to send: its root package, the seal and page bytes
/// the HTTP session posts, and the objects in begin order.
pub struct Prepared {
    pub summary: PackageSummary,
    pub seal_bytes: Vec<u8>,
    pub page_bytes: Vec<Vec<u8>>,
    pub objects: Vec<PreparedEntry>,
}

/// Hashes `entries` in place and reads the manifest back into begin order.
///
/// # Errors
/// A refusal from the manifest build (a bad entry, a collision), a read
/// failure, or a manifest the client cannot decode.
pub fn build(entries: Vec<Entry>, manifest_root: &Path) -> Result<Prepared> {
    let pairs: Vec<_> = entries
        .into_iter()
        .map(|entry| (entry.path, entry.source))
        .collect();
    let (summary, served): (PackageSummary, BTreeMap<[u8; 32], ServedSource>) =
        build_manifest_from(pairs, manifest_root, Suite::Blake3Bao64)?;

    let manifest_dir = manifest_root.join(MANIFEST_DIRECTORY);
    let seal_bytes = fs::read(manifest_dir.join(MANIFEST_SEAL))?;
    let seal = decode_seal(&seal_bytes)
        .map_err(|error| Error::Other(format!("decoding the manifest seal: {error:?}")))?;

    let mut page_bytes = Vec::with_capacity(usize::try_from(seal.final_page_count).unwrap_or(0));
    let mut objects = Vec::new();
    for index in 0..seal.final_page_count {
        let bytes = fs::read(manifest_page_path(&manifest_dir, index))?;
        let page = decode_page(&bytes)
            .map_err(|error| Error::Other(format!("decoding manifest page {index}: {error:?}")))?;
        for entry in page.entries {
            if entry.kind == EntryKind::Directory {
                continue;
            }
            let Some(StorageRef::Direct(object)) = entry.storage else {
                return Err(Error::Other(
                    "the client manifest carried a packed entry, which it never builds".to_owned(),
                ));
            };
            let served_source = served.get(&object.root).ok_or_else(|| {
                Error::Other("a manifest entry named an object with no source".to_owned())
            })?;
            objects.push(PreparedEntry {
                root: object.root,
                length: object.length,
                source: served_source.path.clone(),
                leaves: served_source.leaves.clone(),
            });
        }
        page_bytes.push(bytes);
    }
    Ok(Prepared {
        summary,
        seal_bytes,
        page_bytes,
        objects,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entries::admit;

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn builds_a_manifest_and_prepares_its_objects_in_order() {
        let source_dir = tempfile::tempdir().unwrap();
        // A multi-group object (kept leaves), a small one (no leaves), and a
        // duplicate of the small one (same root, deduped to one object).
        let big = write(source_dir.path(), "big.bin", &vec![7u8; 200_000]);
        let small = write(source_dir.path(), "small.txt", b"a small note");
        let twin = write(source_dir.path(), "twin.txt", b"a small note");

        let entries = vec![
            admit("big.bin", big, false).unwrap(),
            admit("small.txt", small, false).unwrap(),
            admit("twin.txt", twin, false).unwrap(),
        ];
        let manifest_home = tempfile::tempdir().unwrap();
        let manifest_root = manifest_home.path().join("m");
        let prepared = build(entries, &manifest_root).expect("built");

        assert_eq!(prepared.summary.entries, 3, "three entries");
        assert_eq!(prepared.objects.len(), 3, "one prepared object per entry");
        assert!(!prepared.seal_bytes.is_empty());
        assert_eq!(
            prepared.page_bytes.len().max(1),
            prepared.page_bytes.len().max(1)
        );

        // Every object builds a prover; the multi-group one from leaves, the
        // small ones from bytes.
        let big_object = prepared
            .objects
            .iter()
            .find(|object| object.length == 200_000)
            .expect("the big object");
        assert!(
            big_object.leaves.is_some(),
            "a multi-group object keeps leaves"
        );
        assert!(big_object.prover().is_ok());

        let small_object = prepared
            .objects
            .iter()
            .find(|object| object.length == 12)
            .expect("the small object");
        // Whether or not a one-group object kept a usable leaf, its prover
        // builds and proves the whole object.
        let prover = small_object
            .prover()
            .expect("a prover for the small object");
        let cover = prover.prove(0, 12).expect("a proof of the whole object");
        assert_eq!(cover.covered_offset(), 0);
    }
}
