//! Filesystem path admission for received files.
//!
//! The VOT manifest layer already rejects traversal (no "/", "\", ".", "..",
//! control characters, trailing dots). These checks are defense in depth plus
//! votport policy (hidden files off by default), applied before any path
//! touches the disk.

use crate::protocol_paths::is_push_staging_name;
use crate::protocol_paths::is_receipt_name;
use crate::protocol_paths::MAX_PAYLOAD_NAME_BYTES;
use std::path::{Path, PathBuf};

pub use crate::protocol_paths::{admit_component, TENANT_STORAGE_DIR};

pub fn tenant_prefix(key: &str) -> Vec<String> {
    if key.is_empty() {
        Vec::new()
    } else {
        vec![TENANT_STORAGE_DIR.to_owned(), key.to_owned()]
    }
}

/// The receive-root-relative components of a stored file record: the tenant's
/// own subtree, then the stored name. `stored_path` in api::admin joins these
/// under the receive root; the post-restore payload survey in backup shares
/// this one spelling of the layout.
pub fn stored_components(tenant: &str, stored_as: &str) -> Vec<String> {
    let mut components = tenant_prefix(tenant);
    components.extend(
        stored_as
            .split('/')
            .filter(|part| !part.is_empty())
            .map(str::to_owned),
    );
    components
}

pub fn portable_tenant_key(key: &str) -> bool {
    // Audit finding 516: the 128-byte segment cap also lives here so the
    // helper stays self-contained instead of depending on admit_dest's cap
    // having been applied first.
    if key.is_empty()
        || key.len() > 128
        || !key.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return false;
    }
    !matches!(key, "con" | "prn" | "aux" | "nul")
        && !(key.len() == 4
            && matches!(&key[..3], "com" | "lpt")
            && matches!(key.as_bytes()[3], b'1'..=b'9'))
}

/// On-disk location for a tenant's uploaded logo. The tenant key is hex
/// encoded so arbitrary legacy keys cannot shape the path.
pub fn branding_logo_path(data_dir: &Path, tenant: &str, ext: &str) -> PathBuf {
    let stem = if tenant.is_empty() {
        "default".to_owned()
    } else {
        hex::encode(tenant.as_bytes())
    };
    data_dir.join("branding").join(format!("{stem}.{ext}"))
}

/// Selects publication assurance from the destination's mounted filesystem.
pub fn commit_profile(destination: &Path) -> std::io::Result<vot_sdk_file::CommitProfile> {
    #[cfg(target_os = "linux")]
    {
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let directory = std::fs::File::open(parent)?;
        Ok(profile_for_mount(vot_platform_fs::is_smb_or_nfs(
            &directory,
        )?))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = destination;
        Ok(profile_for_mount(false))
    }
}

fn profile_for_mount(remote: bool) -> vot_sdk_file::CommitProfile {
    if remote {
        vot_sdk_file::CommitProfile::Fast
    } else {
        vot_sdk_file::CommitProfile::Balanced
    }
}

/// The verification levels a request link creator can pick (finding 24).
/// These strings are the API and storage spelling; the CHECK constraint on
/// `links.verification` pins them.
pub const VERIFICATION_LEVELS: [&str; 3] = ["default", "balanced", "strict"];

/// Resolves a link's requested verification level against a mount class.
/// "default" keeps today's receive choice (Balanced on local storage and on
/// explicitly qualified Linux CIFS/SMB or NFS, docs/deployment.md); "strict"
/// is documented local-only, so a NAS destination refuses the level instead
/// of silently downgrading.
pub fn verification_for_mount(
    remote: bool,
    requested: &str,
) -> Result<vot_sdk_file::CommitProfile, String> {
    match requested {
        "default" | "balanced" => Ok(vot_sdk_file::CommitProfile::Balanced),
        "strict" if !remote => Ok(vot_sdk_file::CommitProfile::Strict),
        "strict" => {
            Err("strict verification is not offered for network storage destinations".to_owned())
        }
        other => Err(format!("unknown verification level {other:?}")),
    }
}

/// One capability decision for a link's verification level (finding 24),
/// consulted by link creation (422 refusal) and by session publication.
/// The mount probe mirrors [`commit_profile`].
pub fn verification_profile(
    destination: &Path,
    requested: &str,
) -> Result<vot_sdk_file::CommitProfile, String> {
    #[cfg(target_os = "linux")]
    {
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let remote = mount_remote(parent)?;
        verification_for_mount(remote, requested)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = destination;
        verification_for_mount(false, requested)
    }
}

/// Whether the nearest existing ancestor of `destination` sits on SMB/CIFS or
/// NFS. Link creation runs before the destination directories exist, so the
/// probe walks up to the first existing directory, which shares the mount.
#[cfg(target_os = "linux")]
fn mount_remote(destination: &Path) -> Result<bool, String> {
    let mut probe = destination.to_path_buf();
    loop {
        match std::fs::File::open(&probe) {
            Ok(file) => {
                return vot_platform_fs::is_smb_or_nfs(&file)
                    .map_err(|error| format!("inspect {}: {error}", probe.display()));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !probe.pop() {
                    return Ok(false);
                }
            }
            Err(error) => return Err(format!("inspect {}: {error}", probe.display())),
        }
    }
}

/// Drops group/other write bits on a directory files are received into. VOT
/// stages next to the destination and refuses a group-writable parent, so a
/// mount created 0775 (umask 002 hosts) would fail every upload into it.
pub fn tighten_dir(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o7777;
            if mode & 0o022 != 0 {
                let _ =
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & !0o022));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Makes the application state directory private without following a
/// symlink. This is separate from `tighten_dir`, whose group-write policy is
/// intentionally used for receive and outbound trees.
pub fn tighten_private_dir(path: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing symlink for private directory {}",
            path.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!(
            "private state path is not a directory: {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        let file = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| format!("open private directory {}: {error}", path.display()))?;
        rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o700))
            .map_err(|error| format!("protect {}: {error}", path.display()))?;
    }
    Ok(())
}

/// Tightens an existing regular file without following a symlink. Missing
/// files are normal for lazily-created keys and database auxiliaries.
pub fn tighten_private_file(path: &Path) -> Result<bool, String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("inspect {}: {error}", path.display())),
    };
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing symlink for private file {}",
            path.display()
        ));
    }
    if !metadata.is_file() {
        return Err(format!(
            "private state path is not a regular file: {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        let file = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| format!("open private file {}: {error}", path.display()))?;
        rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o600))
            .map_err(|error| format!("protect {}: {error}", path.display()))?;
    }
    Ok(true)
}

/// Creates an empty owner-only regular file, refusing to replace anything
/// that appeared at the path concurrently.
pub fn create_private_file(path: &Path) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path).map(|_| ())
}

/// Makes an existing private directory and its regular child files private.
/// Symlink children are ignored rather than followed.
pub fn tighten_private_dir_contents(path: &Path) -> Result<(), String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("inspect {}: {error}", path.display())),
    };
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing symlink for private directory {}",
            path.display()
        ));
    }
    tighten_private_dir(path)?;
    for entry in std::fs::read_dir(path)
        .map_err(|error| format!("read private directory {}: {error}", path.display()))?
    {
        let entry = entry.map_err(|error| format!("read private directory entry: {error}"))?;
        if entry
            .file_type()
            .map_err(|error| format!("inspect {}: {error}", entry.path().display()))?
            .is_file()
        {
            tighten_private_file(&entry.path())?;
        }
    }
    Ok(())
}

/// Proves at boot that a landing directory can carry a publish. VOT publishes
/// a received file by hard-linking a fsynced staging file into place, checks
/// the link by device and inode, fsyncs the directory, and refuses a parent
/// that is a symlink, group- or world-writable, or owned by someone else,
/// or a staging file it did not end up owning. The outbound library
/// publishes with the same hard link and refuses a symlinked root, but has
/// no owner or mode rule. A network export that lacks any of these
/// (all_squash onto another id, a CIFS mount without link(2) or stable
/// inodes) would otherwise fail every upload after boot instead of here.
pub fn probe_landing_dir(root: &Path, what: &str, vot_publish: bool) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::MetadataExt as _;
        // A trailing slash would make lstat follow a symlink; VOT lstats the
        // parent of its staging path, which has none.
        let root: PathBuf = root.components().collect();
        let root = root.as_path();
        let refuse = |why: String| {
            format!(
                "{what} ({}) cannot receive publishes: {why}",
                root.display()
            )
        };
        let fail = |step: &str, error: std::io::Error| refuse(format!("{step}: {error}"));
        let meta = std::fs::symlink_metadata(root).map_err(|error| fail("stat", error))?;
        if !meta.file_type().is_dir() {
            return Err(refuse(
                "it is a symlink or not a directory; publishing refuses a symlinked root, so point the variable at the real path".to_owned(),
            ));
        }
        if vot_publish {
            let euid = rustix::process::geteuid().as_raw();
            if meta.uid() != euid {
                return Err(refuse(format!(
                    "owned by uid {} but the server runs as uid {euid}; export it with matching ids (no all_squash or anonuid onto another id, and matching NFSv4 idmapping)",
                    meta.uid()
                )));
            }
            if meta.mode() & 0o022 != 0 {
                return Err(refuse(format!(
                    "mode {:o} is group or world writable and chmod did not take; mount it so the server can hold it at 0755",
                    meta.mode() & 0o7777
                )));
            }
        }
        // Reserved staging names: the boot sweep removes a leftover from a
        // kill mid-probe, and admit_component keeps senders off the shape.
        let token = crate::auth::random_token();
        let staging = root.join(format!(".vot-probe-{token}.stage"));
        let published = root.join(format!(".vot-probe-{token}.journal"));
        let mut created = (false, false);
        let result = (|| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staging)
                .map_err(|error| fail("create staging file", error))?;
            created.0 = true;
            file.write_all(b"votport")
                .and_then(|()| file.sync_all())
                .map_err(|error| fail("fsync staging file", error))?;
            std::fs::hard_link(&staging, &published)
                .map_err(|error| fail("hard link (the export must support link(2))", error))?;
            created.1 = true;
            let a = std::fs::metadata(&staging).map_err(|error| fail("stat staging", error))?;
            let b = std::fs::metadata(&published).map_err(|error| fail("stat link", error))?;
            // VOT refuses to unlink a staging file it does not own. An
            // idmapping mismatch or a server-side ACL can show the root as
            // uid 1000 while writing new files as another id.
            let euid = rustix::process::geteuid().as_raw();
            if vot_publish && a.uid() != euid {
                return Err(refuse(format!(
                    "a file the server created is owned by uid {} but the server runs as uid {euid}; the export maps its identity to another id (idmapping, ACL, or squashing)",
                    a.uid()
                )));
            }
            if (a.dev(), a.ino()) != (b.dev(), b.ino()) || b.nlink() < 2 {
                return Err(refuse(
                    "a hard link does not share the inode of its source (CIFS needs serverino; some exports never do)".to_owned(),
                ));
            }
            std::fs::File::open(root)
                .and_then(|dir| dir.sync_all())
                .map_err(|error| fail("fsync directory", error))?;
            Ok(())
        })();
        if created.0 {
            let _ = std::fs::remove_file(&staging);
        }
        if created.1 {
            let _ = std::fs::remove_file(&published);
        }
        result
    }
    #[cfg(not(unix))]
    {
        let _ = (root, what, vot_publish);
        Ok(())
    }
}

/// Validates a link destination subdirectory ("" allowed) and returns its
/// normalized relative form.
pub fn admit_dest(dest: &str) -> Result<String, String> {
    let trimmed = dest.trim().trim_matches('/');
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let mut parts = Vec::new();
    for component in trimmed.split('/') {
        let component = component.trim();
        if is_receipt_name(component) {
            return Err("name is reserved for signed receipts".into());
        }
        if component.is_empty() || component == "." || component == ".." {
            return Err(
                "destination folder may not contain empty, '.' or '..' segments".to_owned(),
            );
        }
        if component.len() > 128
            || !component
                .chars()
                .all(|ch| ch.is_alphanumeric() || matches!(ch, '-' | '_' | '.' | ' '))
            || component.starts_with('.')
        {
            return Err(format!(
                "destination segment {component:?}: use letters, digits, '-', '_', '.', ' '"
            ));
        }
        // Audit finding 512: a Windows-exported SMB3 receive tree refuses
        // device names and strips trailing dots, so the configured folder
        // would silently not be the one created. The portable profile
        // decides per segment.
        vot_manifest::PackagePath::portable([component])
            .map_err(|_| format!("destination segment {component:?} is not portable; rename it"))?;
        parts.push(component);
    }
    Ok(parts.join("/"))
}

/// Joins already-admitted components under a base directory. Re-checks each
/// component so a future caller that skipped admission cannot build a path
/// escaping the base; [`admit_component`] remains the policy layer applied to
/// client input.
pub fn join_under(base: &Path, components: &[String]) -> Result<PathBuf, String> {
    let mut path = base.to_path_buf();
    for component in components {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component
                .chars()
                .any(|ch| ch == '/' || ch == '\\' || ch == '\0')
        {
            return Err(format!("unsafe path component {component:?}"));
        }
        path.push(component);
    }
    Ok(path)
}

/// Rejects names that cannot remain distinct on portable recipient filesystems.
pub(crate) fn admit_portable_paths<'a>(
    names: impl IntoIterator<Item = &'a str>,
) -> Result<(), String> {
    use unicode_normalization::UnicodeNormalization as _;
    let mut keyed = Vec::new();
    for name in names {
        crate::protocol_paths::check_payload_name_length(
            name.rsplit('/').next().unwrap_or_default(),
        )?;
        let path = admit_portable_path(name)?;
        let key = vot_manifest::canonical_path_key(&path, vot_manifest::PathProfile::Portable)
            .map_err(|_| format!("filename {name:?} is not portable; rename it before sharing"))?;
        let key = String::from_utf8(key)
            .map_err(|_| format!("filename {name:?} is not portable; rename it before sharing"))?;
        // Preserve VOT's Turkish-I rule and NUL separators while strengthening Unicode folding.
        let folded: String = unicase::UniCase::new(key).to_folded_case().nfc().collect();
        keyed.push((folded.into_bytes(), name));
    }
    keyed.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    for pair in keyed.windows(2) {
        if pair[0].0 == pair[1].0 || vot_manifest::is_path_prefix(&pair[0].0, &pair[1].0) {
            return Err(format!(
                "filenames {:?} and {:?} collide on recipient filesystems; rename one before sharing",
                pair[0].1, pair[1].1
            ));
        }
    }
    Ok(())
}

/// Validates a path with the portable profile without a payload leaf limit.
pub(crate) fn admit_portable_path(name: &str) -> Result<vot_manifest::PackagePath, String> {
    if name.split('/').any(is_receipt_name) {
        return Err(format!(
            "filename {name:?} is reserved for signed receipts; rename it before sharing"
        ));
    }
    let invalid = || format!("filename {name:?} is not portable; rename it before sharing");
    vot_manifest::PackagePath::portable(name.split('/')).map_err(|_| invalid())
}

/// Produces `name`, `name-1`, `name-2`, ... keeping the extension.
pub fn with_suffix(name: &str, attempt: u32) -> String {
    if attempt == 0 {
        return name.to_owned();
    }
    let (stem, extension) = match name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => (stem, Some(extension)),
        _ => (name, None),
    };
    let suffix = match extension {
        Some(extension) => format!("-{attempt}.{extension}"),
        None => format!("-{attempt}"),
    };
    // Audit finding 540: the collision suffix must not push a name that
    // fills the payload budget past it, where the staged file would exceed
    // the on-disk name cap, the create would fail NameTooLong, and every
    // retry would report a permanent internal error. The stem gives up
    // bytes on a char boundary; the suffix keeps the extension. A leaf
    // whose extension alone overflows the budget still refuses at the
    // payload-length check.
    let mut keep = stem
        .len()
        .min(MAX_PAYLOAD_NAME_BYTES.saturating_sub(suffix.len()));
    while !stem.is_char_boundary(keep) {
        keep -= 1;
    }
    format!("{}{}", &stem[..keep], suffix)
}

/// Removes staging files orphaned by a crash or kill. The idle sweep only
/// covers sessions this process created; anything left on disk from a previous
/// boot would otherwise live forever. vot-sdk-file stages each object as
/// `<name>.stage` (plus `<name>.journal` under the Balanced profile) next to
/// its destination, where `<name>` always starts with `.vot-`; push sessions
/// additionally stage under `.vot-push-<session-id>/`.
/// `keep` names staging and journal files a re-attached upload session
/// still owns; everything else VOT-staged under `root` is an orphan.
pub fn clean_staging(root: &Path, keep: &std::collections::HashSet<PathBuf>) {
    // Audit finding 542: the sweep used to match exact case while admission
    // folded it only for some reservations, so an uppercased staging shape
    // could be admitted and then never swept. Lowercase once, like
    // [`crate::protocol_paths::admit_component`] now does.
    #[cfg(unix)]
    fn is_staging_file(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        lower.starts_with(".vot-") && (lower.ends_with(".stage") || lower.ends_with(".journal"))
    }
    #[cfg(not(unix))]
    let _ = (root, keep);
    #[cfg(unix)]
    walk(root, &mut |path, name, is_dir| {
        if is_dir && is_push_staging_name(&name.to_ascii_lowercase()) {
            // `walk` only labels entries as directories using `file_type`, so
            // symlinks are never handed to `remove_dir_all` and never followed.
            if !keep.contains(path) {
                let _ = std::fs::remove_dir_all(path);
            }
            return false;
        }
        if !is_dir && is_staging_file(name) && !keep.contains(path) {
            let _ = std::fs::remove_file(path);
        }
        true
    });
}

#[cfg(unix)]
pub(crate) fn walk(dir: &Path, visit: &mut impl FnMut(&Path, &str, bool) -> bool) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if visit(&path, &name, file_type.is_dir()) && file_type.is_dir() {
            walk(&path, visit);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn portable_names_reject_aliases_and_file_directory_prefixes() {
        for names in [
            vec!["Café.mov", "Cafe\u{301}.mov"],
            vec!["ΣΊΣΥΦΟΣ.mov", "σίσυφος.mov"],
            vec!["ſtraße.mov", "strasse.mov"],
            vec!["Straße.mov", "STRAẞE.mov"],
            vec!["I.mov", "ı.mov"],
            vec!["İ.mov", "i.mov"],
            vec!["folder/Café", "folder/Cafe\u{301}/clip"],
            vec!["foo", "foo-bar", "FOO/child"],
            vec!["foo", "foo.bar", "foo/child"],
            vec!["duplicate", "duplicate"],
        ] {
            for order in [names.clone(), names.into_iter().rev().collect()] {
                assert!(
                    super::admit_portable_paths(order.iter().copied())
                        .unwrap_err()
                        .contains("collide"),
                    "{order:?}"
                );
            }
        }
        for name in [
            "",
            "/a",
            "a//b",
            "a/../b",
            "a\\b",
            "XML:EDL/a",
            "NUL.txt",
            "a.",
            "a ",
        ] {
            assert!(super::admit_portable_paths([name])
                .unwrap_err()
                .contains("not portable"));
        }
        for names in [
            vec!["Café.mov", "Cafe.mov"],
            vec!["a/Café.mov", "b/Cafe\u{301}.mov"],
            vec!["foo", "foobar/child"],
            vec!["foo/one", "foo/two"],
        ] {
            super::admit_portable_paths(names).unwrap();
        }
    }

    #[test]
    fn landing_probe_accepts_a_tight_directory_and_leaves_nothing_behind() {
        let directory = tempfile::tempdir().unwrap();
        super::tighten_dir(directory.path());
        super::probe_landing_dir(directory.path(), "VOTPORT_RECEIVE_DIR", true).unwrap();
        super::probe_landing_dir(directory.path(), "VOTPORT_OUTBOUND_DIR", false).unwrap();
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn landing_probe_names_a_group_writable_directory_only_for_vot_publishes() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o775)).unwrap();
        let error =
            super::probe_landing_dir(directory.path(), "VOTPORT_RECEIVE_DIR", true).unwrap_err();
        assert!(error.starts_with("VOTPORT_RECEIVE_DIR ("), "{error}");
        assert!(
            error.contains("mode 775 is group or world writable"),
            "{error}"
        );
        // The outbound library hard-links but has no parent rules.
        super::probe_landing_dir(directory.path(), "VOTPORT_OUTBOUND_DIR", false).unwrap();
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn landing_probe_refuses_a_symlinked_root_for_both_volumes() {
        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let error = super::probe_landing_dir(&link, "VOTPORT_RECEIVE_DIR", true).unwrap_err();
        assert!(error.contains("symlink"), "{error}");
        let error = super::probe_landing_dir(&link, "VOTPORT_OUTBOUND_DIR", false).unwrap_err();
        assert!(error.contains("symlink"), "{error}");
        // A trailing slash must not let lstat follow the link, for either
        // root (outbound has no mode rule to fail on instead).
        let slashed = std::path::PathBuf::from(format!("{}/", link.display()));
        let error = super::probe_landing_dir(&slashed, "VOTPORT_RECEIVE_DIR", true).unwrap_err();
        assert!(error.contains("symlink"), "{error}");
        let error = super::probe_landing_dir(&slashed, "VOTPORT_OUTBOUND_DIR", false).unwrap_err();
        assert!(error.contains("symlink"), "{error}");
        super::probe_landing_dir(&real, "VOTPORT_OUTBOUND_DIR", false).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn landing_probe_names_a_missing_directory() {
        let directory = tempfile::tempdir().unwrap();
        let error = super::probe_landing_dir(
            &directory.path().join("absent"),
            "VOTPORT_RECEIVE_DIR",
            true,
        )
        .unwrap_err();
        assert!(error.contains("stat:"), "{error}");
    }

    #[test]
    fn probe_names_are_reserved_from_senders_and_swept_as_staging() {
        assert!(super::admit_component(".vot-probe-abc.stage", true).is_err());
        assert!(super::admit_component(".votport-lease", true).is_err());
        assert!(super::admit_component(".VOTPORT-LEASE", true).is_err());
        assert!(super::admit_component(".vot-probe-abc.journal", true).is_err());
        let directory = tempfile::tempdir().unwrap();
        for name in [".vot-probe-abc.stage", ".vot-probe-abc.journal"] {
            std::fs::write(directory.path().join(name), b"x").unwrap();
        }
        super::clean_staging(directory.path(), &std::collections::HashSet::new());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn staging_sweep_folds_case_like_admission() {
        // Audit finding 542: the sweep matched exact case while admission
        // admitted some uppercased spellings, so those files were never
        // swept. Admission now refuses every casing, and the sweep deletes
        // every casing, so the two rules cannot drift apart again.
        let directory = tempfile::tempdir().unwrap();
        for name in [".VOT-PROBE-ABC.STAGE", ".VOT-PROBE-ABC.JOURNAL"] {
            std::fs::write(directory.path().join(name), b"x").unwrap();
        }
        // Push staging sweeps as a directory, like the real sessions create.
        std::fs::create_dir(
            directory
                .path()
                .join(".VOT-PUSH-0123456789ABCDEF0123456789ABCDEF"),
        )
        .unwrap();
        super::clean_staging(directory.path(), &std::collections::HashSet::new());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    use super::*;

    #[cfg(unix)]
    #[test]
    fn private_modes_tighten_existing_regular_files_and_directories() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let directory = tempfile::tempdir().unwrap();
        let private = directory.path().join("private");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o755)).unwrap();
        let file = private.join("secret");
        std::fs::write(&file, b"secret").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();

        tighten_private_dir(&private).unwrap();
        assert_eq!(
            std::fs::metadata(&private).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(tighten_private_file(&file).unwrap());
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let link = directory.path().join("secret-link");
        symlink(&file, &link).unwrap();
        assert!(tighten_private_file(&link).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_tightening_covers_regular_children_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let backups = directory.path().join("backups");
        std::fs::create_dir(&backups).unwrap();
        let snapshot = backups.join("snapshot.db");
        std::fs::write(&snapshot, b"snapshot").unwrap();
        std::fs::set_permissions(&backups, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&snapshot, std::fs::Permissions::from_mode(0o644)).unwrap();

        tighten_private_dir_contents(&backups).unwrap();
        assert_eq!(
            std::fs::metadata(&backups).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(snapshot).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn components_reject_traversal_and_hidden() {
        assert!(admit_component("report.pdf", false).is_ok());
        assert!(admit_component("..", true).is_err());
        assert!(admit_component("a/b", true).is_err());
        assert!(admit_component("a\\b", true).is_err());
        assert!(admit_component(".env", false).is_err());
        assert!(admit_component(".env", true).is_ok());
        assert!(admit_component("", true).is_err());
        // The staging shape is reserved even when hidden names are allowed:
        // the boot sweep deletes exactly these.
        assert!(admit_component(".vot-1a2b-0-3c4d.stage", true).is_err());
        assert!(admit_component(".vot-1a2b-0-3c4d.journal", true).is_err());
        for name in [".vot-stage", ".VOT-STAGE", ".VoT-StAgE"] {
            assert!(admit_component(name, true).is_err());
            assert!(admit_component(name, false).is_err());
        }
        assert!(admit_component(".vot-notes.txt", true).is_ok());
        assert!(admit_component(TENANT_STORAGE_DIR, true).is_err());
        assert!(admit_component(".VOT-TENANTS.STAGE", true).is_err());
        // Audit finding 514: the tenant reservation folds ASCII case only,
        // so a long-s variant never matches it. This refusal comes from the
        // non-ASCII hidden-name rule; pin that rule by its message so a
        // mutant deleting it no longer survives.
        assert!(admit_component(".VOT-TENANTſ.STAGE", true)
            .unwrap_err()
            .contains("non-ASCII hidden names"));
        assert!(admit_component("VOTTEN~1", true).is_err());
        for name in [
            "report.vot-receipt",
            "report.VOT-RECEIPT",
            "report.vot-receI\u{307}pt",
            ".vot-receipt",
            "report.vot-receipt. ",
        ] {
            for hidden in [false, true] {
                assert!(admit_component(name, hidden)
                    .unwrap_err()
                    .contains("reserved for signed receipts"));
            }
            for path in [
                name.to_owned(),
                format!("folder/{name}"),
                format!("{name}/child"),
            ] {
                assert!(admit_dest(&path)
                    .unwrap_err()
                    .contains("reserved for signed receipts"));
                assert!(admit_portable_paths([path.as_str()])
                    .unwrap_err()
                    .contains("reserved for signed receipts"));
            }
        }
    }

    #[test]
    fn dest_normalizes_and_rejects_escape() {
        assert_eq!(admit_dest("").unwrap(), "");
        assert_eq!(admit_dest("/clients/acme/").unwrap(), "clients/acme");
        assert!(admit_dest("a/../b").is_err());
        assert!(admit_dest(".hidden").is_err());
        assert!(admit_dest("a//b").is_err());
    }

    #[test]
    fn dest_refuses_segments_a_windows_share_strips_or_refuses() {
        // Audit finding 512: device names are refused outright and trailing
        // dots (which SMB3 exports strip) are refused before admission.
        for dest in [
            "con",
            "clients/con",
            "notes.",
            "clients/notes.",
            "COM1",
            "nul.txt",
        ] {
            assert!(
                admit_dest(dest).unwrap_err().contains("is not portable"),
                "{dest:?}"
            );
        }
        assert_eq!(admit_dest("notes").unwrap(), "notes");
        assert_eq!(admit_dest("notes backup").unwrap(), "notes backup");
    }

    #[test]
    fn admin_dest_segments_decide_through_the_portable_profile() {
        // Audit finding 545, pinned: the portable profile decides per
        // destination segment, so device names and dot-trailing segments
        // cannot be configured as a link's receive folder even though the
        // segment rules above them would admit the characters.
        for dest in ["con", "nul", "prn", "aux", "com1", "lpt1", "a.", "a.."] {
            assert!(
                admit_dest(dest).unwrap_err().contains("is not portable"),
                "{dest:?}"
            );
        }
    }

    #[test]
    fn portable_payload_names_leave_space_for_receipts() {
        let parent = "p".repeat(255);
        assert!(admit_component(&parent, false).is_ok());
        for name in ["a".repeat(242), format!("{}ab", "ア".repeat(80))] {
            admit_portable_paths([format!("{parent}/{name}").as_str()]).unwrap();
        }
        for name in ["a".repeat(243), "ア".repeat(81)] {
            assert!(admit_portable_paths([format!("{parent}/{name}").as_str()])
                .unwrap_err()
                .contains("242 UTF-8 bytes; shorten"));
        }
    }

    #[test]
    fn suffixes_keep_extensions() {
        assert_eq!(with_suffix("report.pdf", 0), "report.pdf");
        assert_eq!(with_suffix("report.pdf", 2), "report-2.pdf");
        assert_eq!(with_suffix("README", 1), "README-1");
        assert_eq!(with_suffix(".env", 1), ".env-1");
    }

    #[test]
    fn collision_suffixes_stay_within_the_payload_budget() {
        // Audit finding 540: a name that fills the budget used to get a
        // collision suffix past the cap, where the create failed
        // NameTooLong and the session reported a permanent internal error.
        // The suffix now truncates the stem instead, so the retry succeeds.
        let long = "a".repeat(MAX_PAYLOAD_NAME_BYTES);
        let wide = format!("{}ab", "ア".repeat(80));
        let dotted = format!("{}.exr", "a".repeat(MAX_PAYLOAD_NAME_BYTES - 4));
        for name in [&long, &wide, &dotted] {
            for attempt in 1..100u32 {
                let suffixed = with_suffix(name, attempt);
                assert!(suffixed.len() <= MAX_PAYLOAD_NAME_BYTES, "{suffixed:?}");
                assert!(suffixed.is_char_boundary(suffixed.len()), "{suffixed:?}");
                assert_ne!(suffixed, *name);
            }
        }
        // The extension survives truncation.
        assert!(with_suffix(&dotted, 1).ends_with(".exr"));
        // Short names keep the whole stem.
        assert_eq!(with_suffix(&long, 0), long);
        let short = with_suffix("ab", 1);
        assert_eq!(short, "ab-1");
        // A stem that is not a whole number of characters still truncates
        // on a char boundary.
        let mixed = format!("{}b", "ア".repeat(80));
        let suffixed = with_suffix(&mixed, 9);
        assert!(suffixed.len() <= MAX_PAYLOAD_NAME_BYTES);
        assert!(suffixed.starts_with("ア"));
        assert!(suffixed.is_char_boundary(suffixed.len()));
    }

    #[test]
    fn named_tenants_use_the_reserved_subtree() {
        assert!(tenant_prefix("").is_empty());
        assert_eq!(tenant_prefix("acme"), [TENANT_STORAGE_DIR, "acme"]);
        assert!(portable_tenant_key("acme-1_ok"));
        assert!(!portable_tenant_key("Acme"));
        assert!(!portable_tenant_key("café"));
        for key in ["con", "prn", "aux", "nul", "com1", "com9", "lpt1", "lpt9"] {
            assert!(!portable_tenant_key(key), "{key}");
        }
        assert!(portable_tenant_key("com0"));
    }

    #[test]
    fn portable_tenant_key_enforces_the_length_bound_itself() {
        // Audit finding 516: the 128-byte cap used to come from admit_dest
        // via admit_tenant_ref, so calling the helper alone admitted an
        // over-long key.
        assert!(portable_tenant_key(&"a".repeat(128)));
        assert!(!portable_tenant_key(&"a".repeat(129)));
    }

    #[test]
    fn clean_staging_removes_only_vot_stage_files() {
        let directory = tempfile::tempdir().unwrap();
        let nested = directory.path().join("sub");
        std::fs::create_dir(&nested).unwrap();
        let orphan = directory.path().join(".vot-1a2b-0-3c4d.stage");
        let journal = nested.join(".vot-1a2b-1-3c4d.journal");
        let kept = directory.path().join("report.pdf");
        let foreign = directory.path().join(".vot-notes.txt");
        for path in [&orphan, &journal, &kept, &foreign] {
            std::fs::write(path, b"x").unwrap();
        }
        clean_staging(directory.path(), &Default::default());
        assert!(!orphan.exists());
        assert!(!journal.exists());
        assert!(kept.exists());
        assert!(foreign.exists());
    }

    #[test]
    fn clean_staging_removes_push_directories() {
        let directory = tempfile::tempdir().unwrap();
        let push_staging = directory
            .path()
            .join(".vot-push-0123456789abcdef0123456789abcdef");
        std::fs::create_dir_all(push_staging.join("objects")).unwrap();
        std::fs::write(push_staging.join("objects/file.stage"), b"x").unwrap();
        let foreign = directory.path().join(".vot-push-session");
        std::fs::create_dir_all(foreign.join("objects")).unwrap();

        clean_staging(directory.path(), &Default::default());

        assert!(!push_staging.exists());
        assert!(foreign.exists());
    }

    #[test]
    fn push_staging_names_are_never_admitted() {
        assert!(admit_component(".vot-push-0123456789abcdef0123456789abcdef", true).is_err());
        assert!(admit_component(".vot-push-sender", true).is_ok());
        assert!(admit_component(".vot-push-0123456789abcdef0123456789abcde", true).is_ok());
        // Audit finding 542: the push shape folds case like every other
        // reservation, so an uppercased key is refused too.
        assert!(admit_component(".vot-push-0123456789ABCDEF0123456789abcdef", true).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn clean_staging_does_not_follow_push_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("keep");
        std::fs::write(&outside_file, b"x").unwrap();
        symlink(
            outside.path(),
            directory
                .path()
                .join(".vot-push-0123456789abcdef0123456789abcdef"),
        )
        .unwrap();

        clean_staging(directory.path(), &Default::default());

        assert!(std::fs::symlink_metadata(
            directory
                .path()
                .join(".vot-push-0123456789abcdef0123456789abcdef"),
        )
        .unwrap()
        .file_type()
        .is_symlink());
        assert!(outside_file.exists());
    }

    #[test]
    fn join_under_refuses_escape_attempts() {
        let base = Path::new("/receive");
        let ok = |parts: &[&str]| {
            let owned: Vec<String> = parts.iter().map(|p| (*p).to_owned()).collect();
            join_under(base, &owned)
        };
        assert_eq!(ok(&["a", "b.txt"]).unwrap(), Path::new("/receive/a/b.txt"));
        for bad in [
            vec![".."],
            vec!["a", ".."],
            vec![""],
            vec!["."],
            vec!["a/b"],
            vec!["a\\b"],
        ] {
            let components: Vec<String> = bad.iter().map(|p| (*p).to_owned()).collect();
            assert!(join_under(base, &components).is_err(), "{bad:?}");
        }
    }
}

#[cfg(test)]
#[test]
fn mounted_share_profile_preserves_local_assurance() {
    assert_eq!(profile_for_mount(true), vot_sdk_file::CommitProfile::Fast);
    assert_eq!(
        profile_for_mount(false),
        vot_sdk_file::CommitProfile::Balanced
    );
    let directory = tempfile::tempdir().unwrap();
    assert_eq!(
        commit_profile(&directory.path().join("file")).unwrap(),
        vot_sdk_file::CommitProfile::Balanced
    );
    #[cfg(target_os = "linux")]
    assert!(commit_profile(&directory.path().join("missing/file")).is_err());
}

#[cfg(test)]
#[test]
fn verification_levels_resolve_per_documented_qualification() {
    // Finding 24: "default" keeps today's receive choice, "balanced" pins
    // it, and "strict" is refused on NAS instead of silently downgrading.
    for level in ["default", "balanced"] {
        assert_eq!(
            verification_for_mount(false, level).unwrap(),
            vot_sdk_file::CommitProfile::Balanced
        );
        assert_eq!(
            verification_for_mount(true, level).unwrap(),
            vot_sdk_file::CommitProfile::Balanced
        );
    }
    assert_eq!(
        verification_for_mount(false, "strict").unwrap(),
        vot_sdk_file::CommitProfile::Strict
    );
    assert_eq!(
        verification_for_mount(true, "strict").unwrap_err(),
        "strict verification is not offered for network storage destinations"
    );
    assert!(verification_for_mount(false, "fast").is_err());
}

#[cfg(test)]
#[test]
fn verification_profile_probes_the_destination_mount() {
    let directory = tempfile::tempdir().unwrap();
    // A local destination honors strict, including through directories that
    // do not exist yet (link creation runs before any session).
    assert_eq!(
        verification_profile(&directory.path().join("new/file"), "strict").unwrap(),
        vot_sdk_file::CommitProfile::Strict
    );
    assert_eq!(
        verification_profile(&directory.path().join("new/file"), "default").unwrap(),
        vot_sdk_file::CommitProfile::Balanced
    );
    assert_eq!(
        verification_profile(directory.path(), "nonsense").unwrap_err(),
        "unknown verification level \"nonsense\""
    );
}
