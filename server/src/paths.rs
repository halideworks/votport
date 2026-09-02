//! Filesystem path admission for received files.
//!
//! The VOT manifest layer already rejects traversal (no "/", "\", ".", "..",
//! control characters, trailing dots). These checks are defense in depth plus
//! votport policy (hidden files off by default), applied before any path
//! touches the disk.

use std::path::{Path, PathBuf};

/// Private subtree for named tenants. Package paths can never name it, so
/// the default tenant and named tenants cannot collide on disk.
pub const TENANT_STORAGE_DIR: &str = ".vot-tenants.stage";

pub fn tenant_prefix(key: &str) -> Vec<String> {
    if key.is_empty() {
        Vec::new()
    } else {
        vec![TENANT_STORAGE_DIR.to_owned(), key.to_owned()]
    }
}

pub fn portable_tenant_key(key: &str) -> bool {
    if key.is_empty()
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

/// Validates one package path component for on-disk placement.
pub fn admit_component(component: &str, allow_hidden: bool) -> Result<(), String> {
    if component.is_empty() || component.len() > 255 {
        return Err("empty or oversized path component".to_owned());
    }
    if component == "." || component == ".." {
        return Err("path component is a directory reference".to_owned());
    }
    if component
        .chars()
        .any(|ch| ch == '/' || ch == '\\' || ch == '~' || ch == '\0' || ch <= '\u{1f}')
    {
        return Err(
            "path component contains a separator, control character, or DOS alias marker"
                .to_owned(),
        );
    }
    if !allow_hidden && component.starts_with('.') {
        return Err(
            "hidden file names are not accepted (VOTPORT_ALLOW_HIDDEN=1 to allow)".to_owned(),
        );
    }
    if component.starts_with('.') && !component.is_ascii() {
        return Err("non-ASCII hidden names are reserved for portable storage".to_owned());
    }
    // Reserved even with VOTPORT_ALLOW_HIDDEN: a sender file of this shape
    // would publish fine and then be deleted by the next boot's staging sweep.
    if component.eq_ignore_ascii_case(TENANT_STORAGE_DIR) {
        return Err("name is reserved for tenant storage".to_owned());
    }
    if is_push_staging_name(component)
        || (component.starts_with(".vot-")
            && (component.ends_with(".stage") || component.ends_with(".journal")))
    {
        return Err("name is reserved for votport staging files".to_owned());
    }
    Ok(())
}

fn is_push_staging_name(name: &str) -> bool {
    let Some(session) = name.strip_prefix(".vot-push-") else {
        return false;
    };
    session.len() == 32
        && session
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
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

/// Produces `name`, `name-1`, `name-2`, ... keeping the extension.
pub fn with_suffix(name: &str, attempt: u32) -> String {
    if attempt == 0 {
        return name.to_owned();
    }
    match name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => {
            format!("{stem}-{attempt}.{extension}")
        }
        _ => format!("{name}-{attempt}"),
    }
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
    #[cfg(unix)]
    fn is_staging_file(name: &str) -> bool {
        name.starts_with(".vot-") && (name.ends_with(".stage") || name.ends_with(".journal"))
    }
    #[cfg(not(unix))]
    let _ = (root, keep);
    #[cfg(unix)]
    walk(root, &mut |path, name, is_dir| {
        if is_dir && is_push_staging_name(name) {
            // `walk` only labels entries as directories using `file_type`, so
            // symlinks are never handed to `remove_dir_all` and never followed.
            let _ = std::fs::remove_dir_all(path);
            return false;
        }
        if !is_dir && is_staging_file(name) && !keep.contains(path) {
            let _ = std::fs::remove_file(path);
        }
        true
    });
}

#[cfg(unix)]
fn walk(dir: &Path, visit: &mut impl FnMut(&Path, &str, bool) -> bool) {
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
        assert!(super::admit_component(".vot-probe-abc.journal", true).is_err());
        let directory = tempfile::tempdir().unwrap();
        for name in [".vot-probe-abc.stage", ".vot-probe-abc.journal"] {
            std::fs::write(directory.path().join(name), b"x").unwrap();
        }
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
        assert!(admit_component(".vot-notes.txt", true).is_ok());
        assert!(admit_component(TENANT_STORAGE_DIR, true).is_err());
        assert!(admit_component(".VOT-TENANTS.STAGE", true).is_err());
        assert!(admit_component(".VOT-TENANTſ.STAGE", true).is_err());
        assert!(admit_component("VOTTEN~1", true).is_err());
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
    fn suffixes_keep_extensions() {
        assert_eq!(with_suffix("report.pdf", 0), "report.pdf");
        assert_eq!(with_suffix("report.pdf", 2), "report-2.pdf");
        assert_eq!(with_suffix("README", 1), "README-1");
        assert_eq!(with_suffix(".env", 1), ".env-1");
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
        assert!(admit_component(".vot-push-0123456789ABCDEF0123456789abcdef", true).is_ok());
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
