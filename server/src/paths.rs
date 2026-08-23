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
    !key.is_empty()
        && key.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
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
        .any(|ch| ch == '/' || ch == '\\' || ch == '\0' || ch <= '\u{1f}')
    {
        return Err("path component contains a separator or control character".to_owned());
    }
    if !allow_hidden && component.starts_with('.') {
        return Err(
            "hidden file names are not accepted (VOTPORT_ALLOW_HIDDEN=1 to allow)".to_owned(),
        );
    }
    // Reserved even with VOTPORT_ALLOW_HIDDEN: a sender file of this shape
    // would publish fine and then be deleted by the next boot's staging sweep.
    if component.eq_ignore_ascii_case(TENANT_STORAGE_DIR) {
        return Err("name is reserved for tenant storage".to_owned());
    }
    if component.starts_with(".vot-")
        && (component.ends_with(".stage") || component.ends_with(".journal"))
    {
        return Err("name is reserved for votport staging files".to_owned());
    }
    Ok(())
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
/// its destination, where `<name>` always starts with `.vot-`; nothing else
/// matches that shape.
pub fn clean_staging(root: &Path) {
    #[cfg(unix)]
    fn is_staging(name: &str) -> bool {
        name.starts_with(".vot-") && (name.ends_with(".stage") || name.ends_with(".journal"))
    }
    #[cfg(not(unix))]
    let _ = root;
    #[cfg(unix)]
    walk(root, &mut |path, name| {
        if is_staging(name) {
            let _ = std::fs::remove_file(path);
        }
    });
}

#[cfg(unix)]
fn walk(dir: &Path, visit: &mut impl FnMut(&Path, &str)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        match entry.file_type() {
            Ok(file_type) if file_type.is_dir() => {
                walk(&entry.path(), visit);
            }
            Ok(_) => visit(&entry.path(), &name),
            Err(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        clean_staging(directory.path());
        assert!(!orphan.exists());
        assert!(!journal.exists());
        assert!(kept.exists());
        assert!(foreign.exists());
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
