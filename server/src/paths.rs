//! Filesystem path admission for received files.
//!
//! The VOT manifest layer already rejects traversal (no "/", "\", ".", "..",
//! control characters, trailing dots). These checks are defense in depth plus
//! votport policy (hidden files off by default), applied before any path
//! touches the disk.

use std::path::{Path, PathBuf};

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

/// Joins already-admitted components under a base directory.
pub fn join_under(base: &Path, components: &[String]) -> PathBuf {
    let mut path = base.to_path_buf();
    for component in components {
        path.push(component);
    }
    path
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
}
