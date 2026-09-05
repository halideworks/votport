//! Turning a drop of files and folders into named package entries.
//!
//! The client refuses a bad name before it hashes gigabytes, so a drop fails
//! in milliseconds rather than after a long hash that the server would reject
//! at begin. Two authorities decide a name: vot-manifest's portable profile,
//! applied by building a [`PackagePath`], and votport's own `admit_component`
//! (the rule the server applies at begin), ported here. The check is the
//! union; the server re-checks everything.

use std::path::PathBuf;

use vot_manifest::{Component, PackagePath};

/// The `/`-joined display form of a portable package path, for messages and
/// journal rows. A raw (byte) component is shown lossily; the client only
/// ever builds portable paths.
#[must_use]
pub fn display_path(path: &PackagePath) -> String {
    let parts: Vec<String> = path
        .iter()
        .map(|component| match component {
            Component::Text(text) => text.clone(),
            Component::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        })
        .collect();
    parts.join("/")
}

/// The reserved tenant-storage directory name, from votport's `paths` module.
const TENANT_STORAGE_DIR: &str = ".vot-tenants.stage";

/// A file selected for a drop: the path it takes in the package, and the file
/// on disk that holds its bytes.
#[derive(Debug, Clone)]
pub struct Entry {
    pub path: PackagePath,
    pub source: PathBuf,
}

/// Why a selected file cannot be part of a drop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    /// The path as the caller gave it, for the message.
    pub path: String,
    pub reason: String,
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.path, self.reason)
    }
}

/// Whether a name is `.vot-push-<32 hex>`, the push staging shape.
fn is_push_staging_name(name: &str) -> bool {
    match name.strip_prefix(".vot-push-") {
        Some(rest) => {
            rest.len() == 32
                && rest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }
        None => false,
    }
}

/// votport's per-component policy, the rule the server applies at begin.
///
/// This is the delta over vot-manifest's portable profile: the hidden-name
/// gate, the DOS alias marker `~`, and the reserved staging names. It is
/// ported from `server/src/paths.rs::admit_component` so a name that would
/// fail at begin fails here first, before any bytes are read.
fn admit_component(component: &str, allow_hidden: bool) -> Result<(), String> {
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
        return Err("hidden file names are not accepted here".to_owned());
    }
    if component.starts_with('.') && !component.is_ascii() {
        return Err("non-ASCII hidden names are reserved for portable storage".to_owned());
    }
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

/// Validates a single relative path and turns it into an [`Entry`].
///
/// `relative` is the package path with `/` separators (a folder drop keeps its
/// top folder, as the browser's `webkitRelativePath` does). Empty components
/// are dropped, as the web sender drops them.
///
/// # Errors
/// A component the server would refuse at begin, or a path vot-manifest's
/// portable profile refuses.
pub fn admit(relative: &str, source: PathBuf, allow_hidden: bool) -> Result<Entry, Rejected> {
    let components: Vec<&str> = relative
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    if components.is_empty() {
        return Err(Rejected {
            path: relative.to_owned(),
            reason: "path has no name".to_owned(),
        });
    }
    for component in &components {
        admit_component(component, allow_hidden).map_err(|reason| Rejected {
            path: relative.to_owned(),
            reason,
        })?;
    }
    // vot-manifest's portable profile is the other authority: forbidden
    // characters, trailing dot or space, NFKC directory references, and
    // Windows device names. Building the path applies all of them.
    let path =
        PackagePath::portable(components.iter().map(|part| (*part).to_owned())).map_err(|_| {
            Rejected {
                path: relative.to_owned(),
                reason: "not a portable path (a reserved character, name, or shape)".to_owned(),
            }
        })?;
    Ok(Entry { path, source })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> PathBuf {
        PathBuf::from("/dev/null")
    }

    #[test]
    fn admits_an_ordinary_nested_path() {
        let entry = admit("frames/0001.exr", source(), false).expect("admitted");
        assert_eq!(display_path(&entry.path), "frames/0001.exr");
    }

    #[test]
    fn refuses_the_component_rules_the_server_applies() {
        // Each row is the votport-specific policy that vot-manifest's portable
        // profile does not cover, so a mutant of admit_component is caught by
        // a real refusal rather than only by PackagePath::portable.
        let cases = [
            ("a/../b", false, "directory reference"),
            (
                "a/~b/c",
                false,
                "separator, control character, or DOS alias",
            ),
            (".secret", false, "hidden file names are not accepted"),
            (".vot-tenants.stage", true, "reserved for tenant storage"),
            (
                ".vot-push-00112233445566778899aabbccddeeff",
                true,
                "reserved for votport staging",
            ),
            (
                ".vot-anything.journal",
                true,
                "reserved for votport staging",
            ),
        ];
        for (path, allow_hidden, needle) in cases {
            let rejected = admit(path, source(), allow_hidden).expect_err(path);
            assert!(
                rejected.reason.contains(needle),
                "{path:?} gave {:?}, wanted {needle:?}",
                rejected.reason
            );
        }
    }

    #[test]
    fn allows_a_dotfile_only_when_hidden_is_allowed() {
        assert!(admit(".env", source(), false).is_err());
        assert!(admit(".env", source(), true).is_ok());
        // A non-ASCII dotfile is reserved even when hidden names are allowed.
        assert!(admit(".café", source(), true).is_err());
    }

    #[test]
    fn refuses_what_the_portable_profile_refuses() {
        // These pass admit_component but PackagePath::portable refuses them:
        // a forbidden character, a trailing dot, and a Windows device name.
        for path in ["a<b", "trailing.", "nul", "com1"] {
            assert!(
                admit(path, source(), false).is_err(),
                "{path:?} was admitted"
            );
        }
    }

    #[test]
    fn drops_empty_components_like_the_web_sender() {
        let entry = admit("a//b/", source(), false).expect("admitted");
        assert_eq!(display_path(&entry.path), "a/b");
    }
}
