pub(crate) const MAX_PAYLOAD_NAME_BYTES: usize = 255 - ".vot-".len() - ".journal".len();

/// Private subtree for named tenants. Package paths can never name it, so
/// the default tenant and named tenants cannot collide on disk.
pub const TENANT_STORAGE_DIR: &str = ".vot-tenants.stage";

/// The instance lease file, reserved in every package path.
pub const LEASE_FILE_NAME: &str = ".votport-lease";

pub(crate) fn check_payload_name_length(name: &str) -> Result<(), String> {
    if name.len() <= MAX_PAYLOAD_NAME_BYTES {
        Ok(())
    } else {
        Err(format!(
            "filename {name:?} exceeds {MAX_PAYLOAD_NAME_BYTES} UTF-8 bytes; shorten it to leave room for its signed receipt and receive journal"
        ))
    }
}

pub(crate) fn is_receipt_name(component: &str) -> bool {
    let Some((_, extension)) = component.trim_end_matches(['.', ' ']).rsplit_once('.') else {
        return false;
    };
    if extension.is_ascii() {
        return extension.eq_ignore_ascii_case("vot-receipt");
    }
    vot_manifest::PackagePath::portable([extension])
        .ok()
        .and_then(|path| {
            vot_manifest::canonical_path_key(&path, vot_manifest::PathProfile::Portable).ok()
        })
        .is_some_and(|key| key == b"vot-receipt")
}

/// Whether a name is `.vot-push-<32 hex>`, the push staging shape.
pub(crate) fn is_push_staging_name(name: &str) -> bool {
    let Some(session) = name.strip_prefix(".vot-push-") else {
        return false;
    };
    session.len() == 32
        && session
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Validates one package path component for on-disk placement. This is the
/// one implementation both ends run: the server before any path touches the
/// disk, and the client before a drop hashes gigabytes the server would
/// refuse at begin.
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
    if is_receipt_name(component) {
        return Err("name is reserved for signed receipts".into());
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
    if component.eq_ignore_ascii_case(".votport-workflows") {
        return Err("name is reserved for delivery workflows".into());
    }
    if component.eq_ignore_ascii_case(TENANT_STORAGE_DIR) {
        return Err("name is reserved for the port's own files".to_owned());
    }
    if component.eq_ignore_ascii_case(LEASE_FILE_NAME) {
        return Err("name is reserved for the port's own files".to_owned());
    }
    if component.eq_ignore_ascii_case(".vot-stage")
        || is_push_staging_name(component)
        || (component.starts_with(".vot-")
            && (component.ends_with(".stage") || component.ends_with(".journal")))
    {
        return Err("name is reserved for the port's own files".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        admit_component, check_payload_name_length, is_push_staging_name, is_receipt_name,
        LEASE_FILE_NAME, TENANT_STORAGE_DIR,
    };

    #[test]
    fn payload_name_length_counts_utf8_bytes() {
        for name in ["a".repeat(242), format!("{}ab", "ア".repeat(80))] {
            assert!(check_payload_name_length(&name).is_ok(), "{name:?}");
        }
        for name in ["a".repeat(243), "ア".repeat(81)] {
            let error = check_payload_name_length(&name).unwrap_err();
            assert!(error.contains("242 UTF-8 bytes; shorten"));
            assert!(error.contains(&format!("{name:?}")));
        }
    }

    #[test]
    fn receipt_names_follow_portable_aliases() {
        for name in [
            ".vot-receipt",
            "report.pdf.vot-receipt",
            "report.VOT-RECEIPT",
            "report.vot-receİpt",
            "report.vot-receıpt",
            "report.vot-receI\u{307}pt",
            "report.vot-receipt. ",
        ] {
            assert!(is_receipt_name(name), "{name:?}");
        }
        for name in [
            "",
            "report.pdf",
            "vot-receipt",
            "report.vot-receipt.backup",
            "report.vot-receipt-1",
            "report.vot-receipts",
            "report.récépissé",
            "report.é\0",
        ] {
            assert!(!is_receipt_name(name), "{name:?}");
        }
    }

    /// The full shared reject list, including the case sensitivity of each
    /// rule: the staging suffixes are exact-case (the boot sweep deletes
    /// exactly that shape), while the whole-name reservations fold case. The
    /// server and the client run this one implementation, so this table is
    /// the contract both ends ship. The housekeeping reservations (tenant
    /// subtree, lease, staging) share one plain refusal so neither end names
    /// server internals to senders; the message no longer tells the rules
    /// apart, only that each name is refused.
    #[test]
    fn admission_rejects_exactly_the_shared_reserved_list() {
        let rejected: &[(&str, bool, &str)] = &[
            ("", true, "empty or oversized"),
            (&"a".repeat(256), true, "empty or oversized"),
            (".", true, "directory reference"),
            ("..", true, "directory reference"),
            ("a/b", true, "separator"),
            ("a\\b", true, "separator"),
            ("a~b", true, "separator"),
            ("a\u{1}b", true, "separator"),
            ("report.vot-receipt", true, "signed receipts"),
            ("REPORT.PDF.VOT-RECEIPT", true, "signed receipts"),
            (".secret", false, "hidden file names are not accepted"),
            (".café", true, "non-ASCII hidden names are reserved"),
            (".votport-workflows", true, "delivery workflows"),
            (".VOTPORT-WORKFLOWS", true, "delivery workflows"),
            (TENANT_STORAGE_DIR, true, "port's own files"),
            (".VOT-TENANTS.STAGE", true, "port's own files"),
            (
                ".VOT-TENANTſ.STAGE",
                true,
                "non-ASCII hidden names are reserved",
            ),
            (LEASE_FILE_NAME, true, "port's own files"),
            (".VOTPORT-LEASE", true, "port's own files"),
            (".vot-stage", true, "port's own files"),
            (".VOT-STAGE", true, "port's own files"),
            (".vot-1a2b-0-3c4d.stage", true, "port's own files"),
            (".vot-1a2b-0-3c4d.journal", true, "port's own files"),
            (
                ".vot-push-0123456789abcdef0123456789abcdef",
                true,
                "port's own files",
            ),
        ];
        for (name, hidden, needle) in rejected {
            let error = admit_component(name, *hidden).unwrap_err();
            assert!(error.contains(needle), "{name:?}: {error}");
        }
        // The staging suffix rule is exact-case, matching the sweep, and the
        // push shape needs 32 lowercase hex digits; near misses are admitted
        // (hidden rules permitting).
        let admitted: &[(&str, bool)] = &[
            ("report.pdf", false),
            (".env", true),
            (".vot-notes.txt", true),
            (".vot-X.STAGE", true),
            (".vot-X.JOURNAL", true),
            (".vot-notes.id", true),
            (".vot-notes.lease", true),
            (".vot-push-sender", true),
            (".vot-push-0123456789abcdef0123456789abcde", true),
            (".vot-push-0123456789ABCDEF0123456789abcdef", true),
        ];
        for (name, hidden) in admitted {
            assert!(admit_component(name, *hidden).is_ok(), "{name:?}");
        }
        // The push staging shape is exact: only 32 lowercase hex digits.
        assert!(!is_push_staging_name(
            ".VOT-PUSH-0123456789ABCDEF0123456789ABCDEF"
        ));
        assert!(is_push_staging_name(
            ".vot-push-0123456789abcdef0123456789abcdef"
        ));
    }
}
