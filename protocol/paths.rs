pub(crate) const MAX_PAYLOAD_NAME_BYTES: usize = 255 - ".vot-receipt".len();

pub(crate) fn check_payload_name_length(name: &str) -> Result<(), String> {
    if name.len() <= MAX_PAYLOAD_NAME_BYTES {
        Ok(())
    } else {
        Err(format!(
            "filename {name:?} exceeds {MAX_PAYLOAD_NAME_BYTES} UTF-8 bytes; shorten it to leave room for its signed receipt"
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

#[cfg(test)]
mod tests {
    use super::{check_payload_name_length, is_receipt_name};

    #[test]
    fn payload_name_length_counts_utf8_bytes() {
        for name in ["a".repeat(242), "a".repeat(243), "ア".repeat(81)] {
            assert!(check_payload_name_length(&name).is_ok(), "{name:?}");
        }
        for name in [
            "a".repeat(244),
            format!("{}a", "ア".repeat(81)),
            "ア".repeat(82),
        ] {
            let error = check_payload_name_length(&name).unwrap_err();
            assert!(error.contains("243 UTF-8 bytes; shorten"));
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
}
