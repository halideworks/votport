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
    use super::is_receipt_name;

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
