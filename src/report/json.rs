use serde::Serialize;

use crate::{
    finding::Finding,
    scan::{ScanResult, file_input::ScanMode},
    severity::Severity,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonReport<'a> {
    schema_version: u8,
    mode: ScanMode,
    root: &'a str,
    threshold: Severity,
    summary: JsonSummary,
    findings: &'a [Finding],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonSummary {
    files_considered: usize,
    files_scanned: usize,
    findings_total: usize,
    findings_blocking: usize,
    skipped: JsonSkipped,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonSkipped {
    binary: usize,
    invalid_utf8: usize,
    oversized: usize,
    symlink: usize,
    submodule: usize,
    excluded: usize,
    ignored: usize,
}

pub fn render(result: &ScanResult, threshold: Severity) -> Result<Vec<u8>, serde_json::Error> {
    let summary = &result.summary;
    let report = JsonReport {
        schema_version: 1,
        mode: result.mode,
        root: &result.root,
        threshold,
        summary: JsonSummary {
            files_considered: summary.files_considered,
            files_scanned: summary.files_scanned,
            findings_total: summary.findings_total,
            findings_blocking: summary.findings_blocking,
            skipped: JsonSkipped {
                binary: summary.skipped_binary,
                invalid_utf8: summary.skipped_invalid_utf8,
                oversized: summary.skipped_oversized,
                symlink: summary.skipped_symlink,
                submodule: summary.skipped_submodule,
                excluded: summary.skipped_excluded,
                ignored: summary.skipped_ignored,
            },
        },
        findings: &result.findings,
    };
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::render;
    use crate::{
        finding::ScanSummary,
        scan::{ScanResult, file_input::ScanMode},
        severity::Severity,
    };

    #[test]
    fn schema_has_stable_version_mode_and_nested_skips() {
        let result = ScanResult {
            mode: ScanMode::Folder,
            root: ".".to_owned(),
            findings: Vec::new(),
            summary: ScanSummary {
                skipped_binary: 1,
                ..ScanSummary::default()
            },
        };
        let bytes = render(&result, Severity::High).expect("render JSON");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("parse JSON");
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["mode"], "folder");
        assert_eq!(value["root"], ".");
        assert_eq!(value["summary"]["skipped"]["binary"], 1);
        assert!(value.get("timestamp").is_none());
    }
}
