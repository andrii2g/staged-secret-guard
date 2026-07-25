use std::fmt::Write;

use crate::scan::{ScanResult, file_input::ScanMode};

pub fn render(result: &ScanResult, quiet: bool) -> String {
    if result.findings.is_empty() {
        if quiet {
            return String::new();
        }
        return format!(
            "Secret Guard: no blocking secrets found.\nScanned {} files; 0 findings; {} skipped.\n",
            result.summary.files_scanned,
            result.summary.skipped_total()
        );
    }

    let mut output = String::new();
    if result.summary.findings_blocking > 0 {
        match result.mode {
            ScanMode::Staged => output.push_str("Secret Guard blocked the commit.\n\n"),
            ScanMode::Folder => output.push_str("Secret Guard found blocking secrets.\n\n"),
        }
    } else {
        output.push_str("Secret Guard found findings below the blocking threshold.\n\n");
    }

    for finding in &result.findings {
        let _ = writeln!(
            output,
            "[{}] {}",
            finding.severity.to_string().to_ascii_uppercase(),
            finding.rule_id
        );
        let _ = writeln!(
            output,
            "Path: {}:{}:{}",
            finding.path, finding.line, finding.column
        );
        let _ = writeln!(output, "Reason: {}", finding.message);
        let _ = writeln!(output, "Value: {}\n", finding.redacted);
    }
    let _ = writeln!(
        output,
        "Summary: {} findings; {} blocking; {} files scanned; {} skipped.",
        result.summary.findings_total,
        result.summary.findings_blocking,
        result.summary.files_scanned,
        result.summary.skipped_total()
    );
    output
}

#[cfg(test)]
mod tests {
    use super::render;
    use crate::{
        finding::{Finding, RuleId, ScanSummary},
        scan::{ScanResult, file_input::ScanMode},
        severity::Severity,
    };

    #[test]
    fn clean_and_finding_shapes_are_stable() {
        let clean = ScanResult {
            mode: ScanMode::Folder,
            root: ".".to_owned(),
            findings: Vec::new(),
            summary: ScanSummary {
                files_scanned: 2,
                ..ScanSummary::default()
            },
        };
        assert_eq!(render(&clean, true), "");
        assert!(render(&clean, false).starts_with("Secret Guard: no blocking"));

        let finding = Finding {
            rule_id: RuleId::new("generic-secret-assignment").expect("valid ID"),
            severity: Severity::High,
            confidence: 80,
            path: "src/config.rs".to_owned(),
            line: 3,
            column: 4,
            end_line: 3,
            end_column: 20,
            redacted: "ab\u{2022}\u{2022}\u{2022}\u{2022}yz".to_owned(),
            message: "safe reason".to_owned(),
        };
        let report = ScanResult {
            mode: ScanMode::Folder,
            root: ".".to_owned(),
            findings: vec![finding],
            summary: ScanSummary {
                files_scanned: 1,
                findings_total: 1,
                findings_blocking: 1,
                ..ScanSummary::default()
            },
        };
        let rendered = render(&report, false);
        assert!(rendered.contains("[HIGH] generic-secret-assignment"));
        assert!(rendered.contains("Path: src/config.rs:3:4"));
        assert!(!rendered.contains("source line"));
    }
}
