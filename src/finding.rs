use std::{cmp::Ordering, fmt};

use serde::{Deserialize, Serialize};

use crate::severity::Severity;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RuleId(String);

impl RuleId {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidRuleId> {
        let value = value.into();
        let valid = !value.is_empty()
            && value
                .split('-')
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()));
        if valid {
            Ok(Self(value))
        } else {
            Err(InvalidRuleId)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidRuleId;

impl fmt::Display for InvalidRuleId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("rule ID must be lowercase kebab-case")
    }
}

impl std::error::Error for InvalidRuleId {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub rule_id: RuleId,
    pub severity: Severity,
    pub confidence: u8,
    pub path: String,
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub redacted: String,
    pub message: String,
}

impl Ord for Finding {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .severity
            .cmp(&self.severity)
            .then_with(|| self.path.as_bytes().cmp(other.path.as_bytes()))
            .then_with(|| self.line.cmp(&other.line))
            .then_with(|| self.column.cmp(&other.column))
            .then_with(|| self.rule_id.cmp(&other.rule_id))
            .then_with(|| self.redacted.cmp(&other.redacted))
    }
}

impl PartialOrd for Finding {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort();
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub files_considered: usize,
    pub files_scanned: usize,
    pub findings_total: usize,
    pub findings_blocking: usize,
    pub skipped_binary: usize,
    pub skipped_invalid_utf8: usize,
    pub skipped_oversized: usize,
    pub skipped_symlink: usize,
    pub skipped_submodule: usize,
    pub skipped_excluded: usize,
    pub skipped_ignored: usize,
}

impl ScanSummary {
    pub const fn skipped_total(&self) -> usize {
        self.skipped_binary
            + self.skipped_invalid_utf8
            + self.skipped_oversized
            + self.skipped_symlink
            + self.skipped_submodule
            + self.skipped_excluded
            + self.skipped_ignored
    }
}

#[cfg(test)]
mod tests {
    use super::{Finding, RuleId, sort_findings};
    use crate::severity::Severity;

    fn finding(severity: Severity, path: &str, line: usize, rule: &str) -> Finding {
        Finding {
            rule_id: RuleId::new(rule).expect("valid ID"),
            severity,
            confidence: 90,
            path: path.to_owned(),
            line,
            column: 1,
            end_line: line,
            end_column: 2,
            redacted: "ab??yz".to_owned(),
            message: "safe message".to_owned(),
        }
    }

    #[test]
    fn rule_id_validation_is_strict() {
        assert!(RuleId::new("github-token").is_ok());
        for invalid in ["", "GitHub-token", "github--token", "-token", "token-"] {
            assert!(RuleId::new(invalid).is_err());
        }
    }

    #[test]
    fn sort_order_is_stable_and_severity_descending() {
        let mut findings = vec![
            finding(Severity::Medium, "z.rs", 1, "jwt-token"),
            finding(Severity::High, "b.rs", 2, "github-token"),
            finding(Severity::High, "a.rs", 4, "gitlab-token"),
            finding(Severity::High, "a.rs", 2, "github-token"),
        ];
        sort_findings(&mut findings);
        let keys: Vec<_> = findings
            .iter()
            .map(|item| (item.severity, item.path.as_str(), item.line))
            .collect();
        assert_eq!(
            keys,
            vec![
                (Severity::High, "a.rs", 2),
                (Severity::High, "a.rs", 4),
                (Severity::High, "b.rs", 2),
                (Severity::Medium, "z.rs", 1),
            ]
        );
    }

    #[test]
    fn serialized_finding_has_no_raw_candidate_field() {
        let finding = finding(Severity::High, "src/lib.rs", 1, "github-token");
        let value = serde_json::to_value(finding).expect("serialize finding");
        let object = value.as_object().expect("finding object");
        assert!(object.contains_key("redacted"));
        assert!(!object.contains_key("candidate"));
        assert!(!object.contains_key("raw"));
        assert!(!object.contains_key("value"));
    }
}
