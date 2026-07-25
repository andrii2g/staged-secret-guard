use std::collections::HashSet;

use thiserror::Error;

use crate::{
    config::Config,
    finding::{Finding, RuleId, ScanSummary, sort_findings},
    rules::{generic, pem, provider, suspicious_path},
    scan::{
        file_input::{FileInput, LineRange},
        text::{CandidateMatch, PreparedText, SkipReason, redact},
    },
};

pub struct ScannerEngine<'a> {
    config: &'a Config,
}

impl<'a> ScannerEngine<'a> {
    pub const fn new(config: &'a Config) -> Self {
        Self { config }
    }

    pub fn scan_file(
        &self,
        input: &FileInput,
        summary: &mut ScanSummary,
    ) -> Result<Vec<Finding>, EngineError> {
        summary.files_considered += 1;
        if self.config.is_excluded(&input.relative_path) {
            summary.skipped_excluded += 1;
            return Ok(Vec::new());
        }

        let mut findings = Vec::new();
        if let Some(path_match) = suspicious_path::detect(&input.relative_path) {
            let rule_id =
                RuleId::new("suspicious-file-path").map_err(|_| EngineError::InvalidBuiltInRule)?;
            if !self.config.is_allowed(&rule_id, &input.relative_path) {
                findings.push(Finding {
                    rule_id,
                    severity: path_match.severity,
                    confidence: path_match.confidence,
                    path: input.relative_path.clone(),
                    line: 1,
                    column: 1,
                    end_line: 1,
                    end_column: 1,
                    redacted: "[PATH]".to_owned(),
                    message: path_match.message.to_owned(),
                });
            }
        }

        if input.path_only {
            sort_findings(&mut findings);
            summary.findings_total += findings.len();
            return Ok(findings);
        }

        let prepared = match PreparedText::new(&input.bytes, self.config.scan.max_file_size_bytes) {
            Ok(prepared) => prepared,
            Err(reason) => {
                count_skip(summary, reason);
                sort_findings(&mut findings);
                summary.findings_total += findings.len();
                return Ok(findings);
            }
        };
        summary.files_scanned += 1;

        let mut matches = Vec::new();
        provider::detect(&prepared, &mut matches);
        pem::detect(&prepared, &mut matches);
        generic::detect(&prepared, &input.relative_path, &mut matches);
        suppress_overlaps(&mut matches);
        deduplicate(&mut matches);

        for matched in matches {
            let Some(start) = prepared.position(matched.byte_start) else {
                return Err(EngineError::InvalidMatchOffset);
            };
            let Some(end_offset) = matched.byte_end.checked_sub(1) else {
                return Err(EngineError::InvalidMatchOffset);
            };
            let Some(end) = prepared.position(end_offset) else {
                return Err(EngineError::InvalidMatchOffset);
            };
            let Some(match_range) = LineRange::new(start.line, end.line) else {
                return Err(EngineError::InvalidMatchOffset);
            };
            if !input
                .changed_ranges
                .iter()
                .any(|changed| changed.intersects(match_range))
            {
                continue;
            }
            if is_inline_suppressed(&prepared, start.line, matched.rule_id) {
                continue;
            }
            let rule_id =
                RuleId::new(matched.rule_id).map_err(|_| EngineError::InvalidBuiltInRule)?;
            if self.config.is_allowed(&rule_id, &input.relative_path) {
                continue;
            }
            findings.push(Finding {
                rule_id,
                severity: matched.severity,
                confidence: matched.confidence,
                path: input.relative_path.clone(),
                line: start.line,
                column: start.column,
                end_line: end.line,
                end_column: end.column,
                redacted: redact(matched.candidate),
                message: matched.message.to_owned(),
            });
        }

        sort_findings(&mut findings);
        summary.findings_total += findings.len();
        Ok(findings)
    }
}

fn count_skip(summary: &mut ScanSummary, reason: SkipReason) {
    match reason {
        SkipReason::Binary => summary.skipped_binary += 1,
        SkipReason::InvalidUtf8 => summary.skipped_invalid_utf8 += 1,
        SkipReason::Oversized => summary.skipped_oversized += 1,
    }
}

fn deduplicate(matches: &mut Vec<CandidateMatch<'_>>) {
    let mut seen = HashSet::new();
    matches.retain(|matched| seen.insert((matched.rule_id, matched.byte_start, matched.byte_end)));
}

fn suppress_overlaps(matches: &mut Vec<CandidateMatch<'_>>) {
    let specific_spans = matches
        .iter()
        .filter(|matched| matched.rule_id != "generic-secret-assignment")
        .map(|matched| (matched.rule_id, matched.byte_start, matched.byte_end))
        .collect::<Vec<_>>();
    matches.retain(|matched| {
        if matched.rule_id == "generic-secret-assignment" {
            return !specific_spans.iter().any(|(_, start, end)| {
                spans_overlap(matched.byte_start, matched.byte_end, *start, *end)
            });
        }
        if matched.rule_id == "database-connection-password" {
            return !specific_spans.iter().any(|(rule, start, end)| {
                *rule == "azure-storage-account-key"
                    && spans_overlap(matched.byte_start, matched.byte_end, *start, *end)
            });
        }
        true
    });
}

const fn spans_overlap(
    left_start: usize,
    left_end: usize,
    right_start: usize,
    right_end: usize,
) -> bool {
    left_start < right_end && right_start < left_end
}

fn is_inline_suppressed(prepared: &PreparedText<'_>, match_line: usize, rule_id: &str) -> bool {
    line_has_suppression(prepared.line(match_line), rule_id)
        || match_line
            .checked_sub(1)
            .is_some_and(|line| line_has_suppression(prepared.line(line), rule_id))
}

fn line_has_suppression(line: Option<&str>, rule_id: &str) -> bool {
    let Some(line) = line else {
        return false;
    };
    let marker = format!("secret-guard:allow({rule_id})");
    let Some((_, after)) = line.split_once(&marker) else {
        return false;
    };
    let Some(reason) = after.trim_start().strip_prefix("reason=\"") else {
        return false;
    };
    reason
        .find('"')
        .is_some_and(|end| !reason[..end].trim().is_empty())
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("internal rule catalog contains an invalid rule ID")]
    InvalidBuiltInRule,
    #[error("internal detector returned an invalid text offset")]
    InvalidMatchOffset,
}

#[cfg(test)]
mod tests {
    use crate::{
        config::Config,
        finding::ScanSummary,
        scan::{
            engine::ScannerEngine,
            file_input::{FileInput, LineRange, SourceKind},
        },
    };

    fn line(start: usize, end: usize) -> LineRange {
        LineRange::new(start, end).expect("valid range")
    }

    fn input(path: &str, text: String, changed: Vec<LineRange>) -> FileInput {
        FileInput {
            relative_path: path.to_owned(),
            source_kind: SourceKind::Staged,
            bytes: text.into_bytes(),
            changed_ranges: changed,
            path_only: false,
            index_mode: None,
        }
    }

    fn scan(config: &Config, input: &FileInput) -> Vec<crate::finding::Finding> {
        ScannerEngine::new(config)
            .scan_file(input, &mut ScanSummary::default())
            .expect("scan file")
    }

    #[test]
    fn staged_matches_are_limited_to_changed_ranges() {
        let value = ["Ab", "12", "-complex-", "Value", "9876"].concat();
        let text = format!("password = \"{value}\"\nclean = true\n");
        assert!(
            scan(
                &Config::default(),
                &input("src/a.rs", text.clone(), vec![line(2, 2)])
            )
            .is_empty()
        );
        assert_eq!(
            scan(
                &Config::default(),
                &input("src/a.rs", text, vec![line(1, 1)])
            )
            .len(),
            1
        );
    }

    #[test]
    fn multiline_pem_is_retained_when_any_block_line_changed() {
        let begin = ["-----BEGIN ", "PRIVATE", " KEY-----"].concat();
        let end = ["-----END ", "PRIVATE", " KEY-----"].concat();
        let text = format!("before\n{begin}\nbody\n{end}\nafter\n");
        let findings = scan(
            &Config::default(),
            &input("key.txt", text, vec![line(3, 3)]),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id.as_str(), "private-key-pem");
    }

    #[test]
    fn inline_suppression_requires_exact_rule_and_reason() {
        let value = ["Ab", "12", "-complex-", "Value", "9876"].concat();
        let allowed = format!(
            "// secret-guard:allow(generic-secret-assignment) reason=\"documented synthetic value\"\npassword = \"{value}\""
        );
        assert!(
            scan(
                &Config::default(),
                &input("src/a.rs", allowed, vec![line(2, 2)])
            )
            .is_empty()
        );
        let malformed = format!(
            "// secret-guard:allow(generic-secret-assignment) reason=\"\"\npassword = \"{value}\""
        );
        assert_eq!(
            scan(
                &Config::default(),
                &input("src/a.rs", malformed, vec![line(2, 2)])
            )
            .len(),
            1
        );
    }

    #[test]
    fn allowlist_and_provider_overlap_are_applied() {
        let config = Config::from_toml(
            "[[allowlist]]\nrule = \"generic-secret-assignment\"\npath = \"tests/**\"\nreason = \"runtime fragments\"",
            std::path::Path::new("config.toml"),
        )
        .expect("valid config");
        let generic = ["Ab", "12", "-complex-", "Value", "9876"].concat();
        assert!(
            scan(
                &config,
                &input(
                    "tests/a.rs",
                    format!("password={generic}"),
                    vec![line(1, 1)]
                )
            )
            .is_empty()
        );

        let token = format!("{}{}", ["g", "hp", "_"].concat(), "A".repeat(36));
        let findings = scan(
            &Config::default(),
            &input(
                "src/a.rs",
                format!("password=\"{token}\""),
                vec![line(1, 1)],
            ),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id.as_str(), "github-token");
        let json = serde_json::to_string(&findings).expect("serialize findings");
        assert!(!json.contains(&token));
    }
}
