use std::sync::LazyLock;

use regex::Regex;

use crate::{
    scan::text::{
        CandidateMatch, PreparedText, is_environment_reference, is_placeholder, shannon_entropy,
    },
    severity::Severity,
};

static ASSIGNMENT: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"(?im)(?P<key>password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|auth[_-]?token|bearer[_-]?token|private[_-]?key|connection[_-]?string)["']?\s*[:=]\s*(?P<value>"[^"\r\n]{1,256}"|'[^'\r\n]{1,256}'|[^\s,;#]{1,256})"#,
    )
    .ok()
});

pub fn detect<'a>(
    input: &'a PreparedText<'a>,
    normalized_path: &str,
    sink: &mut Vec<CandidateMatch<'a>>,
) {
    let Some(pattern) = ASSIGNMENT.as_ref() else {
        return;
    };
    let text = input.as_str();
    for captures in pattern.captures_iter(text) {
        let Some(value_match) = captures.name("value") else {
            continue;
        };
        let raw = value_match.as_str();
        let quoted = raw.len() >= 2
            && ((raw.starts_with('"') && raw.ends_with('"'))
                || (raw.starts_with('\'') && raw.ends_with('\'')));
        let (candidate, byte_start, byte_end) = if quoted {
            let Some(candidate) = raw.get(1..raw.len() - 1) else {
                continue;
            };
            (candidate, value_match.start() + 1, value_match.end() - 1)
        } else {
            (raw, value_match.start(), value_match.end())
        };

        if is_placeholder(candidate) || is_environment_reference(candidate) {
            continue;
        }
        let score = score(candidate, quoted, normalized_path);
        let Some(severity) = severity_for_score(score) else {
            continue;
        };
        sink.push(CandidateMatch {
            rule_id: "generic-secret-assignment",
            severity,
            confidence: score.clamp(0, 100) as u8,
            byte_start,
            byte_end,
            message: "Sensitive assignment contains a high-confidence literal value.",
            candidate,
        });
    }
}

pub fn score(candidate: &str, quoted: bool, normalized_path: &str) -> i16 {
    let length = candidate.len();
    let entropy = shannon_entropy(candidate.as_bytes());
    let classes = character_classes(candidate);
    score_from_components(
        length >= 12,
        length >= 20,
        entropy >= 3.5,
        entropy >= 4.2,
        classes >= 3,
        quoted,
        is_documentation_or_fixture(normalized_path),
    )
}

#[allow(clippy::fn_params_excessive_bools)]
fn score_from_components(
    length_12: bool,
    length_20: bool,
    entropy_35: bool,
    entropy_42: bool,
    classes_3: bool,
    quoted: bool,
    documentation_or_fixture: bool,
) -> i16 {
    40 + i16::from(length_12) * 10
        + i16::from(length_20) * 10
        + i16::from(entropy_35) * 15
        + i16::from(entropy_42) * 10
        + i16::from(classes_3) * 10
        + i16::from(quoted) * 5
        - i16::from(documentation_or_fixture) * 15
}

pub const fn severity_for_score(score: i16) -> Option<Severity> {
    if score >= 70 {
        Some(Severity::High)
    } else if score >= 50 {
        Some(Severity::Medium)
    } else {
        None
    }
}

fn character_classes(candidate: &str) -> usize {
    let lower = candidate.chars().any(|character| character.is_ascii_lowercase());
    let upper = candidate.chars().any(|character| character.is_ascii_uppercase());
    let digit = candidate.chars().any(|character| character.is_ascii_digit());
    let other = candidate
        .chars()
        .any(|character| !character.is_ascii_alphanumeric());
    [lower, upper, digit, other]
        .into_iter()
        .filter(|present| *present)
        .count()
}

fn is_documentation_or_fixture(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with("docs/")
        || lower.starts_with("doc/")
        || lower.contains("/fixtures/")
        || lower.starts_with("tests/fixtures/")
        || lower.contains("/examples/")
        || lower.ends_with("readme.md")
}

#[cfg(test)]
mod tests {
    use super::{detect, score, severity_for_score};
    use crate::{scan::text::PreparedText, severity::Severity};

    fn detected(text: &str, path: &str) -> Vec<Severity> {
        let prepared = PreparedText::new(text.as_bytes(), usize::MAX).expect("prepare text");
        let mut matches = Vec::new();
        detect(&prepared, path, &mut matches);
        matches.into_iter().map(|item| item.severity).collect()
    }

    #[test]
    fn severity_boundaries_are_exact() {
        assert_eq!(severity_for_score(49), None);
        assert_eq!(severity_for_score(50), Some(Severity::Medium));
        assert_eq!(severity_for_score(69), Some(Severity::Medium));
        assert_eq!(severity_for_score(70), Some(Severity::High));
    }

    #[test]
    fn documented_score_components_apply() {
        let candidate = ["Ab", "12", "-complex-", "Value", "9876"].concat();
        assert!(score(&candidate, true, "src/config.rs") >= 70);
        assert_eq!(
            score(&candidate, true, "tests/fixtures/config.txt"),
            score(&candidate, true, "src/config.rs") - 15
        );
    }

    #[test]
    fn detects_literals_and_rejects_placeholders_and_references() {
        let value = ["Ab", "12", "-complex-", "Value", "9876"].concat();
        assert_eq!(
            detected(&format!("password = \"{value}\""), "src/config.rs"),
            vec![Severity::High]
        );
        for reference in ["${PASSWORD}", "%PASSWORD%", "process.env.PASSWORD", "changeme"] {
            assert!(detected(&format!("password = {reference}"), "src/config.rs").is_empty());
        }
    }
}
