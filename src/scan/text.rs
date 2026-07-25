use std::sync::LazyLock;

use regex::Regex;

use crate::severity::Severity;

const BINARY_PREFIX_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    Binary,
    InvalidUtf8,
    Oversized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextPosition {
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineIndex {
    starts: Vec<usize>,
    text_len: usize,
    line_count: usize,
}

impl LineIndex {
    pub fn new(text: &str) -> Self {
        let mut starts = vec![0];
        for (offset, byte) in text.bytes().enumerate() {
            if byte == b'\n' {
                starts.push(offset + 1);
            }
        }
        let line_count = if text.is_empty() {
            0
        } else if text.ends_with('\n') {
            starts.len().saturating_sub(1)
        } else {
            starts.len()
        };
        Self {
            starts,
            text_len: text.len(),
            line_count,
        }
    }

    pub const fn line_count(&self) -> usize {
        self.line_count
    }

    pub fn position(&self, text: &str, byte_offset: usize) -> Option<TextPosition> {
        if byte_offset > self.text_len || !text.is_char_boundary(byte_offset) {
            return None;
        }
        let line_index = self.starts.partition_point(|start| *start <= byte_offset) - 1;
        let line_start = self.starts[line_index];
        let column = text.get(line_start..byte_offset)?.chars().count() + 1;
        Some(TextPosition {
            line: line_index + 1,
            column,
        })
    }

    pub fn line<'a>(&self, text: &'a str, one_based_line: usize) -> Option<&'a str> {
        if one_based_line == 0 || one_based_line > self.starts.len() {
            return None;
        }
        let start = self.starts[one_based_line - 1];
        let mut end = self
            .starts
            .get(one_based_line)
            .copied()
            .unwrap_or(text.len());
        if end > start && text.as_bytes().get(end - 1) == Some(&b'\n') {
            end -= 1;
        }
        if end > start && text.as_bytes().get(end - 1) == Some(&b'\r') {
            end -= 1;
        }
        text.get(start..end)
    }
}

pub struct PreparedText<'a> {
    text: &'a str,
    lines: LineIndex,
}

impl<'a> PreparedText<'a> {
    pub fn new(bytes: &'a [u8], max_size: usize) -> Result<Self, SkipReason> {
        if bytes.len() > max_size {
            return Err(SkipReason::Oversized);
        }
        if bytes[..bytes.len().min(BINARY_PREFIX_BYTES)].contains(&0) {
            return Err(SkipReason::Binary);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| SkipReason::InvalidUtf8)?;
        Ok(Self {
            text,
            lines: LineIndex::new(text),
        })
    }

    pub const fn as_str(&self) -> &'a str {
        self.text
    }

    pub const fn line_count(&self) -> usize {
        self.lines.line_count()
    }

    pub fn position(&self, byte_offset: usize) -> Option<TextPosition> {
        self.lines.position(self.text, byte_offset)
    }

    pub fn line(&self, one_based_line: usize) -> Option<&str> {
        self.lines.line(self.text, one_based_line)
    }
}

pub struct CandidateMatch<'a> {
    pub rule_id: &'static str,
    pub severity: Severity,
    pub confidence: u8,
    pub byte_start: usize,
    pub byte_end: usize,
    pub message: &'static str,
    pub candidate: &'a str,
}

pub fn shannon_entropy(candidate: &[u8]) -> f64 {
    if candidate.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in candidate {
        counts[usize::from(*byte)] += 1;
    }
    let length = candidate.len() as f64;
    counts
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

pub fn is_placeholder(candidate: &str) -> bool {
    let trimmed = trim_literal(candidate).trim().to_ascii_lowercase();
    const WORDS: &[&str] = &[
        "example",
        "dummy",
        "fake",
        "placeholder",
        "changeme",
        "change-me",
        "replace-me",
        "your-token-here",
        "your-api-key",
        "not-a-secret",
        "redacted",
        "<password>",
        "<secret>",
        "xxxxx",
        "********",
    ];
    if trimmed.is_empty() || WORDS.contains(&trimmed.as_str()) {
        return true;
    }
    let mut characters = trimmed.chars();
    let first = characters.next();
    first.is_some() && characters.all(|character| Some(character) == first)
}

static ENVIRONMENT_REFERENCE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)^(?:
            \$\{[a-z_][a-z0-9_]*\}|
            \$[a-z_][a-z0-9_]*|
            %[a-z_][a-z0-9_]*%|
            \{\{\s*[^{}]+\s*\}\}|
            env:[a-z_][a-z0-9_]*|
            env\[[a-z_][a-z0-9_]*\]|
            process\.env\.[a-z_][a-z0-9_]*|
            configuration\[["'][^"']+["']\]|
            getenv\(["'][^"']+["']\)
        )$"#,
    )
    .ok()
});

pub fn is_environment_reference(candidate: &str) -> bool {
    ENVIRONMENT_REFERENCE
        .as_ref()
        .is_some_and(|pattern| pattern.is_match(trim_literal(candidate).trim()))
}

fn trim_literal(candidate: &str) -> &str {
    let trimmed = candidate.trim();
    if trimmed.len() >= 2 {
        let bytes = trimmed.as_bytes();
        if (bytes.first() == Some(&b'"') && bytes.last() == Some(&b'"'))
            || (bytes.first() == Some(&b'\'') && bytes.last() == Some(&b'\''))
        {
            return &trimmed[1..trimmed.len() - 1];
        }
    }
    trimmed
}

pub fn redact(candidate: &str) -> String {
    if candidate.chars().count() < 8 {
        return "[REDACTED]".to_owned();
    }

    let prefix: String = candidate
        .chars()
        .take_while(|character| character.is_ascii())
        .take(2)
        .collect();
    let suffix_reversed: String = candidate
        .chars()
        .rev()
        .take_while(|character| character.is_ascii())
        .take(2)
        .collect();
    let suffix: String = suffix_reversed.chars().rev().collect();
    format!("{prefix}\u{2022}\u{2022}\u{2022}\u{2022}{suffix}")
}

#[cfg(test)]
mod tests {
    use super::{
        LineIndex, PreparedText, SkipReason, is_environment_reference, is_placeholder, redact,
        shannon_entropy,
    };

    #[test]
    fn line_counts_cover_empty_final_newline_crlf_and_mixed_input() {
        for (text, expected) in [
            ("", 0),
            ("one", 1),
            ("one\n", 1),
            ("one\r\ntwo", 2),
            ("one\r\ntwo\nthree\r", 3),
        ] {
            assert_eq!(LineIndex::new(text).line_count(), expected);
        }
    }

    #[test]
    fn maps_first_last_and_unicode_offsets() {
        let text = "a\u{00e9}\r\nlast";
        let index = LineIndex::new(text);
        let first = index.position(text, 0).expect("first position");
        assert_eq!((first.line, first.column), (1, 1));
        let last_offset = text.find('t').expect("last character");
        let last = index.position(text, last_offset).expect("last position");
        assert_eq!((last.line, last.column), (2, 4));
        assert_eq!(index.line(text, 1), Some("a\u{00e9}"));
        assert_eq!(index.line(text, 2), Some("last"));
    }

    #[test]
    fn preparation_returns_structured_skip_reasons() {
        assert_eq!(
            PreparedText::new(b"a\0b", 10).err(),
            Some(SkipReason::Binary)
        );
        assert_eq!(
            PreparedText::new(&[0xff], 10).err(),
            Some(SkipReason::InvalidUtf8)
        );
        assert_eq!(
            PreparedText::new(b"1234", 3).err(),
            Some(SkipReason::Oversized)
        );
        assert!(PreparedText::new(b"1234", 4).is_ok());
    }

    #[test]
    fn entropy_has_expected_sanity_values() {
        assert_eq!(shannon_entropy(b""), 0.0);
        assert_eq!(shannon_entropy(b"aaaaaaaa"), 0.0);
        assert!((shannon_entropy(b"abcd") - 2.0).abs() < 0.000_001);
    }

    #[test]
    fn recognizes_every_documented_placeholder() {
        for placeholder in [
            "example",
            "dummy",
            "fake",
            "placeholder",
            "changeme",
            "change-me",
            "replace-me",
            "your-token-here",
            "your-api-key",
            "not-a-secret",
            "redacted",
            "<password>",
            "<secret>",
            "xxxxx",
            "********",
            "!!!!!!!!",
        ] {
            assert!(is_placeholder(placeholder), "missed placeholder form");
        }
        assert!(!is_placeholder("distinct-literal-value"));
    }

    #[test]
    fn recognizes_every_documented_reference_form() {
        for reference in [
            "${PASSWORD}",
            "$PASSWORD",
            "%PASSWORD%",
            "{{ secret }}",
            "env:PASSWORD",
            "ENV[PASSWORD]",
            "process.env.PASSWORD",
            "configuration[\"Password\"]",
            "getenv(\"PASSWORD\")",
        ] {
            assert!(is_environment_reference(reference), "missed reference form");
        }
        assert!(!is_environment_reference("literal-password-value"));
    }

    #[test]
    fn redaction_never_returns_or_contains_the_candidate() {
        for candidate in [
            "short",
            "abcdefgh",
            "ab0123456789yz",
            "\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}",
            "ab\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}yz",
        ] {
            let redacted = redact(candidate);
            assert_ne!(redacted, candidate);
            assert!(!redacted.contains(candidate));
        }
        assert_eq!(redact("short"), "[REDACTED]");
        assert_eq!(
            redact("ab0123456789yz"),
            "ab\u{2022}\u{2022}\u{2022}\u{2022}yz"
        );
        assert_eq!(
            redact("\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}"),
            "\u{2022}\u{2022}\u{2022}\u{2022}"
        );
    }
}
