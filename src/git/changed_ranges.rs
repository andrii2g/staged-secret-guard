use thiserror::Error;

use crate::scan::file_input::{LineRange, merge_line_ranges};

pub fn parse(diff: &[u8]) -> Result<Vec<LineRange>, HunkError> {
    let mut ranges = Vec::new();
    for raw_line in diff.split(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.starts_with(b"@@ ") {
            ranges.extend(parse_header(line)?);
        }
    }
    Ok(merge_line_ranges(ranges))
}

fn parse_header(line: &[u8]) -> Result<Option<LineRange>, HunkError> {
    let text = std::str::from_utf8(line).map_err(|_| HunkError)?;
    let plus = text.find(" +").ok_or(HunkError)? + 2;
    let after_plus = text.get(plus..).ok_or(HunkError)?;
    let token = after_plus.split_ascii_whitespace().next().ok_or(HunkError)?;
    if token.is_empty() || !text.ends_with(" @@") && !text.contains(" @@ ") {
        return Err(HunkError);
    }
    let (start_text, count_text) = token.split_once(',').unwrap_or((token, "1"));
    let start = start_text.parse::<usize>().map_err(|_| HunkError)?;
    let count = count_text.parse::<usize>().map_err(|_| HunkError)?;
    if count == 0 {
        return Ok(None);
    }
    let end = start.checked_add(count - 1).ok_or(HunkError)?;
    LineRange::new(start, end).ok_or(HunkError).map(Some)
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[error("Git emitted a malformed unified-diff hunk header")]
pub struct HunkError;

#[cfg(test)]
mod tests {
    use super::parse;
    use crate::scan::file_input::LineRange;

    fn range(start: usize, end: usize) -> LineRange {
        LineRange::new(start, end).expect("valid range")
    }

    #[test]
    fn parses_omitted_zero_adjacent_and_overlapping_ranges() {
        let diff = b"header\n@@ -1 +2 @@\nbody\n@@ -3,0 +4,0 @@\n@@ -4 +3,2 @@\n@@ -8 +5,3 @@ context\n";
        assert_eq!(parse(diff).expect("valid hunks"), vec![range(2, 7)]);
    }

    #[test]
    fn ignores_patch_body_and_rejects_malformed_hunks() {
        assert!(parse(b"+++ filename\n+@@ not-a-header\n").expect("no hunks").is_empty());
        assert!(parse(b"@@ malformed @@\n").is_err());
        assert!(parse(b"@@ -1 +0,2 @@\n").is_err());
    }
}