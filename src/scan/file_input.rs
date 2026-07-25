use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    Staged,
    Folder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    Staged,
    Folder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextRange {
    pub start: usize,
    pub end: usize,
}

impl TextRange {
    pub const fn new(start: usize, end: usize) -> Option<Self> {
        if end >= start {
            Some(Self { start, end })
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LineRange {
    pub start_line: usize,
    pub end_line: usize,
}

impl LineRange {
    pub const fn new(start_line: usize, end_line: usize) -> Option<Self> {
        if start_line >= 1 && end_line >= start_line {
            Some(Self {
                start_line,
                end_line,
            })
        } else {
            None
        }
    }

    pub const fn intersects(self, other: Self) -> bool {
        self.start_line <= other.end_line && other.start_line <= self.end_line
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInput {
    pub relative_path: String,
    pub source_kind: SourceKind,
    pub bytes: Vec<u8>,
    pub changed_ranges: Vec<LineRange>,
    pub path_only: bool,
    pub index_mode: Option<String>,
}

pub fn normalize_path(path: &Path) -> String {
    normalize_path_text(&path.to_string_lossy())
}

pub fn normalize_path_text(path: &str) -> String {
    let replaced = path.replace('\\', "/");
    let mut parts = Vec::new();
    for part in replaced.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|value| *value != "..") {
                    parts.pop();
                } else {
                    parts.push(part);
                }
            }
            value => parts.push(value),
        }
    }
    parts.join("/")
}

pub fn merge_line_ranges(mut ranges: Vec<LineRange>) -> Vec<LineRange> {
    ranges.sort_unstable();
    let mut merged: Vec<LineRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(previous) = merged.last_mut() {
            if range.start_line <= previous.end_line.saturating_add(1) {
                previous.end_line = previous.end_line.max(range.end_line);
                continue;
            }
        }
        merged.push(range);
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::{LineRange, merge_line_ranges, normalize_path_text};

    fn range(start: usize, end: usize) -> LineRange {
        LineRange::new(start, end).expect("valid line range")
    }

    #[test]
    fn line_range_validation_and_intersection() {
        assert!(LineRange::new(0, 1).is_none());
        assert!(LineRange::new(2, 1).is_none());
        assert!(range(2, 4).intersects(range(4, 8)));
        assert!(!range(2, 4).intersects(range(5, 8)));
    }

    #[test]
    fn adjacent_and_overlapping_ranges_merge() {
        assert_eq!(
            merge_line_ranges(vec![range(8, 10), range(1, 2), range(3, 5), range(9, 12)]),
            vec![range(1, 5), range(8, 12)]
        );
    }

    #[test]
    fn windows_paths_normalize_to_forward_slashes() {
        assert_eq!(
            normalize_path_text(r".\src\nested\..\config.rs"),
            "src/config.rs"
        );
    }
}
