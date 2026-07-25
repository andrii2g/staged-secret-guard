use std::{
    ffi::{OsStr, OsString},
    io,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use thiserror::Error;

use crate::{git::changed_ranges, scan::file_input::LineRange};

#[derive(Debug, Clone)]
pub struct GitClient {
    root: PathBuf,
    executable: OsString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub mode: String,
    pub object_id: String,
}

impl GitClient {
    pub fn discover(current_directory: &Path) -> Result<Self, GitError> {
        Self::discover_with(current_directory, OsStr::new("git"))
    }

    pub fn discover_with(
        current_directory: &Path,
        executable: &OsStr,
    ) -> Result<Self, GitError> {
        let mut command = Command::new(executable);
        command
            .current_dir(current_directory)
            .args(["rev-parse", "--show-toplevel"]);
        let output = checked_output(command, "rev-parse")?;
        let root_bytes = strip_final_line_ending(&output.stdout);
        let root_text = std::str::from_utf8(root_bytes)
            .map_err(|_| GitError::InvalidOutput("repository root is not UTF-8"))?;
        if root_text.is_empty() {
            return Err(GitError::InvalidOutput("repository root is empty"));
        }
        Ok(Self {
            root: PathBuf::from(root_text),
            executable: executable.to_owned(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn staged_paths(&self) -> Result<Vec<String>, GitError> {
        let mut command = self.command();
        command.args([
            "diff",
            "--cached",
            "--name-only",
            "--diff-filter=ACMR",
            "-z",
            "--no-ext-diff",
            "--no-textconv",
            "--ignore-submodules=all",
        ]);
        let output = checked_output(command, "diff --cached --name-only")?;
        parse_nul_paths(&output.stdout)
    }

    pub fn index_entry(&self, path: &str) -> Result<IndexEntry, GitError> {
        let mut command = self.command();
        command
            .args(["ls-files", "--stage", "-z", "--"])
            .arg(path);
        let output = checked_output(command, "ls-files --stage")?;
        parse_index_entry(&output.stdout, path)
    }

    pub fn blob(&self, object_id: &str) -> Result<Vec<u8>, GitError> {
        let mut command = self.command();
        command.args(["cat-file", "blob", object_id]);
        checked_output(command, "cat-file blob").map(|output| output.stdout)
    }

    pub fn changed_ranges(&self, path: &str) -> Result<Vec<LineRange>, GitError> {
        let mut command = self.command();
        command
            .args([
                "diff",
                "--cached",
                "--unified=0",
                "--no-color",
                "--no-ext-diff",
                "--no-textconv",
                "--ignore-submodules=all",
                "--",
            ])
            .arg(path);
        let output = checked_output(command, "diff --cached --unified=0")?;
        changed_ranges::parse(&output.stdout).map_err(GitError::Hunk)
    }

    pub fn git_path(&self, arguments: &[&str], operation: &'static str) -> Result<PathBuf, GitError> {
        let mut command = self.command();
        command.args(arguments);
        let output = checked_output(command, operation)?;
        let bytes = strip_final_line_ending(&output.stdout);
        let text = std::str::from_utf8(bytes)
            .map_err(|_| GitError::InvalidOutput("Git path is not UTF-8"))?;
        if text.is_empty() {
            return Err(GitError::InvalidOutput("Git path is empty"));
        }
        let path = PathBuf::from(text);
        Ok(if path.is_absolute() {
            path
        } else {
            self.root.join(path)
        })
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.executable);
        command.current_dir(&self.root);
        command
    }
}

fn checked_output(mut command: Command, operation: &'static str) -> Result<Output, GitError> {
    let output = command.output().map_err(|source| GitError::Spawn {
        operation,
        source,
    })?;
    if !output.status.success() {
        return Err(GitError::Failed {
            operation,
            status: output.status.code(),
        });
    }
    Ok(output)
}

fn strip_final_line_ending(bytes: &[u8]) -> &[u8] {
    bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .unwrap_or(bytes)
}

pub fn parse_nul_paths(bytes: &[u8]) -> Result<Vec<String>, GitError> {
    let mut paths = Vec::new();
    let records = bytes.split(|byte| *byte == 0);
    for record in records {
        if record.is_empty() {
            continue;
        }
        let path = std::str::from_utf8(record)
            .map_err(|_| GitError::InvalidOutput("staged path is not UTF-8"))?;
        paths.push(path.to_owned());
    }
    Ok(paths)
}

pub fn parse_index_entry(bytes: &[u8], requested_path: &str) -> Result<IndexEntry, GitError> {
    let mut stage_zero = None;
    let mut saw_record = false;
    for record in bytes.split(|byte| *byte == 0).filter(|record| !record.is_empty()) {
        saw_record = true;
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or(GitError::InvalidOutput("malformed index record"))?;
        let header = std::str::from_utf8(&record[..tab])
            .map_err(|_| GitError::InvalidOutput("index header is not UTF-8"))?;
        let mut fields = header.split_ascii_whitespace();
        let (Some(mode), Some(object_id), Some(stage)) =
            (fields.next(), fields.next(), fields.next())
        else {
            return Err(GitError::InvalidOutput("malformed index header"));
        };
        if fields.next().is_some() || !valid_mode(mode) || !valid_object_id(object_id) {
            return Err(GitError::InvalidOutput("invalid index entry"));
        }
        if stage != "0" {
            return Err(GitError::Unmerged(requested_path.to_owned()));
        }
        if stage_zero.is_some() {
            return Err(GitError::InvalidOutput("multiple stage-0 index entries"));
        }
        stage_zero = Some(IndexEntry {
            mode: mode.to_owned(),
            object_id: object_id.to_owned(),
        });
    }
    if !saw_record {
        return Err(GitError::MissingIndexEntry(requested_path.to_owned()));
    }
    stage_zero.ok_or_else(|| GitError::MissingIndexEntry(requested_path.to_owned()))
}

fn valid_mode(mode: &str) -> bool {
    mode.len() == 6 && mode.bytes().all(|byte| matches!(byte, b'0'..=b'7'))
}

fn valid_object_id(object_id: &str) -> bool {
    matches!(object_id.len(), 40 | 64) && object_id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, Error)]
pub enum GitError {
    #[error("unable to execute Git operation {operation}: {source}")]
    Spawn {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("Git operation {operation} failed with status {status:?}")]
    Failed {
        operation: &'static str,
        status: Option<i32>,
    },
    #[error("invalid Git output: {0}")]
    InvalidOutput(&'static str),
    #[error("unmerged index entry: {0}")]
    Unmerged(String),
    #[error("staged index entry is missing: {0}")]
    MissingIndexEntry(String),
    #[error(transparent)]
    Hunk(#[from] changed_ranges::HunkError),
}

#[cfg(test)]
mod tests {
    use super::{GitError, parse_index_entry, parse_nul_paths};

    #[test]
    fn parses_nul_delimited_spaces_and_unicode_paths() {
        let paths = parse_nul_paths("a file.txt\0unicod\u{00e9}.txt\0".as_bytes()).expect("paths");
        assert_eq!(paths, vec!["a file.txt", "unicod\u{00e9}.txt"]);
    }

    #[test]
    fn parses_sha1_and_sha256_stage_zero_records() {
        for object_id in ["a".repeat(40), "B".repeat(64)] {
            let record = format!("100644 {object_id} 0\tpath with space.txt\0");
            let entry = parse_index_entry(record.as_bytes(), "path with space.txt")
                .expect("stage zero entry");
            assert_eq!(entry.object_id, object_id);
            assert_eq!(entry.mode, "100644");
        }
    }

    #[test]
    fn unmerged_and_malformed_records_fail_closed() {
        let unmerged = format!("100644 {} 2\tpath.txt\0", "a".repeat(40));
        assert!(matches!(
            parse_index_entry(unmerged.as_bytes(), "path.txt"),
            Err(GitError::Unmerged(_))
        ));
        assert!(parse_index_entry(b"malformed\0", "path.txt").is_err());
    }
}