use std::{
    collections::HashSet,
    fs, io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use ignore::WalkBuilder;
use thiserror::Error;

use crate::{
    config::Config,
    finding::{ScanSummary, sort_findings},
    scan::{
        ScanResult,
        engine::{EngineError, ScannerEngine},
        file_input::{FileInput, LineRange, ScanMode, SourceKind, normalize_path},
    },
};

const PRUNED_DIRECTORIES: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "bin",
    "obj",
    ".idea",
    ".vs",
    "dist",
    "build",
    "coverage",
];

pub fn scan_folder(
    root: &Path,
    config: &Config,
    output_path: Option<&Path>,
) -> Result<ScanResult, FolderError> {
    let root = root.canonicalize().map_err(|source| FolderError::Root {
        path: root.display().to_string(),
        source,
    })?;
    if !root.is_dir() {
        return Err(FolderError::NotDirectory(root.display().to_string()));
    }

    let raw = inventory(&root, false, config.scan.fail_on_read_error, true)?;
    let filtered = inventory(
        &root,
        config.scan.respect_gitignore,
        config.scan.fail_on_read_error,
        false,
    )?;
    let filtered_set = filtered.regular.iter().collect::<HashSet<_>>();

    let mut summary = ScanSummary {
        skipped_symlink: raw.symlinks,
        skipped_excluded: raw.pruned,
        skipped_ignored: raw
            .regular
            .iter()
            .filter(|path| !filtered_set.contains(path))
            .count(),
        ..ScanSummary::default()
    };

    let mut files = filtered.regular;
    files.sort_by(|left, right| {
        let left_relative = left.strip_prefix(&root).unwrap_or(left);
        let right_relative = right.strip_prefix(&root).unwrap_or(right);
        normalize_path(left_relative)
            .as_bytes()
            .cmp(normalize_path(right_relative).as_bytes())
    });

    let engine = ScannerEngine::new(config);
    let mut findings = Vec::new();
    for path in files {
        if output_path.is_some_and(|output| paths_equal(&path, output)) {
            summary.skipped_excluded += 1;
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_source) if !config.scan.fail_on_read_error => continue,
            Err(source) => {
                return Err(FolderError::Read {
                    path: path.display().to_string(),
                    source,
                });
            }
        };
        let relative = path
            .strip_prefix(&root)
            .map_err(|_| FolderError::OutsideRoot)?;
        let changed_ranges = full_file_range(&bytes).into_iter().collect();
        let input = FileInput {
            relative_path: normalize_path(relative),
            source_kind: SourceKind::Folder,
            bytes,
            changed_ranges,
            path_only: false,
            index_mode: None,
        };
        findings.extend(engine.scan_file(&input, &mut summary)?);
    }
    sort_findings(&mut findings);

    Ok(ScanResult {
        mode: ScanMode::Folder,
        root: ".".to_owned(),
        findings,
        summary,
    })
}

fn full_file_range(bytes: &[u8]) -> Option<LineRange> {
    if bytes.is_empty() {
        return None;
    }
    let newline_count = bytes.iter().filter(|byte| **byte == b'\n').count();
    let line_count = if bytes.ends_with(b"\n") {
        newline_count
    } else {
        newline_count + 1
    };
    LineRange::new(1, line_count.max(1))
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    if cfg!(windows) {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    } else {
        left == right
    }
}

#[derive(Debug)]
struct Inventory {
    regular: Vec<PathBuf>,
    symlinks: usize,
    pruned: usize,
}

fn inventory(
    root: &Path,
    respect_gitignore: bool,
    fail_on_error: bool,
    count_pruned: bool,
) -> Result<Inventory, FolderError> {
    let pruned = Arc::new(AtomicUsize::new(0));
    let filter_counter = Arc::clone(&pruned);
    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false)
        .follow_links(false)
        .parents(respect_gitignore)
        .ignore(respect_gitignore)
        .git_ignore(respect_gitignore)
        .git_exclude(respect_gitignore)
        .git_global(false)
        .require_git(false)
        .filter_entry(move |entry| {
            if entry.depth() == 0 {
                return true;
            }
            let should_prune = entry.file_type().is_some_and(|kind| kind.is_dir())
                && PRUNED_DIRECTORIES
                    .iter()
                    .any(|name| entry.file_name() == *name);
            if should_prune && count_pruned {
                filter_counter.fetch_add(1, Ordering::Relaxed);
            }
            !should_prune
        });
    if !respect_gitignore {
        builder.standard_filters(false).hidden(false);
    }

    let mut regular = Vec::new();
    let mut symlinks = 0;
    for item in builder.build() {
        let entry = match item {
            Ok(entry) => entry,
            Err(_error) if !fail_on_error => continue,
            Err(error) => return Err(FolderError::Traversal(error.to_string())),
        };
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            symlinks += 1;
        } else if file_type.is_file() {
            regular.push(entry.into_path());
        }
    }
    Ok(Inventory {
        regular,
        symlinks,
        pruned: pruned.load(Ordering::Relaxed),
    })
}

#[derive(Debug, Error)]
pub enum FolderError {
    #[error("unable to access scan root {path}: {source}")]
    Root {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("scan path is not a directory: {0}")]
    NotDirectory(String),
    #[error("folder traversal failed: {0}")]
    Traversal(String),
    #[error("unable to read file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("folder traversal returned a path outside the scan root")]
    OutsideRoot,
    #[error(transparent)]
    Engine(#[from] EngineError),
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::scan_folder;
    use crate::config::Config;

    #[test]
    fn scans_nested_and_hidden_files_but_respects_ignores_and_exclusions() {
        let directory = tempdir().expect("temporary directory");
        fs::create_dir_all(directory.path().join("nested")).expect("nested directory");
        fs::create_dir_all(directory.path().join("target")).expect("target directory");
        let value = ["Ab", "12", "-complex-", "Value", "9876"].concat();
        fs::write(
            directory.path().join("nested/config.txt"),
            format!("password={value}"),
        )
        .expect("nested file");
        fs::write(directory.path().join(".env"), "clean=true").expect("hidden file");
        fs::write(
            directory.path().join("ignored.txt"),
            format!("password={value}"),
        )
        .expect("ignored file");
        fs::write(directory.path().join(".gitignore"), "ignored.txt\n").expect("gitignore");
        fs::write(
            directory.path().join("target/generated.txt"),
            format!("password={value}"),
        )
        .expect("excluded file");

        let result = scan_folder(directory.path(), &Config::default(), None).expect("folder scan");
        assert_eq!(result.findings.len(), 2);
        assert!(result.findings.iter().any(|item| item.path == ".env"));
        assert!(
            result
                .findings
                .iter()
                .any(|item| item.path == "nested/config.txt")
        );
        assert_eq!(result.summary.skipped_ignored, 1);
        assert!(result.summary.skipped_excluded >= 1);
    }

    #[test]
    fn reports_binary_invalid_utf8_and_oversized_skips() {
        let directory = tempdir().expect("temporary directory");
        fs::write(directory.path().join("binary.bin"), b"a\0b").expect("binary file");
        fs::write(directory.path().join("invalid.txt"), [0xff]).expect("invalid file");
        fs::write(directory.path().join("large.txt"), b"12345").expect("large file");
        let config = Config::from_toml(
            "[scan]\nmax_file_size_bytes = 4",
            std::path::Path::new("config.toml"),
        )
        .expect("valid config");
        let result = scan_folder(directory.path(), &config, None).expect("folder scan");
        assert_eq!(result.summary.skipped_binary, 1);
        assert_eq!(result.summary.skipped_invalid_utf8, 1);
        assert_eq!(result.summary.skipped_oversized, 1);
    }
}
