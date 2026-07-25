use thiserror::Error;

use crate::{
    config::Config,
    finding::{ScanSummary, sort_findings},
    git::client::{GitClient, GitError},
    scan::{
        ScanResult,
        engine::{EngineError, ScannerEngine},
        file_input::{FileInput, ScanMode, SourceKind, normalize_path_text},
    },
};

pub fn scan_staged(client: &GitClient, config: &Config) -> Result<ScanResult, StagedError> {
    client.ensure_no_unmerged()?;
    let mut paths = client.staged_paths()?;
    let rename_only = client.rename_only_paths()?;
    paths.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    paths.dedup();

    let engine = ScannerEngine::new(config);
    let mut summary = ScanSummary::default();
    let mut findings = Vec::new();

    for git_path in paths {
        let relative_path = normalize_path_text(&git_path);
        if config.is_excluded(&relative_path) {
            summary.files_considered += 1;
            summary.skipped_excluded += 1;
            continue;
        }
        let entry = client.index_entry(&git_path)?;
        match entry.mode.as_str() {
            "160000" => {
                summary.files_considered += 1;
                summary.skipped_submodule += 1;
                continue;
            }
            "120000" => {
                summary.files_considered += 1;
                summary.skipped_symlink += 1;
                continue;
            }
            _ => {}
        }

        let (bytes, changed_ranges, path_only) = if rename_only.contains(&git_path) {
            (Vec::new(), Vec::new(), true)
        } else {
            let bytes = client.blob(&entry.object_id)?;
            let changed_ranges = client.changed_ranges(&git_path)?;
            let path_only = changed_ranges.is_empty();
            (bytes, changed_ranges, path_only)
        };
        let input = FileInput {
            relative_path,
            source_kind: SourceKind::Staged,
            bytes,
            path_only,
            changed_ranges,
            index_mode: Some(entry.mode),
        };
        findings.extend(engine.scan_file(&input, &mut summary)?);
    }
    sort_findings(&mut findings);
    Ok(ScanResult {
        mode: ScanMode::Staged,
        root: ".".to_owned(),
        findings,
        summary,
    })
}

#[derive(Debug, Error)]
pub enum StagedError {
    #[error(transparent)]
    Git(#[from] GitError),
    #[error(transparent)]
    Engine(#[from] EngineError),
}
