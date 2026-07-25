use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("requested operation is not implemented yet")]
    NotImplemented,
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error(transparent)]
    Folder(#[from] crate::scan::folder_source::FolderError),
    #[error(transparent)]
    Git(#[from] crate::git::client::GitError),
    #[error(transparent)]
    Staged(#[from] crate::git::staged_source::StagedError),
    #[error(transparent)]
    Report(#[from] crate::report::ReportError),
    #[error("unable to resolve path {path}: {source}")]
    Path {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("unable to write completed report: {0}")]
    Output(#[source] io::Error),
}
