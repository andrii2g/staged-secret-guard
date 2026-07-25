pub mod console;
pub mod json;

use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use thiserror::Error;

pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ReportError> {
    let temporary = temporary_path(path);
    let result = write_temporary(&temporary, bytes).and_then(|()| replace(&temporary, path));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|source| ReportError::Write {
        path: path.display().to_string(),
        source,
    })
}

fn write_temporary(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()
}

fn replace(temporary: &Path, destination: &Path) -> io::Result<()> {
    match fs::rename(temporary, destination) {
        Ok(()) => Ok(()),
        Err(error)
            if destination.exists()
                && matches!(
                    error.kind(),
                    io::ErrorKind::AlreadyExists | io::ErrorKind::PermissionDenied
                ) =>
        {
            fs::remove_file(destination)?;
            fs::rename(temporary, destination)
        }
        Err(error) => Err(error),
    }
}

fn temporary_path(destination: &Path) -> PathBuf {
    let mut file_name = destination
        .file_name()
        .map_or_else(|| OsString::from("report"), OsString::from);
    file_name.push(format!(".tmp-{}", std::process::id()));
    destination.with_file_name(file_name)
}

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("unable to write report at {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("unable to encode JSON report")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::write_atomic;

    #[test]
    fn output_replaces_existing_file_and_leaves_no_temporary() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("report.json");
        fs::write(&path, b"old").expect("old report");
        write_atomic(&path, b"new\n").expect("atomic report");
        assert_eq!(fs::read(&path).expect("read report"), b"new\n");
        let entries = fs::read_dir(directory.path())
            .expect("read directory")
            .count();
        assert_eq!(entries, 1);
    }
}
