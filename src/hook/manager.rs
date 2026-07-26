use std::{
    fmt, fs, io,
    path::{Path, PathBuf},
};

use thiserror::Error;

use crate::{
    git::client::{GitClient, GitError},
    report,
};

const MARKER_PREFIX: &str = "# Managed by secret-guard";
const MARKER: &str = "# Managed by secret-guard (version 2)";
const SCOPE_PREFIX: &str = "# secret-guard-scope: ";
const CONFIG_PREFIX: &str = "# secret-guard-config: ";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookStatus {
    Absent,
    Installed,
    StaleExecutable,
    ModifiedManaged,
    Unrelated,
}

impl fmt::Display for HookStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Absent => "absent",
            Self::Installed => "installed",
            Self::StaleExecutable => "stale-executable",
            Self::ModifiedManaged => "modified-managed",
            Self::Unrelated => "unrelated",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedScope {
    Global,
    Local,
}

impl fmt::Display for ManagedScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Global => "global",
            Self::Local => "local",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedMetadata {
    pub scope: ManagedScope,
    pub config_owned: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    Installed,
    AlreadyInstalled,
    Updated,
}

impl fmt::Display for InstallOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Installed => "installed",
            Self::AlreadyInstalled => "already installed",
            Self::Updated => "updated managed hook",
        })
    }
}

pub struct HookManager {
    path: PathBuf,
    template: String,
    chaining_snippet: String,
}

impl HookManager {
    pub fn new(client: &GitClient, executable: &Path) -> Result<Self, HookError> {
        let path = client.git_path(
            &["rev-parse", "--git-path", "hooks/pre-commit"],
            "rev-parse --git-path",
        )?;
        Self::from_path(path, executable, ManagedScope::Local, false)
    }

    pub fn from_path(
        path: PathBuf,
        executable: &Path,
        scope: ManagedScope,
        config_owned: bool,
    ) -> Result<Self, HookError> {
        let config = if config_owned { "managed" } else { "external" };
        let executable = posix_executable_path(executable)?;
        let quoted = quote_posix(&executable);
        let template = format!(
            "#!/bin/sh\n{MARKER}\n{SCOPE_PREFIX}{scope}\n{CONFIG_PREFIX}{config}\nexec {quoted} scan --staged\n"
        );
        let chaining_snippet = format!("{quoted} scan --staged");
        Ok(Self {
            path,
            template,
            chaining_snippet,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn metadata(path: &Path) -> Result<Option<ManagedMetadata>, HookError> {
        match fs::read(path) {
            Ok(bytes) => {
                let Ok(text) = std::str::from_utf8(&bytes) else {
                    return Ok(None);
                };
                Ok(parse_metadata(text))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(HookError::Read {
                path: path.display().to_string(),
                source,
            }),
        }
    }

    pub fn status(&self) -> Result<HookStatus, HookError> {
        match fs::read(&self.path) {
            Ok(bytes) if bytes == self.template.as_bytes() => Ok(HookStatus::Installed),
            Ok(bytes) => Ok(classify_other(&bytes)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(HookStatus::Absent),
            Err(source) => Err(HookError::Read {
                path: self.path.display().to_string(),
                source,
            }),
        }
    }

    pub fn install(&self) -> Result<InstallOutcome, HookError> {
        match self.status()? {
            HookStatus::Absent => {
                self.write_template()?;
                Ok(InstallOutcome::Installed)
            }
            HookStatus::Installed => Ok(InstallOutcome::AlreadyInstalled),
            HookStatus::StaleExecutable => {
                self.write_template()?;
                Ok(InstallOutcome::Updated)
            }
            HookStatus::ModifiedManaged | HookStatus::Unrelated => Err(HookError::Conflict {
                path: self.path.display().to_string(),
                snippet: self.chaining_snippet.clone(),
            }),
        }
    }

    pub fn uninstall(&self) -> Result<bool, HookError> {
        match self.status()? {
            HookStatus::Absent => Ok(false),
            HookStatus::Installed | HookStatus::StaleExecutable => {
                fs::remove_file(&self.path).map_err(|source| HookError::Remove {
                    path: self.path.display().to_string(),
                    source,
                })?;
                Ok(true)
            }
            HookStatus::ModifiedManaged | HookStatus::Unrelated => {
                Err(HookError::RefuseUninstall(self.path.display().to_string()))
            }
        }
    }

    fn write_template(&self) -> Result<(), HookError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|source| HookError::Write {
                path: self.path.display().to_string(),
                source,
            })?;
        }
        report::write_atomic(&self.path, self.template.as_bytes())?;
        make_executable(&self.path)?;
        Ok(())
    }
}

fn classify_other(bytes: &[u8]) -> HookStatus {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return HookStatus::Unrelated;
    };
    if is_canonical_managed(text) {
        HookStatus::StaleExecutable
    } else if text.contains(MARKER_PREFIX) {
        HookStatus::ModifiedManaged
    } else {
        HookStatus::Unrelated
    }
}

fn is_canonical_managed(text: &str) -> bool {
    let lines = text.lines().collect::<Vec<_>>();
    let legacy = lines.len() == 3
        && lines[0] == "#!/bin/sh"
        && lines[1] == "# Managed by secret-guard (version 1)"
        && lines[2].starts_with("exec '")
        && lines[2].ends_with("' scan --staged");
    let current = lines.len() == 5
        && lines[0] == "#!/bin/sh"
        && lines[1] == MARKER
        && matches!(
            lines[2],
            "# secret-guard-scope: global" | "# secret-guard-scope: local"
        )
        && matches!(
            lines[3],
            "# secret-guard-config: managed" | "# secret-guard-config: external"
        )
        && lines[4].starts_with("exec '")
        && lines[4].ends_with("' scan --staged");
    legacy || current
}

fn parse_metadata(text: &str) -> Option<ManagedMetadata> {
    if !is_canonical_managed(text) {
        return None;
    }
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() == 3 {
        return Some(ManagedMetadata {
            scope: ManagedScope::Local,
            config_owned: false,
        });
    }
    let scope = match lines[2].strip_prefix(SCOPE_PREFIX)? {
        "global" => ManagedScope::Global,
        "local" => ManagedScope::Local,
        _ => return None,
    };
    Some(ManagedMetadata {
        scope,
        config_owned: lines[3].strip_prefix(CONFIG_PREFIX)? == "managed",
    })
}

pub fn quote_posix(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn posix_executable_path(path: &Path) -> Result<String, HookError> {
    let text = path
        .to_str()
        .ok_or(HookError::ExecutablePathNotUtf8)?
        .replace('\\', "/");
    if text.is_empty() {
        return Err(HookError::ExecutablePathNotUtf8);
    }
    Ok(text)
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<(), HookError> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .map_err(|source| HookError::Permissions {
            path: path.display().to_string(),
            source,
        })?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).map_err(|source| HookError::Permissions {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<(), HookError> {
    Ok(())
}

#[derive(Debug, Error)]
pub enum HookError {
    #[error(transparent)]
    Git(#[from] GitError),
    #[error(transparent)]
    Report(#[from] report::ReportError),
    #[error("unable to read hook at {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("unable to write hook at {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("unable to remove hook at {path}: {source}")]
    Remove {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("unable to set executable permissions on hook at {path}: {source}")]
    Permissions {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("current executable path is not representable as UTF-8")]
    ExecutablePathNotUtf8,
    #[error(
        "refusing to overwrite unrelated or modified hook at {path}. Chain manually with:\n{snippet}"
    )]
    Conflict { path: String, snippet: String },
    #[error("refusing to uninstall unrelated or modified hook at {0}")]
    RefuseUninstall(String),
}

#[cfg(test)]
mod tests {
    use super::{HookStatus, classify_other, quote_posix};

    #[test]
    fn posix_single_quote_escaping_is_safe() {
        assert_eq!(quote_posix("plain path"), "'plain path'");
        assert_eq!(quote_posix("a'b"), "'a'\\''b'");
    }

    #[test]
    fn classifies_stale_modified_and_unrelated_content() {
        let stale = "#!/bin/sh\n# Managed by secret-guard (version 2)\n# secret-guard-scope: local\n# secret-guard-config: external\nexec '/old/path' scan --staged\n";
        assert_eq!(
            classify_other(stale.as_bytes()),
            HookStatus::StaleExecutable
        );
        let modified = format!("{stale}echo changed\n");
        assert_eq!(
            classify_other(modified.as_bytes()),
            HookStatus::ModifiedManaged
        );
        assert_eq!(
            classify_other(b"#!/bin/sh\necho unrelated\n"),
            HookStatus::Unrelated
        );
    }
}
