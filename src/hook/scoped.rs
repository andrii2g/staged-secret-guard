use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use thiserror::Error;

use crate::{
    git::client::GitClient,
    hook::manager::{HookManager, HookStatus, InstallOutcome, ManagedScope},
};

#[derive(Debug, Clone)]
pub enum HookTarget {
    Global,
    Local(PathBuf),
}

impl HookTarget {
    pub const fn scope(&self) -> ManagedScope {
        match self {
            Self::Global => ManagedScope::Global,
            Self::Local(_) => ManagedScope::Local,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopedStatus {
    Hook(HookStatus),
    CoveredByGlobal,
    Shadowed,
}

impl std::fmt::Display for ScopedStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hook(status) => status.fmt(formatter),
            Self::CoveredByGlobal => formatter.write_str("covered-by-global"),
            Self::Shadowed => formatter.write_str("shadowed"),
        }
    }
}

pub enum HookResolution {
    Managed(ScopedHook),
    CoveredByGlobal,
}

pub struct ScopedHook {
    manager: HookManager,
    scope: ManagedScope,
    active: bool,
    config_change: Option<ConfigChange>,
    config_owned: bool,
    config_scope: ConfigScope,
}

impl ScopedHook {
    pub fn resolve(target: HookTarget, executable: &Path) -> Result<HookResolution, ScopeError> {
        match target {
            HookTarget::Global => resolve_global(executable).map(HookResolution::Managed),
            HookTarget::Local(start) => resolve_local(&start, executable),
        }
    }

    pub const fn scope(&self) -> ManagedScope {
        self.scope
    }

    pub fn path(&self) -> &Path {
        self.manager.path()
    }

    pub fn status(&self) -> Result<ScopedStatus, ScopeError> {
        let status = self.manager.status()?;
        if !self.active && matches!(status, HookStatus::Installed | HookStatus::StaleExecutable) {
            Ok(ScopedStatus::Shadowed)
        } else {
            Ok(ScopedStatus::Hook(status))
        }
    }

    pub fn install(&self) -> Result<InstallOutcome, ScopeError> {
        if let Some(change) = &self.config_change {
            change.apply()?;
            match self.manager.install() {
                Ok(outcome) => Ok(outcome),
                Err(error) => {
                    let _ = change.rollback();
                    Err(error.into())
                }
            }
        } else {
            self.manager.install().map_err(Into::into)
        }
    }

    pub fn uninstall(&self) -> Result<bool, ScopeError> {
        let removed = self.manager.uninstall()?;
        if removed && self.config_owned {
            let change = ConfigChange {
                scope: self.config_scope.clone(),
                value: self
                    .manager
                    .path()
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .to_owned(),
            };
            if let Err(error) = change.rollback() {
                let _ = self.manager.install();
                return Err(error);
            }
        }
        Ok(removed)
    }
}

fn resolve_global(executable: &Path) -> Result<ScopedHook, ScopeError> {
    let configured = read_config_path(ConfigScopeRef::Global)?;
    let (hooks_directory, active, change) = if let Some(path) = configured {
        if !path.is_absolute() {
            return Err(ScopeError::RelativeGlobalHooksPath(
                path.display().to_string(),
            ));
        }
        (path, true, None)
    } else {
        let path = default_global_hooks_directory()?;
        (
            path.clone(),
            false,
            Some(ConfigChange {
                scope: ConfigScope::Global,
                value: path,
            }),
        )
    };
    let hook_path = hooks_directory.join("pre-commit");
    let metadata = HookManager::metadata(&hook_path)?;
    let config_owned = metadata.is_some_and(|item| item.config_owned) || change.is_some();
    let manager =
        HookManager::from_path(hook_path, executable, ManagedScope::Global, config_owned)?;
    Ok(ScopedHook {
        manager,
        config_scope: ConfigScope::Global,
        scope: ManagedScope::Global,
        active,
        config_change: change,
        config_owned,
    })
}

fn resolve_local(start: &Path, executable: &Path) -> Result<HookResolution, ScopeError> {
    let client = GitClient::discover(start)?;
    if let Some(configured) = read_config_path(ConfigScopeRef::Local(client.root()))? {
        let hooks_directory = resolve_relative(client.root(), configured);
        return managed_local(
            &hooks_directory,
            executable,
            ConfigScope::Local(client.root().to_owned()),
            None,
        );
    }

    if let Some(global_directory) = read_config_path(ConfigScopeRef::Global)? {
        let global_directory = resolve_relative(client.root(), global_directory);
        let global_path = global_directory.join("pre-commit");
        if let Some(metadata) = HookManager::metadata(&global_path)? {
            if metadata.scope == ManagedScope::Global {
                let global = HookManager::from_path(
                    global_path,
                    executable,
                    ManagedScope::Global,
                    metadata.config_owned,
                )?;
                if global.status()? == HookStatus::Installed {
                    return Ok(HookResolution::CoveredByGlobal);
                }
            }
        }
        if contains_unrelated_hooks(&global_directory)? {
            return Err(ScopeError::UnsafeLocalOverride(
                global_directory.display().to_string(),
            ));
        }
        let common = client.git_path(
            &["rev-parse", "--git-common-dir"],
            "rev-parse --git-common-dir",
        )?;
        let hooks_directory = common.join("hooks");
        let change = ConfigChange {
            scope: ConfigScope::Local(client.root().to_owned()),
            value: hooks_directory.clone(),
        };
        return managed_local(
            &hooks_directory,
            executable,
            ConfigScope::Local(client.root().to_owned()),
            Some(change),
        );
    }

    let hook_path = client.git_path(
        &["rev-parse", "--git-path", "hooks/pre-commit"],
        "rev-parse --git-path",
    )?;
    let hooks_directory = hook_path
        .parent()
        .ok_or(ScopeError::InvalidHookPath)?
        .to_owned();
    managed_local(
        &hooks_directory,
        executable,
        ConfigScope::Local(client.root().to_owned()),
        None,
    )
}

fn managed_local(
    hooks_directory: &Path,
    executable: &Path,
    config_scope: ConfigScope,
    change: Option<ConfigChange>,
) -> Result<HookResolution, ScopeError> {
    let hook_path = hooks_directory.join("pre-commit");
    let metadata = HookManager::metadata(&hook_path)?;
    let config_owned = metadata.is_some_and(|item| item.config_owned) || change.is_some();
    let manager = HookManager::from_path(hook_path, executable, ManagedScope::Local, config_owned)?;
    Ok(HookResolution::Managed(ScopedHook {
        manager,
        scope: ManagedScope::Local,
        active: change.is_none(),
        config_scope,
        config_change: change,
        config_owned,
    }))
}

fn contains_unrelated_hooks(directory: &Path) -> Result<bool, ScopeError> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(ScopeError::ReadDirectory {
                path: directory.display().to_string(),
                source,
            });
        }
    };
    for entry in entries {
        let entry = entry.map_err(|source| ScopeError::ReadDirectory {
            path: directory.display().to_string(),
            source,
        })?;
        let name = entry.file_name();
        if name.to_string_lossy().ends_with(".sample") {
            continue;
        }
        let path = entry.path();
        if name == "pre-commit" && HookManager::metadata(&path)?.is_some() {
            continue;
        }
        return Ok(true);
    }
    Ok(false)
}

#[derive(Debug, Clone)]
enum ConfigScope {
    Global,
    Local(PathBuf),
}

#[derive(Debug, Clone, Copy)]
enum ConfigScopeRef<'a> {
    Global,
    Local(&'a Path),
}

#[derive(Debug, Clone)]
struct ConfigChange {
    scope: ConfigScope,
    value: PathBuf,
}

impl ConfigChange {
    fn apply(&self) -> Result<(), ScopeError> {
        run_config_set(&self.scope, &self.value)
    }

    fn rollback(&self) -> Result<(), ScopeError> {
        run_config_unset(&self.scope)
    }
}

fn read_config_path(scope: ConfigScopeRef<'_>) -> Result<Option<PathBuf>, ScopeError> {
    let mut command = Command::new("git");
    match scope {
        ConfigScopeRef::Global => {
            command.args(["config", "--global", "--path", "--get", "core.hooksPath"]);
        }
        ConfigScopeRef::Local(root) => {
            command.current_dir(root).args([
                "config",
                "--local",
                "--path",
                "--get",
                "core.hooksPath",
            ]);
        }
    }
    let output = command.output().map_err(ScopeError::GitSpawn)?;
    if output.status.code() == Some(1) {
        return Ok(None);
    }
    ensure_config_success(&output, "read core.hooksPath")?;
    let bytes = strip_line_ending(&output.stdout);
    let value = std::str::from_utf8(bytes).map_err(|_| ScopeError::InvalidGitConfigOutput)?;
    if value.is_empty() {
        return Ok(None);
    }
    Ok(Some(PathBuf::from(value)))
}

fn run_config_set(scope: &ConfigScope, value: &Path) -> Result<(), ScopeError> {
    let mut command = Command::new("git");
    match scope {
        ConfigScope::Global => {
            command
                .args(["config", "--global", "core.hooksPath"])
                .arg(value);
        }
        ConfigScope::Local(root) => {
            command
                .current_dir(root)
                .args(["config", "--local", "core.hooksPath"])
                .arg(value);
        }
    }
    let output = command.output().map_err(ScopeError::GitSpawn)?;
    ensure_config_success(&output, "set core.hooksPath")
}

fn run_config_unset(scope: &ConfigScope) -> Result<(), ScopeError> {
    let mut command = Command::new("git");
    match scope {
        ConfigScope::Global => {
            command.args(["config", "--global", "--unset", "core.hooksPath"]);
        }
        ConfigScope::Local(root) => {
            command
                .current_dir(root)
                .args(["config", "--local", "--unset", "core.hooksPath"]);
        }
    }
    let output = command.output().map_err(ScopeError::GitSpawn)?;
    if output.status.code() == Some(5) || output.status.code() == Some(1) {
        return Ok(());
    }
    ensure_config_success(&output, "unset core.hooksPath")
}

fn ensure_config_success(output: &Output, operation: &'static str) -> Result<(), ScopeError> {
    if output.status.success() {
        Ok(())
    } else {
        Err(ScopeError::GitConfig {
            operation,
            status: output.status.code(),
        })
    }
}

fn default_global_hooks_directory() -> Result<PathBuf, ScopeError> {
    if let Some(path) = env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path).join("secret-guard").join("hooks"));
    }
    let home = if cfg!(windows) {
        env::var_os("USERPROFILE").or_else(|| env::var_os("HOME"))
    } else {
        env::var_os("HOME")
    }
    .ok_or(ScopeError::UserConfigDirectoryUnavailable)?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("secret-guard")
        .join("hooks"))
}

fn resolve_relative(root: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

fn strip_line_ending(bytes: &[u8]) -> &[u8] {
    bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .unwrap_or(bytes)
}

#[derive(Debug, Error)]
pub enum ScopeError {
    #[error(transparent)]
    Git(#[from] crate::git::client::GitError),
    #[error(transparent)]
    Hook(#[from] crate::hook::manager::HookError),
    #[error("unable to execute Git configuration command: {0}")]
    GitSpawn(#[source] io::Error),
    #[error("Git configuration operation {operation} failed with status {status:?}")]
    GitConfig {
        operation: &'static str,
        status: Option<i32>,
    },
    #[error("Git returned a non-UTF-8 hooks path")]
    InvalidGitConfigOutput,
    #[error("unable to resolve the current user's configuration directory")]
    UserConfigDirectoryUnavailable,
    #[error(
        "global core.hooksPath must be absolute for a shared hook installation; configured value: {0}"
    )]
    RelativeGlobalHooksPath(String),
    #[error("unable to resolve the managed hook directory")]
    InvalidHookPath,
    #[error("unable to inspect hooks directory {path}: {source}")]
    ReadDirectory {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("refusing to override global hooks directory {0} because it contains unrelated hooks")]
    UnsafeLocalOverride(String),
}
