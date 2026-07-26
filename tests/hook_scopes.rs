use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use tempfile::{TempDir, tempdir};

struct IsolatedUser {
    directory: TempDir,
    global_config: PathBuf,
    config_home: PathBuf,
    outside: PathBuf,
}

impl IsolatedUser {
    fn new() -> Self {
        let directory = tempdir().expect("temporary user directory");
        let global_config = directory.path().join("global.gitconfig");
        let config_home = directory.path().join("config");
        let outside = directory.path().join("outside");
        fs::create_dir(&outside).expect("outside directory");
        Self {
            directory,
            global_config,
            config_home,
            outside,
        }
    }

    fn guard(&self, current: &Path, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_secret-guard"))
            .current_dir(current)
            .env("GIT_CONFIG_GLOBAL", &self.global_config)
            .env("XDG_CONFIG_HOME", &self.config_home)
            .args(arguments)
            .output()
            .expect("run secret guard")
    }

    fn git(&self, current: &Path, arguments: &[&str]) -> Output {
        Command::new("git")
            .current_dir(current)
            .env("GIT_CONFIG_GLOBAL", &self.global_config)
            .env("XDG_CONFIG_HOME", &self.config_home)
            .args(arguments)
            .output()
            .expect("run Git")
    }

    fn managed_hook(&self) -> PathBuf {
        self.config_home
            .join("secret-guard")
            .join("hooks")
            .join("pre-commit")
    }

    fn init_repo(&self, name: &str) -> PathBuf {
        let path = self.directory.path().join(name);
        fs::create_dir(&path).expect("repository directory");
        let output = self.git(&path, &["init", "-b", "main"]);
        assert!(output.status.success());
        path
    }
}

#[test]
fn global_install_works_outside_repository_and_covers_local_repo() {
    let user = IsolatedUser::new();
    let install = user.guard(&user.outside, &["hook", "install"]);
    assert_eq!(
        install.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&install.stderr)
    );
    assert!(String::from_utf8_lossy(&install.stdout).contains("hook(global): installed"));
    assert!(user.managed_hook().exists());

    let status = user.guard(&user.outside, &["hook", "status"]);
    assert_eq!(status.stdout, b"installed\n");

    let repo = user.init_repo("covered");
    let local = user.guard(&repo, &["hook", "status", "--local"]);
    assert_eq!(local.stdout, b"covered-by-global\n");

    let uninstall = user.guard(&user.outside, &["hook", "uninstall"]);
    assert_eq!(uninstall.stdout, b"uninstalled\n");
    assert!(!user.managed_hook().exists());
    let configured = user.git(
        &user.outside,
        &["config", "--global", "--get", "core.hooksPath"],
    );
    assert!(!configured.status.success());
}

#[test]
fn explicit_global_install_applies_configuration_without_prompt() {
    let user = IsolatedUser::new();
    let output = user.guard(&user.outside, &["hook", "install", "--global"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert!(user.managed_hook().exists());

    let configured = user.git(
        &user.outside,
        &["config", "--global", "--get", "core.hooksPath"],
    );
    assert!(configured.status.success());
}

#[test]
fn global_install_adopts_safe_path_and_refuses_unrelated_pre_commit() {
    let user = IsolatedUser::new();
    let custom = user.directory.path().join("custom-hooks");
    fs::create_dir(&custom).expect("custom hooks");
    let configured = user.git(
        &user.outside,
        &[
            "config",
            "--global",
            "core.hooksPath",
            custom.to_str().expect("UTF-8 custom path"),
        ],
    );
    assert!(configured.status.success());
    let unrelated = "#!/bin/sh\necho unrelated\n";
    fs::write(custom.join("pre-commit"), unrelated).expect("unrelated hook");

    let output = user.guard(&user.outside, &["hook", "install"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        fs::read_to_string(custom.join("pre-commit")).expect("preserved hook"),
        unrelated
    );
}

#[test]
fn explicit_repository_path_installs_local_hook() {
    let user = IsolatedUser::new();
    let repo = user.init_repo("selected");
    let output = user.guard(
        &user.outside,
        &[
            "hook",
            "install",
            "--local",
            "--repository",
            repo.to_str().expect("UTF-8 repository"),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("hook(local): installed"));
    let status = user.guard(
        &user.outside,
        &[
            "hook",
            "status",
            "--local",
            "--repository",
            repo.to_str().expect("UTF-8 repository"),
        ],
    );
    assert_eq!(status.stdout, b"installed\n");
}

#[test]
fn global_install_refuses_relative_shared_hooks_path() {
    let user = IsolatedUser::new();
    let configured = user.git(
        &user.outside,
        &[
            "config",
            "--global",
            "core.hooksPath",
            "repository-relative-hooks",
        ],
    );
    assert!(configured.status.success());

    let output = user.guard(&user.outside, &["hook", "install"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("global core.hooksPath must be absolute")
    );
}
