use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use tempfile::{TempDir, tempdir};

struct Repo {
    directory: TempDir,
}

impl Repo {
    fn init() -> Self {
        let directory = tempdir().expect("temporary repository");
        git(directory.path(), &["init", "-b", "main"]);
        git(directory.path(), &["config", "user.name", "Hook Tests"]);
        git(
            directory.path(),
            &["config", "user.email", "hooks@example.test"],
        );
        git(
            directory.path(),
            &["config", "core.hooksPath", ".git/hooks"],
        );
        fs::write(directory.path().join("base.txt"), "base\n").expect("base file");
        git(directory.path(), &["add", "base.txt"]);
        git(directory.path(), &["commit", "--no-gpg-sign", "-m", "base"]);
        Self { directory }
    }

    fn path(&self) -> &Path {
        self.directory.path()
    }

    fn guard(&self, arguments: &[&str]) -> Output {
        let mut scoped = arguments.to_vec();
        if arguments.first() == Some(&"hook") {
            scoped.push("--local");
        }
        Command::new(env!("CARGO_BIN_EXE_secret-guard"))
            .current_dir(self.path())
            .args(scoped)
            .output()
            .expect("run secret guard")
    }

    fn hook_path(&self) -> PathBuf {
        let output = git(
            self.path(),
            &["rev-parse", "--git-path", "hooks/pre-commit"],
        );
        let text = String::from_utf8(output.stdout).expect("UTF-8 hook path");
        let path = PathBuf::from(text.trim());
        if path.is_absolute() {
            path
        } else {
            self.path().join(path)
        }
    }
}

fn git(directory: &Path, arguments: &[&str]) -> Output {
    let output = Command::new("git")
        .current_dir(directory)
        .args(arguments)
        .output()
        .expect("run Git");
    assert!(
        output.status.success(),
        "Git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn git_allow_failure(directory: &Path, arguments: &[&str]) -> Output {
    Command::new("git")
        .current_dir(directory)
        .args(arguments)
        .output()
        .expect("run Git")
}

#[test]
fn install_status_idempotence_update_and_uninstall() {
    let repo = Repo::init();
    assert_eq!(repo.guard(&["hook", "status"]).stdout, b"absent\n");
    let install = repo.guard(&["hook", "install"]);
    assert_eq!(install.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&install.stdout).contains("hook(local): installed"));
    assert_eq!(repo.guard(&["hook", "status"]).stdout, b"installed\n");
    let repeated = repo.guard(&["hook", "install"]);
    assert!(String::from_utf8_lossy(&repeated.stdout).contains("already installed"));

    let hook_path = repo.hook_path();
    let template = fs::read_to_string(&hook_path).expect("managed hook");
    let stale = template
        .lines()
        .enumerate()
        .map(|(index, line)| {
            if index == 4 {
                "exec '/old/secret-guard' scan --staged"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(&hook_path, stale).expect("stale hook");
    assert_eq!(
        repo.guard(&["hook", "status"]).stdout,
        b"stale-executable\n"
    );
    let updated = repo.guard(&["hook", "install"]);
    assert!(String::from_utf8_lossy(&updated.stdout).contains("updated managed hook"));
    assert_eq!(repo.guard(&["hook", "uninstall"]).stdout, b"uninstalled\n");
    assert!(!hook_path.exists());
    assert_eq!(repo.guard(&["hook", "uninstall"]).stdout, b"absent\n");
}

#[test]
fn unrelated_hook_is_never_overwritten() {
    let repo = Repo::init();
    let path = repo.hook_path();
    let unrelated = "#!/bin/sh\necho unrelated\n";
    fs::write(&path, unrelated).expect("unrelated hook");
    let output = repo.guard(&["hook", "install"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Chain manually"));
    assert_eq!(
        fs::read_to_string(&path).expect("preserved hook"),
        unrelated
    );
    assert_eq!(repo.guard(&["hook", "status"]).stdout, b"unrelated\n");
}

#[test]
fn modified_managed_hook_is_never_removed() {
    let repo = Repo::init();
    assert_eq!(repo.guard(&["hook", "install"]).status.code(), Some(0));
    let path = repo.hook_path();
    let mut content = fs::read_to_string(&path).expect("managed hook");
    content.push_str("echo modified\n");
    fs::write(&path, &content).expect("modified hook");
    assert_eq!(
        repo.guard(&["hook", "status"]).stdout,
        b"modified-managed\n"
    );
    let uninstall = repo.guard(&["hook", "uninstall"]);
    assert_eq!(uninstall.status.code(), Some(2));
    assert_eq!(fs::read_to_string(&path).expect("preserved hook"), content);
}

#[test]
fn hook_allows_clean_commit_and_blocks_staged_candidate() {
    let repo = Repo::init();
    assert_eq!(repo.guard(&["hook", "install"]).status.code(), Some(0));
    fs::write(repo.path().join("clean.txt"), "ordinary content\n").expect("clean file");
    git(repo.path(), &["add", "clean.txt"]);
    let clean = git_allow_failure(repo.path(), &["commit", "--no-gpg-sign", "-m", "clean"]);
    assert!(clean.status.success(), "clean hook commit failed");

    let candidate = format!("{}{}", ["g", "hp", "_"].concat(), "A".repeat(36));
    fs::write(
        repo.path().join("config.txt"),
        format!("token={candidate}\n"),
    )
    .expect("candidate file");
    git(repo.path(), &["add", "config.txt"]);
    let blocked = git_allow_failure(repo.path(), &["commit", "--no-gpg-sign", "-m", "blocked"]);
    assert!(!blocked.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&blocked.stdout),
        String::from_utf8_lossy(&blocked.stderr)
    );
    assert!(combined.contains("github-token"));
    assert!(!combined.contains(&candidate));
}

#[cfg(unix)]
#[test]
fn installed_hook_has_executable_bits() {
    use std::os::unix::fs::PermissionsExt;

    let repo = Repo::init();
    assert_eq!(repo.guard(&["hook", "install"]).status.code(), Some(0));
    let mode = fs::metadata(repo.hook_path())
        .expect("hook metadata")
        .permissions()
        .mode();
    assert_ne!(mode & 0o111, 0);
}

#[test]
fn hook_path_resolution_works_from_linked_worktree() {
    let parent = tempdir().expect("worktree parent");
    let main = parent.path().join("main");
    let linked = parent.path().join("linked");
    fs::create_dir(&main).expect("main directory");
    git(&main, &["init", "-b", "main"]);
    git(&main, &["config", "user.name", "Worktree Tests"]);
    git(&main, &["config", "user.email", "worktrees@example.test"]);
    fs::write(main.join("base.txt"), "base\n").expect("base file");
    git(&main, &["add", "base.txt"]);
    git(&main, &["commit", "--no-gpg-sign", "-m", "base"]);
    git(
        &main,
        &[
            "worktree",
            "add",
            "-b",
            "linked",
            linked.to_str().expect("UTF-8 linked path"),
        ],
    );

    let install = Command::new(env!("CARGO_BIN_EXE_secret-guard"))
        .current_dir(&linked)
        .args(["hook", "install", "--local"])
        .output()
        .expect("install from worktree");
    assert_eq!(
        install.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&install.stderr)
    );
    let status = Command::new(env!("CARGO_BIN_EXE_secret-guard"))
        .current_dir(&linked)
        .args(["hook", "status", "--local"])
        .output()
        .expect("status from worktree");
    assert_eq!(status.stdout, b"installed\n");
    let hook = git(&linked, &["rev-parse", "--git-path", "hooks/pre-commit"]);
    let hook = PathBuf::from(
        String::from_utf8(hook.stdout)
            .expect("UTF-8 hook path")
            .trim(),
    );
    let hook = if hook.is_absolute() {
        hook
    } else {
        linked.join(hook)
    };
    assert!(hook.exists());
}
