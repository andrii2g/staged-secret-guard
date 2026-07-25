use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use tempfile::{TempDir, tempdir};

struct Repo {
    directory: TempDir,
}

impl Repo {
    fn init() -> Self {
        let directory = tempdir().expect("temporary repository");
        run_git(directory.path(), &["init", "-b", "main"]);
        run_git(
            directory.path(),
            &["config", "user.name", "Secret Guard Tests"],
        );
        run_git(
            directory.path(),
            &["config", "user.email", "tests@example.test"],
        );
        run_git(
            directory.path(),
            &["config", "core.hooksPath", ".git/hooks"],
        );
        Self { directory }
    }

    fn path(&self) -> &Path {
        self.directory.path()
    }

    fn write(&self, relative: &str, text: &str) {
        let path = self.path().join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create file parent");
        }
        fs::write(path, text).expect("write repository file");
    }

    fn add(&self, relative: &str) {
        run_git(self.path(), &["add", "--", relative]);
    }

    fn commit(&self, message: &str) {
        run_git(self.path(), &["commit", "--no-gpg-sign", "-m", message]);
    }

    fn scan(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_secret-guard"))
            .current_dir(self.path())
            .args(arguments)
            .output()
            .expect("run secret guard")
    }
}

fn run_git(directory: &Path, arguments: &[&str]) -> Output {
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

fn run_git_allow_failure(directory: &Path, arguments: &[&str]) -> Output {
    Command::new("git")
        .current_dir(directory)
        .args(arguments)
        .output()
        .expect("run Git")
}

fn run_git_with_input(directory: &Path, arguments: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new("git")
        .current_dir(directory)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Git");
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input).expect("write Git stdin");
    }
    let output = child.wait_with_output().expect("wait for Git");
    assert!(output.status.success(), "Git with input failed");
    output
}

fn provider_candidate() -> String {
    format!("{}{}", ["g", "hp", "_"].concat(), "A".repeat(36))
}

fn generic_candidate() -> String {
    ["Ab", "12", "-complex-", "Value", "9876"].concat()
}

#[test]
fn initial_commit_clean_content_works_for_all_staged_command_forms() {
    let repo = Repo::init();
    repo.write("clean.txt", "ordinary staged content\n");
    repo.add("clean.txt");
    for arguments in [&[][..], &["scan"][..], &["scan", "--staged"][..]] {
        let output = repo.scan(arguments);
        assert_eq!(output.status.code(), Some(0));
    }
}

#[test]
fn newly_staged_provider_candidate_blocks_without_leaking_json() {
    let repo = Repo::init();
    let candidate = provider_candidate();
    repo.write("config.txt", &format!("token={candidate}\n"));
    repo.add("config.txt");
    let output = repo.scan(&["--format", "json"]);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 JSON");
    assert!(stdout.contains("github-token"));
    assert!(!stdout.contains(&candidate));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(&candidate));
}

#[test]
fn unstaged_secret_does_not_affect_clean_index() {
    let repo = Repo::init();
    repo.write("config.txt", "clean=true\n");
    repo.add("config.txt");
    repo.write("config.txt", &format!("token={}\n", provider_candidate()));
    let output = repo.scan(&[]);
    assert_eq!(output.status.code(), Some(0));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("github-token"));
}

#[test]
fn staged_secret_remains_visible_after_worktree_is_cleaned() {
    let repo = Repo::init();
    let candidate = provider_candidate();
    repo.write("config.txt", &format!("token={candidate}\n"));
    repo.add("config.txt");
    repo.write("config.txt", "clean=true\n");
    let output = repo.scan(&["--format", "json"]);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("github-token"));
    assert!(!stdout.contains(&candidate));
}

#[test]
fn unchanged_historical_secret_does_not_block_unrelated_staged_line() {
    let repo = Repo::init();
    let candidate = provider_candidate();
    repo.write("config.txt", &format!("token={candidate}\nsetting=old\n"));
    repo.add("config.txt");
    repo.commit("historical test data");
    repo.write("config.txt", &format!("token={candidate}\nsetting=new\n"));
    repo.add("config.txt");
    let output = repo.scan(&["--format", "json"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("github-token"));
}

#[test]
fn modified_secret_line_blocks_and_deleted_file_is_ignored() {
    let repo = Repo::init();
    repo.write("config.txt", "token=clean\n");
    repo.write("delete.txt", &format!("password={}\n", generic_candidate()));
    repo.add("config.txt");
    repo.add("delete.txt");
    repo.commit("base");
    repo.write("config.txt", &format!("token={}\n", provider_candidate()));
    repo.add("config.txt");
    run_git(repo.path(), &["rm", "delete.txt"]);
    let output = repo.scan(&["--format", "json"]);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("config.txt"));
    assert!(!stdout.contains("delete.txt"));
}

#[test]
fn rename_only_skips_content_but_new_suspicious_path_is_reported() {
    let repo = Repo::init();
    let candidate = provider_candidate();
    repo.write("ordinary.txt", &format!("token={candidate}\n"));
    repo.add("ordinary.txt");
    repo.commit("base");
    run_git(repo.path(), &["mv", "ordinary.txt", ".env.production"]);
    let output = repo.scan(&["--format", "json"]);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("suspicious-file-path"));
    assert!(!stdout.contains("github-token"));
    assert!(!stdout.contains(&candidate));
}

#[test]
fn spaces_and_unicode_paths_are_handled_deterministically() {
    let repo = Repo::init();
    let candidate = provider_candidate();
    let unicode_path = "nested/unicod\u{00e9} file.txt";
    repo.write(unicode_path, &format!("token={candidate}\n"));
    repo.add(unicode_path);
    let output = repo.scan(&["--format", "json"]);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 JSON");
    assert!(stdout.contains("nested/unicod"));
    assert!(stdout.contains(" file.txt"));
    assert!(!stdout.contains(&candidate));
}

#[test]
fn private_key_block_is_retained_when_changed_body_line_intersects() {
    let repo = Repo::init();
    let begin = ["-----BEGIN ", "PRIVATE", " KEY-----"].concat();
    let end = ["-----END ", "PRIVATE", " KEY-----"].concat();
    repo.write("key.txt", &format!("{begin}\nbody-one\n{end}\n"));
    repo.add("key.txt");
    repo.commit("base block");
    repo.write("key.txt", &format!("{begin}\nbody-two\n{end}\n"));
    repo.add("key.txt");
    let output = repo.scan(&["--format", "json"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stdout).contains("private-key-pem"));
}

#[test]
fn staged_symlink_and_submodule_modes_are_counted_as_skips() {
    let repo = Repo::init();
    repo.write("base.txt", "base\n");
    repo.add("base.txt");
    repo.commit("base");
    let blob = run_git_with_input(
        repo.path(),
        &["hash-object", "-w", "--stdin"],
        b"target.txt",
    )
    .stdout;
    let blob = String::from_utf8(blob).expect("blob ID").trim().to_owned();
    let head =
        String::from_utf8(run_git(repo.path(), &["rev-parse", "HEAD"]).stdout).expect("commit ID");
    let head = head.trim();
    run_git(
        repo.path(),
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("120000,{blob},link.txt"),
        ],
    );
    run_git(
        repo.path(),
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{head},vendor/module"),
        ],
    );
    let output = repo.scan(&["--format", "json"]);
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON report");
    assert_eq!(value["summary"]["skipped"]["symlink"], 1);
    assert_eq!(value["summary"]["skipped"]["submodule"], 1);
}

#[test]
fn unmerged_index_and_non_repository_fail_closed() {
    let repo = Repo::init();
    repo.write("conflict.txt", "base\n");
    repo.add("conflict.txt");
    repo.commit("base");
    run_git(repo.path(), &["checkout", "-b", "other"]);
    repo.write("conflict.txt", "other\n");
    repo.add("conflict.txt");
    repo.commit("other");
    run_git(repo.path(), &["checkout", "main"]);
    repo.write("conflict.txt", "main\n");
    repo.add("conflict.txt");
    repo.commit("main");
    let merge = run_git_allow_failure(repo.path(), &["merge", "other"]);
    assert!(!merge.status.success());
    let output = repo.scan(&[]);
    assert_eq!(output.status.code(), Some(2));

    let outside = tempdir().expect("non-repository directory");
    let no_repo = Command::new(env!("CARGO_BIN_EXE_secret-guard"))
        .current_dir(outside.path())
        .output()
        .expect("run outside repository");
    assert_eq!(no_repo.status.code(), Some(2));
}

#[test]
fn missing_git_executable_is_an_operational_error() {
    let directory = tempdir().expect("temporary directory");
    let missing = PathBuf::from("definitely-missing-secret-guard-git-executable");
    let result =
        secret_guard::git::client::GitClient::discover_with(directory.path(), missing.as_os_str());
    assert!(result.is_err());
}
