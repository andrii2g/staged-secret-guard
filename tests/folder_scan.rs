use std::{fs, process::Command};

use tempfile::tempdir;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_secret-guard"))
}

#[test]
fn clean_folder_scan_and_quiet_mode_succeed() {
    let directory = tempdir().expect("temporary directory");
    fs::write(directory.path().join("clean.txt"), "ordinary content\n").expect("clean file");
    let output = binary()
        .args(["scan", directory.path().to_str().expect("UTF-8 path")])
        .output()
        .expect("run scanner");
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("no blocking secrets"));

    let quiet = binary()
        .args([
            "--quiet",
            "scan",
            directory.path().to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run quiet scanner");
    assert_eq!(quiet.status.code(), Some(0));
    assert!(quiet.stdout.is_empty());
}

#[test]
fn json_folder_scan_blocks_without_candidate_leakage() {
    let directory = tempdir().expect("temporary directory");
    let candidate = ["Ab", "12", "-complex-", "Value", "9876"].concat();
    fs::write(
        directory.path().join("config.txt"),
        format!("password=\"{candidate}\"\n"),
    )
    .expect("secret file");
    let output = binary()
        .args([
            "--format",
            "json",
            "scan",
            directory.path().to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run scanner");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let rendered = String::from_utf8(output.stdout).expect("UTF-8 JSON");
    assert!(rendered.contains("\"schemaVersion\": 1"));
    assert!(rendered.contains("generic-secret-assignment"));
    assert!(!rendered.contains(&candidate));
}

#[test]
fn invalid_configuration_fails_closed_without_source_excerpt() {
    let directory = tempdir().expect("temporary directory");
    let sensitive = "must-not-be-echoed";
    fs::write(
        directory.path().join(".secret-guard.toml"),
        format!("unknown = \"{sensitive}\""),
    )
    .expect("invalid config");
    let output = binary()
        .args(["scan", directory.path().to_str().expect("UTF-8 path")])
        .output()
        .expect("run scanner");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Invalid configuration"));
    assert!(!stderr.contains(sensitive));
}
