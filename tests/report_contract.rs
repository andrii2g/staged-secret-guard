use std::{fs, process::Command};

use tempfile::tempdir;

fn scan(directory: &std::path::Path, arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_secret-guard"))
        .args(arguments)
        .arg("scan")
        .arg(directory)
        .output()
        .expect("run scanner")
}

fn jwt_candidate() -> String {
    ["eyJ", "hbGciOiJub25lIn0.", "cGF5bG9hZA.", "c2lnbmF0dXJl"].concat()
}

#[test]
fn threshold_and_quiet_preserve_nonblocking_findings() {
    let directory = tempdir().expect("temporary directory");
    let candidate = jwt_candidate();
    fs::write(
        directory.path().join("token.txt"),
        format!("value={candidate}\n"),
    )
    .expect("JWT file");

    let default = scan(directory.path(), &[]);
    assert_eq!(default.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&default.stdout).contains("jwt-token"));

    let quiet = scan(directory.path(), &["--quiet"]);
    assert_eq!(quiet.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&quiet.stdout).contains("jwt-token"));

    let blocking = scan(directory.path(), &["--fail-on", "medium"]);
    assert_eq!(blocking.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&blocking.stdout).contains(&candidate));
}

#[test]
fn json_is_deterministic_and_contains_only_redacted_values() {
    let directory = tempdir().expect("temporary directory");
    let candidate = ["Ab", "12", "-complex-", "Value", "9876"].concat();
    fs::write(
        directory.path().join("nested.txt"),
        format!("password=\"{candidate}\"\n"),
    )
    .expect("secret file");
    let first = scan(directory.path(), &["--format", "json"]);
    let second = scan(directory.path(), &["--format", "json"]);
    assert_eq!(first.status.code(), Some(1));
    assert_eq!(first.stdout, second.stdout);
    assert!(!String::from_utf8_lossy(&first.stdout).contains(&candidate));
    let value: serde_json::Value = serde_json::from_slice(&first.stdout).expect("JSON report");
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["findings"][0]["path"], "nested.txt");
    assert!(value["findings"][0].get("redacted").is_some());
    assert!(value["findings"][0].get("candidate").is_none());
    assert!(value.get("timestamp").is_none());
}

#[test]
fn output_file_is_excluded_and_json_stdout_stays_empty() {
    let directory = tempdir().expect("temporary directory");
    fs::write(directory.path().join("clean.txt"), "clean=true\n").expect("clean file");
    let report = directory.path().join("report.json");
    let output = scan(
        directory.path(),
        &[
            "--format",
            "json",
            "--output",
            report.to_str().expect("UTF-8 report path"),
        ],
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(&report).expect("read report")).expect("JSON report");
    assert_eq!(value["findings"].as_array().map(Vec::len), Some(0));
}

#[test]
fn failed_output_write_returns_operational_error_without_partial_json() {
    let directory = tempdir().expect("temporary directory");
    fs::write(directory.path().join("clean.txt"), "clean=true\n").expect("clean file");
    let destination_directory = directory.path().join("destination");
    fs::create_dir(&destination_directory).expect("destination directory");
    let output = scan(
        directory.path(),
        &[
            "--format",
            "json",
            "--output",
            destination_directory.to_str().expect("UTF-8 path"),
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unable to write report"));
}
