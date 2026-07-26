use std::process::Command;

#[test]
fn console_rule_listing_is_sorted_and_complete() {
    let output = Command::new(env!("CARGO_BIN_EXE_secret-guard"))
        .args(["rules", "list"])
        .output()
        .expect("run rule listing");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 listing");
    let mut lines = stdout.lines();
    assert_eq!(
        lines.next(),
        Some("RULE ID | SEVERITY | FAMILY | DESCRIPTION")
    );
    let ids = lines
        .map(|line| line.split(" | ").next().expect("rule ID"))
        .collect::<Vec<_>>();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted);
    assert_eq!(ids.len(), 19);
}

#[test]
fn json_rule_listing_has_stable_schema_and_metadata() {
    let output = Command::new(env!("CARGO_BIN_EXE_secret-guard"))
        .args(["--format", "json", "rules", "list"])
        .output()
        .expect("run JSON rule listing");
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON listing");
    assert_eq!(value["schemaVersion"], 1);
    let rules = value["rules"].as_array().expect("rules array");
    assert_eq!(rules.len(), 19);
    assert_eq!(rules[0]["id"], "aws-access-key-id");
    assert!(rules.iter().all(|rule| {
        rule.get("id").is_some()
            && rule.get("severity").is_some()
            && rule.get("family").is_some()
            && rule.get("description").is_some()
    }));
}
