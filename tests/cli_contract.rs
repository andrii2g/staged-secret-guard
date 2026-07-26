use clap::Parser;
use secret_guard::cli::{Cli, Command, HookAction, OutputFormat, RulesAction};

#[test]
fn no_command_is_reserved_for_default_staged_scan() {
    let cli = Cli::try_parse_from(["secret-guard"]).expect("CLI should parse");
    assert!(cli.command.is_none());
    assert_eq!(cli.format, OutputFormat::Console);
}

#[test]
fn explicit_staged_scan_parses() {
    let cli = Cli::try_parse_from(["secret-guard", "scan", "--staged"])
        .expect("staged scan should parse");

    let Some(Command::Scan(scan)) = cli.command else {
        panic!("expected scan command");
    };

    assert!(scan.staged);
    assert!(scan.path.is_none());
}

#[test]
fn folder_scan_parses() {
    let cli = Cli::try_parse_from(["secret-guard", "scan", "."]).expect("folder scan should parse");

    let Some(Command::Scan(scan)) = cli.command else {
        panic!("expected scan command");
    };

    assert!(!scan.staged);
    assert!(scan.path.is_some());
}

#[test]
fn path_and_staged_are_mutually_exclusive() {
    let result = Cli::try_parse_from(["secret-guard", "scan", ".", "--staged"]);
    assert!(result.is_err());
}

#[test]
fn hook_actions_parse() {
    for name in ["install", "status", "uninstall"] {
        let cli =
            Cli::try_parse_from(["secret-guard", "hook", name]).expect("hook action should parse");
        let Some(Command::Hook { action }) = cli.command else {
            panic!("expected hook command");
        };
        assert!(matches!(
            (name, action),
            ("install", HookAction::Install(_))
                | ("status", HookAction::Status(_))
                | ("uninstall", HookAction::Uninstall(_))
        ));
    }
}

#[test]
fn hook_scope_arguments_parse_and_yes_is_rejected() {
    let cli = Cli::try_parse_from([
        "secret-guard",
        "hook",
        "install",
        "--local",
        "--repository",
        ".",
    ])
    .expect("local hook arguments should parse");
    let Some(Command::Hook {
        action: HookAction::Install(arguments),
    }) = cli.command
    else {
        panic!("expected hook install");
    };
    assert!(arguments.local);
    assert!(arguments.repository.is_some());
    assert!(Cli::try_parse_from(["secret-guard", "hook", "status", "--repository", "."]).is_err());
    assert!(Cli::try_parse_from(["secret-guard", "hook", "install", "--yes"]).is_err());
}

#[test]
fn rules_list_parses() {
    let cli =
        Cli::try_parse_from(["secret-guard", "rules", "list"]).expect("rules list should parse");
    let Some(Command::Rules { action }) = cli.command else {
        panic!("expected rules command");
    };
    assert!(matches!(action, RulesAction::List));
}
