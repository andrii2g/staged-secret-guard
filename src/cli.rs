use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "secret-guard",
    version,
    about = "Detect likely secrets in staged Git content before commit"
)]
pub struct Cli {
    #[arg(long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Console)]
    pub format: OutputFormat,

    #[arg(long, global = true, value_name = "FILE")]
    pub output: Option<PathBuf>,

    #[arg(long, global = true, value_enum)]
    pub fail_on: Option<SeverityArg>,

    #[arg(long, global = true)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan staged Git content or an explicit folder.
    Scan(ScanArgs),
    /// Install, inspect, or remove the managed pre-commit hook.
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },
    /// Inspect the built-in rule catalog.
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Folder to scan recursively. Omit it to scan staged Git content.
    #[arg(value_name = "PATH", conflicts_with = "staged")]
    pub path: Option<PathBuf>,

    /// Explicitly scan staged Git-index content.
    #[arg(long)]
    pub staged: bool,
}

#[derive(Debug, Clone, Copy, Subcommand)]
pub enum HookAction {
    Install,
    Status,
    Uninstall,
}

#[derive(Debug, Clone, Copy, Subcommand)]
pub enum RulesAction {
    List,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Console,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SeverityArg {
    Low,
    Medium,
    High,
    Critical,
}
