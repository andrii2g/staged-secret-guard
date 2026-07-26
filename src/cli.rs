use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "secret-guard",
    version,
    about = "Detect likely secrets in staged Git content before commit"
)]
pub struct Cli {
    /// Explicit TOML configuration file.
    #[arg(long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Report format: console or json.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Console)]
    pub format: OutputFormat,

    /// Write the completed report atomically to a file.
    #[arg(long, global = true, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Minimum severity that produces exit code 1.
    #[arg(long, global = true, value_enum)]
    pub fail_on: Option<SeverityArg>,

    /// Suppress clean-success console output.
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

#[derive(Debug, Clone, Subcommand)]
pub enum HookAction {
    /// Install or update the fully managed pre-commit hook.
    Install(HookTargetArgs),
    /// Print the stable managed-hook status identifier.
    Status(HookTargetArgs),
    /// Remove only a recognized fully managed hook.
    Uninstall(HookTargetArgs),
}

#[derive(Debug, Clone, Args)]
pub struct HookTargetArgs {
    /// Explicitly target the current operating-system user's Git configuration.
    #[arg(long, conflicts_with = "local")]
    pub global: bool,

    /// Target one local Git repository instead of the global user configuration.
    #[arg(long, conflicts_with = "global")]
    pub local: bool,

    /// Repository to target with --local; defaults to the current directory.
    #[arg(long, value_name = "PATH", requires = "local")]
    pub repository: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Subcommand)]
pub enum RulesAction {
    /// List all built-in rule metadata.
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
