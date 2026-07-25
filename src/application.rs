use std::{
    io::{self, Write},
    path::{Path, PathBuf},
};

use crate::{
    cli::{Cli, Command, OutputFormat, SeverityArg},
    config::Config,
    error::ToolError,
    git::{client::GitClient, staged_source::scan_staged},
    exit_code::{CLEAN, FINDINGS, OPERATIONAL_ERROR},
    report,
    scan::{ScanResult, folder_source::scan_folder},
    severity::Severity,
};

pub fn execute(cli: Cli) -> u8 {
    match execute_inner(cli) {
        Ok(code) => code,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "secret-guard: {error}");
            OPERATIONAL_ERROR
        }
    }
}

fn execute_inner(cli: Cli) -> Result<u8, ToolError> {
    let format = cli.format;
    let output = cli.output.clone();
    let quiet = cli.quiet;
    let cli_threshold = cli.fail_on.map(Severity::from);

    match cli.command {
        Some(Command::Scan(scan)) if scan.path.is_some() => {
            let path = scan.path.as_deref().ok_or(ToolError::NotImplemented)?;
            let root = path.canonicalize().map_err(|source| ToolError::Path {
                path: path.display().to_string(),
                source,
            })?;
            let config = Config::load(cli.config.as_deref(), &root.join(".secret-guard.toml"))?;
            let output_absolute = output.as_deref().map(absolute_path).transpose()?;
            let threshold = config.effective_threshold(cli_threshold);
            let result = scan_folder(&root, &config, output_absolute.as_deref())?;
            complete_scan(result, threshold, format, output.as_deref(), quiet)
        }
        None | Some(Command::Scan(_)) => {
            let current = std::env::current_dir().map_err(|source| ToolError::Path {
                path: ".".to_owned(),
                source,
            })?;
            let client = GitClient::discover(&current)?;
            let config = Config::load(
                cli.config.as_deref(),
                &client.root().join(".secret-guard.toml"),
            )?;
            let threshold = config.effective_threshold(cli_threshold);
            let result = scan_staged(&client, &config)?;
            complete_scan(result, threshold, format, output.as_deref(), quiet)
        }
        Some(Command::Hook { .. }) | Some(Command::Rules { .. }) => Err(ToolError::NotImplemented),
    }
}

fn complete_scan(
    mut result: ScanResult,
    threshold: Severity,
    format: OutputFormat,
    output: Option<&Path>,
    quiet: bool,
) -> Result<u8, ToolError> {
    result.summary.findings_total = result.findings.len();
    result.summary.findings_blocking = result
        .findings
        .iter()
        .filter(|finding| finding.severity.blocks(threshold))
        .count();

    let bytes = match format {
        OutputFormat::Console => report::console::render(&result, quiet).into_bytes(),
        OutputFormat::Json => {
            report::json::render(&result, threshold).map_err(report::ReportError::Json)?
        }
    };
    if let Some(path) = output {
        report::write_atomic(path, &bytes)?;
    } else if !bytes.is_empty() {
        io::stdout()
            .lock()
            .write_all(&bytes)
            .map_err(ToolError::Output)?;
    }

    Ok(if result.summary.findings_blocking > 0 {
        FINDINGS
    } else {
        CLEAN
    })
}

fn absolute_path(path: &Path) -> Result<PathBuf, ToolError> {
    if path.is_absolute() {
        return Ok(path.to_owned());
    }
    std::env::current_dir()
        .map(|directory| directory.join(path))
        .map_err(|source| ToolError::Path {
            path: path.display().to_string(),
            source,
        })
}

impl From<SeverityArg> for Severity {
    fn from(value: SeverityArg) -> Self {
        match value {
            SeverityArg::Low => Self::Low,
            SeverityArg::Medium => Self::Medium,
            SeverityArg::High => Self::High,
            SeverityArg::Critical => Self::Critical,
        }
    }
}
