use std::{fs, io, path::Path};

use globset::{Glob, GlobMatcher};
use serde::Deserialize;
use thiserror::Error;

use crate::{finding::RuleId, severity::Severity};

pub const DEFAULT_MAX_FILE_SIZE_BYTES: usize = 1_048_576;

pub const DEFAULT_EXCLUSIONS: &[&str] = &[
    ".git/**",
    "target/**",
    "node_modules/**",
    "bin/**",
    "obj/**",
    ".idea/**",
    ".vs/**",
    "dist/**",
    "build/**",
    "coverage/**",
    "**/*.min.js",
    "**/*.map",
];

const BUILT_IN_RULE_IDS: &[&str] = &[
    "private-key-pem",
    "github-token",
    "gitlab-token",
    "slack-token",
    "slack-webhook",
    "stripe-live-secret-key",
    "stripe-test-secret-key",
    "openai-api-key",
    "google-api-key",
    "npm-token",
    "aws-access-key-id",
    "aws-secret-access-key",
    "azure-storage-account-key",
    "basic-auth-url",
    "database-connection-password",
    "jwt-token",
    "generic-secret-assignment",
    "suspicious-file-path",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanConfig {
    pub fail_on: Severity,
    pub max_file_size_bytes: usize,
    pub respect_gitignore: bool,
    pub fail_on_read_error: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            fail_on: Severity::High,
            max_file_size_bytes: DEFAULT_MAX_FILE_SIZE_BYTES,
            respect_gitignore: true,
            fail_on_read_error: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AllowlistEntry {
    pub rule: RuleId,
    pub path: String,
    pub reason: String,
    matcher: GlobMatcher,
}

impl AllowlistEntry {
    pub fn matches(&self, rule: &RuleId, normalized_path: &str) -> bool {
        &self.rule == rule && self.matcher.is_match(normalized_path)
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub version: u32,
    pub scan: ScanConfig,
    pub exclusion_paths: Vec<String>,
    pub allowlist: Vec<AllowlistEntry>,
    exclusion_matchers: Vec<GlobMatcher>,
}

impl Default for Config {
    fn default() -> Self {
        let exclusion_paths = DEFAULT_EXCLUSIONS
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        let exclusion_matchers = exclusion_paths
            .iter()
            .filter_map(|value| compile_glob(value).ok())
            .collect();
        Self {
            version: 1,
            scan: ScanConfig::default(),
            exclusion_paths,
            allowlist: Vec::new(),
            exclusion_matchers,
        }
    }
}

impl Config {
    pub fn from_toml(source: &str, origin: &Path) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(source).map_err(|error| {
            let (line, column) = error
                .span()
                .map(|span| line_column(source, span.start))
                .unwrap_or((1, 1));
            ConfigError::Invalid {
                path: origin.display().to_string(),
                line,
                column,
                reason: "invalid TOML syntax or schema".to_owned(),
            }
        })?;
        Self::from_raw(raw, origin)
    }

    pub fn load(explicit: Option<&Path>, discovered: &Path) -> Result<Self, ConfigError> {
        let path = explicit.unwrap_or(discovered);
        match fs::read_to_string(path) {
            Ok(source) => Self::from_toml(&source, path),
            Err(error) if explicit.is_none() && error.kind() == io::ErrorKind::NotFound => {
                Ok(Self::default())
            }
            Err(source) => Err(ConfigError::Read {
                path: path.display().to_string(),
                source,
            }),
        }
    }

    pub fn effective_threshold(&self, cli_override: Option<Severity>) -> Severity {
        cli_override.unwrap_or(self.scan.fail_on)
    }

    pub fn is_excluded(&self, normalized_path: &str) -> bool {
        self.exclusion_matchers
            .iter()
            .any(|matcher| matcher.is_match(normalized_path))
    }

    pub fn is_allowed(&self, rule: &RuleId, normalized_path: &str) -> bool {
        self.allowlist
            .iter()
            .any(|entry| entry.matches(rule, normalized_path))
    }

    fn from_raw(raw: RawConfig, origin: &Path) -> Result<Self, ConfigError> {
        let path = origin.display().to_string();
        let version = raw.version.unwrap_or(1);
        if version != 1 {
            return Err(ConfigError::semantic(&path, "version must be 1"));
        }

        let scan = ScanConfig {
            fail_on: raw.scan.fail_on.unwrap_or(Severity::High),
            max_file_size_bytes: raw
                .scan
                .max_file_size_bytes
                .unwrap_or(DEFAULT_MAX_FILE_SIZE_BYTES),
            respect_gitignore: raw.scan.respect_gitignore.unwrap_or(true),
            fail_on_read_error: raw.scan.fail_on_read_error.unwrap_or(true),
        };
        if scan.max_file_size_bytes == 0 {
            return Err(ConfigError::semantic(
                &path,
                "scan.max_file_size_bytes must be greater than zero",
            ));
        }

        let mut exclusion_paths = DEFAULT_EXCLUSIONS
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        exclusion_paths.extend(raw.exclude.paths);
        exclusion_paths.sort();
        exclusion_paths.dedup();

        let mut exclusion_matchers = Vec::with_capacity(exclusion_paths.len());
        for pattern in &exclusion_paths {
            exclusion_matchers.push(compile_glob(pattern).map_err(|()| {
                ConfigError::semantic(&path, &format!("invalid exclusion glob: {pattern}"))
            })?);
        }

        let mut allowlist = Vec::with_capacity(raw.allowlist.len());
        for item in raw.allowlist {
            if item.reason.trim().is_empty() {
                return Err(ConfigError::semantic(
                    &path,
                    "allowlist reason must not be empty",
                ));
            }
            let rule = RuleId::new(item.rule)
                .map_err(|_| ConfigError::semantic(&path, "allowlist rule ID is invalid"))?;
            if !BUILT_IN_RULE_IDS.contains(&rule.as_str()) {
                return Err(ConfigError::semantic(
                    &path,
                    "allowlist rule is not built in",
                ));
            }
            let matcher = compile_glob(&item.path)
                .map_err(|()| ConfigError::semantic(&path, "allowlist path glob is invalid"))?;
            allowlist.push(AllowlistEntry {
                rule,
                path: item.path,
                reason: item.reason,
                matcher,
            });
        }

        Ok(Self {
            version,
            scan,
            exclusion_paths,
            allowlist,
            exclusion_matchers,
        })
    }
}

fn compile_glob(pattern: &str) -> Result<GlobMatcher, ()> {
    Glob::new(pattern)
        .map(|glob| glob.compile_matcher())
        .map_err(|_| ())
}

fn line_column(source: &str, byte_offset: usize) -> (usize, usize) {
    let prefix = source.get(..byte_offset).unwrap_or("");
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix.chars().count() + 1, |(_, tail)| {
            tail.chars().count() + 1
        });
    (line, column)
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Unable to read configuration at {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("Invalid configuration at {path}:{line}:{column}: {reason}.")]
    Invalid {
        path: String,
        line: usize,
        column: usize,
        reason: String,
    },
}

impl ConfigError {
    fn semantic(path: &str, reason: &str) -> Self {
        Self::Invalid {
            path: path.to_owned(),
            line: 1,
            column: 1,
            reason: reason.to_owned(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawConfig {
    version: Option<u32>,
    scan: RawScanConfig,
    exclude: RawExcludeConfig,
    allowlist: Vec<RawAllowlistEntry>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawScanConfig {
    fail_on: Option<Severity>,
    max_file_size_bytes: Option<usize>,
    respect_gitignore: Option<bool>,
    fail_on_read_error: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawExcludeConfig {
    paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAllowlistEntry {
    rule: String,
    path: String,
    reason: String,
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{Config, DEFAULT_EXCLUSIONS, DEFAULT_MAX_FILE_SIZE_BYTES};
    use crate::{finding::RuleId, severity::Severity};

    const ORIGIN: &str = ".secret-guard.toml";

    fn parse(source: &str) -> Result<Config, super::ConfigError> {
        Config::from_toml(source, Path::new(ORIGIN))
    }

    #[test]
    fn defaults_match_the_contract() {
        let config = Config::default();
        assert_eq!(config.version, 1);
        assert_eq!(config.scan.fail_on, Severity::High);
        assert_eq!(config.scan.max_file_size_bytes, DEFAULT_MAX_FILE_SIZE_BYTES);
        assert!(config.scan.respect_gitignore);
        assert!(config.scan.fail_on_read_error);
        assert_eq!(config.exclusion_paths.len(), DEFAULT_EXCLUSIONS.len());
    }

    #[test]
    fn complete_configuration_parses_and_adds_exclusions() {
        let source = r#"
version = 1
[scan]
fail_on = "medium"
max_file_size_bytes = 4096
respect_gitignore = false
fail_on_read_error = false
[exclude]
paths = ["generated/**"]
[[allowlist]]
rule = "generic-secret-assignment"
path = "tests/fixtures/**"
reason = "Synthetic fragments"
"#;
        let config = parse(source).expect("valid complete config");
        assert_eq!(config.scan.fail_on, Severity::Medium);
        assert!(config.is_excluded("target/debug/file"));
        assert!(config.is_excluded("generated/result.txt"));
        let rule = RuleId::new("generic-secret-assignment").expect("valid rule");
        assert!(config.is_allowed(&rule, "tests/fixtures/value.txt"));
    }

    #[test]
    fn cli_threshold_overrides_configuration() {
        let mut config = Config::default();
        config.scan.fail_on = Severity::Medium;
        assert_eq!(config.effective_threshold(None), Severity::Medium);
        assert_eq!(
            config.effective_threshold(Some(Severity::Critical)),
            Severity::Critical
        );
    }

    #[test]
    fn rejects_unknown_fields_without_echoing_source() {
        let sensitive_line = "unexpected = \"should-not-appear\"";
        let error = parse(sensitive_line).expect_err("unknown field must fail");
        let rendered = error.to_string();
        assert!(rendered.contains("Invalid configuration"));
        assert!(!rendered.contains("should-not-appear"));
        assert!(!rendered.contains(sensitive_line));
    }

    #[test]
    fn rejects_invalid_globs_and_semantic_errors() {
        for source in [
            "version = 2",
            "[scan]\nmax_file_size_bytes = 0",
            "[exclude]\npaths = [\"[invalid\"]",
            "[[allowlist]]\nrule = \"unknown-rule\"\npath = \"**\"\nreason = \"why\"",
            "[[allowlist]]\nrule = \"github-token\"\npath = \"**\"\nreason = \"  \"",
        ] {
            assert!(parse(source).is_err(), "configuration unexpectedly valid");
        }
    }
}
