use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const fn blocks(self, threshold: Self) -> bool {
        self as u8 >= threshold as u8
    }
}

impl Default for Severity {
    fn default() -> Self {
        Self::High
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseSeverityError;

impl fmt::Display for ParseSeverityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("expected low, medium, high, or critical")
    }
}

impl std::error::Error for ParseSeverityError {}

impl FromStr for Severity {
    type Err = ParseSeverityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(ParseSeverityError),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::Severity;

    #[test]
    fn ordering_matches_the_contract() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }

    #[test]
    fn threshold_is_inclusive() {
        assert!(Severity::Critical.blocks(Severity::High));
        assert!(Severity::High.blocks(Severity::High));
        assert!(!Severity::Medium.blocks(Severity::High));
    }

    #[test]
    fn parses_and_displays_lowercase_contract_values() {
        for (text, expected) in [
            ("low", Severity::Low),
            ("medium", Severity::Medium),
            ("high", Severity::High),
            ("critical", Severity::Critical),
        ] {
            assert_eq!(Severity::from_str(text), Ok(expected));
            assert_eq!(expected.to_string(), text);
        }
        assert!(Severity::from_str("HIGH").is_err());
    }

    #[test]
    fn serializes_as_lowercase() {
        let rendered = serde_json::to_string(&Severity::Critical).expect("serialize severity");
        assert_eq!(rendered, "\"critical\"");
    }
