use crate::severity::Severity;

use super::rule::{PathMatch, PathRule, RuleMetadata};

pub static METADATA: RuleMetadata = RuleMetadata {
    id: "suspicious-file-path",
    severity: Severity::Medium,
    family: "path",
    description: "Path commonly used to store credentials",
};

pub struct SuspiciousPathRule;

impl PathRule for SuspiciousPathRule {
    fn metadata(&self) -> &'static RuleMetadata {
        &METADATA
    }

    fn detect(&self, normalized_path: &str) -> Option<PathMatch> {
        detect(normalized_path)
    }
}

pub fn detect(normalized_path: &str) -> Option<PathMatch> {
    let name = normalized_path
        .rsplit('/')
        .next()
        .unwrap_or(normalized_path)
        .to_ascii_lowercase();

    if matches!(name.as_str(), ".env.example" | ".env.sample")
        || name.ends_with(".example")
        || name.ends_with(".template")
    {
        return None;
    }

    let severity = if matches!(
        name.as_str(),
        "id_rsa" | "id_dsa" | "id_ecdsa" | "id_ed25519"
    ) || ((name.ends_with(".pem") || name.ends_with(".key"))
        && (name.contains("private") || name.starts_with("id_") || name.contains("signing")))
    {
        Severity::Critical
    } else if matches!(
        name.as_str(),
        ".env.production"
            | ".env.prod"
            | "credentials.json"
            | "service-account.json"
            | "service_account.json"
    ) || name.ends_with(".p12")
        || name.ends_with(".pfx")
    {
        Severity::High
    } else if matches!(
        name.as_str(),
        ".env" | ".env.local" | ".env.development" | ".env.test"
    ) {
        Severity::Medium
    } else {
        return None;
    };

    Some(PathMatch {
        severity,
        confidence: 75,
        message: "This path commonly contains credentials.",
    })
}

#[cfg(test)]
mod tests {
    use super::detect;
    use crate::severity::Severity;

    #[test]
    fn applies_path_groups_and_exceptions() {
        assert_eq!(
            detect("keys/id_rsa").map(|item| item.severity),
            Some(Severity::Critical)
        );
        assert_eq!(
            detect("config/.env.production").map(|item| item.severity),
            Some(Severity::High)
        );
        assert_eq!(
            detect(".env").map(|item| item.severity),
            Some(Severity::Medium)
        );
        for safe in [
            ".env.example",
            ".env.sample",
            "config.template",
            "public.pem",
        ] {
            assert!(detect(safe).is_none());
        }
    }
}
