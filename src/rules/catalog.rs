use crate::severity::Severity;

use super::rule::RuleMetadata;

pub static RULES: &[RuleMetadata] = &[
    RuleMetadata {
        id: "aws-access-key-id",
        severity: Severity::Medium,
        family: "cloud-credential-id",
        description: "AWS access-key identifier",
    },
    RuleMetadata {
        id: "aws-secret-access-key",
        severity: Severity::High,
        family: "cloud-secret",
        description: "AWS secret access key in sensitive context",
    },
    RuleMetadata {
        id: "azure-storage-account-key",
        severity: Severity::High,
        family: "cloud-secret",
        description: "Azure Storage account key in a connection string",
    },
    RuleMetadata {
        id: "basic-auth-url",
        severity: Severity::High,
        family: "url-credential",
        description: "URL containing user and password credentials",
    },
    RuleMetadata {
        id: "database-connection-password",
        severity: Severity::High,
        family: "connection-string",
        description: "Database connection string password",
    },
    RuleMetadata {
        id: "generic-secret-assignment",
        severity: Severity::High,
        family: "generic-context",
        description: "Sensitive assignment containing a likely literal secret",
    },
    RuleMetadata {
        id: "github-token",
        severity: Severity::High,
        family: "provider-token",
        description: "GitHub access token structure",
    },
    RuleMetadata {
        id: "gitlab-token",
        severity: Severity::High,
        family: "provider-token",
        description: "GitLab personal access token structure",
    },
    RuleMetadata {
        id: "google-api-key",
        severity: Severity::High,
        family: "provider-token",
        description: "Google API key structure",
    },
    RuleMetadata {
        id: "jwt-token",
        severity: Severity::Medium,
        family: "structured-token",
        description: "JSON Web Token structure",
    },
    RuleMetadata {
        id: "npm-token",
        severity: Severity::High,
        family: "provider-token",
        description: "npm access token structure",
    },
    RuleMetadata {
        id: "openai-api-key",
        severity: Severity::High,
        family: "provider-token",
        description: "OpenAI project or service-account key structure",
    },
    RuleMetadata {
        id: "private-key-pem",
        severity: Severity::Critical,
        family: "private-key",
        description: "PEM encoded private key block",
    },
    RuleMetadata {
        id: "slack-token",
        severity: Severity::High,
        family: "provider-token",
        description: "Slack access token structure",
    },
    RuleMetadata {
        id: "slack-webhook",
        severity: Severity::High,
        family: "webhook",
        description: "Slack incoming webhook URL",
    },
    RuleMetadata {
        id: "stripe-live-secret-key",
        severity: Severity::High,
        family: "provider-token",
        description: "Stripe live secret or restricted key",
    },
    RuleMetadata {
        id: "stripe-test-secret-key",
        severity: Severity::Medium,
        family: "provider-token",
        description: "Stripe test secret or restricted key",
    },
    RuleMetadata {
        id: "suspicious-file-path",
        severity: Severity::Medium,
        family: "path",
        description: "Path commonly used to store credentials",
    },
];

pub fn all() -> &'static [RuleMetadata] {
    RULES
}

pub fn find(id: &str) -> Option<&'static RuleMetadata> {
    RULES.iter().find(|metadata| metadata.id == id)
}

pub fn is_known(id: &str) -> bool {
    find(id).is_some()
}

#[cfg(test)]
mod tests {
    use super::RULES;

    #[test]
    fn catalog_ids_are_sorted_unique_and_valid() {
        let ids: Vec<_> = RULES.iter().map(|rule| rule.id).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids, sorted);
        assert_eq!(ids.len(), 18);
    }
}
