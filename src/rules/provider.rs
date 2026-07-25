use std::sync::LazyLock;

use regex::Regex;

use crate::{
    scan::text::{CandidateMatch, PreparedText, is_placeholder},
    severity::Severity,
};

fn compile(pattern: &str) -> Option<Regex> {
    Regex::new(pattern).ok()
}

static GITHUB: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{82,255})\b")
});
static GITLAB: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"\bglpat-[A-Za-z0-9_-]{20,64}\b"));
static SLACK_TOKEN: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"\bxox[bpars]-(?:[0-9A-Za-z]+-){2,3}[A-Za-z0-9]{16,64}\b"));
static SLACK_WEBHOOK: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"https://hooks\.slack\.com/services/T[A-Za-z0-9]{8,}/B[A-Za-z0-9]{8,}/[A-Za-z0-9]{20,64}",
    )
});
static STRIPE_LIVE: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"\b[rs]k_live_[A-Za-z0-9]{24,64}\b"));
static STRIPE_TEST: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"\b[rs]k_test_[A-Za-z0-9]{24,64}\b"));
static OPENAI: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"\bsk-(?:proj|svcacct)-[A-Za-z0-9_-]{20,200}\b"));
static GOOGLE: LazyLock<Option<Regex>> = LazyLock::new(|| compile(r"\bAIza[0-9A-Za-z_-]{35}\b"));
static NPM: LazyLock<Option<Regex>> = LazyLock::new(|| compile(r"\bnpm_[A-Za-z0-9]{36}\b"));
static AWS_ID: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b"));
static AWS_SECRET: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r#"(?i)(?:aws[_-]?secret[_-]?access[_-]?key|secretaccesskey)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})"#,
    )
});
static AZURE_KEY: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"(?i)AccountKey\s*=\s*([A-Za-z0-9+/]{40,100}={0,2})"));
static BASIC_AUTH: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(r"(?i)https?://[^:/\s@]+:([^@\s/]{8,128})@[A-Za-z0-9.-]+(?::[0-9]+)?")
});
static DATABASE_URI: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile(
        r"(?i)(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|sqlserver)://[^:/\s@]+:([^@\s/]{8,128})@",
    )
});
static CONNECTION_PASSWORD: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r#"(?i)(?:password|pwd)\s*=\s*["']?([^;\s"']{8,128})"#));
static JWT: LazyLock<Option<Regex>> =
    LazyLock::new(|| compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"));

pub(crate) fn detect<'a>(input: &'a PreparedText<'a>, sink: &mut Vec<CandidateMatch<'a>>) {
    let text = input.as_str();
    emit(
        &GITHUB,
        text,
        0,
        "github-token",
        Severity::High,
        98,
        "Value matches a GitHub token structure.",
        sink,
    );
    emit(
        &GITLAB,
        text,
        0,
        "gitlab-token",
        Severity::High,
        98,
        "Value matches a GitLab token structure.",
        sink,
    );
    emit(
        &SLACK_TOKEN,
        text,
        0,
        "slack-token",
        Severity::High,
        96,
        "Value matches a Slack token structure.",
        sink,
    );
    emit(
        &SLACK_WEBHOOK,
        text,
        0,
        "slack-webhook",
        Severity::High,
        98,
        "Value matches a Slack incoming-webhook structure.",
        sink,
    );
    emit(
        &STRIPE_LIVE,
        text,
        0,
        "stripe-live-secret-key",
        Severity::High,
        98,
        "Value matches a Stripe live secret-key structure.",
        sink,
    );
    emit(
        &STRIPE_TEST,
        text,
        0,
        "stripe-test-secret-key",
        Severity::Medium,
        95,
        "Value matches a Stripe test secret-key structure.",
        sink,
    );
    emit(
        &OPENAI,
        text,
        0,
        "openai-api-key",
        Severity::High,
        98,
        "Value matches an OpenAI key structure.",
        sink,
    );
    emit(
        &GOOGLE,
        text,
        0,
        "google-api-key",
        Severity::High,
        98,
        "Value matches a Google API key structure.",
        sink,
    );
    emit(
        &NPM,
        text,
        0,
        "npm-token",
        Severity::High,
        98,
        "Value matches an npm token structure.",
        sink,
    );
    emit(
        &AWS_ID,
        text,
        0,
        "aws-access-key-id",
        Severity::Medium,
        90,
        "Value matches an AWS access-key identifier.",
        sink,
    );
    emit(
        &AWS_SECRET,
        text,
        1,
        "aws-secret-access-key",
        Severity::High,
        98,
        "Sensitive AWS context contains a secret-access-key structure.",
        sink,
    );
    emit(
        &AZURE_KEY,
        text,
        1,
        "azure-storage-account-key",
        Severity::High,
        98,
        "Azure Storage connection string contains an account key.",
        sink,
    );
    emit(
        &BASIC_AUTH,
        text,
        1,
        "basic-auth-url",
        Severity::High,
        95,
        "URL contains literal user and password credentials.",
        sink,
    );
    emit(
        &DATABASE_URI,
        text,
        1,
        "database-connection-password",
        Severity::High,
        95,
        "Database URI contains a literal password.",
        sink,
    );
    detect_connection_passwords(text, sink);
    emit(
        &JWT,
        text,
        0,
        "jwt-token",
        Severity::Medium,
        80,
        "Value matches a JSON Web Token structure.",
        sink,
    );
}

#[allow(clippy::too_many_arguments)]
fn emit<'a>(
    pattern: &Option<Regex>,
    text: &'a str,
    capture_index: usize,
    rule_id: &'static str,
    severity: Severity,
    confidence: u8,
    message: &'static str,
    sink: &mut Vec<CandidateMatch<'a>>,
) {
    let Some(pattern) = pattern.as_ref() else {
        return;
    };
    for captures in pattern.captures_iter(text) {
        let Some(candidate_match) = captures.get(capture_index) else {
            continue;
        };
        let candidate = candidate_match.as_str();
        if is_placeholder(candidate) {
            continue;
        }
        sink.push(CandidateMatch {
            rule_id,
            severity,
            confidence,
            byte_start: candidate_match.start(),
            byte_end: candidate_match.end(),
            message,
            candidate,
        });
    }
}

fn detect_connection_passwords<'a>(text: &'a str, sink: &mut Vec<CandidateMatch<'a>>) {
    let Some(pattern) = CONNECTION_PASSWORD.as_ref() else {
        return;
    };
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let lower = line.to_ascii_lowercase();
        let database_context = lower.contains("server=")
            || lower.contains("server =")
            || lower.contains("data source=")
            || lower.contains("data source =")
            || lower.contains("host=")
            || lower.contains("host =");
        if database_context {
            for captures in pattern.captures_iter(line) {
                let Some(candidate_match) = captures.get(1) else {
                    continue;
                };
                let candidate = candidate_match.as_str();
                if is_placeholder(candidate) {
                    continue;
                }
                sink.push(CandidateMatch {
                    rule_id: "database-connection-password",
                    severity: Severity::High,
                    confidence: 95,
                    byte_start: offset + candidate_match.start(),
                    byte_end: offset + candidate_match.end(),
                    message: "Database connection string contains a literal password.",
                    candidate,
                });
            }
        }
        offset += line.len();
    }
}

#[cfg(test)]
mod tests {
    use super::detect;
    use crate::scan::text::PreparedText;

    fn ids(text: &str) -> Vec<&'static str> {
        let prepared = PreparedText::new(text.as_bytes(), usize::MAX).expect("prepare text");
        let mut matches = Vec::new();
        detect(&prepared, &mut matches);
        matches.into_iter().map(|item| item.rule_id).collect()
    }

    fn candidate(parts: &[&str], fill: char, count: usize) -> String {
        format!("{}{}", parts.concat(), fill.to_string().repeat(count))
    }

    #[test]
    fn provider_rules_have_positive_and_negative_boundaries() {
        let cases = [
            (candidate(&["g", "hp", "_"], 'A', 36), "github-token"),
            (candidate(&["gl", "pat", "-"], 'B', 20), "gitlab-token"),
            (
                candidate(&["sk", "_live", "_"], 'C', 24),
                "stripe-live-secret-key",
            ),
            (
                candidate(&["sk", "_test", "_"], 'D', 24),
                "stripe-test-secret-key",
            ),
            (candidate(&["sk", "-proj", "-"], 'E', 20), "openai-api-key"),
            (candidate(&["AI", "za"], 'F', 35), "google-api-key"),
            (candidate(&["np", "m_"], 'G', 36), "npm-token"),
            (candidate(&["AK", "IA"], 'H', 16), "aws-access-key-id"),
        ];
        for (value, expected) in cases {
            assert!(ids(&value).contains(&expected), "missing provider rule");
            let too_short = value.get(..value.len() - 1).expect("shortened candidate");
            assert!(!ids(too_short).contains(&expected), "accepted short body");
        }
        assert!(!ids("sk-unrelated-identifier-with-a-long-body").contains(&"openai-api-key"));
    }

    #[test]
    fn structured_slack_webhook_and_jwt_rules() {
        let slack = ["xo", "xb-12345678-87654321-", &"A".repeat(20)].concat();
        assert!(ids(&slack).contains(&"slack-token"));
        let webhook = [
            "https://hooks.slack.com/services/",
            "T12345678/B12345678/",
            &"B".repeat(20),
        ]
        .concat();
        assert!(ids(&webhook).contains(&"slack-webhook"));
        let jwt = ["eyJ", "hbGciOiJub25lIn0.", "cGF5bG9hZA.", "c2lnbmF0dXJl"].concat();
        assert!(ids(&jwt).contains(&"jwt-token"));
        assert!(!ids("eyJabc.only-two").contains(&"jwt-token"));
    }

    #[test]
    fn contextual_cloud_url_and_connection_rules() {
        let aws = format!("aws_secret_access_key = {}", "A1+/".repeat(10));
        assert!(ids(&aws).contains(&"aws-secret-access-key"));
        assert!(!ids(&"A1+/".repeat(10)).contains(&"aws-secret-access-key"));
        let azure = format!(
            "DefaultEndpointsProtocol=https;AccountKey={}",
            "Ab1+".repeat(12)
        );
        assert!(ids(&azure).contains(&"azure-storage-account-key"));
        let basic = ["https://user:", "literal-pass", "@example.test"].concat();
        assert!(ids(&basic).contains(&"basic-auth-url"));
        assert!(!ids("https://user@example.test").contains(&"basic-auth-url"));
        let connection = ["Server=db.example.test;Password=", "literal-pass", ";"].concat();
        assert!(ids(&connection).contains(&"database-connection-password"));
    }
}
