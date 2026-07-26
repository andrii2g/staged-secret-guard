use std::sync::LazyLock;

use regex::Regex;

use crate::{
    scan::text::{CandidateMatch, PreparedText, is_environment_reference, is_placeholder},
    severity::Severity,
};

const RULE_ID: &str = "http-credential-header";
const MESSAGE: &str = "HTTP header contains a literal credential value.";
const MIN_CANDIDATE_LENGTH: usize = 8;

static HEADER_PAIR: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)
        ["']?
        (?P<name>
            authorization|proxy-authorization|
            x-api-key|api-key|x-auth-token|x-access-token|x-auth-key|
            x-client-secret|private-token|x-gitlab-token|x-github-token|
            x-vault-token|x-amz-security-token|x-goog-api-key
        )
        ["']?\s*(?::|=|=>)\s*
        (?P<value>
            "[^"\r\n]{1,512}"|'[^'\r\n]{1,512}'|
            [^\s,;\#\]]{1,512}(?:\s+[^\s,;\#\]]{1,512})?
        )
        "#,
    )
    .ok()
});

static COOKIE_PAIR: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)
        ["']?(?P<name>cookie|set-cookie)["']?\s*(?::|=|=>)\s*
        (?P<value>
            "[^"\r\n]{1,512}"|'[^'\r\n]{1,512}'|[^\r\n]{1,512}
        )
        "#,
    )
    .ok()
});

static CALL_PAIR: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)
        ["'](?P<name>
            authorization|proxy-authorization|
            x-api-key|api-key|x-auth-token|x-access-token|x-auth-key|
            x-client-secret|private-token|x-gitlab-token|x-github-token|
            x-vault-token|x-amz-security-token|x-goog-api-key|
            cookie|set-cookie
        )["']\s*,\s*
        (?P<value>"[^"\r\n]{1,512}"|'[^'\r\n]{1,512}')
        "#,
    )
    .ok()
});

pub(crate) fn detect<'a>(input: &'a PreparedText<'a>, sink: &mut Vec<CandidateMatch<'a>>) {
    for pattern in [
        HEADER_PAIR.as_ref(),
        COOKIE_PAIR.as_ref(),
        CALL_PAIR.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        for captures in pattern.captures_iter(input.as_str()) {
            let (Some(name), Some(value)) = (captures.name("name"), captures.name("value")) else {
                continue;
            };
            emit_header(name.as_str(), value.as_str(), value.start(), sink);
        }
    }
}

fn emit_header<'a>(
    name: &str,
    raw_value: &'a str,
    value_start: usize,
    sink: &mut Vec<CandidateMatch<'a>>,
) {
    let (value, start) = trim_literal(raw_value, value_start);
    if name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("proxy-authorization")
    {
        emit_authorization(value, start, sink);
    } else if name.eq_ignore_ascii_case("cookie") || name.eq_ignore_ascii_case("set-cookie") {
        emit_cookies(value, start, sink);
    } else {
        emit_candidate(value, start, sink);
    }
}

fn emit_authorization<'a>(value: &'a str, value_start: usize, sink: &mut Vec<CandidateMatch<'a>>) {
    let Some(split) = value.find(char::is_whitespace) else {
        return;
    };
    let scheme = &value[..split];
    if !["bearer", "basic", "token", "apikey", "api-key"]
        .iter()
        .any(|expected| scheme.eq_ignore_ascii_case(expected))
    {
        return;
    }
    let rest = &value[split..];
    let trimmed = rest.trim_start();
    emit_candidate(
        trimmed,
        value_start + split + (rest.len() - trimmed.len()),
        sink,
    );
}

fn emit_cookies<'a>(value: &'a str, value_start: usize, sink: &mut Vec<CandidateMatch<'a>>) {
    let mut offset = 0;
    for segment in value.split(';') {
        let leading = segment.len() - segment.trim_start().len();
        let trimmed = segment.trim();
        if let Some((name, candidate)) = trimmed.split_once('=') {
            if is_sensitive_cookie_name(name) {
                let candidate_leading = candidate.len() - candidate.trim_start().len();
                let candidate = candidate.trim();
                let candidate_offset = trimmed
                    .find('=')
                    .map_or(0, |equals| equals + 1 + candidate_leading);
                emit_candidate(
                    candidate,
                    value_start + offset + leading + candidate_offset,
                    sink,
                );
            }
        }
        offset += segment.len() + 1;
    }
}

fn emit_candidate<'a>(candidate: &'a str, byte_start: usize, sink: &mut Vec<CandidateMatch<'a>>) {
    let candidate = candidate.trim_end();
    let candidate = candidate.trim_end_matches(['"', '\'']);
    if looks_like_code_template(candidate) {
        return;
    }
    let candidate = candidate.trim_end_matches([',', '}', ']', ')']).trim_end();
    if candidate.len() < MIN_CANDIDATE_LENGTH
        || is_placeholder(candidate)
        || is_environment_reference(candidate)
    {
        return;
    }
    sink.push(CandidateMatch {
        rule_id: RULE_ID,
        severity: Severity::High,
        confidence: 95,
        byte_start,
        byte_end: byte_start + candidate.len(),
        message: MESSAGE,
        candidate,
    });
}
fn looks_like_code_template(candidate: &str) -> bool {
    candidate.contains('{') && candidate.contains('}')
}

fn trim_literal(value: &str, start: usize) -> (&str, usize) {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes.first() == Some(&b'"') && bytes.last() == Some(&b'"'))
            || (bytes.first() == Some(&b'\'') && bytes.last() == Some(&b'\''))
        {
            return (&value[1..value.len() - 1], start + 1);
        }
    }
    (value, start)
}

fn is_sensitive_cookie_name(name: &str) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    ["session", "auth", "token", "jwt", "secret"]
        .iter()
        .any(|part| normalized.contains(part))
}

#[cfg(test)]
mod tests {
    use super::detect;
    use crate::scan::text::PreparedText;

    fn count(text: &str) -> usize {
        let prepared = PreparedText::new(text.as_bytes(), usize::MAX).expect("prepare text");
        let mut matches = Vec::new();
        detect(&prepared, &mut matches);
        matches.len()
    }

    fn literal() -> String {
        ["Ab", "12", "-header-", "Credential", "9876"].concat()
    }

    #[test]
    fn detects_authorization_api_key_calls_and_sensitive_cookies() {
        let value = literal();
        for (label, text) in [
            ("authorization", format!("Authorization: Bearer {value}")),
            ("proxy", format!("'Proxy-Authorization': 'Basic {value}'")),
            ("api-key", format!("\"x-api-key\": \"{value}\"")),
            (
                "call",
                format!("headers.Add(\"X-Auth-Token\", \"{value}\")"),
            ),
            (
                "cookie",
                format!("Cookie: theme=dark; session_token={value}"),
            ),
            (
                "set-cookie",
                format!("Set-Cookie: auth={value}; Secure; HttpOnly"),
            ),
        ] {
            assert_eq!(count(&text), 1, "missed {label} header form");
        }
    }

    #[test]
    fn rejects_benign_headers_placeholders_references_and_cookies() {
        let api_key_placeholder = ["X-API", "-Key: your-api-key"].concat();
        for text in [
            "Content-Type: application/json",
            "Authorization: Bearer ${TOKEN}",
            api_key_placeholder.as_str(),
            "X-Auth-Token: short",
            "Cookie: theme=dark; language=en-US",
            "Authorization: Bearer {value}",
            "Authorization: Digest username=value",
        ] {
            assert_eq!(count(text), 0, "unexpected header finding");
        }
    }
}
