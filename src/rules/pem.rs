use std::sync::LazyLock;

use regex::Regex;

use crate::{
    scan::text::{CandidateMatch, PreparedText},
    severity::Severity,
};

static BEGIN_PRIVATE_KEY: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN ((?:ENCRYPTED |RSA |EC |DSA |OPENSSH )?PRIVATE KEY)-----").ok()
});

pub(crate) fn detect<'a>(input: &'a PreparedText<'a>, sink: &mut Vec<CandidateMatch<'a>>) {
    let Some(pattern) = BEGIN_PRIVATE_KEY.as_ref() else {
        return;
    };
    let text = input.as_str();
    for captures in pattern.captures_iter(text) {
        let (Some(start_match), Some(label)) = (captures.get(0), captures.get(1)) else {
            continue;
        };
        let end_marker = format!("-----END {}-----", label.as_str());
        let search_start = start_match.end();
        let byte_end = text
            .get(search_start..)
            .and_then(|tail| tail.find(&end_marker))
            .map_or(text.len(), |relative| {
                search_start + relative + end_marker.len()
            });
        let Some(candidate) = text.get(start_match.start()..byte_end) else {
            continue;
        };
        sink.push(CandidateMatch {
            rule_id: "private-key-pem",
            severity: Severity::Critical,
            confidence: 100,
            byte_start: start_match.start(),
            byte_end,
            message: "Content contains PEM private-key material.",
            candidate,
        });
    }
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

    #[test]
    fn matches_complete_and_truncated_multiline_private_keys() {
        let begin = ["-----BEGIN ", "PRIVATE", " KEY-----"].concat();
        let end = ["-----END ", "PRIVATE", " KEY-----"].concat();
        let complete = format!("before\n{begin}\nmaterial\n{end}\nafter");
        assert_eq!(count(&complete), 1);
        assert_eq!(count(&format!("{begin}\ntruncated-material")), 1);
    }

    #[test]
    fn public_keys_and_certificates_are_not_private_keys() {
        let public = ["-----BEGIN ", "PUBLIC", " KEY-----"].concat();
        let certificate = ["-----BEGIN ", "CERTIFICATE", "-----"].concat();
        assert_eq!(count(&public), 0);
        assert_eq!(count(&certificate), 0);
    }
}
