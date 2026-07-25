use serde::Serialize;

use crate::{
    scan::text::{CandidateMatch, PreparedText},
    severity::Severity,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RuleMetadata {
    pub id: &'static str,
    pub severity: Severity,
    pub family: &'static str,
    pub description: &'static str,
}

#[allow(dead_code)]
pub(crate) trait ContentRule {
    fn metadata(&self) -> &'static RuleMetadata;
    fn detect<'a>(&self, input: &'a PreparedText<'a>, sink: &mut Vec<CandidateMatch<'a>>);
}

#[allow(dead_code)]
pub(crate) trait PathRule {
    fn metadata(&self) -> &'static RuleMetadata;
    fn detect(&self, normalized_path: &str) -> Option<PathMatch>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PathMatch {
    pub severity: Severity,
    pub confidence: u8,
    pub message: &'static str,
}
