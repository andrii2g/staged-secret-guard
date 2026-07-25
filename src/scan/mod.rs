pub mod engine;
pub mod file_input;
pub mod folder_source;
pub mod text;

use crate::{
    finding::{Finding, ScanSummary},
    scan::file_input::ScanMode,
};

#[derive(Debug)]
pub struct ScanResult {
    pub mode: ScanMode,
    pub root: String,
    pub findings: Vec<Finding>,
    pub summary: ScanSummary,
}
