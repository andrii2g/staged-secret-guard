pub mod application;
pub mod cli;
pub mod config;
pub mod error;
pub mod exit_code;
pub mod finding;
pub mod git;
pub mod hook;
pub mod report;
pub mod rules;
pub mod scan;
pub mod severity;

use clap::Parser;

pub fn run() -> u8 {
    let cli = cli::Cli::parse();
    application::execute(cli)
}
