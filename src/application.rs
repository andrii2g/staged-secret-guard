use crate::{cli::Cli, exit_code::OPERATIONAL_ERROR};

pub fn execute(cli: Cli) -> u8 {
    let _ = cli;
    eprintln!(
        "secret-guard: operational commands are not implemented in the scaffold; follow PLAN.md"
    );
    OPERATIONAL_ERROR
}
