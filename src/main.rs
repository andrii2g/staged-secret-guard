use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(secret_guard::run())
}
