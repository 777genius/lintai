mod app;
mod args;
mod builtin_providers;
#[cfg(test)]
mod compat_tests;
mod output;
mod path;
#[cfg(test)]
mod sample_repo_tests;

use std::process::ExitCode;

fn main() -> ExitCode {
    match app::run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}
