mod app;
mod args;
mod builtin_providers;
#[cfg(test)]
mod compat_tests;
mod internal_bin;
mod known_scan;
mod output;
mod path;
mod policy_os;
#[cfg(test)]
mod sample_repo_tests;
mod security_rule_catalog;

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
