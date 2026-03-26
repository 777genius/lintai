mod app;
mod args;
#[cfg(test)]
mod compat_tests;
mod output;
mod path;

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
