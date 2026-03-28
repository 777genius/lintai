#[path = "../external_validation.rs"]
mod external_validation;
#[path = "../internal_bin.rs"]
mod internal_bin;

use std::process::ExitCode;

fn main() -> ExitCode {
    match external_validation::run(std::env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}
