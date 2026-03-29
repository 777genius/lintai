use std::process::ExitCode;

fn main() -> ExitCode {
    match lintai_cli::run_external_validation_cli(std::env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}
