use std::process::ExitCode;

fn main() -> ExitCode {
    match lintai_cli::run_cli() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}
