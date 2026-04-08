use std::process::ExitCode;

fn run_with_args<I>(args: I) -> ExitCode
where
    I: Iterator<Item = String>,
{
    match lintai_cli::run_external_validation_cli(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}

fn main() -> ExitCode {
    run_with_args(std::env::args().skip(1))
}

#[cfg(test)]
mod tests {
    use super::run_with_args;

    #[test]
    fn run_with_unknown_command_returns_failure_code() {
        let exit_code = run_with_args(vec!["unknown".to_string()].into_iter());
        assert_eq!(exit_code, std::process::ExitCode::from(2));
    }

    #[test]
    fn run_with_known_render_report_command_succeeds_for_default_package() {
        let exit_code = run_with_args(
            vec![
                "render-report".to_owned(),
                "--package=canonical".to_owned(),
                // keep explicit package to avoid depending on env assumptions.
                "--help".to_owned(),
            ]
            .into_iter(),
        );
        assert_eq!(exit_code, std::process::ExitCode::from(2));
    }
}
