use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedRerunFlags {
    package: ValidationPackage,
    lintai_bin: Option<PathBuf>,
}

pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<(), String> {
    let raw_args = args.collect::<Vec<_>>();
    let Some(command) = raw_args.first().map(String::as_str) else {
        return Err("expected one of: rerun, render-report".to_owned());
    };
    match command {
        "rerun" => {
            let flags = parse_rerun_flags(&raw_args[1..])?;
            rerun(RerunOptions {
                package: flags.package,
                lintai_bin: flags.lintai_bin,
            })?;
            Ok(())
        }
        "render-report" => {
            let package = parse_package_flag(&raw_args[1..])?;
            let markdown = render_report(RenderReportOptions { package })?;
            print!("{markdown}");
            Ok(())
        }
        _ => Err(format!("unknown external validation command `{command}`")),
    }
}

pub(crate) fn rerun(options: RerunOptions) -> Result<(), String> {
    default_external_validation_application().rerun(options)
}

pub(crate) fn render_report(options: RenderReportOptions) -> Result<String, String> {
    default_external_validation_application().render_report(options)
}

pub(crate) fn parse_package_flag(args: &[String]) -> Result<ValidationPackage, String> {
    let mut package = ValidationPackage::Canonical;
    for arg in args {
        let Some(value) = arg.strip_prefix("--package=") else {
            return Err(format!(
                "unexpected external validation argument `{arg}`; expected only --package=<name>"
            ));
        };
        package = ValidationPackage::parse(value)?;
    }
    Ok(package)
}

fn parse_rerun_flags(args: &[String]) -> Result<ParsedRerunFlags, String> {
    let mut package = ValidationPackage::Canonical;
    let mut lintai_bin = None;

    for arg in args {
        if let Some(value) = arg.strip_prefix("--package=") {
            package = ValidationPackage::parse(value)?;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--lintai-bin=") {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(
                    "unexpected external validation argument `--lintai-bin=`; expected a non-empty path"
                        .to_owned(),
                );
            }
            lintai_bin = Some(PathBuf::from(trimmed));
            continue;
        }
        return Err(format!(
            "unexpected external validation argument `{arg}`; expected only --package=<name> or --lintai-bin=<path>"
        ));
    }

    Ok(ParsedRerunFlags {
        package,
        lintai_bin,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal_bin::BinaryResolutionSource;

    #[test]
    fn run_without_arguments_reports_usage() {
        let error = run(std::iter::empty()).unwrap_err();
        assert_eq!(error, "expected one of: rerun, render-report");
    }

    #[test]
    fn run_with_unknown_command_reports_unknown_command() {
        let error = run(vec!["unknown".to_owned()].into_iter()).unwrap_err();
        assert_eq!(error, "unknown external validation command `unknown`");
    }

    #[test]
    fn parse_package_flag_ignores_missing_value_but_preserves_default() {
        assert_eq!(
            parse_package_flag(&[]).unwrap(),
            ValidationPackage::Canonical
        );
    }

    #[test]
    fn parse_package_flag_rejects_invalid_flag() {
        let error = parse_package_flag(&["--bad-flag".to_owned()]).unwrap_err();
        assert_eq!(
            error,
            "unexpected external validation argument `--bad-flag`; expected only --package=<name>"
        );
    }

    #[test]
    fn parse_package_flag_rejects_unknown_package_name() {
        let error = parse_package_flag(&["--package=bogus".to_owned()]).unwrap_err();
        assert_eq!(error, "unknown external validation package `bogus`");
    }

    #[test]
    fn parse_package_flag_uses_last_package_flag() {
        assert_eq!(
            parse_package_flag(&[
                "--package=tool-json-extension".to_owned(),
                "--package=github-actions-extension".to_owned(),
            ])
            .unwrap(),
            ValidationPackage::GithubActionsExtension
        );
    }

    #[test]
    fn run_renders_report_for_known_package() {
        run(["render-report".to_owned(), "--package=canonical".to_owned()].into_iter()).unwrap();
    }

    #[test]
    fn run_renders_reports_for_all_known_packages() {
        let packages = [
            "--package=canonical",
            "--package=tool-json-extension",
            "--package=server-json-extension",
            "--package=github-actions-extension",
            "--package=ai-native-discovery",
        ];

        for package in packages {
            run(["render-report".to_owned(), package.to_owned()].into_iter()).unwrap();
        }
    }

    #[test]
    fn parse_package_flag_accepts_the_last_flag() {
        assert_eq!(
            parse_package_flag(&[
                "--package=tool-json-extension".to_owned(),
                "--package=server-json-extension".to_owned(),
                "--package=canonical".to_owned(),
            ])
            .unwrap(),
            ValidationPackage::Canonical
        );
    }

    #[test]
    fn parse_rerun_flags_defaults_to_canonical_without_explicit_binary() {
        assert_eq!(
            parse_rerun_flags(&[]).unwrap(),
            ParsedRerunFlags {
                package: ValidationPackage::Canonical,
                lintai_bin: None,
            }
        );
    }

    #[test]
    fn parse_rerun_flags_accepts_lintai_bin_and_last_package() {
        assert_eq!(
            parse_rerun_flags(&[
                "--package=tool-json-extension".to_owned(),
                "--lintai-bin=/tmp/lintai".to_owned(),
                "--package=canonical".to_owned(),
            ])
            .unwrap(),
            ParsedRerunFlags {
                package: ValidationPackage::Canonical,
                lintai_bin: Some(PathBuf::from("/tmp/lintai")),
            }
        );
    }

    #[test]
    fn parse_rerun_flags_rejects_empty_lintai_bin() {
        let error = parse_rerun_flags(&["--lintai-bin=".to_owned()]).unwrap_err();
        assert_eq!(
            error,
            "unexpected external validation argument `--lintai-bin=`; expected a non-empty path"
        );
    }

    #[test]
    fn parse_package_flag_rejects_rerun_only_lintai_bin_flag() {
        let error = parse_package_flag(&["--lintai-bin=/tmp/lintai".to_owned()]).unwrap_err();
        assert_eq!(
            error,
            "unexpected external validation argument `--lintai-bin=/tmp/lintai`; expected only --package=<name>"
        );
    }

    #[test]
    fn rerun_driver_contract_requires_explicit_driver_for_workspace_target_sibling_resolution() {
        assert!(requires_explicit_rerun_driver(
            Path::new("/workspace"),
            Path::new("/workspace/target/debug/lintai-external-validation"),
            BinaryResolutionSource::SiblingCandidate,
        ));
        assert!(!requires_explicit_rerun_driver(
            Path::new("/workspace"),
            Path::new("/workspace/target/debug/lintai-external-validation"),
            BinaryResolutionSource::PreferredEnv,
        ));
        assert!(!requires_explicit_rerun_driver(
            Path::new("/workspace"),
            Path::new("/usr/local/bin/lintai-external-validation"),
            BinaryResolutionSource::SiblingCandidate,
        ));
    }
}
