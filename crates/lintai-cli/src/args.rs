use std::path::PathBuf;

use lintai_engine::OutputFormat;

#[derive(Debug)]
pub struct ScanArgs {
    pub target: PathBuf,
    pub format_override: Option<OutputFormat>,
}

pub fn parse_scan_args(args: impl Iterator<Item = String>) -> Result<ScanArgs, String> {
    let mut target = None;
    let mut format_override = None;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--format" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --format".to_owned());
                };
                format_override = Some(parse_output_format(&value)?);
            }
            value if value.starts_with("--format=") => {
                let value = value.trim_start_matches("--format=");
                format_override = Some(parse_output_format(value)?);
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown flag: {value}"));
            }
            value => match target {
                Some(_) => return Err(format!("unexpected extra argument: {value}")),
                None => target = Some(PathBuf::from(value)),
            },
        }
    }

    Ok(ScanArgs {
        target: target.unwrap_or_else(|| PathBuf::from(".")),
        format_override,
    })
}

pub fn parse_explain_config_args(
    mut args: impl Iterator<Item = String>,
) -> Result<PathBuf, String> {
    let target = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "missing file path for explain-config".to_owned())?;
    if let Some(extra) = args.next() {
        return Err(format!("unexpected extra argument: {extra}"));
    }

    Ok(target)
}

fn parse_output_format(value: &str) -> Result<OutputFormat, String> {
    match value {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        "sarif" => Ok(OutputFormat::Sarif),
        other => Err(format!("unsupported output format: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_explain_config_args, parse_scan_args};
    use lintai_engine::OutputFormat;

    #[test]
    fn scan_defaults_to_current_directory() {
        let parsed = parse_scan_args(std::iter::empty()).unwrap();
        assert_eq!(parsed.target, std::path::PathBuf::from("."));
        assert_eq!(parsed.format_override, None);
    }

    #[test]
    fn scan_rejects_extra_positional_argument() {
        let error = parse_scan_args(["docs", "other"].into_iter().map(str::to_owned)).unwrap_err();
        assert!(error.contains("unexpected extra argument"));
    }

    #[test]
    fn scan_parses_inline_format_flag() {
        let parsed = parse_scan_args(["--format=json"].into_iter().map(str::to_owned)).unwrap();
        assert_eq!(parsed.format_override, Some(OutputFormat::Json));
    }

    #[test]
    fn scan_parses_sarif_format_flag() {
        let parsed = parse_scan_args(["--format=sarif"].into_iter().map(str::to_owned)).unwrap();
        assert_eq!(parsed.format_override, Some(OutputFormat::Sarif));
    }

    #[test]
    fn explain_config_requires_single_target() {
        let error =
            parse_explain_config_args(["docs/SKILL.md", "extra"].into_iter().map(str::to_owned))
                .unwrap_err();
        assert!(error.contains("unexpected extra argument"));
    }
}
