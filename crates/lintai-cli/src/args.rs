use std::path::PathBuf;

use lintai_engine::OutputFormat;

use crate::known_scan::{InventoryOsArgs, InventoryOsScope, KnownScope, ScanKnownArgs};

#[derive(Debug)]
pub struct ScanArgs {
    pub target: PathBuf,
    pub format_override: Option<OutputFormat>,
}

#[derive(Debug)]
pub struct FixArgs {
    pub target: PathBuf,
    pub apply: bool,
    pub rule_filters: Vec<String>,
}

pub fn parse_inventory_os_args(
    args: impl Iterator<Item = String>,
) -> Result<InventoryOsArgs, String> {
    let mut format_override = None;
    let mut scope = InventoryOsScope::Both;
    let mut client_filters = std::collections::BTreeSet::new();
    let mut path_root = None;
    let mut write_baseline = None;
    let mut diff_against = None;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--format" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --format".to_owned());
                };
                format_override = Some(parse_output_format(&value)?);
            }
            "--scope" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --scope".to_owned());
                };
                scope = parse_inventory_scope(&value)?;
            }
            "--client" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --client".to_owned());
                };
                client_filters.insert(normalize_client_filter(&value));
            }
            "--path-root" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --path-root".to_owned());
                };
                path_root = Some(PathBuf::from(value));
            }
            "--write-baseline" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --write-baseline".to_owned());
                };
                write_baseline = Some(PathBuf::from(value));
            }
            "--diff-against" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --diff-against".to_owned());
                };
                diff_against = Some(PathBuf::from(value));
            }
            value if value.starts_with("--format=") => {
                let value = value.trim_start_matches("--format=");
                format_override = Some(parse_output_format(value)?);
            }
            value if value.starts_with("--scope=") => {
                let value = value.trim_start_matches("--scope=");
                scope = parse_inventory_scope(value)?;
            }
            value if value.starts_with("--client=") => {
                client_filters.insert(normalize_client_filter(
                    value.trim_start_matches("--client="),
                ));
            }
            value if value.starts_with("--path-root=") => {
                path_root = Some(PathBuf::from(value.trim_start_matches("--path-root=")));
            }
            value if value.starts_with("--write-baseline=") => {
                write_baseline = Some(PathBuf::from(value.trim_start_matches("--write-baseline=")));
            }
            value if value.starts_with("--diff-against=") => {
                diff_against = Some(PathBuf::from(value.trim_start_matches("--diff-against=")));
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown flag: {value}"));
            }
            value => return Err(format!("unexpected extra argument: {value}")),
        }
    }

    Ok(InventoryOsArgs {
        format_override,
        scope,
        client_filters,
        path_root,
        write_baseline,
        diff_against,
    })
}

pub fn parse_scan_known_args(args: impl Iterator<Item = String>) -> Result<ScanKnownArgs, String> {
    let mut format_override = None;
    let mut scope = KnownScope::Both;
    let mut client_filters = std::collections::BTreeSet::new();
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--format" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --format".to_owned());
                };
                format_override = Some(parse_output_format(&value)?);
            }
            "--scope" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --scope".to_owned());
                };
                scope = parse_known_scope(&value)?;
            }
            "--client" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --client".to_owned());
                };
                client_filters.insert(normalize_client_filter(&value));
            }
            value if value.starts_with("--format=") => {
                let value = value.trim_start_matches("--format=");
                format_override = Some(parse_output_format(value)?);
            }
            value if value.starts_with("--scope=") => {
                let value = value.trim_start_matches("--scope=");
                scope = parse_known_scope(value)?;
            }
            value if value.starts_with("--client=") => {
                client_filters.insert(normalize_client_filter(
                    value.trim_start_matches("--client="),
                ));
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown flag: {value}"));
            }
            value => return Err(format!("unexpected extra argument: {value}")),
        }
    }

    Ok(ScanKnownArgs {
        format_override,
        scope,
        client_filters,
    })
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

pub fn parse_fix_args(args: impl Iterator<Item = String>) -> Result<FixArgs, String> {
    let mut target = None;
    let mut apply = false;
    let mut rule_filters = Vec::new();
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--apply" => apply = true,
            "--rule" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --rule".to_owned());
                };
                rule_filters.push(value);
            }
            value if value.starts_with("--rule=") => {
                rule_filters.push(value.trim_start_matches("--rule=").to_owned());
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

    Ok(FixArgs {
        target: target.unwrap_or_else(|| PathBuf::from(".")),
        apply,
        rule_filters,
    })
}

fn parse_output_format(value: &str) -> Result<OutputFormat, String> {
    match value {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        "sarif" => Ok(OutputFormat::Sarif),
        other => Err(format!("unsupported output format: {other}")),
    }
}

fn parse_known_scope(value: &str) -> Result<KnownScope, String> {
    match value {
        "project" => Ok(KnownScope::Project),
        "global" => Ok(KnownScope::Global),
        "both" => Ok(KnownScope::Both),
        other => Err(format!("unsupported --scope value: {other}")),
    }
}

fn parse_inventory_scope(value: &str) -> Result<InventoryOsScope, String> {
    match value {
        "user" => Ok(InventoryOsScope::User),
        "system" => Ok(InventoryOsScope::System),
        "both" => Ok(InventoryOsScope::Both),
        other => Err(format!("unsupported --scope value: {other}")),
    }
}

fn normalize_client_filter(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{
        parse_explain_config_args, parse_fix_args, parse_inventory_os_args, parse_scan_args,
        parse_scan_known_args,
    };
    use crate::known_scan::{InventoryOsScope, KnownScope};
    use lintai_engine::OutputFormat;

    #[test]
    fn scan_defaults_to_current_directory() {
        let parsed = parse_scan_args(std::iter::empty()).unwrap();
        assert_eq!(parsed.target, std::path::PathBuf::from("."));
        assert_eq!(parsed.format_override, None);
    }

    #[test]
    fn scan_known_defaults_to_both_scope() {
        let parsed = parse_scan_known_args(std::iter::empty()).unwrap();
        assert_eq!(parsed.format_override, None);
        assert_eq!(parsed.scope, KnownScope::Both);
        assert!(parsed.client_filters.is_empty());
    }

    #[test]
    fn inventory_os_defaults_to_both_scope_without_path_root() {
        let parsed = parse_inventory_os_args(std::iter::empty()).unwrap();
        assert_eq!(parsed.format_override, None);
        assert_eq!(parsed.scope, InventoryOsScope::Both);
        assert!(parsed.client_filters.is_empty());
        assert_eq!(parsed.path_root, None);
        assert_eq!(parsed.write_baseline, None);
        assert_eq!(parsed.diff_against, None);
    }

    #[test]
    fn scan_known_parses_scope_and_repeated_client_filters() {
        let parsed = parse_scan_known_args(
            ["--scope=global", "--client", "Cursor", "--client=codex"]
                .into_iter()
                .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(parsed.scope, KnownScope::Global);
        assert!(parsed.client_filters.contains("cursor"));
        assert!(parsed.client_filters.contains("codex"));
    }

    #[test]
    fn inventory_os_parses_scope_client_and_path_root() {
        let parsed = parse_inventory_os_args(
            [
                "--scope=user",
                "--client",
                "Goose",
                "--path-root=/tmp/lintai-fixture",
                "--write-baseline=/tmp/baseline.json",
                "--diff-against",
                "/tmp/previous.json",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(parsed.scope, InventoryOsScope::User);
        assert!(parsed.client_filters.contains("goose"));
        assert_eq!(
            parsed.path_root,
            Some(std::path::PathBuf::from("/tmp/lintai-fixture"))
        );
        assert_eq!(
            parsed.write_baseline,
            Some(std::path::PathBuf::from("/tmp/baseline.json"))
        );
        assert_eq!(
            parsed.diff_against,
            Some(std::path::PathBuf::from("/tmp/previous.json"))
        );
    }

    #[test]
    fn scan_rejects_extra_positional_argument() {
        let error = parse_scan_args(["docs", "other"].into_iter().map(str::to_owned)).unwrap_err();
        assert!(error.contains("unexpected extra argument"));
    }

    #[test]
    fn scan_known_rejects_extra_positional_argument() {
        let error = parse_scan_known_args(["project"].into_iter().map(str::to_owned)).unwrap_err();
        assert!(error.contains("unexpected extra argument"));
    }

    #[test]
    fn inventory_os_rejects_extra_positional_argument() {
        let error =
            parse_inventory_os_args(["project"].into_iter().map(str::to_owned)).unwrap_err();
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

    #[test]
    fn fix_defaults_to_preview_in_current_directory() {
        let parsed = parse_fix_args(std::iter::empty()).unwrap();
        assert_eq!(parsed.target, std::path::PathBuf::from("."));
        assert!(!parsed.apply);
        assert!(parsed.rule_filters.is_empty());
    }

    #[test]
    fn fix_parses_apply_and_repeated_rules() {
        let parsed = parse_fix_args(
            ["--apply", "--rule", "SEC101", "--rule=SEC103", "docs"]
                .into_iter()
                .map(str::to_owned),
        )
        .unwrap();
        assert!(parsed.apply);
        assert_eq!(parsed.target, std::path::PathBuf::from("docs"));
        assert_eq!(parsed.rule_filters, vec!["SEC101", "SEC103"]);
    }

    #[test]
    fn fix_rejects_extra_positional_argument() {
        let error = parse_fix_args(["docs", "other"].into_iter().map(str::to_owned)).unwrap_err();
        assert!(error.contains("unexpected extra argument"));
    }
}
