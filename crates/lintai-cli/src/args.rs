use std::path::PathBuf;

use lintai_engine::OutputFormat;

mod common;
mod fix;
mod inventory;
mod known_scan;
mod policy;
mod scan;

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

pub(crate) use fix::parse_fix_args;
pub(crate) use inventory::parse_inventory_os_args;
pub(crate) use known_scan::parse_scan_known_args;
pub(crate) use policy::parse_policy_os_args;
pub(crate) use scan::parse_scan_args;

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

#[cfg(test)]
mod tests {
    use super::{
        parse_explain_config_args, parse_fix_args, parse_inventory_os_args, parse_policy_os_args,
        parse_scan_args, parse_scan_known_args,
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
        assert!(parsed.preset_ids.is_empty());
    }

    #[test]
    fn inventory_os_defaults_to_both_scope_without_path_root() {
        let parsed = parse_inventory_os_args(std::iter::empty()).unwrap();
        assert_eq!(parsed.format_override, None);
        assert_eq!(parsed.scope, InventoryOsScope::Both);
        assert!(parsed.client_filters.is_empty());
        assert!(parsed.preset_ids.is_empty());
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
    fn scan_known_parses_repeated_presets() {
        let parsed = parse_scan_known_args(
            ["--preset", "base", "--preset=mcp", "--preset", "claude"]
                .into_iter()
                .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(parsed.preset_ids, vec!["base", "mcp", "claude"]);
    }

    #[test]
    fn scan_known_trims_preset_values() {
        let parsed = parse_scan_known_args(
            ["--preset", " base ", "--preset= mcp "]
                .into_iter()
                .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(parsed.preset_ids, vec!["base", "mcp"]);
    }

    #[test]
    fn inventory_os_parses_scope_client_and_path_root() {
        let parsed = parse_inventory_os_args(
            [
                "--scope=user",
                "--client",
                "Goose",
                "--preset=base",
                "--preset",
                "mcp",
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
        assert_eq!(parsed.preset_ids, vec!["base", "mcp"]);
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
    fn inventory_os_parses_repeated_presets() {
        let parsed = parse_inventory_os_args(
            ["--preset", "base", "--preset", "mcp", "--preset=claude"]
                .into_iter()
                .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(parsed.preset_ids, vec!["base", "mcp", "claude"]);
    }

    #[test]
    fn policy_os_requires_policy_path() {
        let error = parse_policy_os_args(std::iter::empty()).unwrap_err();
        assert!(error.contains("missing required --policy"));
    }

    #[test]
    fn policy_os_parses_scope_client_path_root_and_policy() {
        let parsed = parse_policy_os_args(
            [
                "--scope=user",
                "--client",
                "Cursor",
                "--preset=base",
                "--preset",
                "claude",
                "--path-root=/tmp/machine",
                "--policy=/tmp/policy.toml",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(parsed.scope, InventoryOsScope::User);
        assert!(parsed.client_filters.contains("cursor"));
        assert_eq!(parsed.preset_ids, vec!["base", "claude"]);
        assert_eq!(
            parsed.path_root,
            Some(std::path::PathBuf::from("/tmp/machine"))
        );
        assert_eq!(
            parsed.policy_path,
            std::path::PathBuf::from("/tmp/policy.toml")
        );
    }

    #[test]
    fn policy_os_parses_repeated_presets() {
        let parsed = parse_policy_os_args(
            [
                "--policy=/tmp/policy.toml",
                "--preset",
                "base",
                "--preset",
                "mcp",
                "--preset=claude",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(parsed.preset_ids, vec!["base", "mcp", "claude"]);
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
