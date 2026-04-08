use std::process::ExitCode;

use crate::args::parse_policy_os_args;
use crate::execution::{
    POLICY_OS_DEFAULT_PRESETS, collect_inventory_os, default_workspace_for_builtin_preset_names,
    default_workspace_for_presets, emit_report, exit_code_for_inventory_summary,
};
use crate::output;
use crate::policy_os::{evaluate_machine_policy, load_machine_policy};

pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<ExitCode, String> {
    let parsed = parse_policy_os_args(args)?;
    let workspace = if parsed.preset_ids.is_empty() {
        default_workspace_for_builtin_preset_names(POLICY_OS_DEFAULT_PRESETS)?
    } else {
        default_workspace_for_presets(&parsed.preset_ids)?
    };
    let inventory = collect_inventory_os(
        parsed.scope,
        &parsed.client_filters,
        parsed.path_root.as_deref(),
        &workspace,
    )?;
    let policy = load_machine_policy(&parsed.policy_path)?;
    let (policy_matches, policy_stats) = evaluate_machine_policy(
        &policy,
        &inventory.report_roots,
        &inventory.aggregate.findings,
    );
    let output_format = parsed
        .format_override
        .unwrap_or(lintai_engine::OutputFormat::Text);
    let report = output::build_envelope_with_inventory(
        &inventory.aggregate,
        Some(&parsed.policy_path),
        None,
        output::InventoryEnvelopeArgs {
            inventory_roots: inventory.report_roots,
            inventory_stats: Some(inventory.inventory_stats),
            inventory_diff: None,
            policy_matches: policy_matches.clone(),
            policy_stats: Some(policy_stats),
        },
    );

    emit_report(&report, output_format)?;
    Ok(exit_code_for_inventory_summary(
        &inventory.aggregate,
        inventory.blocking || has_deny_policy_matches(&policy_matches),
    ))
}

fn has_deny_policy_matches(matches: &[crate::policy_os::PolicyMatch]) -> bool {
    matches
        .iter()
        .any(|policy_match| policy_match.severity == "deny")
}
