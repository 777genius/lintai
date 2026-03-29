use std::process::ExitCode;

use crate::args::parse_policy_os_args;
use crate::execution::{collect_inventory_os, emit_report, exit_code_for_blocking_bool};
use crate::output;
use crate::policy_os::{evaluate_machine_policy, load_machine_policy};

pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<ExitCode, String> {
    let parsed = parse_policy_os_args(args)?;
    let inventory = collect_inventory_os(
        parsed.scope,
        &parsed.client_filters,
        parsed.path_root.as_deref(),
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
        inventory.report_roots,
        Some(inventory.inventory_stats),
        None,
        policy_matches.clone(),
        Some(policy_stats),
    );

    emit_report(&report, output_format)?;
    Ok(exit_code_for_blocking_bool(
        inventory.blocking || has_deny_policy_matches(&policy_matches),
    ))
}

fn has_deny_policy_matches(matches: &[crate::policy_os::PolicyMatch]) -> bool {
    matches
        .iter()
        .any(|policy_match| policy_match.severity == "deny")
}
