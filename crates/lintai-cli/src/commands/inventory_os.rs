use std::process::ExitCode;

use crate::args::parse_inventory_os_args;
use crate::execution::{
    collect_inventory_os, default_workspace_for_presets, emit_report,
    exit_code_for_inventory_summary,
};
use crate::output;

pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<ExitCode, String> {
    let parsed = parse_inventory_os_args(args)?;
    let output_format = parsed
        .format_override
        .unwrap_or(lintai_engine::OutputFormat::Text);
    let workspace = default_workspace_for_presets(&parsed.preset_ids)?;
    let inventory = collect_inventory_os(
        parsed.scope,
        &parsed.client_filters,
        parsed.path_root.as_deref(),
        &workspace,
    )?;
    let snapshot = crate::known_scan::build_inventory_snapshot(
        &inventory.report_roots,
        &inventory.inventory_stats,
        &inventory.aggregate.findings,
    );
    let inventory_diff = if let Some(baseline_path) = parsed.diff_against.as_deref() {
        let baseline = crate::known_scan::load_inventory_snapshot(baseline_path)?;
        Some(crate::known_scan::diff_inventory_snapshots(
            &baseline, &snapshot,
        ))
    } else {
        None
    };

    if let Some(baseline_path) = parsed.write_baseline.as_deref() {
        crate::known_scan::write_inventory_snapshot(baseline_path, &snapshot)?;
    }

    let report = output::build_envelope_with_inventory(
        &inventory.aggregate,
        None,
        None,
        output::InventoryEnvelopeArgs {
            inventory_roots: inventory.report_roots,
            inventory_stats: Some(inventory.inventory_stats),
            inventory_diff,
            policy_matches: Vec::new(),
            policy_stats: None,
        },
    );
    emit_report(&report, output_format, parsed.color_mode)?;
    Ok(exit_code_for_inventory_summary(
        &inventory.aggregate,
        inventory.blocking,
    ))
}
