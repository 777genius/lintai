use std::path::Path;
use std::process::ExitCode;

use lintai_engine::{EngineConfig, OutputFormat, WorkspaceConfig, load_workspace_config};

use crate::args::parse_scan_known_args;
use crate::execution::{
    build_engine, emit_report, exit_code_for_blocking_bool, exit_code_for_findings,
};
use crate::known_scan::{
    ArtifactMode, DiscoveredRoot, DiscoveryStats, KnownRootScope, absolute_base_for_scan,
    discover_known_roots, inventory_lintable_root, merge_summary_with_absolute_paths,
    workspace_for_known_root,
};
use crate::output;

pub(crate) fn run(
    current_dir: &Path,
    args: impl Iterator<Item = String>,
) -> Result<ExitCode, String> {
    let parsed = parse_scan_known_args(args)?;
    let mut project_workspace = if parsed.scope.includes_project() {
        Some(
            load_workspace_config(current_dir)
                .map_err(|error| format!("config resolution failed: {error}"))?,
        )
    } else {
        None
    };
    if let Some(workspace) = project_workspace.as_mut()
        && workspace.engine_config.project_root.is_none()
    {
        workspace
            .engine_config
            .set_project_root(Some(current_dir.to_path_buf()));
    }
    let project_root = project_workspace
        .as_ref()
        .and_then(|workspace| workspace.engine_config.project_root.as_deref())
        .unwrap_or(current_dir);
    let discovered_roots =
        discover_known_roots(Some(project_root), parsed.scope, &parsed.client_filters)?;

    let output_format = parsed
        .format_override
        .or_else(|| {
            project_workspace
                .as_ref()
                .map(|workspace| workspace.engine_config.output_format)
        })
        .unwrap_or(OutputFormat::Text);

    let mut aggregate = lintai_engine::ScanSummary::default();
    let mut report_roots = Vec::<DiscoveredRoot>::with_capacity(discovered_roots.len());
    let mut discovery_stats = DiscoveryStats::default();
    let mut blocking = false;
    let default_workspace = WorkspaceConfig {
        source_path: None,
        engine_config: EngineConfig::default(),
    };

    for root in discovered_roots {
        discovery_stats.record_root(root.mode);
        report_roots.push(root.to_report());
        if matches!(root.mode, ArtifactMode::DiscoveredOnly) {
            continue;
        }

        let base_workspace = match root.scope {
            KnownRootScope::Project => project_workspace
                .as_ref()
                .ok_or_else(|| "project workspace was not initialized".to_owned())?,
            KnownRootScope::Global => &default_workspace,
        };
        let workspace = workspace_for_known_root(&root, base_workspace)?;
        let engine = build_engine(&workspace)?;

        let inventory = inventory_lintable_root(&root, &workspace)
            .map_err(|error| format!("inventory failed for {}: {error}", root.path.display()))?;
        discovery_stats.record_lintable_inventory(&inventory);

        let summary = engine
            .scan_path(&root.path)
            .map_err(|error| format!("scan failed for {}: {error}", root.path.display()))?;
        blocking |= matches!(
            exit_code_for_findings(&summary.findings, &workspace.engine_config.ci_policy),
            ExitCode::FAILURE
        );
        discovery_stats.supported_artifacts_scanned += summary.scanned_files;
        let absolute_base = absolute_base_for_scan(&root.path, &workspace);
        merge_summary_with_absolute_paths(&mut aggregate, summary, &absolute_base);
    }

    let report = output::build_envelope_with_discovery(
        &aggregate,
        None,
        None,
        report_roots,
        Some(discovery_stats),
    );
    emit_report(&report, output_format)?;
    Ok(exit_code_for_blocking_bool(blocking))
}
