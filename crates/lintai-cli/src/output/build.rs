use std::path::Path;

use lintai_engine::{ScanSummary, normalize_path_string};

use super::model::{ReportEnvelope, ReportStats, ToolMetadata};
use crate::known_scan::{
    DiscoveredRoot, DiscoveryStats, InventoryDiff, InventoryRoot, InventoryStats,
};
use crate::policy_os::{PolicyMatch, PolicyStats};

pub(crate) fn build_envelope<'a>(
    summary: &'a ScanSummary,
    config_source: Option<&Path>,
    project_root: Option<&Path>,
) -> ReportEnvelope<'a> {
    build_envelope_with_discovery(summary, config_source, project_root, Vec::new(), None)
}

pub(crate) fn build_envelope_with_discovery<'a>(
    summary: &'a ScanSummary,
    config_source: Option<&Path>,
    project_root: Option<&Path>,
    discovered_roots: Vec<DiscoveredRoot>,
    discovery_stats: Option<DiscoveryStats>,
) -> ReportEnvelope<'a> {
    ReportEnvelope {
        schema_version: 1,
        tool: ToolMetadata { name: "lintai" },
        config_source: config_source.map(normalize_path_string),
        project_root: project_root.map(normalize_path_string),
        discovered_roots,
        discovery_stats,
        inventory_roots: Vec::new(),
        inventory_stats: None,
        inventory_diff: None,
        policy_matches: Vec::new(),
        policy_stats: None,
        stats: ReportStats {
            scanned_files: summary.scanned_files,
            skipped_files: summary.skipped_files,
        },
        findings: &summary.findings,
        diagnostics: &summary.diagnostics,
        runtime_errors: &summary.runtime_errors,
    }
}

pub(crate) struct InventoryEnvelopeArgs {
    pub(crate) inventory_roots: Vec<InventoryRoot>,
    pub(crate) inventory_stats: Option<InventoryStats>,
    pub(crate) inventory_diff: Option<InventoryDiff>,
    pub(crate) policy_matches: Vec<PolicyMatch>,
    pub(crate) policy_stats: Option<PolicyStats>,
}

pub(crate) fn build_envelope_with_inventory<'a>(
    summary: &'a ScanSummary,
    config_source: Option<&Path>,
    project_root: Option<&Path>,
    args: InventoryEnvelopeArgs,
) -> ReportEnvelope<'a> {
    let InventoryEnvelopeArgs {
        inventory_roots,
        inventory_stats,
        inventory_diff,
        policy_matches,
        policy_stats,
    } = args;
    ReportEnvelope {
        schema_version: 1,
        tool: ToolMetadata { name: "lintai" },
        config_source: config_source.map(normalize_path_string),
        project_root: project_root.map(normalize_path_string),
        discovered_roots: Vec::new(),
        discovery_stats: None,
        inventory_roots,
        inventory_stats,
        inventory_diff,
        policy_matches,
        policy_stats,
        stats: ReportStats {
            scanned_files: summary.scanned_files,
            skipped_files: summary.skipped_files,
        },
        findings: &summary.findings,
        diagnostics: &summary.diagnostics,
        runtime_errors: &summary.runtime_errors,
    }
}
