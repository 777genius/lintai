use crate::known_scan::{
    DiscoveredRoot, DiscoveryStats, InventoryDiff, InventoryRoot, InventoryStats,
};
use crate::policy_os::{PolicyMatch, PolicyStats};
use lintai_api::Finding;
use lintai_engine::{ScanDiagnostic, ScanRuntimeError};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ReportEnvelope<'a> {
    pub(crate) schema_version: u32,
    pub(crate) tool: ToolMetadata<'a>,
    pub(crate) config_source: Option<String>,
    pub(crate) project_root: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub(crate) discovered_roots: Vec<DiscoveredRoot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) discovery_stats: Option<DiscoveryStats>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub(crate) inventory_roots: Vec<InventoryRoot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) inventory_stats: Option<InventoryStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) inventory_diff: Option<InventoryDiff>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub(crate) policy_matches: Vec<PolicyMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) policy_stats: Option<PolicyStats>,
    pub(crate) stats: ReportStats,
    pub(crate) findings: &'a [Finding],
    pub(crate) diagnostics: &'a [ScanDiagnostic],
    pub(crate) runtime_errors: &'a [ScanRuntimeError],
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ToolMetadata<'a> {
    pub(crate) name: &'a str,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ReportStats {
    pub(crate) scanned_files: usize,
    pub(crate) skipped_files: usize,
}
