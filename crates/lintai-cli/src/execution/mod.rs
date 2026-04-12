use std::collections::BTreeSet;
use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use lintai_api::{Confidence, Finding, Severity};
use lintai_engine::{
    CiPolicy, Engine, EngineConfig, FileSuppressions, OutputFormat, ScanRuntimeError, ScanSummary,
    WorkspaceConfig, load_workspace_config,
};

use crate::builtin_providers::product_provider_set;
use crate::known_scan::{
    ArtifactMode, InventoryOsScope, InventoryRoot, InventoryStats, absolute_base_for_scan,
    discover_inventory_roots, inventory_lintable_root, merge_summary_with_absolute_paths,
    workspace_for_known_root,
};
use crate::{output, path::validate_path_within_project};

pub(crate) struct InventoryCollection {
    pub(crate) aggregate: ScanSummary,
    pub(crate) report_roots: Vec<InventoryRoot>,
    pub(crate) inventory_stats: InventoryStats,
    pub(crate) blocking: bool,
}

pub(crate) const POLICY_OS_DEFAULT_PRESETS: &[&str] = &["base", "mcp", "claude"];

pub(crate) fn emit_report(
    report: &output::ReportEnvelope<'_>,
    output_format: OutputFormat,
    color_mode: output::ColorMode,
) -> Result<(), String> {
    match output_format {
        OutputFormat::Text => {
            let style = output::ResolvedTextStyle::from_environment(
                output::TextRenderOptions::new(color_mode, std::io::stdout().is_terminal()),
                &output::TextColorEnvironment::current(),
            );
            print!("{}", output::format_text_with_style(report, style));
        }
        OutputFormat::Json => {
            println!(
                "{}",
                output::format_json(report)
                    .map_err(|error| format!("json output failed: {error}"))?
            );
        }
        OutputFormat::Sarif => {
            println!(
                "{}",
                output::format_sarif(report)
                    .map_err(|error| format!("sarif output failed: {error}"))?
            );
        }
    }
    Ok(())
}

pub(crate) fn load_validated_workspace(
    current_dir: &Path,
    target: &Path,
) -> Result<WorkspaceConfig, String> {
    let workspace = load_workspace_config(current_dir)
        .map_err(|error| format!("config resolution failed: {error}"))?;
    validate_path_within_project(target, workspace.engine_config.project_root.as_deref())
        .map_err(|error| format!("target validation failed: {error}"))?;
    Ok(workspace)
}

pub(crate) fn load_validated_workspace_for_scan(
    current_dir: &Path,
    target: &Path,
    preset_ids: &[String],
) -> Result<WorkspaceConfig, String> {
    if preset_ids.is_empty() {
        return load_validated_workspace(current_dir, target);
    }

    let mut workspace = default_workspace_for_presets(preset_ids)?;
    workspace
        .engine_config
        .set_project_root(Some(current_dir.to_path_buf()));
    validate_path_within_project(target, workspace.engine_config.project_root.as_deref())
        .map_err(|error| format!("target validation failed: {error}"))?;
    Ok(workspace)
}

pub(crate) fn default_workspace_for_presets(
    preset_ids: &[String],
) -> Result<WorkspaceConfig, String> {
    let engine_config = if preset_ids.is_empty() {
        EngineConfig::default()
    } else {
        EngineConfig::from_enabled_presets(preset_ids)
            .map_err(|error| format!("preset resolution failed: {error}"))?
    };
    Ok(WorkspaceConfig {
        source_path: None,
        engine_config,
    })
}

pub(crate) fn default_workspace_for_builtin_preset_names(
    preset_ids: &[&str],
) -> Result<WorkspaceConfig, String> {
    let preset_ids = preset_ids
        .iter()
        .map(|preset| (*preset).to_owned())
        .collect::<Vec<_>>();
    default_workspace_for_presets(&preset_ids)
}

pub(crate) fn build_engine(workspace: &WorkspaceConfig) -> Result<Engine, String> {
    let suppressions = FileSuppressions::load(&workspace.engine_config)
        .map_err(|error| format!("suppress loading failed: {error}"))?;
    let builder = Engine::builder()
        .with_config(workspace.engine_config.clone())
        .with_suppressions(Arc::new(suppressions))
        .with_backends(product_provider_set());

    Ok(builder.build())
}

pub(crate) fn exit_code_for_findings(findings: &[Finding], ci_policy: &CiPolicy) -> ExitCode {
    if has_blocking_findings(findings, ci_policy) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

pub(crate) fn exit_code_for_scan_summary(summary: &ScanSummary, ci_policy: &CiPolicy) -> ExitCode {
    if has_runtime_errors(&summary.runtime_errors) {
        ExitCode::from(2)
    } else {
        exit_code_for_findings(&summary.findings, ci_policy)
    }
}

pub(crate) fn exit_code_for_inventory_summary(summary: &ScanSummary, blocking: bool) -> ExitCode {
    if has_runtime_errors(&summary.runtime_errors) {
        ExitCode::from(2)
    } else {
        exit_code_for_blocking_bool(blocking)
    }
}

pub(crate) fn exit_code_for_blocking_bool(blocking: bool) -> ExitCode {
    if blocking {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

pub(crate) fn collect_inventory_os(
    scope: InventoryOsScope,
    client_filters: &BTreeSet<String>,
    path_root: Option<&Path>,
    default_workspace: &WorkspaceConfig,
) -> Result<InventoryCollection, String> {
    let discovered_roots = discover_inventory_roots(scope, client_filters, path_root)?;

    let mut aggregate = ScanSummary::default();
    let mut report_roots = Vec::<InventoryRoot>::with_capacity(discovered_roots.len());
    let mut inventory_stats = InventoryStats::default();
    let mut blocking = false;

    for root in discovered_roots {
        inventory_stats.record_root(&root);
        report_roots.push(root.to_inventory_report());
        if matches!(root.mode, ArtifactMode::DiscoveredOnly) {
            continue;
        }

        let workspace = workspace_for_known_root(&root, default_workspace)?;
        let engine = build_engine(&workspace)?;
        let inventory = inventory_lintable_root(&root, &workspace)
            .map_err(|error| format!("inventory failed for {}: {error}", root.path.display()))?;
        inventory_stats.record_lintable_inventory(&inventory);

        let summary = engine
            .scan_path(&root.path)
            .map_err(|error| format!("scan failed for {}: {error}", root.path.display()))?;
        blocking |= has_blocking_findings(&summary.findings, &workspace.engine_config.ci_policy);
        inventory_stats.supported_artifacts_scanned += summary.scanned_files;
        let absolute_base = absolute_base_for_scan(&root.path, &workspace);
        merge_summary_with_absolute_paths(&mut aggregate, summary, &absolute_base);
    }

    Ok(InventoryCollection {
        aggregate,
        report_roots,
        inventory_stats,
        blocking,
    })
}

fn has_blocking_findings(findings: &[Finding], ci_policy: &CiPolicy) -> bool {
    findings
        .iter()
        .filter(|finding| {
            confidence_rank(finding.confidence) >= confidence_rank(ci_policy.min_confidence)
        })
        .any(|finding| severity_rank(finding.severity) >= severity_rank(ci_policy.fail_on))
}

fn has_runtime_errors(runtime_errors: &[ScanRuntimeError]) -> bool {
    !runtime_errors.is_empty()
}

fn severity_rank(severity: Severity) -> usize {
    match severity {
        Severity::Allow => 0,
        Severity::Warn => 1,
        Severity::Deny => 2,
    }
}

fn confidence_rank(confidence: Confidence) -> usize {
    match confidence {
        Confidence::Low => 0,
        Confidence::Medium => 1,
        Confidence::High => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lintai_engine::{RuntimeErrorKind, ScanRuntimeError};

    #[test]
    fn scan_summary_runtime_errors_override_blocking_finding_exit_code() {
        let finding = Finding::new(
            &lintai_api::RuleMetadata::new(
                "TEST001",
                "demo",
                lintai_api::Category::Security,
                Severity::Deny,
                Confidence::High,
                lintai_api::RuleTier::Preview,
            ),
            lintai_api::Location::new("file.txt", lintai_api::Span::new(0, 1)),
            "demo",
        );
        let summary = ScanSummary {
            findings: vec![finding],
            runtime_errors: vec![ScanRuntimeError {
                normalized_path: "file.txt".to_owned(),
                kind: RuntimeErrorKind::Read,
                provider_id: Some("demo".to_owned()),
                phase: None,
                message: "boom".to_owned(),
            }],
            ..ScanSummary::default()
        };

        assert_eq!(
            exit_code_for_scan_summary(&summary, &CiPolicy::default()),
            ExitCode::from(2)
        );
    }

    #[test]
    fn inventory_summary_runtime_errors_override_blocking_flag() {
        let summary = ScanSummary {
            runtime_errors: vec![ScanRuntimeError {
                normalized_path: "file.txt".to_owned(),
                kind: RuntimeErrorKind::Read,
                provider_id: Some("demo".to_owned()),
                phase: None,
                message: "boom".to_owned(),
            }],
            ..ScanSummary::default()
        };

        assert_eq!(
            exit_code_for_inventory_summary(&summary, true),
            ExitCode::from(2)
        );
        assert_eq!(
            exit_code_for_inventory_summary(&summary, false),
            ExitCode::from(2)
        );
    }
}
