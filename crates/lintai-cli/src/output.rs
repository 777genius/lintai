use std::path::Path;

use lintai_api::Finding;
use lintai_engine::{
    normalize_path_string, DiagnosticSeverity, RuntimeErrorKind, ScanDiagnostic, ScanRuntimeError,
    ScanSummary,
};
use serde::Serialize;

use crate::known_scan::{
    DiscoveredRoot, DiscoveryStats, InventoryChangedRoot, InventoryDiff, InventoryRoot,
    InventoryStats,
};

#[derive(Clone, Debug, Serialize)]
pub struct ReportEnvelope<'a> {
    pub schema_version: u32,
    pub tool: ToolMetadata<'a>,
    pub config_source: Option<String>,
    pub project_root: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub discovered_roots: Vec<DiscoveredRoot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery_stats: Option<DiscoveryStats>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub inventory_roots: Vec<InventoryRoot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory_stats: Option<InventoryStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory_diff: Option<InventoryDiff>,
    pub stats: ReportStats,
    pub findings: &'a [Finding],
    pub diagnostics: &'a [ScanDiagnostic],
    pub runtime_errors: &'a [ScanRuntimeError],
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolMetadata<'a> {
    pub name: &'a str,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReportStats {
    pub scanned_files: usize,
    pub skipped_files: usize,
}

pub fn build_envelope<'a>(
    summary: &'a ScanSummary,
    config_source: Option<&Path>,
    project_root: Option<&Path>,
) -> ReportEnvelope<'a> {
    build_envelope_with_discovery(summary, config_source, project_root, Vec::new(), None)
}

pub fn build_envelope_with_discovery<'a>(
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
        stats: ReportStats {
            scanned_files: summary.scanned_files,
            skipped_files: summary.skipped_files,
        },
        findings: &summary.findings,
        diagnostics: &summary.diagnostics,
        runtime_errors: &summary.runtime_errors,
    }
}

pub fn build_envelope_with_inventory<'a>(
    summary: &'a ScanSummary,
    config_source: Option<&Path>,
    project_root: Option<&Path>,
    inventory_roots: Vec<InventoryRoot>,
    inventory_stats: Option<InventoryStats>,
    inventory_diff: Option<InventoryDiff>,
) -> ReportEnvelope<'a> {
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
        stats: ReportStats {
            scanned_files: summary.scanned_files,
            skipped_files: summary.skipped_files,
        },
        findings: &summary.findings,
        diagnostics: &summary.diagnostics,
        runtime_errors: &summary.runtime_errors,
    }
}

pub fn format_text(report: &ReportEnvelope<'_>) -> String {
    let mut output = String::new();
    if let Some(inventory_diff) = &report.inventory_diff {
        let inventory_stats = report
            .inventory_stats
            .as_ref()
            .expect("inventory_diff requires inventory_stats");
        output.push_str(&format!(
            "inventory diff discovered {} root(s), new {} root(s), removed {} root(s), changed {} root(s), new lintable {} root(s), risk increased {} root(s), new findings {}\n",
            report.inventory_roots.len(),
            inventory_diff.new_roots.len(),
            inventory_diff.removed_roots.len(),
            inventory_diff.changed_roots.len(),
            inventory_diff.new_lintable_roots.len(),
            inventory_diff.risk_increased_roots.len(),
            inventory_diff.new_findings.len()
        ));
        output.push_str(&format!(
            "inventory counters: user={} system={} lintable={} discovered_only={} high={} medium={} low={} scanned={} non_target={} excluded={} binary={} unreadable={} unrecognized={}\n",
            inventory_stats.user_roots,
            inventory_stats.system_roots,
            inventory_stats.lintable_roots,
            inventory_stats.discovered_only_roots,
            inventory_stats.high_risk_roots,
            inventory_stats.medium_risk_roots,
            inventory_stats.low_risk_roots,
            inventory_stats.supported_artifacts_scanned,
            inventory_stats.non_target_files_in_lintable_roots,
            inventory_stats.excluded_files,
            inventory_stats.binary_files,
            inventory_stats.unreadable_files,
            inventory_stats.unrecognized_files,
        ));
    } else if let Some(inventory_stats) = &report.inventory_stats {
        output.push_str(&format!(
            "inventory discovered {} root(s), user {} root(s), system {} root(s), lintable {} root(s), discovered-only {} root(s), high risk {} root(s), medium risk {} root(s), low risk {} root(s), scanned {} supported artifact(s), non-target {} file(s), found {} finding(s), {} diagnostic(s), {} runtime error(s)\n",
            report.inventory_roots.len(),
            inventory_stats.user_roots,
            inventory_stats.system_roots,
            inventory_stats.lintable_roots,
            inventory_stats.discovered_only_roots,
            inventory_stats.high_risk_roots,
            inventory_stats.medium_risk_roots,
            inventory_stats.low_risk_roots,
            inventory_stats.supported_artifacts_scanned,
            inventory_stats.non_target_total(),
            report.findings.len(),
            report.diagnostics.len(),
            report.runtime_errors.len()
        ));
        output.push_str(&format!(
            "inventory counters: non_target={} excluded={} binary={} unreadable={} unrecognized={}\n",
            inventory_stats.non_target_files_in_lintable_roots,
            inventory_stats.excluded_files,
            inventory_stats.binary_files,
            inventory_stats.unreadable_files,
            inventory_stats.unrecognized_files,
        ));
    } else if let Some(discovery_stats) = &report.discovery_stats {
        output.push_str(&format!(
            "discovered {} root(s), lintable {} root(s), discovered-only {} root(s), scanned {} supported artifact(s), non-target {} file(s), found {} finding(s), {} diagnostic(s), {} runtime error(s)\n",
            report.discovered_roots.len(),
            discovery_stats.lintable_roots,
            discovery_stats.discovered_only_roots,
            discovery_stats.supported_artifacts_scanned,
            discovery_stats.non_target_total(),
            report.findings.len(),
            report.diagnostics.len(),
            report.runtime_errors.len()
        ));
        output.push_str(&format!(
            "discovery counters: non_target={} excluded={} binary={} unreadable={} unrecognized={}\n",
            discovery_stats.non_target_files_in_lintable_roots,
            discovery_stats.excluded_files,
            discovery_stats.binary_files,
            discovery_stats.unreadable_files,
            discovery_stats.unrecognized_files,
        ));
    } else {
        output.push_str(&format!(
            "scanned {} file(s), skipped {} file(s), found {} finding(s), {} diagnostic(s), {} runtime error(s)\n",
            report.stats.scanned_files,
            report.stats.skipped_files,
            report.findings.len(),
            report.diagnostics.len(),
            report.runtime_errors.len()
        ));
    }

    for root in &report.discovered_roots {
        output.push_str(&format!(
            "root [{} {}] {} {} {}\n",
            root.scope, root.mode, root.client, root.surface, root.path
        ));
    }

    for root in &report.inventory_roots {
        output.push_str(&format!(
            "inventory-root [{} {} {}] {} {} {}\n",
            root.provenance.origin_scope,
            root.risk_level,
            root.mode,
            root.client,
            root.surface,
            root.path
        ));
    }

    if let Some(inventory_diff) = &report.inventory_diff {
        for root in &inventory_diff.new_roots {
            output.push_str(&format!(
                "new-root [{} {}] {} {} {}\n",
                root.risk_level, root.mode, root.client, root.surface, root.path
            ));
        }
        for root in &inventory_diff.removed_roots {
            output.push_str(&format!(
                "removed-root [{} {}] {} {} {}\n",
                root.risk_level, root.mode, root.client, root.surface, root.path
            ));
        }
        for root in &inventory_diff.changed_roots {
            output.push_str(&format!(
                "changed-root [{}] {} {} {}\n",
                changed_root_fragment(root),
                root.client,
                root.surface,
                root.path
            ));
        }
        for root in &inventory_diff.new_lintable_roots {
            output.push_str(&format!(
                "new-lintable-root [{}] {} {} {}\n",
                root.risk_level, root.client, root.surface, root.path
            ));
        }
        for root in &inventory_diff.risk_increased_roots {
            output.push_str(&format!(
                "risk-increased-root [{}->{}] {} {} {}\n",
                root.old_risk_level, root.new_risk_level, root.client, root.surface, root.path
            ));
        }
        for finding in &inventory_diff.new_findings {
            output.push_str(&format!(
                "new-finding {} {} {}\n",
                finding.rule_code,
                client_for_inventory_finding(
                    &report.inventory_roots,
                    finding.location.normalized_path.as_str()
                ),
                finding.location.normalized_path
            ));
        }
    }

    for finding in report.findings {
        output.push_str(&format!(
            "{} [{}] {}:{}-{} {}\n",
            finding.rule_code,
            severity_label(finding.severity),
            finding.location.normalized_path,
            finding.location.span.start_byte,
            finding.location.span.end_byte,
            finding.message
        ));
        for suggestion in &finding.suggestions {
            output.push_str(&format!("  suggest: {}\n", suggestion.message));
        }
    }

    for diagnostic in report.diagnostics {
        output.push_str(&format!(
            "diagnostic [{}] {} {}\n",
            diagnostic_label(diagnostic.severity),
            diagnostic.normalized_path,
            diagnostic.message
        ));
    }

    for error in report.runtime_errors {
        let provider_fragment = error
            .provider_id
            .as_deref()
            .map(|provider_id| format!(" provider={provider_id}"))
            .unwrap_or_default();
        let phase_fragment = error
            .phase
            .map(|phase| format!(" phase={}", provider_execution_phase_label(phase)))
            .unwrap_or_default();
        output.push_str(&format!(
            "error [{}] {}{}{} {}\n",
            error_kind_label(error.kind),
            error.normalized_path,
            provider_fragment,
            phase_fragment,
            error.message
        ));
    }

    output
}

pub fn format_json(report: &ReportEnvelope<'_>) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

pub fn format_sarif(report: &ReportEnvelope<'_>) -> Result<String, serde_json::Error> {
    let results = report
        .findings
        .iter()
        .map(|finding| {
            serde_json::json!({
                "ruleId": finding.rule_code,
                "level": sarif_level(finding.severity),
                "message": { "text": finding.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": finding.location.normalized_path },
                        "region": {
                            "startLine": finding.location.start.as_ref().map(|v| v.line),
                            "startColumn": finding.location.start.as_ref().map(|v| v.column),
                            "endLine": finding.location.end.as_ref().map(|v| v.line),
                            "endColumn": finding.location.end.as_ref().map(|v| v.column),
                            "charOffset": finding.location.span.start_byte,
                            "charLength": finding.location.span.end_byte.saturating_sub(finding.location.span.start_byte),
                        }
                    }
                }],
                "partialFingerprints": {
                    "stableKey": format!(
                        "{}:{}:{}:{}:{}",
                        finding.stable_key.rule_code,
                        finding.stable_key.normalized_path,
                        finding.stable_key.span.start_byte,
                        finding.stable_key.span.end_byte,
                        finding.stable_key.subject_id.as_deref().unwrap_or("")
                    )
                },
                "properties": {
                    "confidence": format!("{:?}", finding.confidence).to_lowercase(),
                    "category": format!("{:?}", finding.category).to_lowercase(),
                    "evidenceCount": finding.evidence.len(),
                }
            })
        })
        .collect::<Vec<_>>();
    let rules = report
        .findings
        .iter()
        .map(|finding| {
            serde_json::json!({
                "id": finding.rule_code,
                "shortDescription": { "text": finding.rule_code },
                "properties": {
                    "tags": finding.tags,
                    "cwe": finding.cwe,
                }
            })
        })
        .collect::<Vec<_>>();

    serde_json::to_string_pretty(&serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": report.tool.name,
                    "rules": rules,
                }
            },
            "results": results,
        }]
    }))
}

fn severity_label(severity: lintai_api::Severity) -> &'static str {
    match severity {
        lintai_api::Severity::Deny => "deny",
        lintai_api::Severity::Warn => "warn",
        lintai_api::Severity::Allow => "allow",
    }
}

fn diagnostic_label(kind: DiagnosticSeverity) -> &'static str {
    match kind {
        DiagnosticSeverity::Info => "info",
        DiagnosticSeverity::Warn => "warn",
    }
}

fn error_kind_label(kind: RuntimeErrorKind) -> &'static str {
    match kind {
        RuntimeErrorKind::Read => "read",
        RuntimeErrorKind::InvalidUtf8 => "invalid_utf8",
        RuntimeErrorKind::Parse => "parse",
        RuntimeErrorKind::ProviderExecution => "provider_execution",
        RuntimeErrorKind::ProviderTimeout => "provider_timeout",
    }
}

fn provider_execution_phase_label(phase: lintai_engine::ProviderExecutionPhase) -> &'static str {
    match phase {
        lintai_engine::ProviderExecutionPhase::File => "file",
        lintai_engine::ProviderExecutionPhase::Workspace => "workspace",
    }
}

fn sarif_level(severity: lintai_api::Severity) -> &'static str {
    match severity {
        lintai_api::Severity::Deny => "error",
        lintai_api::Severity::Warn => "warning",
        lintai_api::Severity::Allow => "note",
    }
}

fn changed_root_fragment(root: &InventoryChangedRoot) -> String {
    let mut parts = Vec::new();
    if root.old_risk_level != root.new_risk_level {
        parts.push(format!(
            "risk {}->{}",
            root.old_risk_level, root.new_risk_level
        ));
    }
    if root.old_mode != root.new_mode {
        parts.push(format!("mode {}->{}", root.old_mode, root.new_mode));
    }
    if root.old_path_type != root.new_path_type {
        parts.push(format!(
            "path_type {}->{}",
            root.old_path_type, root.new_path_type
        ));
    }
    if root.old_mtime_epoch_s != root.new_mtime_epoch_s {
        parts.push(format!(
            "mtime {}->{}",
            option_u64_label(root.old_mtime_epoch_s),
            option_u64_label(root.new_mtime_epoch_s)
        ));
    }
    parts.join(" ")
}

fn option_u64_label(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_owned())
}

fn client_for_inventory_finding<'a>(roots: &'a [InventoryRoot], normalized_path: &str) -> &'a str {
    let finding_path = std::path::Path::new(normalized_path);
    roots
        .iter()
        .find(|root| match root.provenance.path_type.as_str() {
            "directory" => {
                let root_path = std::path::Path::new(&root.path);
                finding_path == root_path || finding_path.starts_with(root_path)
            }
            _ => root.path == normalized_path,
        })
        .map(|root| root.client.as_str())
        .unwrap_or("unknown")
}

#[cfg(test)]
mod tests {
    use super::{format_json, format_sarif, ReportStats, ToolMetadata};
    use crate::known_scan::{
        DiscoveredRoot, DiscoveryStats, InventoryChangedRoot, InventoryDiff, InventoryProvenance,
        InventoryRoot, InventoryStats,
    };

    #[test]
    fn sarif_output_contains_stable_fingerprint() {
        let finding = lintai_api::Finding::new(
            &lintai_api::RuleMetadata::new(
                "SEC900",
                "demo",
                lintai_api::Category::Security,
                lintai_api::Severity::Warn,
                lintai_api::Confidence::High,
                lintai_api::RuleTier::Stable,
            ),
            lintai_api::Location::new("SKILL.md", lintai_api::Span::new(0, 4)),
            "demo finding",
        );
        let report = super::ReportEnvelope {
            schema_version: 1,
            tool: ToolMetadata { name: "lintai" },
            config_source: None,
            project_root: None,
            discovered_roots: Vec::new(),
            discovery_stats: None,
            inventory_roots: Vec::new(),
            inventory_stats: None,
            inventory_diff: None,
            stats: ReportStats {
                scanned_files: 1,
                skipped_files: 0,
            },
            findings: std::slice::from_ref(&finding),
            diagnostics: &[],
            runtime_errors: &[],
        };

        let sarif = format_sarif(&report).unwrap();
        assert!(sarif.contains("\"version\": \"2.1.0\""));
        assert!(sarif.contains("\"stableKey\""));
        assert!(sarif.contains("\"ruleId\": \"SEC900\""));
    }

    #[test]
    fn json_output_includes_schema_version() {
        let report = super::ReportEnvelope {
            schema_version: 1,
            tool: ToolMetadata { name: "lintai" },
            config_source: None,
            project_root: None,
            discovered_roots: Vec::new(),
            discovery_stats: None,
            inventory_roots: Vec::new(),
            inventory_stats: None,
            inventory_diff: None,
            stats: ReportStats {
                scanned_files: 0,
                skipped_files: 0,
            },
            findings: &[],
            diagnostics: &[],
            runtime_errors: &[],
        };

        let json = format_json(&report).unwrap();
        assert!(json.contains("\"schema_version\": 1"));
    }

    #[test]
    fn text_output_renders_suggestions_under_findings() {
        let finding = lintai_api::Finding::new(
            &lintai_api::RuleMetadata::new(
                "SEC901",
                "demo",
                lintai_api::Category::Security,
                lintai_api::Severity::Warn,
                lintai_api::Confidence::High,
                lintai_api::RuleTier::Stable,
            ),
            lintai_api::Location::new("SKILL.md", lintai_api::Span::new(0, 4)),
            "demo finding",
        )
        .with_suggestion(lintai_api::Suggestion::new(
            "convert it to inert prose",
            None,
        ));
        let report = super::ReportEnvelope {
            schema_version: 1,
            tool: ToolMetadata { name: "lintai" },
            config_source: None,
            project_root: None,
            discovered_roots: Vec::new(),
            discovery_stats: None,
            inventory_roots: Vec::new(),
            inventory_stats: None,
            inventory_diff: None,
            stats: ReportStats {
                scanned_files: 1,
                skipped_files: 0,
            },
            findings: std::slice::from_ref(&finding),
            diagnostics: &[],
            runtime_errors: &[],
        };

        let text = super::format_text(&report);
        assert!(text.contains("SEC901"));
        assert!(text.contains("  suggest: convert it to inert prose"));
    }

    #[test]
    fn json_output_preserves_suggestion_fix_payload() {
        let finding = lintai_api::Finding::new(
            &lintai_api::RuleMetadata::new(
                "SEC902",
                "demo",
                lintai_api::Category::Security,
                lintai_api::Severity::Warn,
                lintai_api::Confidence::High,
                lintai_api::RuleTier::Stable,
            ),
            lintai_api::Location::new("mcp.json", lintai_api::Span::new(0, 7)),
            "demo finding",
        )
        .with_suggestion(lintai_api::Suggestion::new(
            "upgrade transport",
            Some(lintai_api::Fix::new(
                lintai_api::Span::new(0, 7),
                "https://",
                lintai_api::Applicability::Suggestion,
                Some("rewrite the endpoint to HTTPS".to_owned()),
            )),
        ));
        let report = super::ReportEnvelope {
            schema_version: 1,
            tool: ToolMetadata { name: "lintai" },
            config_source: None,
            project_root: None,
            discovered_roots: Vec::new(),
            discovery_stats: None,
            inventory_roots: Vec::new(),
            inventory_stats: None,
            inventory_diff: None,
            stats: ReportStats {
                scanned_files: 1,
                skipped_files: 0,
            },
            findings: std::slice::from_ref(&finding),
            diagnostics: &[],
            runtime_errors: &[],
        };

        let json = format_json(&report).unwrap();
        assert!(json.contains("\"suggestions\""));
        assert!(json.contains("\"replacement\": \"https://\""));
        assert!(json.contains("\"applicability\": \"suggestion\""));
    }

    #[test]
    fn text_output_renders_provider_execution_metadata() {
        let runtime_error = lintai_engine::ScanRuntimeError {
            normalized_path: "SKILL.md".to_owned(),
            kind: lintai_engine::RuntimeErrorKind::ProviderExecution,
            provider_id: Some("demo-provider".to_owned()),
            phase: Some(lintai_engine::ProviderExecutionPhase::File),
            message: "provider execution failed".to_owned(),
        };
        let report = super::ReportEnvelope {
            schema_version: 1,
            tool: ToolMetadata { name: "lintai" },
            config_source: None,
            project_root: None,
            discovered_roots: Vec::new(),
            discovery_stats: None,
            inventory_roots: Vec::new(),
            inventory_stats: None,
            inventory_diff: None,
            stats: ReportStats {
                scanned_files: 1,
                skipped_files: 0,
            },
            findings: &[],
            diagnostics: &[],
            runtime_errors: std::slice::from_ref(&runtime_error),
        };

        let text = super::format_text(&report);
        assert!(text.contains("error [provider_execution] SKILL.md"));
        assert!(text.contains("provider=demo-provider"));
        assert!(text.contains("phase=file"));
    }

    #[test]
    fn text_output_renders_diagnostics_separately_from_runtime_errors() {
        let diagnostic = lintai_engine::ScanDiagnostic {
            normalized_path: "SKILL.md".to_owned(),
            severity: lintai_engine::DiagnosticSeverity::Warn,
            code: Some("parse_recovery".to_owned()),
            message: "frontmatter was ignored because YAML was invalid".to_owned(),
        };
        let report = super::ReportEnvelope {
            schema_version: 1,
            tool: ToolMetadata { name: "lintai" },
            config_source: None,
            project_root: None,
            discovered_roots: Vec::new(),
            discovery_stats: None,
            inventory_roots: Vec::new(),
            inventory_stats: None,
            inventory_diff: None,
            stats: ReportStats {
                scanned_files: 1,
                skipped_files: 0,
            },
            findings: &[],
            diagnostics: std::slice::from_ref(&diagnostic),
            runtime_errors: &[],
        };

        let text = super::format_text(&report);
        assert!(text.contains("1 diagnostic(s), 0 runtime error(s)"));
        assert!(text.contains("diagnostic [warn] SKILL.md"));
        assert!(!text.contains("error [parse]"));
    }

    #[test]
    fn text_output_renders_known_scan_summary_with_modes() {
        let report = super::ReportEnvelope {
            schema_version: 1,
            tool: ToolMetadata { name: "lintai" },
            config_source: None,
            project_root: None,
            discovered_roots: vec![DiscoveredRoot {
                client: "cursor".to_owned(),
                scope: "global".to_owned(),
                surface: "mcp".to_owned(),
                path: "/tmp/.cursor/mcp.json".to_owned(),
                mode: "lintable".to_owned(),
            }],
            discovery_stats: Some(DiscoveryStats {
                lintable_roots: 1,
                discovered_only_roots: 0,
                supported_artifacts_scanned: 1,
                non_target_files_in_lintable_roots: 2,
                excluded_files: 3,
                binary_files: 0,
                unreadable_files: 1,
                unrecognized_files: 2,
            }),
            inventory_roots: Vec::new(),
            inventory_stats: None,
            inventory_diff: None,
            stats: ReportStats {
                scanned_files: 1,
                skipped_files: 6,
            },
            findings: &[],
            diagnostics: &[],
            runtime_errors: &[],
        };

        let text = super::format_text(&report);
        assert!(text.contains("discovered 1 root(s), lintable 1 root(s)"));
        assert!(text.contains("discovery counters: non_target=2 excluded=3"));
        assert!(text.contains("root [global lintable] cursor mcp /tmp/.cursor/mcp.json"));
    }

    #[test]
    fn text_output_renders_inventory_os_summary_with_risk_levels() {
        let report = super::ReportEnvelope {
            schema_version: 1,
            tool: ToolMetadata { name: "lintai" },
            config_source: None,
            project_root: None,
            discovered_roots: Vec::new(),
            discovery_stats: None,
            inventory_roots: vec![InventoryRoot {
                client: "windsurf".to_owned(),
                surface: "mcp-config".to_owned(),
                path: "/tmp/.codeium/windsurf/mcp_config.json".to_owned(),
                mode: "lintable".to_owned(),
                risk_level: "high".to_owned(),
                provenance: InventoryProvenance {
                    origin_scope: "user".to_owned(),
                    path_type: "file".to_owned(),
                    target_path: None,
                    owner: Some("501".to_owned()),
                    mtime_epoch_s: Some(1),
                },
            }],
            inventory_stats: Some(InventoryStats {
                user_roots: 1,
                system_roots: 0,
                lintable_roots: 1,
                discovered_only_roots: 0,
                high_risk_roots: 1,
                medium_risk_roots: 0,
                low_risk_roots: 0,
                supported_artifacts_scanned: 1,
                non_target_files_in_lintable_roots: 0,
                excluded_files: 0,
                binary_files: 0,
                unreadable_files: 0,
                unrecognized_files: 0,
            }),
            inventory_diff: None,
            stats: ReportStats {
                scanned_files: 1,
                skipped_files: 0,
            },
            findings: &[],
            diagnostics: &[],
            runtime_errors: &[],
        };

        let text = super::format_text(&report);
        assert!(text.contains("inventory discovered 1 root(s), user 1 root(s), system 0 root(s)"));
        assert!(text.contains("high risk 1 root(s)"));
        assert!(text.contains("inventory-root [user high lintable] windsurf mcp-config /tmp/.codeium/windsurf/mcp_config.json"));
    }

    #[test]
    fn text_output_renders_inventory_diff_summary() {
        let finding = lintai_api::Finding::new(
            &lintai_api::RuleMetadata::new(
                "SEC301",
                "demo",
                lintai_api::Category::Security,
                lintai_api::Severity::Warn,
                lintai_api::Confidence::High,
                lintai_api::RuleTier::Stable,
            ),
            lintai_api::Location::new(
                "/tmp/.codeium/windsurf/mcp_config.json",
                lintai_api::Span::new(0, 7),
            ),
            "demo diff finding",
        );
        let report = super::ReportEnvelope {
            schema_version: 1,
            tool: ToolMetadata { name: "lintai" },
            config_source: None,
            project_root: None,
            discovered_roots: Vec::new(),
            discovery_stats: None,
            inventory_roots: vec![InventoryRoot {
                client: "windsurf".to_owned(),
                surface: "mcp-config".to_owned(),
                path: "/tmp/.codeium/windsurf/mcp_config.json".to_owned(),
                mode: "lintable".to_owned(),
                risk_level: "high".to_owned(),
                provenance: InventoryProvenance {
                    origin_scope: "user".to_owned(),
                    path_type: "file".to_owned(),
                    target_path: None,
                    owner: None,
                    mtime_epoch_s: Some(2),
                },
            }],
            inventory_stats: Some(InventoryStats {
                user_roots: 1,
                system_roots: 0,
                lintable_roots: 1,
                discovered_only_roots: 0,
                high_risk_roots: 1,
                medium_risk_roots: 0,
                low_risk_roots: 0,
                supported_artifacts_scanned: 1,
                non_target_files_in_lintable_roots: 0,
                excluded_files: 0,
                binary_files: 0,
                unreadable_files: 0,
                unrecognized_files: 0,
            }),
            inventory_diff: Some(InventoryDiff {
                new_roots: Vec::new(),
                removed_roots: Vec::new(),
                changed_roots: vec![InventoryChangedRoot {
                    client: "windsurf".to_owned(),
                    surface: "mcp-config".to_owned(),
                    path: "/tmp/.codeium/windsurf/mcp_config.json".to_owned(),
                    old_mode: "discovered_only".to_owned(),
                    new_mode: "lintable".to_owned(),
                    old_risk_level: "low".to_owned(),
                    new_risk_level: "high".to_owned(),
                    old_path_type: "file".to_owned(),
                    new_path_type: "file".to_owned(),
                    old_mtime_epoch_s: Some(1),
                    new_mtime_epoch_s: Some(2),
                }],
                new_lintable_roots: Vec::new(),
                risk_increased_roots: Vec::new(),
                new_findings: vec![finding.clone()],
            }),
            stats: ReportStats {
                scanned_files: 1,
                skipped_files: 0,
            },
            findings: std::slice::from_ref(&finding),
            diagnostics: &[],
            runtime_errors: &[],
        };

        let text = super::format_text(&report);
        assert!(text.contains(
            "inventory diff discovered 1 root(s), new 0 root(s), removed 0 root(s), changed 1 root(s)"
        ));
        assert!(text.contains(
            "changed-root [risk low->high mode discovered_only->lintable mtime 1->2] windsurf mcp-config /tmp/.codeium/windsurf/mcp_config.json"
        ));
        assert!(text.contains("new-finding SEC301 windsurf /tmp/.codeium/windsurf/mcp_config.json"));
    }
}
