use std::path::Path;

use lintai_api::Finding;
use lintai_engine::{
    DiagnosticSeverity, RuntimeErrorKind, ScanDiagnostic, ScanRuntimeError, ScanSummary,
    normalize_path_string,
};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct ReportEnvelope<'a> {
    pub schema_version: u32,
    pub tool: ToolMetadata<'a>,
    pub config_source: Option<String>,
    pub project_root: Option<String>,
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
    ReportEnvelope {
        schema_version: 1,
        tool: ToolMetadata { name: "lintai" },
        config_source: config_source.map(normalize_path_string),
        project_root: project_root.map(normalize_path_string),
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
    output.push_str(&format!(
        "scanned {} file(s), skipped {} file(s), found {} finding(s), {} diagnostic(s), {} runtime error(s)\n",
        report.stats.scanned_files,
        report.stats.skipped_files,
        report.findings.len(),
        report.diagnostics.len(),
        report.runtime_errors.len()
    ));

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

#[cfg(test)]
mod tests {
    use super::{ReportStats, ToolMetadata, format_json, format_sarif};

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
}
