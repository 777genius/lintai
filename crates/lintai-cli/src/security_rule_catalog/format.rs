use crate::shipped_rules::{
    CatalogDetectionClass, CatalogRemediationSupport, CatalogSurface, RuleScope,
};
use lintai_api::{RuleMetadata, RuleTier};

pub(super) fn format_scope(scope: RuleScope) -> &'static str {
    match scope {
        RuleScope::PerFile => "per_file",
        RuleScope::Workspace => "workspace",
    }
}

pub(super) fn format_surface(surface: CatalogSurface) -> &'static str {
    match surface {
        CatalogSurface::Markdown => "markdown",
        CatalogSurface::Hook => "hook",
        CatalogSurface::DockerCompose => "docker-compose",
        CatalogSurface::Dockerfile => "dockerfile",
        CatalogSurface::Json => "json",
        CatalogSurface::ClaudeSettings => "claude_settings",
        CatalogSurface::ToolJson => "tool_json",
        CatalogSurface::ServerJson => "server_json",
        CatalogSurface::GithubWorkflow => "github_workflow",
        CatalogSurface::Workspace => "workspace",
    }
}

pub(super) fn format_detection(detection_class: CatalogDetectionClass) -> &'static str {
    match detection_class {
        CatalogDetectionClass::Structural => "structural",
        CatalogDetectionClass::Heuristic => "heuristic",
    }
}

pub(super) fn format_remediation(remediation_support: CatalogRemediationSupport) -> &'static str {
    match remediation_support {
        CatalogRemediationSupport::SafeFix => "safe_fix",
        CatalogRemediationSupport::Suggestion => "suggestion",
        CatalogRemediationSupport::MessageOnly => "message_only",
        CatalogRemediationSupport::None => "none",
    }
}

pub(super) fn format_tier(tier: RuleTier) -> &'static str {
    match tier {
        RuleTier::Stable => "Stable",
        RuleTier::Preview => "Preview",
    }
}

pub(super) fn format_severity(metadata: RuleMetadata) -> &'static str {
    match metadata.default_severity {
        lintai_api::Severity::Deny => "Deny",
        lintai_api::Severity::Warn => "Warn",
        lintai_api::Severity::Allow => "Allow",
    }
}

pub(super) fn format_confidence(metadata: RuleMetadata) -> &'static str {
    match metadata.default_confidence {
        lintai_api::Confidence::Low => "Low",
        lintai_api::Confidence::Medium => "Medium",
        lintai_api::Confidence::High => "High",
    }
}

pub(super) fn format_case_ids(case_ids: &[&str]) -> String {
    case_ids
        .iter()
        .map(|case_id| render_inline_code(case_id))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn format_presets(presets: &[&str]) -> String {
    presets
        .iter()
        .map(|preset| render_inline_code(preset))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn format_bool(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

pub(super) fn render_inline_code(text: &str) -> String {
    let normalized = normalize_line_breaks(text, " ");
    let max_backtick_run = normalized
        .chars()
        .fold((0usize, 0usize), |(max_run, current_run), ch| {
            if ch == '`' {
                let next_run = current_run + 1;
                (max_run.max(next_run), next_run)
            } else {
                (max_run, 0)
            }
        })
        .0;
    let fence = "`".repeat(max_backtick_run + 1);
    if normalized.starts_with('`') || normalized.ends_with('`') {
        format!("{fence} {normalized} {fence}")
    } else {
        format!("{fence}{normalized}{fence}")
    }
}

pub(super) fn escape_markdown_table_cell(text: &str) -> String {
    escape_markdown_text(text).replace('|', "\\|")
}

pub(super) fn escape_markdown_text(text: &str) -> String {
    normalize_line_breaks(text, " ")
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn normalize_line_breaks(text: &str, separator: &str) -> String {
    text.replace("\r\n", "\n").replace(['\r', '\n'], separator)
}
