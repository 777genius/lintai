use crate::shipped_rules::{
    CatalogDetectionClass, CatalogRemediationSupport, CatalogSurface, RuleScope,
};
use lintai_api::{RuleMetadata, RuleTier};

pub(super) fn format_scope(scope: RuleScope) -> &'static str {
    scope.slug()
}

pub(super) fn format_surface(surface: CatalogSurface) -> &'static str {
    surface.slug()
}

pub(super) fn format_detection(detection_class: CatalogDetectionClass) -> &'static str {
    detection_class.slug()
}

pub(super) fn format_remediation(remediation_support: CatalogRemediationSupport) -> &'static str {
    remediation_support.slug()
}

pub(super) fn format_tier(tier: RuleTier) -> &'static str {
    tier.label()
}

pub(super) fn format_severity(metadata: RuleMetadata) -> &'static str {
    metadata.default_severity.label()
}

pub(super) fn format_confidence(metadata: RuleMetadata) -> &'static str {
    metadata.default_confidence.label()
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
