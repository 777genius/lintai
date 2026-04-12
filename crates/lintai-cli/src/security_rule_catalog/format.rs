use crate::shipped_rules::{
    CatalogDetectionClass, CatalogRemediationSupport, CatalogRuleLifecycle, CatalogSurface,
    PublicLane, RuleScope,
};
use lintai_api::{Category, RuleMetadata, RuleTier};

pub(crate) fn format_scope(scope: RuleScope) -> &'static str {
    match scope {
        RuleScope::PerFile => "per-file",
        RuleScope::Workspace => "workspace",
    }
}

pub(crate) fn format_surface(surface: CatalogSurface) -> &'static str {
    surface.slug()
}

pub(crate) fn format_detection(detection_class: CatalogDetectionClass) -> &'static str {
    match detection_class {
        CatalogDetectionClass::Structural => "structural",
        CatalogDetectionClass::Heuristic => "heuristic",
    }
}

pub(crate) fn format_remediation(
    remediation_support: CatalogRemediationSupport,
) -> &'static str {
    match remediation_support {
        CatalogRemediationSupport::None => "none",
        CatalogRemediationSupport::MessageOnly => "message only",
        CatalogRemediationSupport::Suggestion => "suggestion",
        CatalogRemediationSupport::SafeFix => "safe fix",
    }
}

pub(crate) fn format_public_lane(public_lane: PublicLane) -> &'static str {
    public_lane.slug()
}

pub(crate) fn format_tier(tier: RuleTier) -> &'static str {
    tier.label()
}

pub(crate) fn format_severity(metadata: RuleMetadata) -> &'static str {
    metadata.default_severity.label()
}

pub(crate) fn format_confidence(metadata: RuleMetadata) -> &'static str {
    metadata.default_confidence.label()
}

pub(crate) fn format_category(category: Category) -> &'static str {
    match category {
        Category::Critical => "critical",
        Category::Security => "security",
        Category::Hardening => "hardening",
        Category::Quality => "quality",
        Category::Audit => "audit",
        Category::Nursery => "nursery",
    }
}

pub(crate) fn format_lifecycle(lifecycle: CatalogRuleLifecycle) -> &'static str {
    match lifecycle {
        CatalogRuleLifecycle::Preview { .. } => "preview",
        CatalogRuleLifecycle::Stable { .. } => "stable",
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
