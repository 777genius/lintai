use crate::security_rule_catalog::format::{
    escape_markdown_table_cell, escape_markdown_text, format_bool, format_case_ids,
    format_confidence, format_detection, format_remediation, format_scope, format_severity,
    format_surface, format_tier, render_inline_code,
};
use crate::shipped_rules::{CatalogRuleLifecycle, SecurityRuleCatalogEntry};

pub(super) fn provider_ids(entries: &[SecurityRuleCatalogEntry]) -> Vec<&'static str> {
    let mut provider_ids = Vec::new();
    for entry in entries {
        if !provider_ids.contains(&entry.provider_id) {
            provider_ids.push(entry.provider_id);
        }
    }
    provider_ids
}

pub(super) fn render_provider_summary(
    provider_ids: &[&'static str],
    render_inline_code: fn(&str) -> String,
) -> Vec<String> {
    provider_ids
        .iter()
        .map(|provider_id| format!("- {}", render_inline_code(provider_id)))
        .collect()
}

pub(super) fn render_summary(entries: &[SecurityRuleCatalogEntry]) -> Vec<String> {
    let mut lines = vec![
        String::new(),
        "## Summary".to_owned(),
        String::new(),
        "| Code | Summary | Tier | Lifecycle | Severity | Scope | Surface | Detection | Remediation |".to_owned(),
        "|---|---|---|---|---|---|---|---|---|".to_owned(),
    ];

    let mut summary_entries = entries.to_vec();
    summary_entries.sort_by_key(|entry| entry.metadata.code);
    for entry in summary_entries {
        lines.push(format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            render_inline_code(entry.metadata.code),
            escape_markdown_table_cell(entry.metadata.summary),
            format_tier(entry.metadata.tier),
            render_inline_code(entry.lifecycle_state()),
            format_severity(entry.metadata),
            render_inline_code(format_scope(entry.scope)),
            render_inline_code(format_surface(entry.surface)),
            render_inline_code(format_detection(entry.detection_class)),
            render_inline_code(format_remediation(entry.remediation_support)),
        ));
    }

    lines
}

pub(super) fn render_provider_sections(
    entries: &[SecurityRuleCatalogEntry],
    provider_ids: &[&'static str],
) -> Vec<String> {
    let mut lines = Vec::new();

    for provider_id in provider_ids {
        lines.push(String::new());
        lines.push(format!("## Provider: {}", render_inline_code(provider_id)));

        for entry in entries
            .iter()
            .copied()
            .filter(|entry| entry.provider_id == *provider_id)
        {
            lines.extend(render_detail_section(entry));
        }
    }

    lines
}

fn render_detail_section(entry: SecurityRuleCatalogEntry) -> Vec<String> {
    let mut lines = vec![
        String::new(),
        format!(
            "### {} — {}",
            render_inline_code(entry.metadata.code),
            escape_markdown_text(entry.metadata.summary)
        ),
        String::new(),
        format!("- Provider: {}", render_inline_code(entry.provider_id)),
        format!("- Scope: {}", render_inline_code(format_scope(entry.scope))),
        format!(
            "- Surface: {}",
            render_inline_code(format_surface(entry.surface))
        ),
        format!(
            "- Detection: {}",
            render_inline_code(format_detection(entry.detection_class))
        ),
        format!(
            "- Default Severity: {}",
            render_inline_code(format_severity(entry.metadata))
        ),
        format!(
            "- Default Confidence: {}",
            render_inline_code(format_confidence(entry.metadata))
        ),
        format!(
            "- Tier: {}",
            render_inline_code(format_tier(entry.metadata.tier))
        ),
        format!(
            "- Remediation: {}",
            render_inline_code(format_remediation(entry.remediation_support))
        ),
        format!(
            "- Lifecycle: {}",
            render_inline_code(entry.lifecycle_state())
        ),
    ];

    match entry.lifecycle {
        CatalogRuleLifecycle::Preview {
            blocker,
            promotion_requirements,
        } => {
            lines.push(format!(
                "- Promotion Blocker: {}",
                escape_markdown_text(blocker)
            ));
            lines.push(format!(
                "- Promotion Requirements: {}",
                escape_markdown_text(promotion_requirements)
            ));
        }
        CatalogRuleLifecycle::Stable {
            rationale,
            malicious_case_ids,
            benign_case_ids,
            requires_structured_evidence,
            remediation_reviewed,
            deterministic_signal_basis,
        } => {
            lines.push(format!(
                "- Graduation Rationale: {}",
                escape_markdown_text(rationale)
            ));
            lines.push(format!(
                "- Deterministic Signal Basis: {}",
                escape_markdown_text(deterministic_signal_basis)
            ));
            lines.push(format!(
                "- Malicious Corpus: {}",
                format_case_ids(malicious_case_ids)
            ));
            lines.push(format!(
                "- Benign Corpus: {}",
                format_case_ids(benign_case_ids)
            ));
            lines.push(format!(
                "- Structured Evidence Required: `{}`",
                format_bool(requires_structured_evidence)
            ));
            lines.push(format!(
                "- Remediation Reviewed: `{}`",
                format_bool(remediation_reviewed)
            ));
        }
    }

    lines.push(format!(
        "- Canonical Note: {}",
        escape_markdown_text(entry.canonical_note())
    ));
    lines
}
