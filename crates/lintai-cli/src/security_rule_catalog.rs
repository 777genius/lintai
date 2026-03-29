use crate::shipped_rules::{
    CatalogDetectionClass, CatalogRemediationSupport, CatalogRuleLifecycle, CatalogSurface,
    RuleScope, shipped_security_rule_catalog_entries,
};
use lintai_api::{RuleMetadata, RuleTier};

pub(crate) fn render_security_rules_markdown() -> String {
    let entries = shipped_security_rule_catalog_entries();
    let native_provider_id = entries
        .first()
        .map(|entry| entry.provider_id)
        .unwrap_or("lintai-ai-security");
    let policy_provider_id = entries
        .iter()
        .find(|entry| entry.scope == RuleScope::Workspace)
        .map(|entry| entry.provider_id)
        .unwrap_or("lintai-policy-mismatch");
    let mut lines = vec![
        "# Security Rules Catalog".to_owned(),
        String::new(),
        "> Generated file. Do not edit by hand.".to_owned(),
        "> Source: `lintai-cli` shipped rule inventory aggregated from provider catalogs.".to_owned(),
        String::new(),
        "Canonical catalog for the shipped security rules currently exposed by:".to_owned(),
        format!("- `{native_provider_id}`"),
        format!("- `{policy_provider_id}`"),
        String::new(),
        "## Summary".to_owned(),
        String::new(),
        "| Code | Summary | Tier | Lifecycle | Severity | Scope | Surface | Detection | Remediation |".to_owned(),
        "|---|---|---|---|---|---|---|---|---|".to_owned(),
    ];

    let mut summary_entries = entries.clone();
    summary_entries.sort_by_key(|entry| entry.metadata.code);
    for entry in summary_entries {
        lines.push(format!(
            "| `{}` | {} | {} | `{}` | {} | `{}` | `{}` | `{}` | `{}` |",
            entry.metadata.code,
            entry.metadata.summary,
            format_tier(entry.metadata.tier),
            entry.lifecycle_state(),
            format_severity(entry.metadata),
            format_scope(entry.scope),
            format_surface(entry.surface),
            format_detection(entry.detection_class),
            format_remediation(entry.remediation_support),
        ));
    }

    lines.extend(render_top_priority_section());

    for provider_id in [native_provider_id, policy_provider_id] {
        lines.push(String::new());
        lines.push(format!("## Provider: `{provider_id}`"));

        for entry in entries
            .iter()
            .copied()
            .filter(|entry| entry.provider_id == provider_id)
        {
            lines.push(String::new());
            lines.push(format!(
                "### `{}` — {}",
                entry.metadata.code, entry.metadata.summary
            ));
            lines.push(String::new());
            lines.push(format!("- Provider: `{}`", entry.provider_id));
            lines.push(format!("- Scope: `{}`", format_scope(entry.scope)));
            lines.push(format!("- Surface: `{}`", format_surface(entry.surface)));
            lines.push(format!(
                "- Detection: `{}`",
                format_detection(entry.detection_class)
            ));
            lines.push(format!(
                "- Default Severity: `{}`",
                format_severity(entry.metadata)
            ));
            lines.push(format!(
                "- Default Confidence: `{}`",
                format_confidence(entry.metadata)
            ));
            lines.push(format!("- Tier: `{}`", format_tier(entry.metadata.tier)));
            lines.push(format!(
                "- Remediation: `{}`",
                format_remediation(entry.remediation_support)
            ));
            lines.push(format!("- Lifecycle: `{}`", entry.lifecycle_state()));
            match entry.lifecycle {
                CatalogRuleLifecycle::Preview {
                    blocker,
                    promotion_requirements,
                } => {
                    lines.push(format!("- Promotion Blocker: {}", blocker));
                    lines.push(format!(
                        "- Promotion Requirements: {}",
                        promotion_requirements
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
                    lines.push(format!("- Graduation Rationale: {}", rationale));
                    lines.push(format!(
                        "- Deterministic Signal Basis: {}",
                        deterministic_signal_basis
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
            lines.push(format!("- Canonical Note: {}", entry.canonical_note()));
        }
    }

    lines.push(String::new());
    lines.join("\n")
}

fn render_top_priority_section() -> Vec<String> {
    vec![
        String::new(),
        "## Top-Important AI Security Rules (2026-03-29)".to_owned(),
        String::new(),
        "### Обновлённый top-3 приоритизации".to_owned(),
        String::new(),
        "Если поднимать только три новых AI/MCP/agent-skills правила в ближайший top-3, приоритет должен быть таким:".to_owned(),
        String::new(),
        "| Rank | Rule | Axis | Почему поднимать сейчас | Уверенность | Надёжность |".to_owned(),
        "|---|---|---|---|---:|---:|".to_owned(),
        "| 1 | `SEC:ai-trusted-context-boundary` | Trust boundary | Закрывает базовую ошибку класса agentic systems: tool output, MCP metadata, RAG content и plugin responses не должны становиться system/developer instructions. Это наиболее общий и самый частый confused-deputy/prompt-injection boundary, который бьёт сразу по skills, MCP и plugin surfaces. | `10/10` | `10/10` |".to_owned(),
        "| 2 | `SEC:ai-manifest-integrity` | Manifest integrity | Без проверки подписи, digest/hash pinning и происхождения skill/plugin/tool manifests любой последующий schema- или policy-check можно обойти подменой артефакта до загрузки. Это прямой supply-chain choke point. | `10/10` | `9/10` |".to_owned(),
        "| 3 | `SEC:ai-tool-intent-gate` | Runtime control | На рантайме нужен deny-by-default слой: сверка цели, scope, destructive action policy, cost/rate limits и explicit approval перед tool execution. Это сдерживает blast radius даже когда boundary и manifest уже частично обойдены. | `9/10` | `9/10` |".to_owned(),
        String::new(),
        "### Rationale".to_owned(),
        String::new(),
        "- `SEC:ai-trusted-context-boundary` стоит первым, потому что это первичный барьер между недоверенным контентом и управляющими инструкциями; без него остальные контроли слишком легко обходятся через reinterpretation attack surface.".to_owned(),
        "- `SEC:ai-manifest-integrity` стоит вторым, потому что защищает точку входа артефакта до выполнения: если манифест или descriptor подменён, trust model уже сломана до старта runtime.".to_owned(),
        "- `SEC:ai-tool-intent-gate` стоит третьим, потому что это лучший прикладной runtime control для v0.1/v0.2: он ограничивает реальные действия, а не только их аудит post factum.".to_owned(),
        String::new(),
        "### Почему не `SEC:ai-runtime-provenance` в top-3".to_owned(),
        String::new(),
        "- `SEC:ai-runtime-provenance` важен, но для ближайшего top-3 он слабее как immediate control: provenance и attestation чаще улучшают расследование, доверие и policy enforcement, чем напрямую режут execution blast radius в момент вызова.".to_owned(),
        "- Поэтому оптимальный порядок сейчас: boundary first, artifact integrity second, execution control third; provenance идёт сразу следом как top-4 кандидат. Уверенность: `9/10`, Надёжность: `9/10`.".to_owned(),
    ]
}

fn format_scope(scope: RuleScope) -> &'static str {
    match scope {
        RuleScope::PerFile => "per_file",
        RuleScope::Workspace => "workspace",
    }
}

fn format_surface(surface: CatalogSurface) -> &'static str {
    match surface {
        CatalogSurface::Markdown => "markdown",
        CatalogSurface::Hook => "hook",
        CatalogSurface::Json => "json",
        CatalogSurface::ClaudeSettings => "claude_settings",
        CatalogSurface::ToolJson => "tool_json",
        CatalogSurface::ServerJson => "server_json",
        CatalogSurface::GithubWorkflow => "github_workflow",
        CatalogSurface::Workspace => "workspace",
    }
}

fn format_detection(detection_class: CatalogDetectionClass) -> &'static str {
    match detection_class {
        CatalogDetectionClass::Structural => "structural",
        CatalogDetectionClass::Heuristic => "heuristic",
    }
}

fn format_remediation(remediation_support: CatalogRemediationSupport) -> &'static str {
    match remediation_support {
        CatalogRemediationSupport::SafeFix => "safe_fix",
        CatalogRemediationSupport::Suggestion => "suggestion",
        CatalogRemediationSupport::MessageOnly => "message_only",
        CatalogRemediationSupport::None => "none",
    }
}

fn format_tier(tier: RuleTier) -> &'static str {
    match tier {
        RuleTier::Stable => "Stable",
        RuleTier::Preview => "Preview",
    }
}

fn format_severity(metadata: RuleMetadata) -> &'static str {
    match metadata.default_severity {
        lintai_api::Severity::Deny => "Deny",
        lintai_api::Severity::Warn => "Warn",
        lintai_api::Severity::Allow => "Allow",
    }
}

fn format_confidence(metadata: RuleMetadata) -> &'static str {
    match metadata.default_confidence {
        lintai_api::Confidence::Low => "Low",
        lintai_api::Confidence::Medium => "Medium",
        lintai_api::Confidence::High => "High",
    }
}

fn format_case_ids(case_ids: &[&str]) -> String {
    case_ids
        .iter()
        .map(|case_id| format!("`{case_id}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_bool(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{CatalogDetectionClass, CatalogRuleLifecycle, render_security_rules_markdown};
    use crate::shipped_rules::{provider_sort_key, shipped_security_rule_catalog_entries};
    use lintai_ai_security::{NativeCatalogDetectionClass, native_rule_catalog_entries};
    use lintai_api::RuleTier;
    use lintai_policy::policy_rule_catalog_entries;

    #[test]
    fn catalog_render_matches_checked_in_markdown() {
        let expected = include_str!("../../../docs/SECURITY_RULES.md");
        assert_eq!(render_security_rules_markdown(), expected);
    }

    #[test]
    fn all_shipped_security_rules_are_documented() {
        let entries = shipped_security_rule_catalog_entries();
        let documented_codes: BTreeSet<_> =
            entries.iter().map(|entry| entry.metadata.code).collect();
        let expected_codes: BTreeSet<_> = native_rule_catalog_entries()
            .iter()
            .map(|entry| entry.metadata.code)
            .chain(
                policy_rule_catalog_entries()
                    .iter()
                    .map(|entry| entry.metadata.code),
            )
            .collect();
        assert_eq!(documented_codes, expected_codes);
        assert_eq!(entries.len(), expected_codes.len());
    }

    #[test]
    fn catalog_order_is_stable() {
        let entries = shipped_security_rule_catalog_entries();
        let actual: Vec<_> = entries
            .iter()
            .map(|entry| (entry.provider_id, entry.metadata.code))
            .collect();
        let mut expected: Vec<_> = native_rule_catalog_entries()
            .iter()
            .map(|entry| (entry.provider_id, entry.metadata.code))
            .chain(
                policy_rule_catalog_entries()
                    .iter()
                    .map(|entry| (entry.provider_id, entry.metadata.code)),
            )
            .collect();
        expected.sort_by_key(|(provider_id, code)| (provider_sort_key(provider_id), *code));
        assert_eq!(actual, expected);
    }

    #[test]
    fn heuristic_entries_remain_preview() {
        for entry in shipped_security_rule_catalog_entries() {
            if entry.detection_class == CatalogDetectionClass::Heuristic {
                assert_eq!(entry.metadata.tier, RuleTier::Preview);
            }
        }

        assert!(
            native_rule_catalog_entries()
                .iter()
                .any(|entry| entry.detection_class == NativeCatalogDetectionClass::Heuristic)
        );
    }

    #[test]
    fn stable_entries_have_completed_metadata() {
        for entry in shipped_security_rule_catalog_entries() {
            if entry.metadata.tier != RuleTier::Stable {
                continue;
            }
            match entry.lifecycle {
                CatalogRuleLifecycle::Stable {
                    rationale,
                    malicious_case_ids,
                    benign_case_ids,
                    deterministic_signal_basis,
                    ..
                } => {
                    assert!(!rationale.is_empty());
                    assert!(!malicious_case_ids.is_empty());
                    assert!(!benign_case_ids.is_empty());
                    assert!(!deterministic_signal_basis.is_empty());
                }
                CatalogRuleLifecycle::Preview { .. } => {
                    panic!("stable rule {} has preview lifecycle", entry.metadata.code);
                }
            }
        }
    }
}
