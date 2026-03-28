#![allow(dead_code)]

use lintai_ai_security::{
    NativeCatalogDetectionClass, NativeCatalogRemediationSupport, NativeCatalogRuleLifecycle,
    NativeCatalogSurface, native_rule_catalog_entries,
};
use lintai_api::{RuleMetadata, RuleTier};
use lintai_policy::{
    PolicyDetectionClass, PolicyRemediationSupport, PolicyRuleLifecycle, PolicySurface,
    policy_rule_catalog_entries,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuleScope {
    PerFile,
    Workspace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CatalogSurface {
    Markdown,
    Hook,
    Json,
    ClaudeSettings,
    ToolJson,
    ServerJson,
    GithubWorkflow,
    Workspace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CatalogDetectionClass {
    Structural,
    Heuristic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CatalogRuleLifecycle {
    Preview {
        blocker: &'static str,
        promotion_requirements: &'static str,
    },
    Stable {
        rationale: &'static str,
        malicious_case_ids: &'static [&'static str],
        benign_case_ids: &'static [&'static str],
        requires_structured_evidence: bool,
        remediation_reviewed: bool,
        deterministic_signal_basis: &'static str,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CatalogRemediationSupport {
    SafeFix,
    Suggestion,
    MessageOnly,
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SecurityRuleCatalogEntry {
    pub(crate) metadata: RuleMetadata,
    pub(crate) provider_id: &'static str,
    pub(crate) scope: RuleScope,
    pub(crate) surface: CatalogSurface,
    pub(crate) detection_class: CatalogDetectionClass,
    pub(crate) lifecycle: CatalogRuleLifecycle,
    pub(crate) remediation_support: CatalogRemediationSupport,
}

impl SecurityRuleCatalogEntry {
    fn canonical_note(self) -> &'static str {
        if self.metadata.code == "SEC324" {
            return "Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.";
        }
        match (self.detection_class, self.metadata.tier) {
            (CatalogDetectionClass::Heuristic, _) => {
                "Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves."
            }
            (CatalogDetectionClass::Structural, RuleTier::Stable) => {
                "Structural stable rule intended as a high-precision check with deterministic evidence."
            }
            (CatalogDetectionClass::Structural, RuleTier::Preview) => {
                "Structural preview rule; deterministic today, but the preview contract may still evolve."
            }
        }
    }

    fn lifecycle_state(self) -> &'static str {
        match self.lifecycle {
            CatalogRuleLifecycle::Preview { .. } => "preview_blocked",
            CatalogRuleLifecycle::Stable { .. } => "stable_gated",
        }
    }
}

pub(crate) fn security_rule_catalog_entries() -> Vec<SecurityRuleCatalogEntry> {
    let mut entries = Vec::new();
    entries.extend(native_rule_catalog_entries().into_iter().map(|entry| {
        SecurityRuleCatalogEntry {
            metadata: entry.metadata,
            provider_id: entry.provider_id,
            scope: RuleScope::PerFile,
            surface: match entry.surface {
                NativeCatalogSurface::Markdown => CatalogSurface::Markdown,
                NativeCatalogSurface::Hook => CatalogSurface::Hook,
                NativeCatalogSurface::Json => CatalogSurface::Json,
                NativeCatalogSurface::ClaudeSettings => CatalogSurface::ClaudeSettings,
                NativeCatalogSurface::ToolJson => CatalogSurface::ToolJson,
                NativeCatalogSurface::ServerJson => CatalogSurface::ServerJson,
                NativeCatalogSurface::GithubWorkflow => CatalogSurface::GithubWorkflow,
            },
            detection_class: match entry.detection_class {
                NativeCatalogDetectionClass::Structural => CatalogDetectionClass::Structural,
                NativeCatalogDetectionClass::Heuristic => CatalogDetectionClass::Heuristic,
            },
            lifecycle: match entry.lifecycle {
                NativeCatalogRuleLifecycle::Preview {
                    blocker,
                    promotion_requirements,
                } => CatalogRuleLifecycle::Preview {
                    blocker,
                    promotion_requirements,
                },
                NativeCatalogRuleLifecycle::Stable {
                    rationale,
                    malicious_case_ids,
                    benign_case_ids,
                    requires_structured_evidence,
                    remediation_reviewed,
                    deterministic_signal_basis,
                } => CatalogRuleLifecycle::Stable {
                    rationale,
                    malicious_case_ids,
                    benign_case_ids,
                    requires_structured_evidence,
                    remediation_reviewed,
                    deterministic_signal_basis,
                },
            },
            remediation_support: match entry.remediation_support {
                NativeCatalogRemediationSupport::SafeFix => CatalogRemediationSupport::SafeFix,
                NativeCatalogRemediationSupport::Suggestion => {
                    CatalogRemediationSupport::Suggestion
                }
                NativeCatalogRemediationSupport::MessageOnly => {
                    CatalogRemediationSupport::MessageOnly
                }
                NativeCatalogRemediationSupport::None => CatalogRemediationSupport::None,
            },
        }
    }));
    entries.extend(policy_rule_catalog_entries().iter().copied().map(|entry| {
        SecurityRuleCatalogEntry {
            metadata: entry.metadata,
            provider_id: entry.provider_id,
            scope: RuleScope::Workspace,
            surface: match entry.surface {
                PolicySurface::Workspace => CatalogSurface::Workspace,
            },
            detection_class: match entry.detection_class {
                PolicyDetectionClass::Structural => CatalogDetectionClass::Structural,
            },
            lifecycle: match entry.lifecycle {
                PolicyRuleLifecycle::Preview {
                    blocker,
                    promotion_requirements,
                } => CatalogRuleLifecycle::Preview {
                    blocker,
                    promotion_requirements,
                },
            },
            remediation_support: match entry.remediation_support {
                PolicyRemediationSupport::None => CatalogRemediationSupport::None,
            },
        }
    }));
    entries.sort_by_key(|entry| (provider_sort_key(entry.provider_id), entry.metadata.code));
    entries
}

pub(crate) fn render_security_rules_markdown() -> String {
    let entries = security_rule_catalog_entries();
    let native_provider_id = native_rule_catalog_entries()
        .first()
        .map(|entry| entry.provider_id)
        .unwrap_or("lintai-ai-security");
    let policy_provider_id = policy_rule_catalog_entries()
        .first()
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

fn provider_sort_key(provider_id: &str) -> usize {
    match provider_id {
        "lintai-ai-security" => 0,
        "lintai-policy-mismatch" => 1,
        _ => usize::MAX,
    }
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

    use super::{
        CatalogDetectionClass, CatalogRuleLifecycle, render_security_rules_markdown,
        security_rule_catalog_entries,
    };
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
        let entries = security_rule_catalog_entries();
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
        let entries = security_rule_catalog_entries();
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
        expected.sort_by_key(|(provider_id, code)| (super::provider_sort_key(provider_id), *code));
        assert_eq!(actual, expected);
    }

    #[test]
    fn heuristic_entries_remain_preview() {
        for entry in security_rule_catalog_entries() {
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
        for entry in security_rule_catalog_entries() {
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
