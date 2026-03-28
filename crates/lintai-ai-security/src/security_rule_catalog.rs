use lintai_api::{RuleMetadata, RuleTier};

use crate::policy_provider::{
    POLICY_RULE_SPECS, PROVIDER_ID as POLICY_PROVIDER_ID, PolicyRuleSpec,
};
use crate::registry::{
    DetectionClass, PROVIDER_ID as NATIVE_PROVIDER_ID, RemediationSupport, RuleLifecycle, Surface,
    rule_specs,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuleScope {
    PerFile,
    Workspace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SecurityRuleCatalogEntry {
    pub(crate) metadata: RuleMetadata,
    pub(crate) provider_id: &'static str,
    pub(crate) scope: RuleScope,
    pub(crate) surface: Surface,
    pub(crate) detection_class: DetectionClass,
    pub(crate) lifecycle: RuleLifecycle,
    pub(crate) remediation_support: RemediationSupport,
}

impl SecurityRuleCatalogEntry {
    fn canonical_note(self) -> &'static str {
        if self.metadata.code == "SEC324" {
            return "Structural stable rule positioned as a supply-chain hardening control: high-precision and actionable, but not a blanket claim of direct repository compromise.";
        }
        match (self.detection_class, self.metadata.tier) {
            (DetectionClass::Heuristic, _) => {
                "Heuristic preview rule; not a stable contract and may evolve as false-positive tuning improves."
            }
            (DetectionClass::Structural, RuleTier::Stable) => {
                "Structural stable rule intended as a high-precision check with deterministic evidence."
            }
            (DetectionClass::Structural, RuleTier::Preview) => {
                "Structural preview rule; deterministic today, but the preview contract may still evolve."
            }
        }
    }

    fn lifecycle_state(self) -> &'static str {
        match self.lifecycle {
            RuleLifecycle::Preview { .. } => "preview_blocked",
            RuleLifecycle::Stable { .. } => "stable_gated",
        }
    }
}

pub(crate) fn security_rule_catalog_entries() -> Vec<SecurityRuleCatalogEntry> {
    let native_specs = rule_specs();
    let mut entries = Vec::with_capacity(native_specs.len() + POLICY_RULE_SPECS.len());
    entries.extend(native_specs.iter().map(|spec| SecurityRuleCatalogEntry {
        metadata: spec.metadata,
        provider_id: NATIVE_PROVIDER_ID,
        scope: RuleScope::PerFile,
        surface: spec.surface,
        detection_class: spec.detection_class,
        lifecycle: spec.lifecycle,
        remediation_support: spec.remediation_support(),
    }));
    entries.extend(
        POLICY_RULE_SPECS
            .iter()
            .copied()
            .map(policy_rule_catalog_entry),
    );
    entries.sort_by_key(|entry| (provider_sort_key(entry.provider_id), entry.metadata.code));
    entries
}

pub fn render_security_rules_markdown() -> String {
    let entries = security_rule_catalog_entries();
    let mut lines = vec![
        "# Security Rules Catalog".to_owned(),
        String::new(),
        "> Generated file. Do not edit by hand.".to_owned(),
        "> Source: `lintai-ai-security` native rule specs and policy rule specs.".to_owned(),
        String::new(),
        "Canonical catalog for the shipped security rules currently exposed by:".to_owned(),
        format!("- `{NATIVE_PROVIDER_ID}`"),
        format!("- `{POLICY_PROVIDER_ID}`"),
        String::new(),
        "## Summary".to_owned(),
        String::new(),
        "| Code | Summary | Tier | Lifecycle | Severity | Scope | Surface | Detection | Remediation |"
            .to_owned(),
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

    for provider_id in [NATIVE_PROVIDER_ID, POLICY_PROVIDER_ID] {
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
                RuleLifecycle::Preview {
                    blocker,
                    promotion_requirements,
                } => {
                    lines.push(format!("- Promotion Blocker: {}", blocker));
                    lines.push(format!(
                        "- Promotion Requirements: {}",
                        promotion_requirements
                    ));
                }
                RuleLifecycle::Stable {
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

fn policy_rule_catalog_entry(spec: PolicyRuleSpec) -> SecurityRuleCatalogEntry {
    SecurityRuleCatalogEntry {
        metadata: spec.metadata,
        provider_id: POLICY_PROVIDER_ID,
        scope: RuleScope::Workspace,
        surface: spec.surface,
        detection_class: spec.detection_class,
        lifecycle: spec.lifecycle,
        remediation_support: spec.remediation_support,
    }
}

fn provider_sort_key(provider_id: &str) -> usize {
    match provider_id {
        NATIVE_PROVIDER_ID => 0,
        POLICY_PROVIDER_ID => 1,
        _ => usize::MAX,
    }
}

fn format_scope(scope: RuleScope) -> &'static str {
    match scope {
        RuleScope::PerFile => "per_file",
        RuleScope::Workspace => "workspace",
    }
}

fn format_surface(surface: Surface) -> &'static str {
    match surface {
        Surface::Markdown => "markdown",
        Surface::Hook => "hook",
        Surface::Json => "json",
        Surface::ClaudeSettings => "claude_settings",
        Surface::ToolJson => "tool_json",
        Surface::ServerJson => "server_json",
        Surface::GithubWorkflow => "github_workflow",
        Surface::Workspace => "workspace",
    }
}

fn format_detection(detection_class: DetectionClass) -> &'static str {
    match detection_class {
        DetectionClass::Structural => "structural",
        DetectionClass::Heuristic => "heuristic",
    }
}

fn format_remediation(remediation_support: RemediationSupport) -> &'static str {
    match remediation_support {
        RemediationSupport::SafeFix => "safe_fix",
        RemediationSupport::Suggestion => "suggestion",
        RemediationSupport::MessageOnly => "message_only",
        RemediationSupport::None => "none",
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
    use std::path::PathBuf;

    use super::{
        NATIVE_PROVIDER_ID, POLICY_PROVIDER_ID, render_security_rules_markdown,
        security_rule_catalog_entries,
    };
    use crate::policy_provider::POLICY_RULE_SPECS;
    use crate::registry::{DetectionClass, RuleLifecycle, rule_specs};
    use lintai_api::RuleTier;
    use lintai_testing::{CaseManifest, discover_case_dirs};

    #[test]
    fn catalog_render_matches_checked_in_markdown() {
        let expected = include_str!("../../../docs/SECURITY_RULES.md");
        assert_eq!(render_security_rules_markdown(), expected);
    }

    #[test]
    fn all_security_provider_rules_are_documented() {
        let entries = security_rule_catalog_entries();
        let documented_codes: BTreeSet<_> =
            entries.iter().map(|entry| entry.metadata.code).collect();
        let expected_codes: BTreeSet<_> = rule_specs()
            .iter()
            .map(|spec| spec.metadata.code)
            .chain(POLICY_RULE_SPECS.iter().map(|spec| spec.metadata.code))
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
        let mut expected: Vec<_> = rule_specs()
            .iter()
            .map(|spec| (NATIVE_PROVIDER_ID, spec.metadata.code))
            .chain(
                POLICY_RULE_SPECS
                    .iter()
                    .map(|spec| (POLICY_PROVIDER_ID, spec.metadata.code)),
            )
            .collect();
        expected.sort_by_key(|(provider_id, code)| (super::provider_sort_key(provider_id), *code));

        assert_eq!(actual, expected);
    }

    #[test]
    fn catalog_marks_preview_vs_stable_correctly() {
        let entries = security_rule_catalog_entries();

        for entry in entries {
            if entry.detection_class == DetectionClass::Heuristic {
                assert_eq!(entry.metadata.tier, RuleTier::Preview);
            }

            if matches!(
                entry.metadata.code,
                "SEC201"
                    | "SEC202"
                    | "SEC203"
                    | "SEC204"
                    | "SEC205"
                    | "SEC206"
                    | "SEC301"
                    | "SEC302"
                    | "SEC303"
                    | "SEC304"
                    | "SEC305"
                    | "SEC309"
                    | "SEC310"
                    | "SEC311"
                    | "SEC312"
                    | "SEC314"
                    | "SEC315"
                    | "SEC316"
                    | "SEC317"
                    | "SEC318"
                    | "SEC319"
                    | "SEC320"
                    | "SEC321"
                    | "SEC322"
                    | "SEC324"
                    | "SEC329"
                    | "SEC330"
                    | "SEC331"
                    | "SEC337"
                    | "SEC338"
                    | "SEC339"
            ) {
                assert_eq!(entry.metadata.tier, RuleTier::Stable);
                assert_eq!(entry.detection_class, DetectionClass::Structural);
            } else if matches!(entry.metadata.code, "SEC336") {
                assert_eq!(entry.metadata.tier, RuleTier::Preview);
                assert_eq!(entry.detection_class, DetectionClass::Structural);
            }
        }
    }

    #[test]
    fn catalog_includes_lifecycle_state_for_all_rules() {
        let rendered = render_security_rules_markdown();

        for entry in security_rule_catalog_entries() {
            assert!(
                rendered.contains(&format!("- Lifecycle: `{}`", entry.lifecycle_state())),
                "catalog missing lifecycle state for {}",
                entry.metadata.code
            );
        }
    }

    #[test]
    fn stable_rules_have_completed_graduation_checklists() {
        for entry in security_rule_catalog_entries() {
            if entry.metadata.tier != RuleTier::Stable {
                continue;
            }

            match entry.lifecycle {
                RuleLifecycle::Stable {
                    rationale,
                    malicious_case_ids,
                    benign_case_ids,
                    requires_structured_evidence,
                    remediation_reviewed,
                    deterministic_signal_basis,
                } => {
                    assert_eq!(entry.detection_class, DetectionClass::Structural);
                    assert!(
                        !rationale.is_empty(),
                        "{} missing rationale",
                        entry.metadata.code
                    );
                    assert!(
                        !deterministic_signal_basis.is_empty(),
                        "{} missing deterministic signal basis",
                        entry.metadata.code
                    );
                    assert!(
                        !malicious_case_ids.is_empty(),
                        "{} missing malicious corpus proof",
                        entry.metadata.code
                    );
                    assert!(
                        !benign_case_ids.is_empty(),
                        "{} missing benign corpus proof",
                        entry.metadata.code
                    );
                    assert!(requires_structured_evidence);
                    assert!(remediation_reviewed);
                }
                RuleLifecycle::Preview { .. } => {
                    panic!(
                        "stable rule {} must use RuleLifecycle::Stable",
                        entry.metadata.code
                    )
                }
            }
        }
    }

    #[test]
    fn preview_rules_have_explicit_blockers() {
        for entry in security_rule_catalog_entries() {
            if entry.metadata.tier != RuleTier::Preview {
                continue;
            }

            match entry.lifecycle {
                RuleLifecycle::Preview {
                    blocker,
                    promotion_requirements,
                } => {
                    assert!(
                        !blocker.is_empty(),
                        "{} missing blocker",
                        entry.metadata.code
                    );
                    assert!(
                        !promotion_requirements.is_empty(),
                        "{} missing promotion requirements",
                        entry.metadata.code
                    );
                }
                RuleLifecycle::Stable { .. } => {
                    panic!(
                        "preview rule {} must use RuleLifecycle::Preview",
                        entry.metadata.code
                    )
                }
            }
        }
    }

    #[test]
    fn stable_rules_reference_existing_corpus_cases() {
        let corpus_case_ids = all_corpus_case_ids();

        for entry in security_rule_catalog_entries() {
            let RuleLifecycle::Stable {
                malicious_case_ids,
                benign_case_ids,
                ..
            } = entry.lifecycle
            else {
                continue;
            };

            for case_id in malicious_case_ids.iter().chain(benign_case_ids.iter()) {
                assert!(
                    corpus_case_ids.contains(*case_id),
                    "{} references missing corpus case `{}`",
                    entry.metadata.code,
                    case_id
                );
            }
        }
    }

    #[test]
    fn heuristic_rules_cannot_graduate_to_stable() {
        for entry in security_rule_catalog_entries() {
            if entry.detection_class == DetectionClass::Heuristic {
                assert_ne!(
                    entry.metadata.tier,
                    RuleTier::Stable,
                    "heuristic rule {} cannot graduate to Stable",
                    entry.metadata.code
                );
                assert!(matches!(entry.lifecycle, RuleLifecycle::Preview { .. }));
            }
        }
    }

    fn all_corpus_case_ids() -> BTreeSet<String> {
        let mut ids = BTreeSet::new();
        for bucket in ["benign", "malicious"] {
            let root = corpus_root(bucket);
            for case_dir in discover_case_dirs(&root).unwrap() {
                let manifest = CaseManifest::load(&case_dir).unwrap();
                ids.insert(manifest.id);
            }
        }
        ids
    }

    fn corpus_root(bucket: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus")
            .join(bucket)
    }
}
