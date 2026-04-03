use std::sync::OnceLock;

use super::{
    DetectionClass, NativeRuleSpec, RuleLifecycle, claude_settings, devcontainer, docker_compose,
    dockerfile, github_workflow, hooks, json, markdown, server_json, tool_json,
};
use lintai_api::{
    CatalogDetectionClassKind, CatalogLifecycleDetails, CatalogRuleIdentity, validate_group_ids,
    validate_rule_identities, validate_rule_presets, validate_rule_quality_contract,
};

#[derive(Clone, Copy)]
pub(crate) struct RuleSpecGroup {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) id: &'static str,
    pub(crate) specs: &'static [NativeRuleSpec],
}

const RULE_SPEC_GROUPS: &[RuleSpecGroup] = &[
    RuleSpecGroup {
        id: "markdown",
        specs: &markdown::RULE_SPECS,
    },
    RuleSpecGroup {
        id: "hooks",
        specs: &hooks::RULE_SPECS,
    },
    RuleSpecGroup {
        id: "devcontainer",
        specs: &devcontainer::RULE_SPECS,
    },
    RuleSpecGroup {
        id: "docker-compose",
        specs: &docker_compose::RULE_SPECS,
    },
    RuleSpecGroup {
        id: "dockerfile",
        specs: &dockerfile::RULE_SPECS,
    },
    RuleSpecGroup {
        id: "json",
        specs: &json::RULE_SPECS,
    },
    RuleSpecGroup {
        id: "tool-json",
        specs: &tool_json::RULE_SPECS,
    },
    RuleSpecGroup {
        id: "server-json",
        specs: &server_json::RULE_SPECS,
    },
    RuleSpecGroup {
        id: "github-workflow",
        specs: &github_workflow::RULE_SPECS,
    },
    RuleSpecGroup {
        id: "claude-settings",
        specs: &claude_settings::RULE_SPECS,
    },
];

pub(crate) fn rule_spec_groups() -> &'static [RuleSpecGroup] {
    RULE_SPEC_GROUPS
}

pub(crate) fn rule_specs() -> &'static [NativeRuleSpec] {
    static RULE_SPECS: OnceLock<Vec<NativeRuleSpec>> = OnceLock::new();

    RULE_SPECS
        .get_or_init(|| {
            let capacity = rule_spec_groups()
                .iter()
                .map(|group| group.specs.len())
                .sum();
            let mut specs = Vec::with_capacity(capacity);
            for group in rule_spec_groups() {
                specs.extend_from_slice(group.specs);
            }
            validate_rule_specs(&specs);
            specs
        })
        .as_slice()
}

fn validate_rule_specs(specs: &[NativeRuleSpec]) {
    validate_group_ids(
        "native",
        "rule group",
        rule_spec_groups()
            .iter()
            .map(|group| (group.id, group.specs.is_empty())),
    );
    validate_rule_identities(
        "native",
        specs.iter().map(|spec| CatalogRuleIdentity {
            owner: spec.metadata.code,
            code: spec.metadata.code,
            doc_title: spec.metadata.doc_title,
        }),
    );

    for spec in specs {
        validate_rule_presets(
            "native",
            spec.metadata.code,
            spec.default_presets,
            crate::native_catalog::public_lane_for_presets(spec.default_presets),
        );
        validate_rule_quality_contract(
            "native",
            spec.metadata.code,
            spec.metadata.tier,
            match spec.detection_class {
                DetectionClass::Structural => CatalogDetectionClassKind::Structural,
                DetectionClass::Heuristic => CatalogDetectionClassKind::Heuristic,
            },
            match spec.lifecycle {
                RuleLifecycle::Preview {
                    blocker,
                    promotion_requirements,
                } => CatalogLifecycleDetails::Preview {
                    blocker,
                    promotion_requirements,
                },
                RuleLifecycle::Stable {
                    rationale,
                    malicious_case_ids,
                    benign_case_ids,
                    requires_structured_evidence,
                    remediation_reviewed,
                    deterministic_signal_basis,
                } => CatalogLifecycleDetails::Stable {
                    rationale,
                    malicious_case_ids,
                    benign_case_ids,
                    requires_structured_evidence,
                    remediation_reviewed,
                    deterministic_signal_basis,
                },
            },
            match spec.remediation_support() {
                super::RemediationSupport::SafeFix => {
                    lintai_api::CatalogRemediationSupport::SafeFix
                }
                super::RemediationSupport::Suggestion => {
                    lintai_api::CatalogRemediationSupport::Suggestion
                }
                super::RemediationSupport::MessageOnly => {
                    lintai_api::CatalogRemediationSupport::MessageOnly
                }
                super::RemediationSupport::None => lintai_api::CatalogRemediationSupport::None,
            },
            spec.default_presets,
        );

        match (spec.detection_class, spec.lifecycle) {
            (
                DetectionClass::Heuristic,
                RuleLifecycle::Preview {
                    blocker,
                    promotion_requirements,
                },
            ) => {
                assert!(
                    !blocker.is_empty(),
                    "preview heuristic rule {} should declare a blocker",
                    spec.metadata.code
                );
                assert!(
                    !promotion_requirements.is_empty(),
                    "preview heuristic rule {} should declare promotion requirements",
                    spec.metadata.code
                );
            }
            (DetectionClass::Heuristic, RuleLifecycle::Stable { .. }) => {
                panic!(
                    "heuristic rule {} cannot declare stable lifecycle",
                    spec.metadata.code
                );
            }
            (
                DetectionClass::Structural,
                RuleLifecycle::Preview {
                    blocker,
                    promotion_requirements,
                },
            ) => {
                assert!(
                    !blocker.is_empty(),
                    "preview structural rule {} should declare a blocker",
                    spec.metadata.code
                );
                assert!(
                    !promotion_requirements.is_empty(),
                    "preview structural rule {} should declare promotion requirements",
                    spec.metadata.code
                );
            }
            (
                DetectionClass::Structural,
                RuleLifecycle::Stable {
                    rationale,
                    malicious_case_ids,
                    benign_case_ids,
                    deterministic_signal_basis,
                    ..
                },
            ) => {
                assert!(
                    !rationale.is_empty(),
                    "stable structural rule {} should declare rationale",
                    spec.metadata.code
                );
                assert!(
                    !malicious_case_ids.is_empty(),
                    "stable structural rule {} should link malicious corpus",
                    spec.metadata.code
                );
                assert!(
                    !benign_case_ids.is_empty(),
                    "stable structural rule {} should link benign corpus",
                    spec.metadata.code
                );
                assert!(
                    !deterministic_signal_basis.is_empty(),
                    "stable structural rule {} should declare signal basis",
                    spec.metadata.code
                );
                assert!(
                    spec.default_presets.contains(&"base") || !spec.default_presets.is_empty(),
                    "structural stable-lifecycle rule {} should stay reachable through a preset lane",
                    spec.metadata.code
                );
            }
        }
    }
}
