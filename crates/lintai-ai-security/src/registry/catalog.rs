use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use super::{
    DetectionClass, NativeRuleSpec, RuleLifecycle, claude_settings, devcontainer, docker_compose,
    dockerfile, github_workflow, hooks, json, markdown, server_json, tool_json,
};
use lintai_api::{RuleTier, builtin_preset_ids};

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
    let known_preset_ids = builtin_preset_ids();
    let mut group_ids = BTreeSet::new();
    for group in rule_spec_groups() {
        assert!(
            group_ids.insert(group.id),
            "duplicate native rule group id {}",
            group.id
        );
        assert!(
            !group.specs.is_empty(),
            "native rule group {} should not be empty",
            group.id
        );
    }

    let mut codes = BTreeSet::new();
    let mut doc_titles = BTreeMap::new();
    for spec in specs {
        assert!(
            codes.insert(spec.metadata.code),
            "duplicate native rule code {}",
            spec.metadata.code
        );
        if let Some(previous_code) = doc_titles.insert(spec.metadata.doc_title, spec.metadata.code)
        {
            panic!(
                "duplicate native rule doc title {:?} used by {} and {}",
                spec.metadata.doc_title, previous_code, spec.metadata.code
            );
        }

        let mut preset_ids = BTreeSet::new();
        for preset_id in spec.default_presets {
            assert!(
                preset_ids.insert(*preset_id),
                "rule {} repeats preset {}",
                spec.metadata.code,
                preset_id
            );
            assert!(
                known_preset_ids.contains(preset_id),
                "rule {} references unknown preset {}",
                spec.metadata.code,
                preset_id
            );
        }

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
                assert_eq!(
                    spec.metadata.tier,
                    RuleTier::Preview,
                    "heuristic rule {} must stay preview",
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
                assert_eq!(
                    spec.metadata.tier,
                    RuleTier::Preview,
                    "structural preview rule {} must stay preview",
                    spec.metadata.code
                );
                assert!(
                    !spec.default_presets.contains(&"base"),
                    "preview-tier rule {} must not ship in the base preset",
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
                if spec.metadata.tier == RuleTier::Stable {
                    assert!(
                        spec.default_presets.contains(&"base") || !spec.default_presets.is_empty(),
                        "stable-tier rule {} should stay reachable through a preset lane",
                        spec.metadata.code
                    );
                }
            }
        }

        if spec.metadata.tier == RuleTier::Stable {
            assert!(
                matches!(spec.lifecycle, RuleLifecycle::Stable { .. }),
                "stable-tier rule {} must declare stable lifecycle",
                spec.metadata.code
            );
        }
    }
}
