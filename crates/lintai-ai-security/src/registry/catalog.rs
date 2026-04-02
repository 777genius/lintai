use std::sync::OnceLock;

use super::{
    NativeRuleSpec, claude_settings, devcontainer, docker_compose, dockerfile, github_workflow,
    hooks, json, markdown, server_json, tool_json,
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
            specs
        })
        .as_slice()
}
