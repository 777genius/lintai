use std::sync::OnceLock;

use super::{
    NativeRuleSpec, claude_settings, docker_compose, dockerfile, github_workflow, hooks, json,
    markdown, server_json, tool_json,
};

pub(crate) fn rule_specs() -> &'static [NativeRuleSpec] {
    static RULE_SPECS: OnceLock<Vec<NativeRuleSpec>> = OnceLock::new();

    RULE_SPECS
        .get_or_init(|| {
            let mut specs = Vec::with_capacity(
                markdown::RULE_SPECS.len()
                    + hooks::RULE_SPECS.len()
                    + docker_compose::RULE_SPECS.len()
                    + dockerfile::RULE_SPECS.len()
                    + json::RULE_SPECS.len()
                    + tool_json::RULE_SPECS.len()
                    + server_json::RULE_SPECS.len()
                    + github_workflow::RULE_SPECS.len()
                    + claude_settings::RULE_SPECS.len(),
            );
            specs.extend_from_slice(&markdown::RULE_SPECS);
            specs.extend_from_slice(&hooks::RULE_SPECS);
            specs.extend_from_slice(&docker_compose::RULE_SPECS);
            specs.extend_from_slice(&dockerfile::RULE_SPECS);
            specs.extend_from_slice(&json::RULE_SPECS);
            specs.extend_from_slice(&tool_json::RULE_SPECS);
            specs.extend_from_slice(&server_json::RULE_SPECS);
            specs.extend_from_slice(&github_workflow::RULE_SPECS);
            specs.extend_from_slice(&claude_settings::RULE_SPECS);
            specs
        })
        .as_slice()
}
