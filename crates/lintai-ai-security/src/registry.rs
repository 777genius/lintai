mod catalog;
mod claude_settings;
mod devcontainer;
mod docker_compose;
mod dockerfile;
mod github_workflow;
mod hooks;
mod json;
mod markdown;
mod metadata;
mod presets;
mod remediation;
mod server_json;
mod tool_json;

#[cfg(test)]
pub(crate) use catalog::rule_spec_groups;
pub(crate) use catalog::rule_specs;
#[allow(unused_imports)]
pub(crate) use metadata::{
    CheckFn, DetectionClass, NativeRuleSpec, PROVIDER_ID, RemediationSupport, RuleLifecycle,
    SafeFixFn, SuggestionFixFn, Surface, preview_native_message_rule_spec,
    stable_native_message_rule_spec,
};
pub(crate) use presets::{
    BASE_CLAUDE_PRESETS, BASE_MCP_PRESETS, BASE_PRESETS, BASE_SKILLS_PRESETS,
    COMPAT_CLAUDE_PRESETS, COMPAT_MCP_PRESETS, GOVERNANCE_MCP_PRESETS, GOVERNANCE_PRESETS,
    GUIDANCE_PRESETS,
    HEURISTIC_PREVIEW_REQUIREMENTS, PREVIEW_MCP_PRESETS, PREVIEW_SKILLS_PRESETS,
    RECOMMENDED_BASE_CLAUDE_PRESETS, RECOMMENDED_BASE_MCP_PRESETS,
    STRUCTURAL_PREVIEW_REQUIREMENTS, SUPPLY_CHAIN_PRESETS,
};
#[allow(unused_imports)]
pub(crate) use remediation::{
    first_download_exec_span, hook_base64_exec_fix, hook_download_exec_fix,
    hook_plain_http_exfil_fix, hook_secret_exfil_fix, https_rewrite_fix, line_span_for_offset,
    markdown_inline_code_fix, remove_hidden_comment_fix, remove_hidden_download_exec_comment_fix,
    replace_line_with_comment_fix,
};
