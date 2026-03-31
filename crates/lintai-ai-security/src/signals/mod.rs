use lintai_api::{ScanContext, Span};

use crate::json_locator::JsonLocationMap;

mod claude_settings;
mod github_workflow;
mod hook;
mod json;
mod markdown;
mod server_json;
mod shared;
#[cfg(test)]
mod tests;
mod tool_json;

#[derive(Clone, Debug, Default)]
pub(crate) struct ArtifactSignals {
    markdown: Option<MarkdownSignals>,
    hook: Option<HookSignals>,
    json: Option<JsonSignals>,
    claude_settings: Option<ClaudeSettingsSignals>,
    server_json: Option<ServerJsonSignals>,
    tool_json: Option<ToolJsonSignals>,
    github_workflow: Option<GithubWorkflowSignals>,
    metrics: SignalWorkBudget,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct SignalWorkBudget {
    pub(crate) markdown_regions_visited: usize,
    pub(crate) hook_lines_visited: usize,
    pub(crate) hook_tokens_visited: usize,
    pub(crate) json_values_visited: usize,
    pub(crate) json_locator_builds: usize,
}

impl ArtifactSignals {
    pub(crate) fn from_context(ctx: &ScanContext) -> Self {
        let mut metrics = SignalWorkBudget::default();
        Self {
            markdown: MarkdownSignals::from_context(ctx, &mut metrics),
            hook: HookSignals::from_context(ctx, &mut metrics),
            json: JsonSignals::from_context(ctx, &mut metrics),
            claude_settings: ClaudeSettingsSignals::from_context(ctx, &mut metrics),
            server_json: ServerJsonSignals::from_context(ctx, &mut metrics),
            tool_json: ToolJsonSignals::from_context(ctx, &mut metrics),
            github_workflow: GithubWorkflowSignals::from_context(ctx, &mut metrics),
            metrics,
        }
    }

    pub(crate) fn markdown(&self) -> Option<&MarkdownSignals> {
        self.markdown.as_ref()
    }

    pub(crate) fn hook(&self) -> Option<&HookSignals> {
        self.hook.as_ref()
    }

    pub(crate) fn json(&self) -> Option<&JsonSignals> {
        self.json.as_ref()
    }

    pub(crate) fn claude_settings(&self) -> Option<&ClaudeSettingsSignals> {
        self.claude_settings.as_ref()
    }

    pub(crate) fn server_json(&self) -> Option<&ServerJsonSignals> {
        self.server_json.as_ref()
    }

    pub(crate) fn tool_json(&self) -> Option<&ToolJsonSignals> {
        self.tool_json.as_ref()
    }

    pub(crate) fn github_workflow(&self) -> Option<&GithubWorkflowSignals> {
        self.github_workflow.as_ref()
    }

    pub(crate) fn metrics(&self) -> SignalWorkBudget {
        self.metrics
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct MarkdownSignals {
    pub(crate) directive_comment_spans: Vec<Span>,
    pub(crate) prose_download_exec_spans: Vec<Span>,
    pub(crate) prose_base64_exec_spans: Vec<Span>,
    pub(crate) prose_path_traversal_spans: Vec<Span>,
    pub(crate) comment_download_exec_spans: Vec<Span>,
    pub(crate) private_key_spans: Vec<Span>,
    pub(crate) fenced_pipe_shell_spans: Vec<Span>,
    pub(crate) metadata_service_access_spans: Vec<Span>,
    pub(crate) mutable_mcp_launcher_spans: Vec<Span>,
    pub(crate) mutable_docker_image_spans: Vec<Span>,
    pub(crate) docker_host_escape_spans: Vec<Span>,
    pub(crate) untrusted_instruction_promotion_spans: Vec<Span>,
    pub(crate) approval_bypass_instruction_spans: Vec<Span>,
    pub(crate) unscoped_bash_allowed_tools_spans: Vec<Span>,
    pub(crate) wildcard_tool_access_spans: Vec<Span>,
    pub(crate) plugin_agent_permission_mode_spans: Vec<Span>,
    pub(crate) plugin_agent_hooks_spans: Vec<Span>,
    pub(crate) plugin_agent_mcp_servers_spans: Vec<Span>,
    pub(crate) cursor_rule_always_apply_type_spans: Vec<Span>,
    pub(crate) cursor_rule_globs_type_spans: Vec<Span>,
    pub(crate) cursor_rule_redundant_globs_spans: Vec<Span>,
    pub(crate) cursor_rule_unknown_frontmatter_key_spans: Vec<Span>,
    pub(crate) cursor_rule_missing_description_spans: Vec<Span>,
    pub(crate) copilot_instruction_too_long_spans: Vec<Span>,
    pub(crate) copilot_instruction_missing_apply_to_spans: Vec<Span>,
    pub(crate) copilot_instruction_wrong_suffix_spans: Vec<Span>,
    pub(crate) copilot_instruction_invalid_apply_to_spans: Vec<Span>,
    pub(crate) copilot_instruction_invalid_apply_to_glob_spans: Vec<Span>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct HookSignals {
    pub(crate) non_comment_line_spans: Vec<Span>,
    pub(crate) download_exec_span: Option<Span>,
    pub(crate) secret_exfil_span: Option<Span>,
    pub(crate) plain_http_secret_exfil_span: Option<Span>,
    pub(crate) tls_bypass_span: Option<Span>,
    pub(crate) static_auth_exposure_span: Option<Span>,
    pub(crate) base64_exec_span: Option<Span>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct JsonSignals {
    pub(crate) locator: Option<JsonLocationMap>,
    pub(crate) expanded_mcp_client_variant: bool,
    pub(crate) fixture_like_expanded_mcp_client_variant: bool,
    pub(crate) shell_wrapper_span: Option<Span>,
    pub(crate) mutable_mcp_launcher_span: Option<Span>,
    pub(crate) inline_download_exec_command_span: Option<Span>,
    pub(crate) network_tls_bypass_command_span: Option<Span>,
    pub(crate) mutable_plugin_hook_launcher_span: Option<Span>,
    pub(crate) inline_download_exec_plugin_hook_span: Option<Span>,
    pub(crate) network_tls_bypass_plugin_hook_span: Option<Span>,
    pub(crate) mutable_docker_image_span: Option<Span>,
    pub(crate) mutable_docker_pull_span: Option<Span>,
    pub(crate) sensitive_docker_mount_span: Option<Span>,
    pub(crate) dangerous_docker_flag_span: Option<Span>,
    pub(crate) autoapprove_wildcard_span: Option<Span>,
    pub(crate) autoapprove_tools_true_span: Option<Span>,
    pub(crate) trust_tools_true_span: Option<Span>,
    pub(crate) sandbox_disabled_span: Option<Span>,
    pub(crate) capabilities_wildcard_span: Option<Span>,
    pub(crate) broad_env_file_span: Option<Span>,
    pub(crate) plain_http_endpoint_span: Option<Span>,
    pub(crate) credential_env_passthrough_span: Option<Span>,
    pub(crate) trust_verification_disabled_span: Option<Span>,
    pub(crate) static_auth_exposure_span: Option<Span>,
    pub(crate) hidden_instruction_span: Option<Span>,
    pub(crate) sensitive_env_reference_span: Option<Span>,
    pub(crate) suspicious_remote_endpoint_span: Option<Span>,
    pub(crate) literal_secret_span: Option<Span>,
    pub(crate) dangerous_endpoint_host_span: Option<Span>,
    pub(crate) unsafe_plugin_path_span: Option<Span>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ClaudeSettingsSignals {
    #[allow(dead_code)]
    pub(crate) locator: Option<JsonLocationMap>,
    pub(crate) fixture_like_path: bool,
    pub(crate) insecure_http_hook_url_span: Option<Span>,
    pub(crate) dangerous_http_hook_host_span: Option<Span>,
    pub(crate) bypass_permissions_span: Option<Span>,
    pub(crate) missing_schema_span: Option<Span>,
    pub(crate) missing_hook_timeout_span: Option<Span>,
    pub(crate) invalid_hook_matcher_event_span: Option<Span>,
    pub(crate) missing_required_hook_matcher_span: Option<Span>,
    pub(crate) bash_wildcard_span: Option<Span>,
    pub(crate) webfetch_wildcard_span: Option<Span>,
    pub(crate) write_wildcard_span: Option<Span>,
    pub(crate) read_wildcard_span: Option<Span>,
    pub(crate) edit_wildcard_span: Option<Span>,
    pub(crate) websearch_wildcard_span: Option<Span>,
    pub(crate) unscoped_websearch_span: Option<Span>,
    pub(crate) git_push_permission_span: Option<Span>,
    pub(crate) npx_permission_span: Option<Span>,
    pub(crate) enabled_mcpjson_servers_span: Option<Span>,
    pub(crate) package_install_permission_span: Option<Span>,
    pub(crate) git_add_permission_span: Option<Span>,
    pub(crate) git_clone_permission_span: Option<Span>,
    pub(crate) gh_pr_permission_span: Option<Span>,
    pub(crate) git_fetch_permission_span: Option<Span>,
    pub(crate) git_ls_remote_permission_span: Option<Span>,
    pub(crate) curl_permission_span: Option<Span>,
    pub(crate) wget_permission_span: Option<Span>,
    pub(crate) git_config_permission_span: Option<Span>,
    pub(crate) git_tag_permission_span: Option<Span>,
    pub(crate) git_checkout_permission_span: Option<Span>,
    pub(crate) git_commit_permission_span: Option<Span>,
    pub(crate) git_stash_permission_span: Option<Span>,
    pub(crate) glob_wildcard_span: Option<Span>,
    pub(crate) grep_wildcard_span: Option<Span>,
    pub(crate) home_directory_hook_command_span: Option<Span>,
    pub(crate) external_absolute_hook_command_span: Option<Span>,
    pub(crate) mutable_launcher_span: Option<Span>,
    pub(crate) inline_download_exec_span: Option<Span>,
    pub(crate) network_tls_bypass_span: Option<Span>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ToolJsonSignals {
    #[allow(dead_code)]
    pub(crate) locator: Option<JsonLocationMap>,
    pub(crate) fixture_like_path: bool,
    pub(crate) mcp_missing_machine_field_span: Option<Span>,
    pub(crate) duplicate_mcp_tool_name_span: Option<Span>,
    pub(crate) openai_strict_additional_properties_span: Option<Span>,
    pub(crate) openai_strict_required_span: Option<Span>,
    pub(crate) anthropic_strict_locked_input_schema_span: Option<Span>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ServerJsonSignals {
    pub(crate) locator: Option<JsonLocationMap>,
    pub(crate) insecure_remote_url_span: Option<Span>,
    pub(crate) unresolved_remote_variable_span: Option<Span>,
    pub(crate) literal_auth_header_span: Option<Span>,
    pub(crate) unresolved_header_variable_span: Option<Span>,
    pub(crate) auth_header_policy_mismatch_span: Option<Span>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct GithubWorkflowSignals {
    pub(crate) unpinned_third_party_action_spans: Vec<Span>,
    pub(crate) direct_untrusted_run_interpolation_spans: Vec<Span>,
    pub(crate) pull_request_target_head_checkout_spans: Vec<Span>,
    pub(crate) write_all_permission_spans: Vec<Span>,
    pub(crate) write_capable_third_party_action_spans: Vec<Span>,
}
