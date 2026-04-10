use lintai_api::{Category, Confidence, RuleTier, Severity, declare_rule};

use super::*;
use crate::json_rules::{
    check_json_dangerous_endpoint_host, check_json_hidden_instruction, check_json_literal_secret,
    check_json_sensitive_env_reference, check_json_suspicious_remote_endpoint,
    check_json_unsafe_plugin_path, check_mcp_authorized_keys_write,
    check_mcp_autoapprove_bash_unscoped, check_mcp_autoapprove_bash_wildcard,
    check_mcp_autoapprove_bunx, check_mcp_autoapprove_chgrp, check_mcp_autoapprove_chmod,
    check_mcp_autoapprove_chown, check_mcp_autoapprove_crontab, check_mcp_autoapprove_curl,
    check_mcp_autoapprove_edit_unsafe_path, check_mcp_autoapprove_edit_unscoped,
    check_mcp_autoapprove_edit_wildcard, check_mcp_autoapprove_gh_api_delete,
    check_mcp_autoapprove_gh_api_patch, check_mcp_autoapprove_gh_api_post,
    check_mcp_autoapprove_gh_api_put, check_mcp_autoapprove_gh_issue_create,
    check_mcp_autoapprove_gh_pr, check_mcp_autoapprove_gh_release_create,
    check_mcp_autoapprove_gh_release_delete, check_mcp_autoapprove_gh_release_upload,
    check_mcp_autoapprove_gh_repo_create, check_mcp_autoapprove_gh_repo_delete,
    check_mcp_autoapprove_gh_repo_edit, check_mcp_autoapprove_gh_repo_transfer,
    check_mcp_autoapprove_gh_secret_delete, check_mcp_autoapprove_gh_secret_set,
    check_mcp_autoapprove_gh_variable_delete, check_mcp_autoapprove_gh_variable_set,
    check_mcp_autoapprove_gh_workflow_disable, check_mcp_autoapprove_gh_workflow_run,
    check_mcp_autoapprove_git_add, check_mcp_autoapprove_git_am, check_mcp_autoapprove_git_apply,
    check_mcp_autoapprove_git_branch, check_mcp_autoapprove_git_checkout,
    check_mcp_autoapprove_git_cherry_pick, check_mcp_autoapprove_git_clean,
    check_mcp_autoapprove_git_clone, check_mcp_autoapprove_git_commit,
    check_mcp_autoapprove_git_config, check_mcp_autoapprove_git_fetch,
    check_mcp_autoapprove_git_ls_remote, check_mcp_autoapprove_git_merge,
    check_mcp_autoapprove_git_push, check_mcp_autoapprove_git_rebase,
    check_mcp_autoapprove_git_reset, check_mcp_autoapprove_git_restore,
    check_mcp_autoapprove_git_stash, check_mcp_autoapprove_git_tag,
    check_mcp_autoapprove_glob_unsafe_path, check_mcp_autoapprove_glob_unscoped,
    check_mcp_autoapprove_glob_wildcard, check_mcp_autoapprove_grep_unsafe_path,
    check_mcp_autoapprove_grep_unscoped, check_mcp_autoapprove_grep_wildcard,
    check_mcp_autoapprove_launchctl_bootstrap, check_mcp_autoapprove_launchctl_load,
    check_mcp_autoapprove_npm_exec, check_mcp_autoapprove_npx,
    check_mcp_autoapprove_package_install, check_mcp_autoapprove_pipx_run,
    check_mcp_autoapprove_pnpm_dlx, check_mcp_autoapprove_read_unsafe_path,
    check_mcp_autoapprove_read_unscoped, check_mcp_autoapprove_read_wildcard,
    check_mcp_autoapprove_rm, check_mcp_autoapprove_su, check_mcp_autoapprove_sudo,
    check_mcp_autoapprove_systemctl_enable, check_mcp_autoapprove_tools_true,
    check_mcp_autoapprove_uvx, check_mcp_autoapprove_webfetch_raw_githubusercontent,
    check_mcp_autoapprove_webfetch_unscoped, check_mcp_autoapprove_webfetch_wildcard,
    check_mcp_autoapprove_websearch_unscoped, check_mcp_autoapprove_websearch_wildcard,
    check_mcp_autoapprove_wget, check_mcp_autoapprove_wildcard,
    check_mcp_autoapprove_write_unsafe_path, check_mcp_autoapprove_write_unscoped,
    check_mcp_autoapprove_write_wildcard, check_mcp_autoapprove_yarn_dlx, check_mcp_broad_env_file,
    check_mcp_browser_secret_store_access, check_mcp_browser_secret_store_exfil,
    check_mcp_camera_capture, check_mcp_camera_capture_exfil, check_mcp_capabilities_wildcard,
    check_mcp_clipboard_exfil, check_mcp_clipboard_read, check_mcp_credential_env_passthrough,
    check_mcp_cron_persistence, check_mcp_dangerous_docker_flag, check_mcp_environment_dump,
    check_mcp_environment_dump_exfil, check_mcp_inline_download_exec,
    check_mcp_insecure_permission_change, check_mcp_keylogging, check_mcp_keylogging_exfil,
    check_mcp_launchd_registration, check_mcp_linux_capability_manipulation,
    check_mcp_microphone_capture, check_mcp_microphone_capture_exfil,
    check_mcp_mutable_docker_pull, check_mcp_mutable_launcher,
    check_mcp_network_tls_bypass_command, check_mcp_password_file_access,
    check_mcp_plain_http_secret_exfil, check_mcp_root_delete, check_mcp_sandbox_disabled,
    check_mcp_screen_capture, check_mcp_screen_capture_exfil, check_mcp_secret_exfil,
    check_mcp_sensitive_docker_mount, check_mcp_sensitive_file_exfil, check_mcp_setuid_setgid,
    check_mcp_shell_profile_write, check_mcp_shell_wrapper, check_mcp_sudo_args0,
    check_mcp_sudo_command, check_mcp_systemd_service_registration, check_mcp_trust_tools_true,
    check_mcp_unpinned_docker_image, check_mcp_webhook_secret_exfil,
    check_package_manifest_dangerous_lifecycle_script,
    check_package_manifest_direct_url_dependency, check_package_manifest_git_dependency,
    check_package_manifest_unbounded_dependency, check_plain_http_config,
    check_plugin_hook_authorized_keys_write, check_plugin_hook_browser_secret_store_access,
    check_plugin_hook_browser_secret_store_exfil, check_plugin_hook_camera_capture,
    check_plugin_hook_camera_capture_exfil, check_plugin_hook_clipboard_exfil,
    check_plugin_hook_clipboard_read, check_plugin_hook_cron_persistence,
    check_plugin_hook_environment_dump, check_plugin_hook_environment_dump_exfil,
    check_plugin_hook_inline_download_exec, check_plugin_hook_insecure_permission_change,
    check_plugin_hook_keylogging, check_plugin_hook_keylogging_exfil,
    check_plugin_hook_launchd_registration, check_plugin_hook_linux_capability_manipulation,
    check_plugin_hook_microphone_capture, check_plugin_hook_microphone_capture_exfil,
    check_plugin_hook_mutable_launcher, check_plugin_hook_network_tls_bypass,
    check_plugin_hook_password_file_access, check_plugin_hook_plain_http_secret_exfil,
    check_plugin_hook_root_delete, check_plugin_hook_screen_capture,
    check_plugin_hook_screen_capture_exfil, check_plugin_hook_secret_exfil,
    check_plugin_hook_sensitive_file_exfil, check_plugin_hook_setuid_setgid,
    check_plugin_hook_shell_profile_write, check_plugin_hook_systemd_service_registration,
    check_plugin_hook_webhook_secret_exfil, check_static_auth_exposure_config,
    check_trust_verification_disabled_config,
};

declare_rule! {
    pub struct McpShellWrapperRule {
        code: "SEC301",
        summary: "MCP configuration shells out through sh -c or bash -c",
        doc_title: "MCP config: shell trampoline",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PlainHttpConfigRule {
        code: "SEC302",
        summary: "Configuration contains an insecure http:// endpoint",
        doc_title: "Config: insecure HTTP endpoint",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpCredentialEnvPassthroughRule {
        code: "SEC303",
        summary: "MCP configuration passes through credential environment variables",
        doc_title: "MCP config: credential env passthrough",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct TrustVerificationDisabledConfigRule {
        code: "SEC304",
        summary: "Configuration disables TLS or certificate verification",
        doc_title: "Config: TLS verification disabled",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct StaticAuthExposureConfigRule {
        code: "SEC305",
        summary: "Configuration embeds static authentication material in a connection or auth value",
        doc_title: "Config: hardcoded auth material",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct JsonHiddenInstructionRule {
        code: "SEC306",
        summary: "JSON configuration description contains override-style hidden instructions",
        doc_title: "JSON config: hidden override instructions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct JsonSensitiveEnvReferenceRule {
        code: "SEC307",
        summary: "Configuration forwards sensitive environment variable references",
        doc_title: "Config: sensitive env forwarding",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct JsonSuspiciousRemoteEndpointRule {
        code: "SEC308",
        summary: "Configuration points at a suspicious remote endpoint",
        doc_title: "Config: suspicious remote endpoint",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct JsonLiteralSecretRule {
        code: "SEC309",
        summary: "Configuration commits literal secret material in env, auth, or header values",
        doc_title: "Config: literal secrets in config",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct JsonDangerousEndpointHostRule {
        code: "SEC310",
        summary: "Configuration endpoint targets a metadata or private-network host literal",
        doc_title: "Config: metadata or private-network host",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct CursorPluginUnsafePathRule {
        code: "SEC311",
        summary: "Cursor plugin manifest contains an unsafe absolute or parent-traversing path",
        doc_title: "Cursor plugin: unsafe path traversal",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpMutableLauncherRule {
        code: "SEC329",
        summary: "MCP configuration launches tooling through a mutable package runner",
        doc_title: "MCP config: mutable package runner",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpInlineDownloadExecRule {
        code: "SEC330",
        summary: "MCP configuration command downloads remote content and pipes it into a shell",
        doc_title: "MCP config: remote content piped to shell",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpNetworkTlsBypassCommandRule {
        code: "SEC331",
        summary: "MCP configuration command disables TLS verification in a network-capable execution path",
        doc_title: "MCP config: TLS verification disabled",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpBroadEnvFileRule {
        code: "SEC336",
        summary: "Repo-local MCP client config loads a broad dotenv-style envFile",
        doc_title: "MCP client config: broad envFile",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct McpAutoApproveWildcardRule {
        code: "SEC394",
        summary: "MCP configuration auto-approves all tools with `autoApprove: [\"*\"]`",
        doc_title: "MCP config: wildcard auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveBashWildcardRule {
        code: "SEC546",
        summary: "MCP configuration auto-approves blanket shell execution with `autoApprove: [\"Bash(*)\"]`",
        doc_title: "MCP config: Bash(*) auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveCurlRule {
        code: "SEC547",
        summary: "MCP configuration auto-approves `Bash(curl:*)` through `autoApprove`",
        doc_title: "MCP config: curl auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveWgetRule {
        code: "SEC548",
        summary: "MCP configuration auto-approves `Bash(wget:*)` through `autoApprove`",
        doc_title: "MCP config: wget auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveSudoRule {
        code: "SEC549",
        summary: "MCP configuration auto-approves `Bash(sudo:*)` through `autoApprove`",
        doc_title: "MCP config: sudo auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveRmRule {
        code: "SEC550",
        summary: "MCP configuration auto-approves `Bash(rm:*)` through `autoApprove`",
        doc_title: "MCP config: rm auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGitPushRule {
        code: "SEC551",
        summary: "MCP configuration auto-approves `Bash(git push)` through `autoApprove`",
        doc_title: "MCP config: git push auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGhApiPostRule {
        code: "SEC552",
        summary: "MCP configuration auto-approves `Bash(gh api --method POST:*)` through `autoApprove`",
        doc_title: "MCP config: gh api POST auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGitCheckoutRule {
        code: "SEC553",
        summary: "MCP configuration auto-approves `Bash(git checkout:*)` through `autoApprove`",
        doc_title: "MCP config: git checkout auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGitCommitRule {
        code: "SEC554",
        summary: "MCP configuration auto-approves `Bash(git commit:*)` through `autoApprove`",
        doc_title: "MCP config: git commit auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGitResetRule {
        code: "SEC555",
        summary: "MCP configuration auto-approves `Bash(git reset:*)` through `autoApprove`",
        doc_title: "MCP config: git reset auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGitCleanRule {
        code: "SEC556",
        summary: "MCP configuration auto-approves `Bash(git clean:*)` through `autoApprove`",
        doc_title: "MCP config: git clean auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGhApiDeleteRule {
        code: "SEC557",
        summary: "MCP configuration auto-approves `Bash(gh api --method DELETE:*)` through `autoApprove`",
        doc_title: "MCP config: gh api DELETE auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGhApiPatchRule {
        code: "SEC558",
        summary: "MCP configuration auto-approves `Bash(gh api --method PATCH:*)` through `autoApprove`",
        doc_title: "MCP config: gh api PATCH auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGhApiPutRule {
        code: "SEC559",
        summary: "MCP configuration auto-approves `Bash(gh api --method PUT:*)` through `autoApprove`",
        doc_title: "MCP config: gh api PUT auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGhIssueCreateRule {
        code: "SEC560",
        summary: "MCP configuration auto-approves `Bash(gh issue create:*)` through `autoApprove`",
        doc_title: "MCP config: gh issue create auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGhRepoCreateRule {
        code: "SEC561",
        summary: "MCP configuration auto-approves `Bash(gh repo create:*)` through `autoApprove`",
        doc_title: "MCP config: gh repo create auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGhRepoDeleteRule {
        code: "SEC562",
        summary: "MCP configuration auto-approves `Bash(gh repo delete:*)` through `autoApprove`",
        doc_title: "MCP config: gh repo delete auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGhRepoEditRule {
        code: "SEC563",
        summary: "MCP configuration auto-approves `Bash(gh repo edit:*)` through `autoApprove`",
        doc_title: "MCP config: gh repo edit auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGhSecretSetRule {
        code: "SEC564",
        summary: "MCP configuration auto-approves `Bash(gh secret set:*)` through `autoApprove`",
        doc_title: "MCP config: gh secret set auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGhVariableSetRule {
        code: "SEC565",
        summary: "MCP configuration auto-approves `Bash(gh variable set:*)` through `autoApprove`",
        doc_title: "MCP config: gh variable set auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGhWorkflowRunRule {
        code: "SEC566",
        summary: "MCP configuration auto-approves `Bash(gh workflow run:*)` through `autoApprove`",
        doc_title: "MCP config: gh workflow run auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGhSecretDeleteRule {
        code: "SEC579",
        summary: "MCP configuration auto-approves `Bash(gh secret delete:*)` through `autoApprove`",
        doc_title: "MCP config: gh secret delete auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGhVariableDeleteRule {
        code: "SEC580",
        summary: "MCP configuration auto-approves `Bash(gh variable delete:*)` through `autoApprove`",
        doc_title: "MCP config: gh variable delete auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGhWorkflowDisableRule {
        code: "SEC581",
        summary: "MCP configuration auto-approves `Bash(gh workflow disable:*)` through `autoApprove`",
        doc_title: "MCP config: gh workflow disable auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGhRepoTransferRule {
        code: "SEC582",
        summary: "MCP configuration auto-approves `Bash(gh repo transfer:*)` through `autoApprove`",
        doc_title: "MCP config: gh repo transfer auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGhReleaseCreateRule {
        code: "SEC583",
        summary: "MCP configuration auto-approves `Bash(gh release create:*)` through `autoApprove`",
        doc_title: "MCP config: gh release create auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGhReleaseDeleteRule {
        code: "SEC584",
        summary: "MCP configuration auto-approves `Bash(gh release delete:*)` through `autoApprove`",
        doc_title: "MCP config: gh release delete auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGhReleaseUploadRule {
        code: "SEC585",
        summary: "MCP configuration auto-approves `Bash(gh release upload:*)` through `autoApprove`",
        doc_title: "MCP config: gh release upload auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveNpxRule {
        code: "SEC586",
        summary: "MCP configuration auto-approves `Bash(npx ...)` through `autoApprove`",
        doc_title: "MCP config: npx auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveUvxRule {
        code: "SEC587",
        summary: "MCP configuration auto-approves `Bash(uvx ...)` through `autoApprove`",
        doc_title: "MCP config: uvx auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveNpmExecRule {
        code: "SEC588",
        summary: "MCP configuration auto-approves `Bash(npm exec ...)` through `autoApprove`",
        doc_title: "MCP config: npm exec auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveBunxRule {
        code: "SEC589",
        summary: "MCP configuration auto-approves `Bash(bunx ...)` through `autoApprove`",
        doc_title: "MCP config: bunx auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApprovePnpmDlxRule {
        code: "SEC590",
        summary: "MCP configuration auto-approves `Bash(pnpm dlx ...)` through `autoApprove`",
        doc_title: "MCP config: pnpm dlx auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveYarnDlxRule {
        code: "SEC591",
        summary: "MCP configuration auto-approves `Bash(yarn dlx ...)` through `autoApprove`",
        doc_title: "MCP config: yarn dlx auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApprovePipxRunRule {
        code: "SEC592",
        summary: "MCP configuration auto-approves `Bash(pipx run ...)` through `autoApprove`",
        doc_title: "MCP config: pipx run auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApprovePackageInstallRule {
        code: "SEC593",
        summary: "MCP configuration auto-approves package installation commands through `autoApprove`",
        doc_title: "MCP config: package install auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGitCloneRule {
        code: "SEC594",
        summary: "MCP configuration auto-approves `Bash(git clone:*)` through `autoApprove`",
        doc_title: "MCP config: git clone auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGitFetchRule {
        code: "SEC595",
        summary: "MCP configuration auto-approves `Bash(git fetch:*)` through `autoApprove`",
        doc_title: "MCP config: git fetch auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGitLsRemoteRule {
        code: "SEC596",
        summary: "MCP configuration auto-approves `Bash(git ls-remote:*)` through `autoApprove`",
        doc_title: "MCP config: git ls-remote auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGitAddRule {
        code: "SEC597",
        summary: "MCP configuration auto-approves `Bash(git add:*)` through `autoApprove`",
        doc_title: "MCP config: git add auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGitConfigRule {
        code: "SEC598",
        summary: "MCP configuration auto-approves `Bash(git config:*)` through `autoApprove`",
        doc_title: "MCP config: git config auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGitTagRule {
        code: "SEC599",
        summary: "MCP configuration auto-approves `Bash(git tag:*)` through `autoApprove`",
        doc_title: "MCP config: git tag auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGitBranchRule {
        code: "SEC600",
        summary: "MCP configuration auto-approves `Bash(git branch:*)` through `autoApprove`",
        doc_title: "MCP config: git branch auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGhPrRule {
        code: "SEC601",
        summary: "MCP configuration auto-approves `Bash(gh pr:*)` through `autoApprove`",
        doc_title: "MCP config: gh pr auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGitStashRule {
        code: "SEC602",
        summary: "MCP configuration auto-approves `Bash(git stash:*)` through `autoApprove`",
        doc_title: "MCP config: git stash auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGitRestoreRule {
        code: "SEC603",
        summary: "MCP configuration auto-approves `Bash(git restore:*)` through `autoApprove`",
        doc_title: "MCP config: git restore auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGitRebaseRule {
        code: "SEC604",
        summary: "MCP configuration auto-approves `Bash(git rebase:*)` through `autoApprove`",
        doc_title: "MCP config: git rebase auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGitMergeRule {
        code: "SEC605",
        summary: "MCP configuration auto-approves `Bash(git merge:*)` through `autoApprove`",
        doc_title: "MCP config: git merge auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGitCherryPickRule {
        code: "SEC606",
        summary: "MCP configuration auto-approves `Bash(git cherry-pick:*)` through `autoApprove`",
        doc_title: "MCP config: git cherry-pick auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGitApplyRule {
        code: "SEC607",
        summary: "MCP configuration auto-approves `Bash(git apply:*)` through `autoApprove`",
        doc_title: "MCP config: git apply auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGitAmRule {
        code: "SEC608",
        summary: "MCP configuration auto-approves `Bash(git am:*)` through `autoApprove`",
        doc_title: "MCP config: git am auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveCrontabRule {
        code: "SEC609",
        summary: "MCP configuration auto-approves `Bash(crontab:*)` through `autoApprove`",
        doc_title: "MCP config: crontab auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveSystemctlEnableRule {
        code: "SEC610",
        summary: "MCP configuration auto-approves `Bash(systemctl enable:*)` through `autoApprove`",
        doc_title: "MCP config: systemctl enable auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveLaunchctlLoadRule {
        code: "SEC611",
        summary: "MCP configuration auto-approves `Bash(launchctl load:*)` through `autoApprove`",
        doc_title: "MCP config: launchctl load auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveLaunchctlBootstrapRule {
        code: "SEC612",
        summary: "MCP configuration auto-approves `Bash(launchctl bootstrap:*)` through `autoApprove`",
        doc_title: "MCP config: launchctl bootstrap auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveChmodRule {
        code: "SEC613",
        summary: "MCP configuration auto-approves `Bash(chmod:*)` through `autoApprove`",
        doc_title: "MCP config: chmod auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveChownRule {
        code: "SEC614",
        summary: "MCP configuration auto-approves `Bash(chown:*)` through `autoApprove`",
        doc_title: "MCP config: chown auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveChgrpRule {
        code: "SEC615",
        summary: "MCP configuration auto-approves `Bash(chgrp:*)` through `autoApprove`",
        doc_title: "MCP config: chgrp auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveSuRule {
        code: "SEC616",
        summary: "MCP configuration auto-approves `Bash(su:*)` through `autoApprove`",
        doc_title: "MCP config: su auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveWebFetchRawGithubusercontentRule {
        code: "SEC617",
        summary: "MCP configuration auto-approves `WebFetch(domain:raw.githubusercontent.com)` through `autoApprove`",
        doc_title: "MCP config: raw.githubusercontent.com WebFetch auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveBashRule {
        code: "SEC625",
        summary: "MCP configuration auto-approves bare `Bash` through `autoApprove`",
        doc_title: "MCP config: bare Bash auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveReadRule {
        code: "SEC618",
        summary: "MCP configuration auto-approves bare `Read` through `autoApprove`",
        doc_title: "MCP config: bare Read auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveWriteRule {
        code: "SEC619",
        summary: "MCP configuration auto-approves bare `Write` through `autoApprove`",
        doc_title: "MCP config: bare Write auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveEditRule {
        code: "SEC620",
        summary: "MCP configuration auto-approves bare `Edit` through `autoApprove`",
        doc_title: "MCP config: bare Edit auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGlobRule {
        code: "SEC621",
        summary: "MCP configuration auto-approves bare `Glob` through `autoApprove`",
        doc_title: "MCP config: bare Glob auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGrepRule {
        code: "SEC622",
        summary: "MCP configuration auto-approves bare `Grep` through `autoApprove`",
        doc_title: "MCP config: bare Grep auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveWebFetchRule {
        code: "SEC623",
        summary: "MCP configuration auto-approves bare `WebFetch` through `autoApprove`",
        doc_title: "MCP config: bare WebFetch auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveWebSearchRule {
        code: "SEC624",
        summary: "MCP configuration auto-approves bare `WebSearch` through `autoApprove`",
        doc_title: "MCP config: bare WebSearch auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveReadWildcardRule {
        code: "SEC567",
        summary: "MCP configuration auto-approves `Read(*)` through `autoApprove`",
        doc_title: "MCP config: Read wildcard auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveWriteWildcardRule {
        code: "SEC568",
        summary: "MCP configuration auto-approves `Write(*)` through `autoApprove`",
        doc_title: "MCP config: Write wildcard auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveEditWildcardRule {
        code: "SEC569",
        summary: "MCP configuration auto-approves `Edit(*)` through `autoApprove`",
        doc_title: "MCP config: Edit wildcard auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGlobWildcardRule {
        code: "SEC570",
        summary: "MCP configuration auto-approves `Glob(*)` through `autoApprove`",
        doc_title: "MCP config: Glob wildcard auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGrepWildcardRule {
        code: "SEC571",
        summary: "MCP configuration auto-approves `Grep(*)` through `autoApprove`",
        doc_title: "MCP config: Grep wildcard auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveWebFetchWildcardRule {
        code: "SEC572",
        summary: "MCP configuration auto-approves `WebFetch(*)` through `autoApprove`",
        doc_title: "MCP config: WebFetch wildcard auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveWebSearchWildcardRule {
        code: "SEC573",
        summary: "MCP configuration auto-approves `WebSearch(*)` through `autoApprove`",
        doc_title: "MCP config: WebSearch wildcard auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveReadUnsafePathRule {
        code: "SEC574",
        summary: "MCP configuration auto-approves `Read(...)` over an unsafe path through `autoApprove`",
        doc_title: "MCP config: Read unsafe path auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveWriteUnsafePathRule {
        code: "SEC575",
        summary: "MCP configuration auto-approves `Write(...)` over an unsafe path through `autoApprove`",
        doc_title: "MCP config: Write unsafe path auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveEditUnsafePathRule {
        code: "SEC576",
        summary: "MCP configuration auto-approves `Edit(...)` over an unsafe path through `autoApprove`",
        doc_title: "MCP config: Edit unsafe path auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGlobUnsafePathRule {
        code: "SEC577",
        summary: "MCP configuration auto-approves `Glob(...)` over an unsafe path through `autoApprove`",
        doc_title: "MCP config: Glob unsafe path auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveGrepUnsafePathRule {
        code: "SEC578",
        summary: "MCP configuration auto-approves `Grep(...)` over an unsafe path through `autoApprove`",
        doc_title: "MCP config: Grep unsafe path auto-approve",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAutoApproveToolsTrueRule {
        code: "SEC395",
        summary: "MCP configuration auto-approves all tools with `autoApproveTools: true`",
        doc_title: "MCP config: autoApproveTools true",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpTrustToolsTrueRule {
        code: "SEC396",
        summary: "MCP configuration fully trusts tools with `trustTools: true`",
        doc_title: "MCP config: trustTools true",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpSandboxDisabledRule {
        code: "SEC397",
        summary: "MCP configuration disables sandboxing with `sandbox: false` or `disableSandbox: true`",
        doc_title: "MCP config: sandbox disabled",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpCapabilitiesWildcardRule {
        code: "SEC398",
        summary: "MCP configuration grants all capabilities with `capabilities: [\"*\"]` or `capabilities: \"*\"`",
        doc_title: "MCP config: wildcard capabilities",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpSudoCommandRule {
        code: "SEC422",
        summary: "MCP configuration launches the server through `sudo`",
        doc_title: "MCP config: sudo command",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpSudoArgs0Rule {
        code: "SEC446",
        summary: "MCP configuration passes `sudo` as the first launch argument",
        doc_title: "MCP config: sudo first argument",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpUnpinnedDockerImageRule {
        code: "SEC337",
        summary: "MCP configuration launches Docker with an image reference that is not digest-pinned",
        doc_title: "MCP config: Docker image not digest-pinned",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpSensitiveDockerMountRule {
        code: "SEC338",
        summary: "MCP configuration launches Docker with a bind mount of sensitive host material",
        doc_title: "MCP config: sensitive host bind mount",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpDangerousDockerFlagRule {
        code: "SEC339",
        summary: "MCP configuration launches Docker with a host-escape or privileged runtime flag",
        doc_title: "MCP config: privileged Docker flags",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpMutableDockerPullRule {
        code: "SEC346",
        summary: "MCP configuration forces Docker to refresh from a mutable registry source",
        doc_title: "MCP config: mutable registry refresh",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookMutableLauncherRule {
        code: "SEC343",
        summary: "Plugin hook command uses a mutable package launcher",
        doc_title: "Plugin hook: mutable package launcher",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookInlineDownloadExecRule {
        code: "SEC344",
        summary: "Plugin hook command downloads remote content and pipes it into a shell",
        doc_title: "Plugin hook: remote content piped to shell",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookNetworkTlsBypassRule {
        code: "SEC345",
        summary: "Plugin hook command disables TLS verification in a network-capable execution path",
        doc_title: "Plugin hook: TLS verification disabled",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpRootDeleteRule {
        code: "SEC637",
        summary: "MCP configuration command attempts destructive root deletion",
        doc_title: "MCP config: destructive root deletion",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpPasswordFileAccessRule {
        code: "SEC638",
        summary: "MCP configuration command accesses a sensitive system password file",
        doc_title: "MCP config: password file access",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpShellProfileWriteRule {
        code: "SEC639",
        summary: "MCP configuration command writes to a shell profile startup file",
        doc_title: "MCP config: shell profile write",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpAuthorizedKeysWriteRule {
        code: "SEC640",
        summary: "MCP configuration command writes to SSH authorized_keys",
        doc_title: "MCP config: authorized_keys write",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookRootDeleteRule {
        code: "SEC645",
        summary: "Plugin hook command attempts destructive root deletion",
        doc_title: "Plugin hook: destructive root deletion",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookPasswordFileAccessRule {
        code: "SEC646",
        summary: "Plugin hook command accesses a sensitive system password file",
        doc_title: "Plugin hook: password file access",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookShellProfileWriteRule {
        code: "SEC647",
        summary: "Plugin hook command writes to a shell profile startup file",
        doc_title: "Plugin hook: shell profile write",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookAuthorizedKeysWriteRule {
        code: "SEC648",
        summary: "Plugin hook command writes to SSH authorized_keys",
        doc_title: "Plugin hook: authorized_keys write",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpCronPersistenceRule {
        code: "SEC652",
        summary: "MCP configuration command manipulates cron persistence",
        doc_title: "MCP config: cron persistence",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpSystemdServiceRegistrationRule {
        code: "SEC653",
        summary: "MCP configuration command registers a systemd service or unit for persistence",
        doc_title: "MCP config: systemd persistence",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpLaunchdRegistrationRule {
        code: "SEC654",
        summary: "MCP configuration command registers a launchd plist for persistence",
        doc_title: "MCP config: launchd persistence",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookCronPersistenceRule {
        code: "SEC658",
        summary: "Plugin hook command manipulates cron persistence",
        doc_title: "Plugin hook: cron persistence",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookSystemdServiceRegistrationRule {
        code: "SEC659",
        summary: "Plugin hook command registers a systemd service or unit for persistence",
        doc_title: "Plugin hook: systemd persistence",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookLaunchdRegistrationRule {
        code: "SEC660",
        summary: "Plugin hook command registers a launchd plist for persistence",
        doc_title: "Plugin hook: launchd persistence",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpInsecurePermissionChangeRule {
        code: "SEC664",
        summary: "MCP configuration command performs an insecure permission change",
        doc_title: "MCP config: insecure chmod",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpSetuidSetgidRule {
        code: "SEC665",
        summary: "MCP configuration command manipulates setuid or setgid permissions",
        doc_title: "MCP config: setuid or setgid manipulation",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpLinuxCapabilityManipulationRule {
        code: "SEC666",
        summary: "MCP configuration command manipulates Linux capabilities",
        doc_title: "MCP config: Linux capability manipulation",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookInsecurePermissionChangeRule {
        code: "SEC670",
        summary: "Plugin hook command performs an insecure permission change",
        doc_title: "Plugin hook: insecure chmod",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookSetuidSetgidRule {
        code: "SEC671",
        summary: "Plugin hook command manipulates setuid or setgid permissions",
        doc_title: "Plugin hook: setuid or setgid manipulation",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookLinuxCapabilityManipulationRule {
        code: "SEC672",
        summary: "Plugin hook command manipulates Linux capabilities",
        doc_title: "Plugin hook: Linux capability manipulation",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpSecretExfilRule {
        code: "SEC674",
        summary: "MCP configuration command appears to send secret material over the network",
        doc_title: "MCP config: secret exfiltration",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpPlainHttpSecretExfilRule {
        code: "SEC675",
        summary: "MCP configuration command sends secret material to an insecure http:// endpoint",
        doc_title: "MCP config: insecure HTTP secret send",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpWebhookSecretExfilRule {
        code: "SEC676",
        summary: "MCP configuration command posts secret material to a webhook endpoint",
        doc_title: "MCP config: webhook secret exfiltration",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookSecretExfilRule {
        code: "SEC680",
        summary: "Plugin hook command appears to send secret material over the network",
        doc_title: "Plugin hook: secret exfiltration",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookPlainHttpSecretExfilRule {
        code: "SEC681",
        summary: "Plugin hook command sends secret material to an insecure http:// endpoint",
        doc_title: "Plugin hook: insecure HTTP secret send",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookWebhookSecretExfilRule {
        code: "SEC682",
        summary: "Plugin hook command posts secret material to a webhook endpoint",
        doc_title: "Plugin hook: webhook secret exfiltration",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpSensitiveFileExfilRule {
        code: "SEC684",
        summary: "MCP configuration command transfers a sensitive credential file to a remote destination",
        doc_title: "MCP config: sensitive file exfiltration",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookSensitiveFileExfilRule {
        code: "SEC686",
        summary: "Plugin hook command transfers a sensitive credential file to a remote destination",
        doc_title: "Plugin hook: sensitive file exfiltration",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpClipboardReadRule {
        code: "SEC689",
        summary: "MCP configuration command reads local clipboard contents",
        doc_title: "MCP config: clipboard read",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpBrowserSecretStoreAccessRule {
        code: "SEC690",
        summary: "MCP configuration command accesses browser credential or cookie stores",
        doc_title: "MCP config: browser credential store access",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookClipboardReadRule {
        code: "SEC693",
        summary: "Plugin hook command reads local clipboard contents",
        doc_title: "Plugin hook: clipboard read",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookBrowserSecretStoreAccessRule {
        code: "SEC694",
        summary: "Plugin hook command accesses browser credential or cookie stores",
        doc_title: "Plugin hook: browser credential store access",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpClipboardExfilRule {
        code: "SEC697",
        summary: "MCP configuration command exfiltrates clipboard contents over the network",
        doc_title: "MCP config: clipboard exfiltration",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpBrowserSecretStoreExfilRule {
        code: "SEC698",
        summary: "MCP configuration command exfiltrates browser credential or cookie store data",
        doc_title: "MCP config: browser credential store exfiltration",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookClipboardExfilRule {
        code: "SEC701",
        summary: "Plugin hook command exfiltrates clipboard contents over the network",
        doc_title: "Plugin hook: clipboard exfiltration",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookBrowserSecretStoreExfilRule {
        code: "SEC702",
        summary: "Plugin hook command exfiltrates browser credential or cookie store data",
        doc_title: "Plugin hook: browser credential store exfiltration",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpScreenCaptureRule {
        code: "SEC705",
        summary: "MCP configuration command captures a screenshot or desktop image",
        doc_title: "MCP config: screen capture",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpScreenCaptureExfilRule {
        code: "SEC706",
        summary: "MCP configuration command captures and exfiltrates a screenshot or desktop image",
        doc_title: "MCP config: screen capture exfiltration",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookScreenCaptureRule {
        code: "SEC709",
        summary: "Plugin hook command captures a screenshot or desktop image",
        doc_title: "Plugin hook: screen capture",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookScreenCaptureExfilRule {
        code: "SEC710",
        summary: "Plugin hook command captures and exfiltrates a screenshot or desktop image",
        doc_title: "Plugin hook: screen capture exfiltration",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpCameraCaptureRule {
        code: "SEC715",
        summary: "MCP configuration command captures a webcam or camera image",
        doc_title: "MCP config: camera capture",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpMicrophoneCaptureRule {
        code: "SEC716",
        summary: "MCP configuration command captures microphone audio",
        doc_title: "MCP config: microphone capture",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpCameraCaptureExfilRule {
        code: "SEC717",
        summary: "MCP configuration command captures and exfiltrates webcam or camera data",
        doc_title: "MCP config: camera capture exfiltration",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpMicrophoneCaptureExfilRule {
        code: "SEC718",
        summary: "MCP configuration command captures and exfiltrates microphone audio",
        doc_title: "MCP config: microphone capture exfiltration",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookCameraCaptureRule {
        code: "SEC723",
        summary: "Plugin hook command captures a webcam or camera image",
        doc_title: "Plugin hook: camera capture",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookMicrophoneCaptureRule {
        code: "SEC724",
        summary: "Plugin hook command captures microphone audio",
        doc_title: "Plugin hook: microphone capture",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookCameraCaptureExfilRule {
        code: "SEC725",
        summary: "Plugin hook command captures and exfiltrates webcam or camera data",
        doc_title: "Plugin hook: camera capture exfiltration",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookMicrophoneCaptureExfilRule {
        code: "SEC726",
        summary: "Plugin hook command captures and exfiltrates microphone audio",
        doc_title: "Plugin hook: microphone capture exfiltration",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpKeyloggingRule {
        code: "SEC729",
        summary: "MCP configuration command captures keystrokes or keyboard input",
        doc_title: "MCP config: keylogger capture",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpKeyloggingExfilRule {
        code: "SEC730",
        summary: "MCP configuration command captures and exfiltrates keystrokes or keyboard input",
        doc_title: "MCP config: keylogger exfiltration",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookKeyloggingRule {
        code: "SEC733",
        summary: "Plugin hook command captures keystrokes or keyboard input",
        doc_title: "Plugin hook: keylogger capture",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookKeyloggingExfilRule {
        code: "SEC734",
        summary: "Plugin hook command captures and exfiltrates keystrokes or keyboard input",
        doc_title: "Plugin hook: keylogger exfiltration",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpEnvironmentDumpRule {
        code: "SEC737",
        summary: "MCP configuration command dumps environment variables or shell state",
        doc_title: "MCP config: environment dump",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct McpEnvironmentDumpExfilRule {
        code: "SEC738",
        summary: "MCP configuration command dumps and exfiltrates environment variables or shell state",
        doc_title: "MCP config: environment dump exfiltration",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookEnvironmentDumpRule {
        code: "SEC741",
        summary: "Plugin hook command dumps environment variables or shell state",
        doc_title: "Plugin hook: environment dump",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PluginHookEnvironmentDumpExfilRule {
        code: "SEC742",
        summary: "Plugin hook command dumps and exfiltrates environment variables or shell state",
        doc_title: "Plugin hook: environment dump exfiltration",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PackageManifestDangerousLifecycleScriptRule {
        code: "SEC743",
        summary: "package.json defines a dangerous install-time lifecycle script",
        doc_title: "package.json: dangerous lifecycle script",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PackageManifestGitDependencyRule {
        code: "SEC744",
        summary: "package.json installs a dependency from a git or forge shortcut source",
        doc_title: "package.json: git or forge dependency source",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PackageManifestUnboundedDependencyRule {
        code: "SEC745",
        summary: "package.json uses an unbounded dependency version like * or latest",
        doc_title: "package.json: unbounded dependency version",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct PackageManifestDirectUrlDependencyRule {
        code: "SEC753",
        summary: "package.json installs a dependency from a direct archive URL source",
        doc_title: "package.json: direct archive URL dependency source",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

pub(crate) static RULE_SPECS: [NativeRuleSpec; 169] = [
    NativeRuleSpec {
        metadata: McpShellWrapperRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit shell-wrapper command structure in JSON config, whether the shell is the command itself or the first launch argument.",
            malicious_case_ids: &["mcp-shell-wrapper", "mcp-shell-wrapper-args0"],
            benign_case_ids: &["mcp-safe-basic", "mcp-shell-wrapper-args-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command and args structure observation for sh -c or bash -c wrappers, either through `command` or `args[0]`.",
        },
        check: check_mcp_shell_wrapper,
        safe_fix: None,
        suggestion_message: Some(
            "replace the shell wrapper with a direct command and explicit args",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PlainHttpConfigRule::METADATA,
        surface: Surface::Json,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit insecure http:// endpoints in configuration values.",
            malicious_case_ids: &["mcp-plain-http"],
            benign_case_ids: &["mcp-trusted-endpoint-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals precise http:// endpoint span resolution from parsed JSON location map.",
        },
        check: check_plain_http_config,
        safe_fix: None,
        suggestion_message: Some(
            "replace the insecure http:// endpoint with https:// or a local/stdio transport",
        ),
        suggestion_fix: Some(https_rewrite_fix),
    },
    NativeRuleSpec {
        metadata: McpCredentialEnvPassthroughRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit credential env passthrough by key inside configuration env maps.",
            malicious_case_ids: &["mcp-credential-env-passthrough"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals env-map key observation for credential passthrough keys.",
        },
        check: check_mcp_credential_env_passthrough,
        safe_fix: None,
        suggestion_message: Some(
            "remove credential env passthrough and configure secrets only inside the target service",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: TrustVerificationDisabledConfigRule::METADATA,
        surface: Surface::Json,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit TLS or certificate verification disable flags in configuration.",
            malicious_case_ids: &["mcp-trust-verification-disabled"],
            benign_case_ids: &["mcp-trust-verified-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals boolean and key observation for trust-verification disable settings.",
        },
        check: check_trust_verification_disabled_config,
        safe_fix: None,
        suggestion_message: Some(
            "re-enable certificate verification and use trusted HTTPS or local/stdio transport",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: StaticAuthExposureConfigRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches literal static auth material embedded directly in configuration values.",
            malicious_case_ids: &["mcp-static-authorization"],
            benign_case_ids: &["mcp-authorization-placeholder-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals literal authorization or userinfo span extraction excluding dynamic placeholders.",
        },
        check: check_static_auth_exposure_config,
        safe_fix: None,
        suggestion_message: Some(
            "remove embedded credentials from config values and source auth from environment or provider-local secret configuration",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: JsonHiddenInstructionRule::METADATA,
        surface: Surface::Json,
        default_presets: PREVIEW_MCP_PRESETS,
        detection_class: DetectionClass::Heuristic,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Depends on descriptive-field phrase heuristics in JSON text.",
            promotion_requirements: HEURISTIC_PREVIEW_REQUIREMENTS,
        },
        check: check_json_hidden_instruction,
        safe_fix: None,
        suggestion_message: Some(
            "remove override-style instructions from descriptive JSON fields and keep tool or plugin metadata declarative",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: JsonSensitiveEnvReferenceRule::METADATA,
        surface: Surface::Json,
        default_presets: PREVIEW_MCP_PRESETS,
        detection_class: DetectionClass::Heuristic,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Depends on sensitive env-name heuristics in forwarded references.",
            promotion_requirements: HEURISTIC_PREVIEW_REQUIREMENTS,
        },
        check: check_json_sensitive_env_reference,
        safe_fix: None,
        suggestion_message: Some(
            "stop forwarding sensitive env references through config and resolve secrets only inside the target service",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: JsonSuspiciousRemoteEndpointRule::METADATA,
        surface: Surface::Json,
        default_presets: PREVIEW_MCP_PRESETS,
        detection_class: DetectionClass::Heuristic,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Depends on suspicious host-marker heuristics for remote endpoints.",
            promotion_requirements: HEURISTIC_PREVIEW_REQUIREMENTS,
        },
        check: check_json_suspicious_remote_endpoint,
        safe_fix: None,
        suggestion_message: Some(
            "replace the suspicious remote endpoint with a trusted internal, verified, or pinned service endpoint",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: JsonLiteralSecretRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches literal secret material committed into env, header, or auth-like JSON fields.",
            malicious_case_ids: &["mcp-literal-secret-config"],
            benign_case_ids: &["mcp-secret-placeholder-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals literal secret observation over env, header, and auth-like keys excluding dynamic placeholders.",
        },
        check: check_json_literal_secret,
        safe_fix: None,
        suggestion_message: Some(
            "replace committed secret literals with environment or input indirection before shipping the config",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: JsonDangerousEndpointHostRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit metadata-service or private-network host literals in endpoint-like configuration values.",
            malicious_case_ids: &["mcp-metadata-host-literal"],
            benign_case_ids: &["mcp-public-endpoint-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals endpoint-host extraction over URL-like endpoint fields with metadata/private-host classification.",
        },
        check: check_json_dangerous_endpoint_host,
        safe_fix: None,
        suggestion_message: Some(
            "replace metadata or private-network host literals with a trusted public endpoint or local stdio transport",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: CursorPluginUnsafePathRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches absolute or parent-traversing paths in committed Cursor plugin manifest path fields.",
            malicious_case_ids: &["cursor-plugin-unsafe-path"],
            benign_case_ids: &["cursor-plugin-safe-paths"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals plugin-manifest path observation limited to known plugin path fields.",
        },
        check: check_json_unsafe_plugin_path,
        safe_fix: None,
        suggestion_message: Some(
            "keep plugin manifest paths project-relative and inside the plugin root",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpMutableLauncherRule::METADATA,
        surface: Surface::Json,
        default_presets: RECOMMENDED_BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP config command launchers for mutable package-runner forms such as npx, uvx, pnpm dlx, yarn dlx, and pipx run.",
            malicious_case_ids: &["mcp-mutable-launcher"],
            benign_case_ids: &["mcp-pinned-launcher-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command/args analysis over ArtifactKind::McpConfig objects with launcher-specific argument gating.",
        },
        check: check_mcp_mutable_launcher,
        safe_fix: None,
        suggestion_message: Some(
            "replace the mutable launcher with a vendored, pinned, or otherwise reproducible MCP execution path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpInlineDownloadExecRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP config command and args values for explicit curl|shell or wget|shell execution chains.",
            malicious_case_ids: &["mcp-inline-download-exec"],
            benign_case_ids: &["mcp-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command/args string analysis over ArtifactKind::McpConfig objects, limited to explicit download-pipe-shell patterns.",
        },
        check: check_mcp_inline_download_exec,
        safe_fix: None,
        suggestion_message: Some(
            "remove the inline download-and-exec flow from the MCP command and pin or vendor the fetched content instead",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpNetworkTlsBypassCommandRule::METADATA,
        surface: Surface::Json,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP config command and args values for explicit TLS-bypass tokens in a network-capable execution context.",
            malicious_case_ids: &["mcp-command-tls-bypass"],
            benign_case_ids: &["mcp-network-tls-verified-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command/args string analysis over ArtifactKind::McpConfig objects gated by network markers plus TLS-bypass tokens.",
        },
        check: check_mcp_network_tls_bypass_command,
        safe_fix: None,
        suggestion_message: Some(
            "remove TLS-bypass flags or NODE_TLS_REJECT_UNAUTHORIZED=0 from the network-capable MCP command path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpBroadEnvFileRule::METADATA,
        surface: Surface::Json,
        default_presets: PREVIEW_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Broad envFile loading is useful review signal, but whether it is materially risky still depends on repo-local review policy and env contents.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_mcp_broad_env_file,
        safe_fix: None,
        suggestion_message: Some(
            "prefer narrower env injection over broad repo-local .env files for committed MCP client configs",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveWildcardRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit wildcard auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-wildcard"],
            benign_case_ids: &["mcp-autoapprove-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"*\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_wildcard,
        safe_fix: None,
        suggestion_message: Some(
            "remove wildcard auto-approval and explicitly list only narrowly reviewed MCP tools",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveBashWildcardRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit blanket shell auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-bash-wildcard"],
            benign_case_ids: &["mcp-autoapprove-bash-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_bash_wildcard,
        safe_fix: None,
        suggestion_message: Some(
            "remove blanket shell auto-approval and explicitly list only narrowly reviewed MCP tools",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveCurlRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit `curl` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-curl-wget"],
            benign_case_ids: &["mcp-autoapprove-curl-wget-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(curl:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_curl,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `curl` auto-approval and keep network download execution under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveWgetRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit `wget` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-curl-wget"],
            benign_case_ids: &["mcp-autoapprove-curl-wget-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(wget:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_wget,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `wget` auto-approval and keep network download execution under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveSudoRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `sudo` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-sudo-rm"],
            benign_case_ids: &["mcp-autoapprove-sudo-rm-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(sudo:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_sudo,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `sudo` auto-approval and keep privilege escalation under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveRmRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact destructive `rm` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-sudo-rm"],
            benign_case_ids: &["mcp-autoapprove-sudo-rm-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(rm:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_rm,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `rm` auto-approval and keep destructive file deletion under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGitPushRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `git push` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-git-push-gh-api-post"],
            benign_case_ids: &["mcp-autoapprove-git-push-gh-api-post-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(git push)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_git_push,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `git push` auto-approval and keep remote git mutation under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGhApiPostRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact GitHub API POST auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-git-push-gh-api-post"],
            benign_case_ids: &["mcp-autoapprove-git-push-gh-api-post-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(gh api --method POST:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_gh_api_post,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh api --method POST` auto-approval and keep GitHub API mutation under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGitCheckoutRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `git checkout` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-git-destructive-family"],
            benign_case_ids: &["mcp-autoapprove-git-destructive-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(git checkout:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_git_checkout,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `git checkout` auto-approval and keep repo state changes under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGitCommitRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `git commit` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-git-destructive-family"],
            benign_case_ids: &["mcp-autoapprove-git-destructive-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(git commit:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_git_commit,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `git commit` auto-approval and keep local history mutation under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGitResetRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `git reset` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-git-destructive-family"],
            benign_case_ids: &["mcp-autoapprove-git-destructive-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(git reset:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_git_reset,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `git reset` auto-approval and keep destructive history rewrites under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGitCleanRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `git clean` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-git-destructive-family"],
            benign_case_ids: &["mcp-autoapprove-git-destructive-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(git clean:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_git_clean,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `git clean` auto-approval and keep destructive workspace cleanup under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGhApiDeleteRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact GitHub API DELETE auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-gh-api-mutation-family"],
            benign_case_ids: &["mcp-autoapprove-gh-api-mutation-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(gh api --method DELETE:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_gh_api_delete,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh api --method DELETE` auto-approval and keep destructive GitHub API mutations under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGhApiPatchRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact GitHub API PATCH auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-gh-api-mutation-family"],
            benign_case_ids: &["mcp-autoapprove-gh-api-mutation-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(gh api --method PATCH:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_gh_api_patch,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh api --method PATCH` auto-approval and keep GitHub API mutations under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGhApiPutRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact GitHub API PUT auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-gh-api-mutation-family"],
            benign_case_ids: &["mcp-autoapprove-gh-api-mutation-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(gh api --method PUT:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_gh_api_put,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh api --method PUT` auto-approval and keep GitHub API mutations under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGhIssueCreateRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `gh issue create` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-gh-mutation-family"],
            benign_case_ids: &["mcp-autoapprove-gh-mutation-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(gh issue create:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_gh_issue_create,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh issue create` auto-approval and keep GitHub mutation under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGhRepoCreateRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `gh repo create` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-gh-mutation-family"],
            benign_case_ids: &["mcp-autoapprove-gh-mutation-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(gh repo create:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_gh_repo_create,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh repo create` auto-approval and keep repository creation under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGhRepoDeleteRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `gh repo delete` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-gh-mutation-family"],
            benign_case_ids: &["mcp-autoapprove-gh-mutation-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(gh repo delete:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_gh_repo_delete,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh repo delete` auto-approval and keep destructive repository deletion under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGhRepoEditRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `gh repo edit` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-gh-mutation-family"],
            benign_case_ids: &["mcp-autoapprove-gh-mutation-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(gh repo edit:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_gh_repo_edit,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh repo edit` auto-approval and keep repository mutation under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGhSecretSetRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `gh secret set` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-gh-mutation-family"],
            benign_case_ids: &["mcp-autoapprove-gh-mutation-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(gh secret set:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_gh_secret_set,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh secret set` auto-approval and keep secret mutation under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGhVariableSetRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `gh variable set` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-gh-mutation-family"],
            benign_case_ids: &["mcp-autoapprove-gh-mutation-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(gh variable set:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_gh_variable_set,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh variable set` auto-approval and keep variable mutation under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGhWorkflowRunRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `gh workflow run` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-gh-mutation-family"],
            benign_case_ids: &["mcp-autoapprove-gh-mutation-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(gh workflow run:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_gh_workflow_run,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh workflow run` auto-approval and keep workflow dispatch under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGhSecretDeleteRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `gh secret delete` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-gh-delete-family"],
            benign_case_ids: &["mcp-autoapprove-gh-delete-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(gh secret delete:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_gh_secret_delete,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh secret delete` auto-approval and keep secret deletion under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGhVariableDeleteRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `gh variable delete` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-gh-delete-family"],
            benign_case_ids: &["mcp-autoapprove-gh-delete-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(gh variable delete:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_gh_variable_delete,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh variable delete` auto-approval and keep variable deletion under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGhWorkflowDisableRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `gh workflow disable` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-gh-delete-family"],
            benign_case_ids: &["mcp-autoapprove-gh-delete-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(gh workflow disable:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_gh_workflow_disable,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh workflow disable` auto-approval and keep workflow disabling under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGhRepoTransferRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `gh repo transfer` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-gh-release-transfer-family"],
            benign_case_ids: &["mcp-autoapprove-gh-release-transfer-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(gh repo transfer:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_gh_repo_transfer,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh repo transfer` auto-approval and keep repository transfer under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGhReleaseCreateRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `gh release create` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-gh-release-transfer-family"],
            benign_case_ids: &["mcp-autoapprove-gh-release-transfer-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(gh release create:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_gh_release_create,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh release create` auto-approval and keep release publishing under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGhReleaseDeleteRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `gh release delete` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-gh-release-transfer-family"],
            benign_case_ids: &["mcp-autoapprove-gh-release-transfer-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(gh release delete:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_gh_release_delete,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh release delete` auto-approval and keep release deletion under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGhReleaseUploadRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `gh release upload` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-gh-release-transfer-family"],
            benign_case_ids: &["mcp-autoapprove-gh-release-transfer-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(gh release upload:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_gh_release_upload,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh release upload` auto-approval and keep release asset mutation under explicit user review",
        ),
        suggestion_fix: None,
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveNpxRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact `Bash(npx ...)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-mutable-runner-family"],
        benign_case_ids: &["mcp-autoapprove-mutable-runner-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item prefix detection for `autoApprove` entries starting with `Bash(npx ` on parsed MCP configuration.",
        check: check_mcp_autoapprove_npx,
        suggestion_message: "remove shared `npx` auto-approval and keep mutable package execution under explicit user review",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveUvxRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact `Bash(uvx ...)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-mutable-runner-family"],
        benign_case_ids: &["mcp-autoapprove-mutable-runner-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item prefix detection for `autoApprove` entries starting with `Bash(uvx ` on parsed MCP configuration.",
        check: check_mcp_autoapprove_uvx,
        suggestion_message: "remove shared `uvx` auto-approval and keep mutable package execution under explicit user review",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveNpmExecRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact `Bash(npm exec ...)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-mutable-runner-family"],
        benign_case_ids: &["mcp-autoapprove-mutable-runner-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item prefix detection for `autoApprove` entries starting with `Bash(npm exec ` on parsed MCP configuration.",
        check: check_mcp_autoapprove_npm_exec,
        suggestion_message: "remove shared `npm exec` auto-approval and keep mutable package execution under explicit user review",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveBunxRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact `Bash(bunx ...)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-mutable-runner-family"],
        benign_case_ids: &["mcp-autoapprove-mutable-runner-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item prefix detection for `autoApprove` entries starting with `Bash(bunx ` on parsed MCP configuration.",
        check: check_mcp_autoapprove_bunx,
        suggestion_message: "remove shared `bunx` auto-approval and keep mutable package execution under explicit user review",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApprovePnpmDlxRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact `Bash(pnpm dlx ...)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-mutable-runner-family"],
        benign_case_ids: &["mcp-autoapprove-mutable-runner-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item prefix detection for `autoApprove` entries starting with `Bash(pnpm dlx ` on parsed MCP configuration.",
        check: check_mcp_autoapprove_pnpm_dlx,
        suggestion_message: "remove shared `pnpm dlx` auto-approval and keep mutable package execution under explicit user review",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveYarnDlxRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact `Bash(yarn dlx ...)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-mutable-runner-family"],
        benign_case_ids: &["mcp-autoapprove-mutable-runner-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item prefix detection for `autoApprove` entries starting with `Bash(yarn dlx ` on parsed MCP configuration.",
        check: check_mcp_autoapprove_yarn_dlx,
        suggestion_message: "remove shared `yarn dlx` auto-approval and keep mutable package execution under explicit user review",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApprovePipxRunRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact `Bash(pipx run ...)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-mutable-runner-family"],
        benign_case_ids: &["mcp-autoapprove-mutable-runner-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item prefix detection for `autoApprove` entries starting with `Bash(pipx run ` on parsed MCP configuration.",
        check: check_mcp_autoapprove_pipx_run,
        suggestion_message: "remove shared `pipx run` auto-approval and keep mutable package execution under explicit user review",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApprovePackageInstallRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact package installation auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-package-install-family"],
        benign_case_ids: &["mcp-autoapprove-package-install-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for package installation entries such as `Bash(pip install)` and `Bash(npm install)` inside `autoApprove` on parsed MCP configuration.",
        check: check_mcp_autoapprove_package_install,
        suggestion_message: "remove shared package installation auto-approval and keep dependency installation under explicit user review",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveGitCloneRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact `Bash(git clone:*)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-repo-fetch-family"],
        benign_case_ids: &["mcp-autoapprove-repo-fetch-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(git clone:*)\"]` on parsed MCP configuration.",
        check: check_mcp_autoapprove_git_clone,
        suggestion_message: "remove shared `git clone` auto-approval and keep repository fetches under explicit user review",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveGitFetchRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact `Bash(git fetch:*)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-repo-fetch-family"],
        benign_case_ids: &["mcp-autoapprove-repo-fetch-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(git fetch:*)\"]` on parsed MCP configuration.",
        check: check_mcp_autoapprove_git_fetch,
        suggestion_message: "remove shared `git fetch` auto-approval and keep repository synchronization under explicit user review",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveGitLsRemoteRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact `Bash(git ls-remote:*)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-repo-fetch-family"],
        benign_case_ids: &["mcp-autoapprove-repo-fetch-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(git ls-remote:*)\"]` on parsed MCP configuration.",
        check: check_mcp_autoapprove_git_ls_remote,
        suggestion_message: "remove shared `git ls-remote` auto-approval and keep remote repository inspection under explicit user review",
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGitAddRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `Bash(git add:*)` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-repo-management-family"],
            benign_case_ids: &["mcp-autoapprove-repo-management-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(git add:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_git_add,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `git add` auto-approval and keep staging authority under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGitConfigRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `Bash(git config:*)` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-repo-management-family"],
            benign_case_ids: &["mcp-autoapprove-repo-management-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(git config:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_git_config,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `git config` auto-approval and keep repository configuration changes under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGitTagRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `Bash(git tag:*)` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-repo-management-family"],
            benign_case_ids: &["mcp-autoapprove-repo-management-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(git tag:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_git_tag,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `git tag` auto-approval and keep repository release markers under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGitBranchRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `Bash(git branch:*)` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-repo-management-family"],
            benign_case_ids: &["mcp-autoapprove-repo-management-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(git branch:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_git_branch,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `git branch` auto-approval and keep branch mutation under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGhPrRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `Bash(gh pr:*)` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-repo-management-family"],
            benign_case_ids: &["mcp-autoapprove-repo-management-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(gh pr:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_gh_pr,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh pr` auto-approval and keep pull-request mutation authority under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGitStashRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `Bash(git stash:*)` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-git-history-family"],
            benign_case_ids: &["mcp-autoapprove-git-history-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(git stash:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_git_stash,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `git stash` auto-approval and keep workspace state shelving under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGitRestoreRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `Bash(git restore:*)` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-git-history-family"],
            benign_case_ids: &["mcp-autoapprove-git-history-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(git restore:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_git_restore,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `git restore` auto-approval and keep working tree rollback under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGitRebaseRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `Bash(git rebase:*)` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-git-history-family"],
            benign_case_ids: &["mcp-autoapprove-git-history-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(git rebase:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_git_rebase,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `git rebase` auto-approval and keep history rewriting under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGitMergeRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `Bash(git merge:*)` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-git-history-family"],
            benign_case_ids: &["mcp-autoapprove-git-history-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(git merge:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_git_merge,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `git merge` auto-approval and keep history mutation under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGitCherryPickRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `Bash(git cherry-pick:*)` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-git-history-family"],
            benign_case_ids: &["mcp-autoapprove-git-history-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(git cherry-pick:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_git_cherry_pick,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `git cherry-pick` auto-approval and keep commit replay under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGitApplyRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `Bash(git apply:*)` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-git-history-family"],
            benign_case_ids: &["mcp-autoapprove-git-history-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(git apply:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_git_apply,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `git apply` auto-approval and keep patch application under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveGitAmRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `Bash(git am:*)` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-git-history-family"],
            benign_case_ids: &["mcp-autoapprove-git-history-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(git am:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_git_am,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `git am` auto-approval and keep mailbox patch application under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveCrontabRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `Bash(crontab:*)` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-persistence-family"],
            benign_case_ids: &["mcp-autoapprove-persistence-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(crontab:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_crontab,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `crontab` auto-approval and keep scheduled task persistence under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveSystemctlEnableRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `Bash(systemctl enable:*)` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-persistence-family"],
            benign_case_ids: &["mcp-autoapprove-persistence-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(systemctl enable:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_systemctl_enable,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `systemctl enable` auto-approval and keep service persistence under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveLaunchctlLoadRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `Bash(launchctl load:*)` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-persistence-family"],
            benign_case_ids: &["mcp-autoapprove-persistence-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(launchctl load:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_launchctl_load,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `launchctl load` auto-approval and keep launchd job persistence under explicit user review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAutoApproveLaunchctlBootstrapRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact `Bash(launchctl bootstrap:*)` auto-approval in MCP client config.",
            malicious_case_ids: &["mcp-autoapprove-persistence-family"],
            benign_case_ids: &["mcp-autoapprove-persistence-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(launchctl bootstrap:*)\"]` on parsed MCP configuration.",
        },
        check: check_mcp_autoapprove_launchctl_bootstrap,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `launchctl bootstrap` auto-approval and keep launchd bootstrap authority under explicit user review",
        ),
        suggestion_fix: None,
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveChmodRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact `Bash(chmod:*)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-privileged-shell-family"],
        benign_case_ids: &["mcp-autoapprove-privileged-shell-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(chmod:*)\"]` on parsed MCP configuration.",
        check: check_mcp_autoapprove_chmod,
        suggestion_message: "remove shared `chmod` auto-approval and keep permission mutation under explicit user review",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveChownRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact `Bash(chown:*)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-privileged-shell-family"],
        benign_case_ids: &["mcp-autoapprove-privileged-shell-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(chown:*)\"]` on parsed MCP configuration.",
        check: check_mcp_autoapprove_chown,
        suggestion_message: "remove shared `chown` auto-approval and keep ownership mutation under explicit user review",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveChgrpRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact `Bash(chgrp:*)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-privileged-shell-family"],
        benign_case_ids: &["mcp-autoapprove-privileged-shell-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(chgrp:*)\"]` on parsed MCP configuration.",
        check: check_mcp_autoapprove_chgrp,
        suggestion_message: "remove shared `chgrp` auto-approval and keep group-ownership mutation under explicit user review",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveSuRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact `Bash(su:*)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-privileged-shell-family"],
        benign_case_ids: &["mcp-autoapprove-privileged-shell-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash(su:*)\"]` on parsed MCP configuration.",
        check: check_mcp_autoapprove_su,
        suggestion_message: "remove shared `su` auto-approval and keep user-switching authority under explicit user review",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveWebFetchRawGithubusercontentRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact raw GitHub WebFetch auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-webfetch-raw-github"],
        benign_case_ids: &["mcp-autoapprove-webfetch-raw-github-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"WebFetch(domain:raw.githubusercontent.com)\"]` on parsed MCP configuration.",
        check: check_mcp_autoapprove_webfetch_raw_githubusercontent,
        suggestion_message: "remove shared raw GitHub WebFetch auto-approval and keep mutable remote raw-content fetch under explicit user review",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveReadWildcardRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches explicit `Read(*)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-wildcard-tool-family"],
        benign_case_ids: &["mcp-autoapprove-wildcard-tool-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Read(*)\"]` on parsed MCP configuration.",
        check: check_mcp_autoapprove_read_wildcard,
        suggestion_message: "remove shared `Read(*)` auto-approval and keep broad file reading under narrower reviewed scopes",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveWriteWildcardRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches explicit `Write(*)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-wildcard-tool-family"],
        benign_case_ids: &["mcp-autoapprove-wildcard-tool-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Write(*)\"]` on parsed MCP configuration.",
        check: check_mcp_autoapprove_write_wildcard,
        suggestion_message: "remove shared `Write(*)` auto-approval and keep broad file mutation under narrower reviewed scopes",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveEditWildcardRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches explicit `Edit(*)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-wildcard-tool-family"],
        benign_case_ids: &["mcp-autoapprove-wildcard-tool-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Edit(*)\"]` on parsed MCP configuration.",
        check: check_mcp_autoapprove_edit_wildcard,
        suggestion_message: "remove shared `Edit(*)` auto-approval and keep broad editing under narrower reviewed scopes",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveGlobWildcardRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches explicit `Glob(*)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-wildcard-tool-family"],
        benign_case_ids: &["mcp-autoapprove-wildcard-tool-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Glob(*)\"]` on parsed MCP configuration.",
        check: check_mcp_autoapprove_glob_wildcard,
        suggestion_message: "remove shared `Glob(*)` auto-approval and keep broad file discovery under narrower reviewed scopes",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveGrepWildcardRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches explicit `Grep(*)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-wildcard-tool-family"],
        benign_case_ids: &["mcp-autoapprove-wildcard-tool-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Grep(*)\"]` on parsed MCP configuration.",
        check: check_mcp_autoapprove_grep_wildcard,
        suggestion_message: "remove shared `Grep(*)` auto-approval and keep broad content search under narrower reviewed scopes",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveWebFetchWildcardRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches explicit `WebFetch(*)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-wildcard-tool-family"],
        benign_case_ids: &["mcp-autoapprove-wildcard-tool-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"WebFetch(*)\"]` on parsed MCP configuration.",
        check: check_mcp_autoapprove_webfetch_wildcard,
        suggestion_message: "remove shared `WebFetch(*)` auto-approval and keep broad network fetch under narrower reviewed scopes",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveWebSearchWildcardRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches explicit `WebSearch(*)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-wildcard-tool-family"],
        benign_case_ids: &["mcp-autoapprove-wildcard-tool-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"WebSearch(*)\"]` on parsed MCP configuration.",
        check: check_mcp_autoapprove_websearch_wildcard,
        suggestion_message: "remove shared `WebSearch(*)` auto-approval and keep broad remote search under narrower reviewed scopes",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveBashRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact bare `Bash` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-unscoped-tool-family"],
        benign_case_ids: &["mcp-autoapprove-unscoped-tool-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for `autoApprove: [\"Bash\"]` on parsed MCP configuration.",
        check: check_mcp_autoapprove_bash_unscoped,
        suggestion_message: "remove shared bare `Bash` auto-approval and keep shell execution under narrower reviewed command scopes",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveReadRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact bare `Read` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-unscoped-tool-family"],
        benign_case_ids: &["mcp-autoapprove-unscoped-tool-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for bare `Read` in parsed `autoApprove` entries.",
        check: check_mcp_autoapprove_read_unscoped,
        suggestion_message: "replace shared bare `Read` auto-approval with narrower reviewed scopes like `Read(./docs/**)`",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveWriteRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact bare `Write` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-unscoped-tool-family"],
        benign_case_ids: &["mcp-autoapprove-unscoped-tool-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for bare `Write` in parsed `autoApprove` entries.",
        check: check_mcp_autoapprove_write_unscoped,
        suggestion_message: "replace shared bare `Write` auto-approval with narrower reviewed scopes like `Write(./artifacts/**)`",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveEditRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact bare `Edit` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-unscoped-tool-family"],
        benign_case_ids: &["mcp-autoapprove-unscoped-tool-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for bare `Edit` in parsed `autoApprove` entries.",
        check: check_mcp_autoapprove_edit_unscoped,
        suggestion_message: "replace shared bare `Edit` auto-approval with narrower reviewed scopes like `Edit(./docs/**)`",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveGlobRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact bare `Glob` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-unscoped-tool-family"],
        benign_case_ids: &["mcp-autoapprove-unscoped-tool-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for bare `Glob` in parsed `autoApprove` entries.",
        check: check_mcp_autoapprove_glob_unscoped,
        suggestion_message: "replace shared bare `Glob` auto-approval with narrower reviewed scopes like `Glob(./src/**)`",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveGrepRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact bare `Grep` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-unscoped-tool-family"],
        benign_case_ids: &["mcp-autoapprove-unscoped-tool-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for bare `Grep` in parsed `autoApprove` entries.",
        check: check_mcp_autoapprove_grep_unscoped,
        suggestion_message: "replace shared bare `Grep` auto-approval with narrower reviewed scopes like `Grep(todo:)`",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveWebFetchRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact bare `WebFetch` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-unscoped-tool-family"],
        benign_case_ids: &["mcp-autoapprove-unscoped-tool-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for bare `WebFetch` in parsed `autoApprove` entries.",
        check: check_mcp_autoapprove_webfetch_unscoped,
        suggestion_message: "replace shared bare `WebFetch` auto-approval with narrower reviewed scopes like `WebFetch(domain:docs.example.com)`",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveWebSearchRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact bare `WebSearch` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-unscoped-tool-family"],
        benign_case_ids: &["mcp-autoapprove-unscoped-tool-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item detection for bare `WebSearch` in parsed `autoApprove` entries.",
        check: check_mcp_autoapprove_websearch_unscoped,
        suggestion_message: "replace shared bare `WebSearch` auto-approval with narrower reviewed scopes like `WebSearch(site:docs.example.com)`",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveReadUnsafePathRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact unsafe-path `Read(...)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-unsafe-path-family"],
        benign_case_ids: &["mcp-autoapprove-unsafe-path-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item predicate detection for `autoApprove` entries where `Read(...)` targets an absolute, home-relative, parent-traversing, or drive-qualified path.",
        check: check_mcp_autoapprove_read_unsafe_path,
        suggestion_message: "replace broad `Read(...)` auto-approval with repository-scoped allowlists or remove shared access to absolute, home-relative, or parent-traversing paths",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveWriteUnsafePathRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact unsafe-path `Write(...)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-unsafe-path-family"],
        benign_case_ids: &["mcp-autoapprove-unsafe-path-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item predicate detection for `autoApprove` entries where `Write(...)` targets an absolute, home-relative, parent-traversing, or drive-qualified path.",
        check: check_mcp_autoapprove_write_unsafe_path,
        suggestion_message: "replace broad `Write(...)` auto-approval with repository-scoped allowlists or remove shared access to absolute, home-relative, or parent-traversing paths",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveEditUnsafePathRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact unsafe-path `Edit(...)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-unsafe-path-family"],
        benign_case_ids: &["mcp-autoapprove-unsafe-path-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item predicate detection for `autoApprove` entries where `Edit(...)` targets an absolute, home-relative, parent-traversing, or drive-qualified path.",
        check: check_mcp_autoapprove_edit_unsafe_path,
        suggestion_message: "replace broad `Edit(...)` auto-approval with repository-scoped allowlists or remove shared access to absolute, home-relative, or parent-traversing paths",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveGlobUnsafePathRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact unsafe-path `Glob(...)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-unsafe-path-family"],
        benign_case_ids: &["mcp-autoapprove-unsafe-path-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item predicate detection for `autoApprove` entries where `Glob(...)` targets an absolute, home-relative, parent-traversing, or drive-qualified path.",
        check: check_mcp_autoapprove_glob_unsafe_path,
        suggestion_message: "replace broad `Glob(...)` auto-approval with repository-scoped allowlists or remove shared access to absolute, home-relative, or parent-traversing paths",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveGrepUnsafePathRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches exact unsafe-path `Grep(...)` auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-unsafe-path-family"],
        benign_case_ids: &["mcp-autoapprove-unsafe-path-family-specific-safe"],
        deterministic_signal_basis: "JsonSignals exact array-item predicate detection for `autoApprove` entries where `Grep(...)` targets an absolute, home-relative, parent-traversing, or drive-qualified path.",
        check: check_mcp_autoapprove_grep_unsafe_path,
        suggestion_message: "replace broad `Grep(...)` auto-approval with repository-scoped allowlists or remove shared access to absolute, home-relative, or parent-traversing paths",
    },
    stable_native_message_rule_spec! {
        metadata: McpAutoApproveToolsTrueRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches explicit blanket auto-approval in MCP client config.",
        malicious_case_ids: &["mcp-autoapprove-tools-true"],
        benign_case_ids: &["mcp-autoapprove-tools-false-safe"],
        deterministic_signal_basis: "JsonSignals exact boolean detection for `autoApproveTools: true` on parsed MCP configuration.",
        check: check_mcp_autoapprove_tools_true,
        suggestion_message: "disable blanket auto-approval and require explicit review or narrowly scoped tool allowlists",
    },
    stable_native_message_rule_spec! {
        metadata: McpTrustToolsTrueRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches explicit blanket tool trust in MCP client config.",
        malicious_case_ids: &["mcp-trust-tools-true"],
        benign_case_ids: &["mcp-trust-tools-false-safe"],
        deterministic_signal_basis: "JsonSignals exact boolean detection for `trustTools: true` on parsed MCP configuration.",
        check: check_mcp_trust_tools_true,
        suggestion_message: "disable blanket tool trust and require explicit review or narrower tool approval settings",
    },
    stable_native_message_rule_spec! {
        metadata: McpSandboxDisabledRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches explicit MCP config booleans that disable sandbox isolation.",
        malicious_case_ids: &["mcp-sandbox-disabled"],
        benign_case_ids: &["mcp-sandbox-enabled-safe"],
        deterministic_signal_basis: "JsonSignals exact boolean detection for `sandbox: false` or `disableSandbox: true` on parsed MCP configuration.",
        check: check_mcp_sandbox_disabled,
        suggestion_message: "re-enable sandboxing and prefer reviewed, least-privilege MCP isolation settings",
    },
    stable_native_message_rule_spec! {
        metadata: McpCapabilitiesWildcardRule::METADATA,
        surface: Surface::Json,
        default_presets: GOVERNANCE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        rationale: "Matches explicit wildcard capability grants in MCP config.",
        malicious_case_ids: &["mcp-capabilities-wildcard"],
        benign_case_ids: &["mcp-capabilities-scoped-safe"],
        deterministic_signal_basis: "JsonSignals exact wildcard detection for `capabilities` scalar or array values on parsed MCP configuration.",
        check: check_mcp_capabilities_wildcard,
        suggestion_message: "replace wildcard capabilities with only the narrowly reviewed MCP capabilities that are actually required",
    },
    NativeRuleSpec {
        metadata: McpSudoCommandRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact MCP server launch paths that run under `sudo`.",
            malicious_case_ids: &["mcp-command-sudo"],
            benign_case_ids: &["mcp-command-non-sudo-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact string detection for `command: \"sudo\"` on parsed MCP configuration objects.",
        },
        check: check_mcp_sudo_command,
        safe_fix: None,
        suggestion_message: Some(
            "remove `sudo` from the MCP launch path and use a reviewed non-privileged server command instead",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpSudoArgs0Rule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches exact MCP server launch paths that pass `sudo` as the first argv element.",
            malicious_case_ids: &["mcp-args-sudo"],
            benign_case_ids: &["mcp-args-non-sudo-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals exact string detection for `args[0] == \"sudo\"` on parsed MCP configuration objects.",
        },
        check: check_mcp_sudo_args0,
        safe_fix: None,
        suggestion_message: Some(
            "remove `sudo` from the MCP launch arguments and use a reviewed non-privileged server command instead",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpUnpinnedDockerImageRule::METADATA,
        surface: Surface::Json,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP config Docker launch paths for image references that are not pinned by digest, including tag-only refs such as :latest or :1.2.3.",
            malicious_case_ids: &["mcp-docker-unpinned-image"],
            benign_case_ids: &["mcp-docker-digest-pinned-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals docker run argument analysis over ArtifactKind::McpConfig objects, limited to command == docker plus args beginning with run.",
        },
        check: check_mcp_unpinned_docker_image,
        safe_fix: None,
        suggestion_message: Some(
            "pin the Docker image by digest in the committed MCP launch path instead of relying on a mutable tag or floating reference",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpSensitiveDockerMountRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP config Docker launch paths for bind mounts of sensitive host sources such as docker.sock, SSH material, cloud credentials, and kubeconfig directories.",
            malicious_case_ids: &["mcp-docker-sensitive-mount"],
            benign_case_ids: &["mcp-docker-named-volume-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals docker run argument analysis over ArtifactKind::McpConfig objects, limited to -v/--volume and --mount bind forms with sensitive host-path markers.",
        },
        check: check_mcp_sensitive_docker_mount,
        safe_fix: None,
        suggestion_message: Some(
            "remove the sensitive host bind mount from the MCP Docker launch path or replace it with a narrower, non-secret volume strategy",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpDangerousDockerFlagRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP config Docker launch paths for privileged or host-escape runtime flags such as --privileged, --network host, --pid host, and --ipc host.",
            malicious_case_ids: &["mcp-docker-host-escape"],
            benign_case_ids: &["mcp-docker-safe-run"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals docker run argument analysis over ArtifactKind::McpConfig objects, limited to explicit privileged and host namespace flags.",
        },
        check: check_mcp_dangerous_docker_flag,
        safe_fix: None,
        suggestion_message: Some(
            "remove privileged or host-namespace flags from the committed MCP Docker launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpMutableDockerPullRule::METADATA,
        surface: Surface::Json,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP config Docker launch paths for explicit --pull always refresh policies that force a mutable registry fetch at runtime.",
            malicious_case_ids: &["gemini-mcp-docker-pull-always"],
            benign_case_ids: &["gemini-mcp-docker-digest-pinned-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals docker run argument analysis over ArtifactKind::McpConfig objects, limited to explicit --pull=always or --pull always forms.",
        },
        check: check_mcp_mutable_docker_pull,
        safe_fix: None,
        suggestion_message: Some(
            "remove the forced Docker pull policy from the committed MCP client config and prefer pinned, reproducible image references",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookMutableLauncherRule::METADATA,
        surface: Surface::Json,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for mutable package launchers such as npx, uvx, pnpm dlx, yarn dlx, and pipx run.",
            malicious_case_ids: &["plugin-hook-command-mutable-launcher"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks objects limited to actual hook command values.",
        },
        check: check_plugin_hook_mutable_launcher,
        safe_fix: None,
        suggestion_message: Some(
            "replace the mutable hook launcher with a vendored, pinned, or otherwise reproducible execution path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookInlineDownloadExecRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit curl|shell or wget|shell execution chains.",
            malicious_case_ids: &["plugin-hook-command-inline-download-exec"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks objects, limited to explicit download-pipe-shell patterns.",
        },
        check: check_plugin_hook_inline_download_exec,
        safe_fix: None,
        suggestion_message: Some(
            "remove the inline download-and-exec flow from the plugin hook command and pin or vendor the fetched content instead",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookNetworkTlsBypassRule::METADATA,
        surface: Surface::Json,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit TLS-bypass tokens in a network-capable execution context.",
            malicious_case_ids: &["plugin-hook-command-tls-bypass"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks objects gated by network markers plus TLS-bypass tokens.",
        },
        check: check_plugin_hook_network_tls_bypass,
        safe_fix: None,
        suggestion_message: Some(
            "remove TLS-bypass flags or NODE_TLS_REJECT_UNAUTHORIZED=0 from the network-capable plugin hook command",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpRootDeleteRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for explicit `rm`-style destructive root deletion payloads.",
            malicious_case_ids: &["mcp-command-persistence-escalation"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for `rm` with recursive+force flags targeting `/` or using `--no-preserve-root`.",
        },
        check: check_mcp_root_delete,
        safe_fix: None,
        suggestion_message: Some(
            "remove the destructive root deletion command from the committed MCP launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpPasswordFileAccessRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for direct access to sensitive password and sudo policy files.",
            malicious_case_ids: &["mcp-command-persistence-escalation"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args path detection over ArtifactKind::McpConfig for `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/etc/gshadow`, or `/etc/master.passwd`.",
        },
        check: check_mcp_password_file_access,
        safe_fix: None,
        suggestion_message: Some(
            "remove the sensitive password-file access from the committed MCP launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpShellProfileWriteRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for explicit writes to shell startup profile files.",
            malicious_case_ids: &["mcp-command-persistence-escalation"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig using redirection-or-tee targeting of `.bashrc`, `.bash_profile`, `.zshrc`, or `.profile`.",
        },
        check: check_mcp_shell_profile_write,
        safe_fix: None,
        suggestion_message: Some(
            "remove the shell profile write and keep startup-file persistence out of the committed MCP launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpAuthorizedKeysWriteRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for explicit writes to SSH `authorized_keys`.",
            malicious_case_ids: &["mcp-command-persistence-escalation"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig using redirection-or-tee targeting of `authorized_keys`.",
        },
        check: check_mcp_authorized_keys_write,
        safe_fix: None,
        suggestion_message: Some(
            "remove the `authorized_keys` modification from the committed MCP launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookRootDeleteRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit `rm`-style destructive root deletion payloads.",
            malicious_case_ids: &["plugin-hook-command-persistence-escalation"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for `rm` with recursive+force flags targeting `/` or using `--no-preserve-root`.",
        },
        check: check_plugin_hook_root_delete,
        safe_fix: None,
        suggestion_message: Some(
            "remove the destructive root deletion command from the committed plugin hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookPasswordFileAccessRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for direct access to sensitive password and sudo policy files.",
            malicious_case_ids: &["plugin-hook-command-persistence-escalation"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string path detection over ArtifactKind::CursorPluginHooks for `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/etc/gshadow`, or `/etc/master.passwd`.",
        },
        check: check_plugin_hook_password_file_access,
        safe_fix: None,
        suggestion_message: Some(
            "remove the sensitive password-file access from the committed plugin hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookShellProfileWriteRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit writes to shell startup profile files.",
            malicious_case_ids: &["plugin-hook-command-persistence-escalation"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks using redirection-or-tee targeting of `.bashrc`, `.bash_profile`, `.zshrc`, or `.profile`.",
        },
        check: check_plugin_hook_shell_profile_write,
        safe_fix: None,
        suggestion_message: Some(
            "remove the shell profile write and keep startup-file persistence out of the committed plugin hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookAuthorizedKeysWriteRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit writes to SSH `authorized_keys`.",
            malicious_case_ids: &["plugin-hook-command-persistence-escalation"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks using redirection-or-tee targeting of `authorized_keys`.",
        },
        check: check_plugin_hook_authorized_keys_write,
        safe_fix: None,
        suggestion_message: Some(
            "remove the `authorized_keys` modification from the committed plugin hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpCronPersistenceRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for explicit cron persistence setup.",
            malicious_case_ids: &["mcp-command-service-persistence"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for `crontab` mutation or writes to cron persistence paths.",
        },
        check: check_mcp_cron_persistence,
        safe_fix: None,
        suggestion_message: Some(
            "remove cron persistence from the committed MCP launch path and keep scheduled-task changes under explicit review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpSystemdServiceRegistrationRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for explicit systemd service registration or unit-file writes.",
            malicious_case_ids: &["mcp-command-service-persistence"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for `systemctl enable|link` or writes to systemd unit paths.",
        },
        check: check_mcp_systemd_service_registration,
        safe_fix: None,
        suggestion_message: Some(
            "remove systemd persistence from the committed MCP launch path and keep service registration out of shared config",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpLaunchdRegistrationRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for explicit launchd registration or LaunchAgents/LaunchDaemons plist writes.",
            malicious_case_ids: &["mcp-command-service-persistence"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for `launchctl load|bootstrap` or writes to LaunchAgents/LaunchDaemons plist paths.",
        },
        check: check_mcp_launchd_registration,
        safe_fix: None,
        suggestion_message: Some(
            "remove launchd persistence from the committed MCP launch path and keep plist registration out of shared config",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookCronPersistenceRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit cron persistence setup.",
            malicious_case_ids: &["plugin-hook-command-service-persistence"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for `crontab` mutation or writes to cron persistence paths.",
        },
        check: check_plugin_hook_cron_persistence,
        safe_fix: None,
        suggestion_message: Some(
            "remove cron persistence from the committed plugin hook and keep scheduled-task changes under explicit review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookSystemdServiceRegistrationRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit systemd service registration or unit-file writes.",
            malicious_case_ids: &["plugin-hook-command-service-persistence"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for `systemctl enable|link` or writes to systemd unit paths.",
        },
        check: check_plugin_hook_systemd_service_registration,
        safe_fix: None,
        suggestion_message: Some(
            "remove systemd persistence from the committed plugin hook and keep service registration out of shared hooks",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookLaunchdRegistrationRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit launchd registration or LaunchAgents/LaunchDaemons plist writes.",
            malicious_case_ids: &["plugin-hook-command-service-persistence"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for `launchctl load|bootstrap` or writes to LaunchAgents/LaunchDaemons plist paths.",
        },
        check: check_plugin_hook_launchd_registration,
        safe_fix: None,
        suggestion_message: Some(
            "remove launchd persistence from the committed plugin hook and keep plist registration out of shared hooks",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpInsecurePermissionChangeRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for explicit insecure chmod payloads.",
            malicious_case_ids: &["mcp-command-privilege-escalation-payloads"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for `chmod 777`, `chmod 0777`, or symbolic world-writable modes such as `a+rwx`.",
        },
        check: check_mcp_insecure_permission_change,
        safe_fix: None,
        suggestion_message: Some(
            "remove the insecure chmod change from the committed MCP launch path and use the minimum required permissions",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpSetuidSetgidRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for explicit setuid or setgid chmod payloads.",
            malicious_case_ids: &["mcp-command-privilege-escalation-payloads"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for chmod octal modes with setuid/setgid bits or symbolic modes such as `u+s` and `g+s`.",
        },
        check: check_mcp_setuid_setgid,
        safe_fix: None,
        suggestion_message: Some(
            "remove setuid or setgid manipulation from the committed MCP launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpLinuxCapabilityManipulationRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for explicit Linux capability manipulation payloads.",
            malicious_case_ids: &["mcp-command-privilege-escalation-payloads"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for `setcap` or dangerous Linux capability tokens such as `cap_setuid` and `cap_sys_admin`.",
        },
        check: check_mcp_linux_capability_manipulation,
        safe_fix: None,
        suggestion_message: Some(
            "remove Linux capability manipulation from the committed MCP launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookInsecurePermissionChangeRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit insecure chmod payloads.",
            malicious_case_ids: &["plugin-hook-command-privilege-escalation-payloads"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for `chmod 777`, `chmod 0777`, or symbolic world-writable modes such as `a+rwx`.",
        },
        check: check_plugin_hook_insecure_permission_change,
        safe_fix: None,
        suggestion_message: Some(
            "remove the insecure chmod change from the committed plugin hook and use the minimum required permissions",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookSetuidSetgidRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit setuid or setgid chmod payloads.",
            malicious_case_ids: &["plugin-hook-command-privilege-escalation-payloads"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for chmod octal modes with setuid/setgid bits or symbolic modes such as `u+s` and `g+s`.",
        },
        check: check_plugin_hook_setuid_setgid,
        safe_fix: None,
        suggestion_message: Some(
            "remove setuid or setgid manipulation from the committed plugin hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookLinuxCapabilityManipulationRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit Linux capability manipulation payloads.",
            malicious_case_ids: &["plugin-hook-command-privilege-escalation-payloads"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for `setcap` or dangerous Linux capability tokens such as `cap_setuid` and `cap_sys_admin`.",
        },
        check: check_plugin_hook_linux_capability_manipulation,
        safe_fix: None,
        suggestion_message: Some(
            "remove Linux capability manipulation from the committed plugin hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpSecretExfilRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for explicit secret-bearing network exfil payloads.",
            malicious_case_ids: &["mcp-command-secret-exfil-payloads"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for secret markers combined with network-capable command context.",
        },
        check: check_mcp_secret_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove the secret-bearing network send from the committed MCP launch path and keep secret access local",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpPlainHttpSecretExfilRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for secret-bearing exfil over insecure HTTP.",
            malicious_case_ids: &["mcp-command-secret-exfil-payloads"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for `http://` endpoints gated by concurrent secret markers in a network-capable command path.",
        },
        check: check_mcp_plain_http_secret_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove the insecure secret-bearing HTTP send from the committed MCP launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpWebhookSecretExfilRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for secret-bearing posts to webhook endpoints.",
            malicious_case_ids: &["mcp-command-secret-exfil-payloads"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for secret markers plus webhook endpoint markers such as `hooks.slack.com/services/` or `discord.com/api/webhooks/`.",
        },
        check: check_mcp_webhook_secret_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove the secret-bearing webhook post from the committed MCP launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookSecretExfilRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit secret-bearing network exfil payloads.",
            malicious_case_ids: &["plugin-hook-command-secret-exfil-payloads"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for secret markers combined with network-capable command context.",
        },
        check: check_plugin_hook_secret_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove the secret-bearing network send from the committed plugin hook and keep secret access local",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookPlainHttpSecretExfilRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for secret-bearing exfil over insecure HTTP.",
            malicious_case_ids: &["plugin-hook-command-secret-exfil-payloads"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for `http://` endpoints gated by concurrent secret markers in a network-capable command path.",
        },
        check: check_plugin_hook_plain_http_secret_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove the insecure secret-bearing HTTP send from the committed plugin hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookWebhookSecretExfilRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for secret-bearing posts to webhook endpoints.",
            malicious_case_ids: &["plugin-hook-command-secret-exfil-payloads"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for secret markers plus webhook endpoint markers such as `hooks.slack.com/services/` or `discord.com/api/webhooks/`.",
        },
        check: check_plugin_hook_webhook_secret_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove the secret-bearing webhook post from the committed plugin hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpSensitiveFileExfilRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for explicit transfer of sensitive credential files to remote destinations.",
            malicious_case_ids: &[
                "mcp-command-sensitive-file-exfil",
                "mcp-command-sensitive-file-rclone-exfil",
            ],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for sensitive file paths such as `.env`, `.aws/credentials`, `.ssh/id_rsa`, or `.kube/config` combined with transfer commands like `scp`, `sftp`, `rsync`, `curl`, `aws s3 cp`, `gsutil cp`, or `rclone copy`.",
        },
        check: check_mcp_sensitive_file_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove the remote transfer of sensitive credential files from the committed MCP launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookSensitiveFileExfilRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit transfer of sensitive credential files to remote destinations.",
            malicious_case_ids: &[
                "plugin-hook-command-sensitive-file-exfil",
                "plugin-hook-command-sensitive-file-rclone-exfil",
            ],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for sensitive file paths such as `.env`, `.aws/credentials`, `.ssh/id_rsa`, or `.kube/config` combined with transfer commands like `scp`, `sftp`, `rsync`, `curl`, `aws s3 cp`, `gsutil cp`, or `rclone copy`.",
        },
        check: check_plugin_hook_sensitive_file_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove the remote transfer of sensitive credential files from the committed plugin hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpClipboardReadRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for clipboard-reading commands that can extract local user data.",
            malicious_case_ids: &["mcp-command-local-data-theft"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for clipboard read utilities such as `pbpaste`, `wl-paste`, `xclip -o`, `xsel --output`, or PowerShell `Get-Clipboard`.",
        },
        check: check_mcp_clipboard_read,
        safe_fix: None,
        suggestion_message: Some("remove clipboard reads from the committed MCP launch path"),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpBrowserSecretStoreAccessRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for direct access to browser credential or cookie storage files.",
            malicious_case_ids: &["mcp-command-local-data-theft"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for browser profile paths such as Chrome or Firefox state directories paired with secret-store files like `Cookies`, `Login Data`, `logins.json`, `key4.db`, `Web Data`, or `Local State`.",
        },
        check: check_mcp_browser_secret_store_access,
        safe_fix: None,
        suggestion_message: Some(
            "remove browser credential or cookie store access from the committed MCP launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookClipboardReadRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for clipboard-reading behavior that can extract local user data.",
            malicious_case_ids: &["plugin-hook-command-local-data-theft"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for clipboard read utilities such as `pbpaste`, `wl-paste`, `xclip -o`, `xsel --output`, or PowerShell `Get-Clipboard`.",
        },
        check: check_plugin_hook_clipboard_read,
        safe_fix: None,
        suggestion_message: Some("remove clipboard reads from the committed plugin hook"),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookBrowserSecretStoreAccessRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for direct access to browser credential or cookie storage files.",
            malicious_case_ids: &["plugin-hook-command-local-data-theft"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for browser profile paths such as Chrome or Firefox state directories paired with secret-store files like `Cookies`, `Login Data`, `logins.json`, `key4.db`, `Web Data`, or `Local State`.",
        },
        check: check_plugin_hook_browser_secret_store_access,
        safe_fix: None,
        suggestion_message: Some(
            "remove browser credential or cookie store access from the committed plugin hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpClipboardExfilRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for clipboard-reading commands that also transmit captured data to remote destinations.",
            malicious_case_ids: &["mcp-command-local-data-exfil"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for clipboard read utilities such as `pbpaste`, `wl-paste`, `xclip -o`, `xsel --output`, or PowerShell `Get-Clipboard` combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_mcp_clipboard_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove network exfiltration of clipboard contents from the committed MCP launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpBrowserSecretStoreExfilRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for direct access to browser credential or cookie storage files combined with remote transfer behavior.",
            malicious_case_ids: &["mcp-command-local-data-exfil"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for browser profile paths such as Chrome or Firefox state directories paired with secret-store files like `Cookies`, `Login Data`, `logins.json`, `key4.db`, `Web Data`, or `Local State`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_mcp_browser_secret_store_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove network exfiltration of browser credential or cookie store data from the committed MCP launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookClipboardExfilRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for clipboard reads that also transmit captured data to remote destinations.",
            malicious_case_ids: &["plugin-hook-command-local-data-exfil"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for clipboard read utilities such as `pbpaste`, `wl-paste`, `xclip -o`, `xsel --output`, or PowerShell `Get-Clipboard` combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_plugin_hook_clipboard_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove network exfiltration of clipboard contents from the committed plugin hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookBrowserSecretStoreExfilRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for direct access to browser credential or cookie storage files combined with remote transfer behavior.",
            malicious_case_ids: &["plugin-hook-command-local-data-exfil"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for browser profile paths such as Chrome or Firefox state directories paired with secret-store files like `Cookies`, `Login Data`, `logins.json`, `key4.db`, `Web Data`, or `Local State`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_plugin_hook_browser_secret_store_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove network exfiltration of browser credential or cookie store data from the committed plugin hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpScreenCaptureRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for explicit screen capture utilities.",
            malicious_case_ids: &[
                "mcp-command-screen-capture",
                "mcp-command-screen-capture-exfil",
            ],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for explicit screen capture utilities such as `screencapture`, `scrot`, `gnome-screenshot`, `grim`, `maim`, `grimshot`, ImageMagick `import -window root`, or PowerShell `CopyFromScreen`.",
        },
        check: check_mcp_screen_capture,
        safe_fix: None,
        suggestion_message: Some(
            "remove screenshot capture behavior from the committed MCP launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpScreenCaptureExfilRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for explicit screen capture utilities combined with remote transfer behavior.",
            malicious_case_ids: &["mcp-command-screen-capture-exfil"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for explicit screen capture utilities such as `screencapture`, `scrot`, `gnome-screenshot`, `grim`, `maim`, `grimshot`, ImageMagick `import -window root`, or PowerShell `CopyFromScreen`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_mcp_screen_capture_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove screenshot capture and remote transfer behavior from the committed MCP launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookScreenCaptureRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit screen capture utilities.",
            malicious_case_ids: &[
                "plugin-hook-command-screen-capture",
                "plugin-hook-command-screen-capture-exfil",
            ],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for explicit screen capture utilities such as `screencapture`, `scrot`, `gnome-screenshot`, `grim`, `maim`, `grimshot`, ImageMagick `import -window root`, or PowerShell `CopyFromScreen`.",
        },
        check: check_plugin_hook_screen_capture,
        safe_fix: None,
        suggestion_message: Some(
            "remove screenshot capture behavior from the committed plugin hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookScreenCaptureExfilRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit screen capture utilities combined with remote transfer behavior.",
            malicious_case_ids: &["plugin-hook-command-screen-capture-exfil"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for explicit screen capture utilities such as `screencapture`, `scrot`, `gnome-screenshot`, `grim`, `maim`, `grimshot`, ImageMagick `import -window root`, or PowerShell `CopyFromScreen`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_plugin_hook_screen_capture_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove screenshot capture and remote transfer behavior from the committed plugin hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpCameraCaptureRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for explicit webcam or camera capture utilities.",
            malicious_case_ids: &[
                "mcp-command-device-capture",
                "mcp-command-device-capture-exfil",
            ],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for explicit camera capture utilities such as `imagesnap`, `fswebcam`, or `ffmpeg` with camera-oriented selectors like `video=`, `/dev/video`, `-f v4l2`, `-f video4linux2`, `webcam`, or `camera`.",
        },
        check: check_mcp_camera_capture,
        safe_fix: None,
        suggestion_message: Some(
            "remove webcam or camera capture behavior from the committed MCP launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpMicrophoneCaptureRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for explicit microphone recording utilities.",
            malicious_case_ids: &[
                "mcp-command-device-capture",
                "mcp-command-device-capture-exfil",
            ],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for explicit microphone capture utilities such as `arecord`, `parecord`, `parec`, `rec`, `sox -d`, or `ffmpeg` with audio-oriented selectors like `audio=`, `-f alsa`, `-f pulse`, `microphone`, or ` mic`.",
        },
        check: check_mcp_microphone_capture,
        safe_fix: None,
        suggestion_message: Some(
            "remove microphone capture behavior from the committed MCP launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpCameraCaptureExfilRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for explicit webcam or camera capture utilities combined with remote transfer behavior.",
            malicious_case_ids: &["mcp-command-device-capture-exfil"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for explicit camera capture utilities such as `imagesnap`, `fswebcam`, or `ffmpeg` with camera-oriented selectors like `video=`, `/dev/video`, `-f v4l2`, `-f video4linux2`, `webcam`, or `camera`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_mcp_camera_capture_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove webcam or camera capture and remote transfer behavior from the committed MCP launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpMicrophoneCaptureExfilRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for explicit microphone recording utilities combined with remote transfer behavior.",
            malicious_case_ids: &["mcp-command-device-capture-exfil"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for explicit microphone capture utilities such as `arecord`, `parecord`, `parec`, `rec`, `sox -d`, or `ffmpeg` with audio-oriented selectors like `audio=`, `-f alsa`, `-f pulse`, `microphone`, or ` mic`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_mcp_microphone_capture_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove microphone capture and remote transfer behavior from the committed MCP launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookCameraCaptureRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit webcam or camera capture utilities.",
            malicious_case_ids: &[
                "plugin-hook-command-device-capture",
                "plugin-hook-command-device-capture-exfil",
            ],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for explicit camera capture utilities such as `imagesnap`, `fswebcam`, or `ffmpeg` with camera-oriented selectors like `video=`, `/dev/video`, `-f v4l2`, `-f video4linux2`, `webcam`, or `camera`.",
        },
        check: check_plugin_hook_camera_capture,
        safe_fix: None,
        suggestion_message: Some(
            "remove webcam or camera capture behavior from the committed plugin hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookMicrophoneCaptureRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit microphone recording utilities.",
            malicious_case_ids: &[
                "plugin-hook-command-device-capture",
                "plugin-hook-command-device-capture-exfil",
            ],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for explicit microphone capture utilities such as `arecord`, `parecord`, `parec`, `rec`, `sox -d`, or `ffmpeg` with audio-oriented selectors like `audio=`, `-f alsa`, `-f pulse`, `microphone`, or ` mic`.",
        },
        check: check_plugin_hook_microphone_capture,
        safe_fix: None,
        suggestion_message: Some(
            "remove microphone capture behavior from the committed plugin hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookCameraCaptureExfilRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit webcam or camera capture utilities combined with remote transfer behavior.",
            malicious_case_ids: &["plugin-hook-command-device-capture-exfil"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for explicit camera capture utilities such as `imagesnap`, `fswebcam`, or `ffmpeg` with camera-oriented selectors like `video=`, `/dev/video`, `-f v4l2`, `-f video4linux2`, `webcam`, or `camera`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_plugin_hook_camera_capture_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove webcam or camera capture and remote transfer behavior from the committed plugin hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookMicrophoneCaptureExfilRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit microphone recording utilities combined with remote transfer behavior.",
            malicious_case_ids: &["plugin-hook-command-device-capture-exfil"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for explicit microphone capture utilities such as `arecord`, `parecord`, `parec`, `rec`, `sox -d`, or `ffmpeg` with audio-oriented selectors like `audio=`, `-f alsa`, `-f pulse`, `microphone`, or ` mic`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_plugin_hook_microphone_capture_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove microphone capture and remote transfer behavior from the committed plugin hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpKeyloggingRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for explicit keystroke capture utilities or keylogger markers.",
            malicious_case_ids: &["mcp-command-keylogger", "mcp-command-keylogger-exfil"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for explicit keylogger primitives such as `logkeys`, `xinput test`, `evtest`, `showkey`, PowerShell `GetAsyncKeyState`, or inline Python listener markers like `pynput.keyboard.Listener`.",
        },
        check: check_mcp_keylogging,
        safe_fix: None,
        suggestion_message: Some(
            "remove keystroke capture or keylogger behavior from the committed MCP launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpKeyloggingExfilRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for explicit keystroke capture utilities or keylogger markers combined with remote transfer behavior.",
            malicious_case_ids: &["mcp-command-keylogger-exfil"],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for explicit keylogger primitives such as `logkeys`, `xinput test`, `evtest`, `showkey`, PowerShell `GetAsyncKeyState`, or inline Python listener markers like `pynput.keyboard.Listener`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_mcp_keylogging_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove keystroke capture and remote transfer behavior from the committed MCP launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookKeyloggingRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit keystroke capture utilities or keylogger markers.",
            malicious_case_ids: &[
                "plugin-hook-command-keylogger",
                "plugin-hook-command-keylogger-exfil",
            ],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for explicit keylogger primitives such as `logkeys`, `xinput test`, `evtest`, `showkey`, PowerShell `GetAsyncKeyState`, or inline Python listener markers like `pynput.keyboard.Listener`.",
        },
        check: check_plugin_hook_keylogging,
        safe_fix: None,
        suggestion_message: Some(
            "remove keystroke capture or keylogger behavior from the committed plugin hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookKeyloggingExfilRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit keystroke capture utilities or keylogger markers combined with remote transfer behavior.",
            malicious_case_ids: &["plugin-hook-command-keylogger-exfil"],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for explicit keylogger primitives such as `logkeys`, `xinput test`, `evtest`, `showkey`, PowerShell `GetAsyncKeyState`, or inline Python listener markers like `pynput.keyboard.Listener`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_plugin_hook_keylogging_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove keystroke capture and remote transfer behavior from the committed plugin hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpEnvironmentDumpRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for explicit environment or shell-state enumeration commands.",
            malicious_case_ids: &[
                "mcp-command-env-dump",
                "mcp-command-env-dump-exfil",
                "mcp-command-env-dump-cloud-exfil",
            ],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for explicit environment enumeration primitives such as `printenv`, `env` used as a dump, `export -p`, `declare -xp`, or `compgen -v`.",
        },
        check: check_mcp_environment_dump,
        safe_fix: None,
        suggestion_message: Some(
            "remove environment dumping behavior from the committed MCP launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: McpEnvironmentDumpExfilRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed MCP launch paths for explicit environment or shell-state enumeration commands combined with remote transfer behavior.",
            malicious_case_ids: &[
                "mcp-command-env-dump-exfil",
                "mcp-command-env-dump-cloud-exfil",
            ],
            benign_case_ids: &["mcp-safe-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-plus-args analysis over ArtifactKind::McpConfig for explicit environment enumeration primitives such as `printenv`, `env` used as a dump, `export -p`, `declare -xp`, or `compgen -v`, combined with remote sinks such as `curl`, `wget`, `scp`, `sftp`, `rsync`, `nc`, `aws s3 cp`, `gsutil cp`, `rclone copy`, or HTTP(S) endpoints.",
        },
        check: check_mcp_environment_dump_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove environment dumping and remote transfer behavior from the committed MCP launch path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookEnvironmentDumpRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit environment or shell-state enumeration commands.",
            malicious_case_ids: &[
                "plugin-hook-command-env-dump",
                "plugin-hook-command-env-dump-exfil",
                "plugin-hook-command-env-dump-cloud-exfil",
            ],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for explicit environment enumeration primitives such as `printenv`, `env` used as a dump, `export -p`, `declare -xp`, or `compgen -v`.",
        },
        check: check_plugin_hook_environment_dump,
        safe_fix: None,
        suggestion_message: Some(
            "remove environment dumping behavior from the committed plugin hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PluginHookEnvironmentDumpExfilRule::METADATA,
        surface: Surface::Json,
        default_presets: BASE_MCP_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed plugin hook command values for explicit environment or shell-state enumeration commands combined with remote transfer behavior.",
            malicious_case_ids: &[
                "plugin-hook-command-env-dump-exfil",
                "plugin-hook-command-env-dump-cloud-exfil",
            ],
            benign_case_ids: &["plugin-hook-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals command-string analysis over ArtifactKind::CursorPluginHooks for explicit environment enumeration primitives such as `printenv`, `env` used as a dump, `export -p`, `declare -xp`, or `compgen -v`, combined with remote sinks such as `curl`, `wget`, `scp`, `sftp`, `rsync`, `nc`, `aws s3 cp`, `gsutil cp`, `rclone copy`, or HTTP(S) endpoints.",
        },
        check: check_plugin_hook_environment_dump_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove environment dumping and remote transfer behavior from the committed plugin hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PackageManifestDangerousLifecycleScriptRule::METADATA,
        surface: Surface::Json,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed package.json install-time lifecycle hooks for explicit download-exec, eval, or npm-explore shell behavior.",
            malicious_case_ids: &["package-manifest-dangerous-lifecycle-script"],
            benign_case_ids: &["package-manifest-safe-lifecycle-script"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals package manifest analysis over `scripts.preinstall|install|postinstall|prepare` values for download-exec patterns, `eval`, or `npm explore` shell execution.",
        },
        check: check_package_manifest_dangerous_lifecycle_script,
        safe_fix: None,
        suggestion_message: Some(
            "remove install-time lifecycle execution that downloads, evals, or shells into remote code",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PackageManifestGitDependencyRule::METADATA,
        surface: Surface::Json,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed package.json dependency sections for direct git or forge shortcut sources that bypass the normal registry release path.",
            malicious_case_ids: &["package-manifest-git-url-dependency"],
            benign_case_ids: &["package-manifest-registry-dependency-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals package manifest analysis over dependency sections for specs starting with `git://`, `git+https://`, `git+ssh://`, `github:`, `gitlab:`, or `bitbucket:`.",
        },
        check: check_package_manifest_git_dependency,
        safe_fix: None,
        suggestion_message: Some(
            "prefer a published registry release over a direct git or forge dependency source",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PackageManifestUnboundedDependencyRule::METADATA,
        surface: Surface::Json,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed package.json dependency sections for unbounded or mutable selectors that undermine reproducibility.",
            malicious_case_ids: &["package-manifest-unbounded-dependency"],
            benign_case_ids: &["package-manifest-pinned-dependency-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals package manifest analysis over dependency sections for exact specs equal to `*` or `latest`.",
        },
        check: check_package_manifest_unbounded_dependency,
        safe_fix: None,
        suggestion_message: Some(
            "replace `*` or `latest` with an explicit reviewed dependency version or constrained range",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: PackageManifestDirectUrlDependencyRule::METADATA,
        surface: Surface::Json,
        default_presets: SUPPLY_CHAIN_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed package.json dependency sections for direct archive URL sources that bypass the normal registry release path.",
            malicious_case_ids: &["package-manifest-direct-url-dependency"],
            benign_case_ids: &["package-manifest-registry-archive-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "JsonSignals package manifest analysis over dependency sections for direct `http://` or `https://` archive-like specs ending in `.tgz`, `.tar.gz`, `.tar`, `.zip`, or containing `/tarball/`.",
        },
        check: check_package_manifest_direct_url_dependency,
        safe_fix: None,
        suggestion_message: Some(
            "prefer a published registry release over a direct archive URL dependency source",
        ),
        suggestion_fix: None,
    },
];

pub(crate) fn rule_specs() -> &'static [NativeRuleSpec] {
    &RULE_SPECS
}
