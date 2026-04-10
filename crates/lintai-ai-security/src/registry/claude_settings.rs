use lintai_api::{Category, Confidence, RuleTier, Severity, declare_rule};

use super::*;
use crate::claude_settings_rules::{
    check_claude_settings_authorized_keys_write, check_claude_settings_bash_wildcard,
    check_claude_settings_browser_secret_store_access,
    check_claude_settings_browser_secret_store_exfil, check_claude_settings_bunx_permission,
    check_claude_settings_bypass_permissions, check_claude_settings_camera_capture,
    check_claude_settings_camera_capture_exfil, check_claude_settings_clipboard_exfil,
    check_claude_settings_clipboard_read, check_claude_settings_cron_persistence,
    check_claude_settings_curl_permission, check_claude_settings_dangerous_http_hook_host,
    check_claude_settings_edit_unsafe_path, check_claude_settings_edit_wildcard,
    check_claude_settings_enabled_mcpjson_servers, check_claude_settings_environment_dump,
    check_claude_settings_environment_dump_exfil,
    check_claude_settings_external_absolute_hook_command,
    check_claude_settings_gh_api_delete_permission, check_claude_settings_gh_api_patch_permission,
    check_claude_settings_gh_api_post_permission, check_claude_settings_gh_api_put_permission,
    check_claude_settings_gh_issue_create_permission, check_claude_settings_gh_pr_permission,
    check_claude_settings_gh_release_create_permission,
    check_claude_settings_gh_release_delete_permission,
    check_claude_settings_gh_release_upload_permission,
    check_claude_settings_gh_repo_create_permission,
    check_claude_settings_gh_repo_delete_permission, check_claude_settings_gh_repo_edit_permission,
    check_claude_settings_gh_repo_transfer_permission,
    check_claude_settings_gh_secret_delete_permission,
    check_claude_settings_gh_secret_set_permission,
    check_claude_settings_gh_variable_delete_permission,
    check_claude_settings_gh_variable_set_permission,
    check_claude_settings_gh_workflow_disable_permission,
    check_claude_settings_gh_workflow_run_permission, check_claude_settings_git_add_permission,
    check_claude_settings_git_am_permission, check_claude_settings_git_apply_permission,
    check_claude_settings_git_branch_permission, check_claude_settings_git_checkout_permission,
    check_claude_settings_git_cherry_pick_permission, check_claude_settings_git_clean_permission,
    check_claude_settings_git_clone_permission, check_claude_settings_git_commit_permission,
    check_claude_settings_git_config_permission, check_claude_settings_git_fetch_permission,
    check_claude_settings_git_ls_remote_permission, check_claude_settings_git_merge_permission,
    check_claude_settings_git_push_permission, check_claude_settings_git_rebase_permission,
    check_claude_settings_git_reset_permission, check_claude_settings_git_restore_permission,
    check_claude_settings_git_stash_permission, check_claude_settings_git_tag_permission,
    check_claude_settings_glob_unsafe_path, check_claude_settings_glob_wildcard,
    check_claude_settings_grep_unsafe_path, check_claude_settings_grep_wildcard,
    check_claude_settings_home_directory_hook_command, check_claude_settings_inline_download_exec,
    check_claude_settings_insecure_http_hook_url, check_claude_settings_insecure_permission_change,
    check_claude_settings_invalid_hook_matcher_event, check_claude_settings_keylogging,
    check_claude_settings_keylogging_exfil, check_claude_settings_launchd_registration,
    check_claude_settings_linux_capability_manipulation, check_claude_settings_microphone_capture,
    check_claude_settings_microphone_capture_exfil, check_claude_settings_missing_hook_timeout,
    check_claude_settings_missing_required_hook_matcher, check_claude_settings_missing_schema,
    check_claude_settings_mutable_launcher, check_claude_settings_network_tls_bypass,
    check_claude_settings_npm_exec_permission, check_claude_settings_npx_permission,
    check_claude_settings_package_install_permission, check_claude_settings_password_file_access,
    check_claude_settings_pipx_run_permission, check_claude_settings_plain_http_secret_exfil,
    check_claude_settings_pnpm_dlx_permission, check_claude_settings_read_unsafe_path,
    check_claude_settings_read_wildcard, check_claude_settings_root_delete,
    check_claude_settings_screen_capture, check_claude_settings_screen_capture_exfil,
    check_claude_settings_secret_exfil, check_claude_settings_sensitive_file_exfil,
    check_claude_settings_setuid_setgid, check_claude_settings_shell_profile_write,
    check_claude_settings_systemd_service_registration, check_claude_settings_unscoped_bash,
    check_claude_settings_unscoped_edit, check_claude_settings_unscoped_glob,
    check_claude_settings_unscoped_grep, check_claude_settings_unscoped_read,
    check_claude_settings_unscoped_webfetch, check_claude_settings_unscoped_websearch,
    check_claude_settings_unscoped_write, check_claude_settings_uvx_permission,
    check_claude_settings_webfetch_raw_githubusercontent, check_claude_settings_webfetch_wildcard,
    check_claude_settings_webhook_secret_exfil, check_claude_settings_websearch_wildcard,
    check_claude_settings_wget_permission, check_claude_settings_write_unsafe_path,
    check_claude_settings_write_wildcard, check_claude_settings_yarn_dlx_permission,
};
use crate::registry::presets::{
    GOVERNANCE_CLAUDE_PRESETS, SUPPLY_CHAIN_CLAUDE_PRESETS,
};

declare_rule! {
    pub struct ClaudeSettingsMissingHookTimeoutRule {
        code: "SEC381",
        summary: "Claude settings command hook should set `timeout` in a shared committed config",
        doc_title: "Claude settings: command hook missing `timeout`",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsInvalidHookMatcherEventRule {
        code: "SEC382",
        summary: "Claude settings should not use `matcher` on unsupported hook events",
        doc_title: "Claude settings: `matcher` on unsupported hook event",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsMissingRequiredHookMatcherRule {
        code: "SEC383",
        summary: "Claude settings should set `matcher` on matcher-capable hook events",
        doc_title: "Claude settings: missing `matcher` on matcher-capable hook event",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsWriteWildcardRule {
        code: "SEC369",
        summary: "Claude settings permissions allow `Write(*)` in a shared committed config",
        doc_title: "Claude settings: wildcard Write permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsReadWildcardRule {
        code: "SEC372",
        summary: "Claude settings permissions allow `Read(*)` in a shared committed config",
        doc_title: "Claude settings: wildcard Read permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsEditWildcardRule {
        code: "SEC373",
        summary: "Claude settings permissions allow `Edit(*)` in a shared committed config",
        doc_title: "Claude settings: wildcard Edit permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsReadUnsafePathRule {
        code: "SEC475",
        summary: "Claude settings permissions allow `Read(...)` over an unsafe path in a shared committed config",
        doc_title: "Claude settings: unsafe Read path permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsWriteUnsafePathRule {
        code: "SEC476",
        summary: "Claude settings permissions allow `Write(...)` over an unsafe path in a shared committed config",
        doc_title: "Claude settings: unsafe Write path permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsEditUnsafePathRule {
        code: "SEC477",
        summary: "Claude settings permissions allow `Edit(...)` over an unsafe path in a shared committed config",
        doc_title: "Claude settings: unsafe Edit path permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGlobUnsafePathRule {
        code: "SEC486",
        summary: "Claude settings permissions allow `Glob(...)` over an unsafe path in a shared committed config",
        doc_title: "Claude settings: unsafe Glob path permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGrepUnsafePathRule {
        code: "SEC487",
        summary: "Claude settings permissions allow `Grep(...)` over an unsafe path in a shared committed config",
        doc_title: "Claude settings: unsafe Grep path permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsWebSearchWildcardRule {
        code: "SEC374",
        summary: "Claude settings permissions allow `WebSearch(*)` in a shared committed config",
        doc_title: "Claude settings: wildcard WebSearch permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitResetPermissionRule {
        code: "SEC478",
        summary: "Claude settings permissions allow `Bash(git reset:*)` in a shared committed config",
        doc_title: "Claude settings: shared git reset permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitCleanPermissionRule {
        code: "SEC479",
        summary: "Claude settings permissions allow `Bash(git clean:*)` in a shared committed config",
        doc_title: "Claude settings: shared git clean permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitRestorePermissionRule {
        code: "SEC480",
        summary: "Claude settings permissions allow `Bash(git restore:*)` in a shared committed config",
        doc_title: "Claude settings: shared git restore permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitRebasePermissionRule {
        code: "SEC481",
        summary: "Claude settings permissions allow `Bash(git rebase:*)` in a shared committed config",
        doc_title: "Claude settings: shared git rebase permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitMergePermissionRule {
        code: "SEC482",
        summary: "Claude settings permissions allow `Bash(git merge:*)` in a shared committed config",
        doc_title: "Claude settings: shared git merge permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitCherryPickPermissionRule {
        code: "SEC483",
        summary: "Claude settings permissions allow `Bash(git cherry-pick:*)` in a shared committed config",
        doc_title: "Claude settings: shared git cherry-pick permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitApplyPermissionRule {
        code: "SEC484",
        summary: "Claude settings permissions allow `Bash(git apply:*)` in a shared committed config",
        doc_title: "Claude settings: shared git apply permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitAmPermissionRule {
        code: "SEC485",
        summary: "Claude settings permissions allow `Bash(git am:*)` in a shared committed config",
        doc_title: "Claude settings: shared git am permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsUnscopedWebSearchRule {
        code: "SEC384",
        summary: "Claude settings permissions allow bare `WebSearch` in a shared committed config",
        doc_title: "Claude settings: bare WebSearch permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsWebFetchRawGithubusercontentRule {
        code: "SEC418",
        summary: "Claude settings permissions allow `WebFetch(domain:raw.githubusercontent.com)` in a shared committed config",
        doc_title: "Claude settings: shared raw.githubusercontent.com WebFetch permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitPushPermissionRule {
        code: "SEC385",
        summary: "Claude settings permissions allow `Bash(git push)` in a shared committed config",
        doc_title: "Claude settings: shared git push permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitAddPermissionRule {
        code: "SEC406",
        summary: "Claude settings permissions allow `Bash(git add:*)` in a shared committed config",
        doc_title: "Claude settings: shared git add permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitClonePermissionRule {
        code: "SEC407",
        summary: "Claude settings permissions allow `Bash(git clone:*)` in a shared committed config",
        doc_title: "Claude settings: shared git clone permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGhPrPermissionRule {
        code: "SEC408",
        summary: "Claude settings permissions allow `Bash(gh pr:*)` in a shared committed config",
        doc_title: "Claude settings: shared gh pr permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGhApiPostPermissionRule {
        code: "SEC502",
        summary: "Claude settings permissions allow `Bash(gh api --method POST:*)` in a shared committed config",
        doc_title: "Claude settings: shared gh api POST permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGhApiDeletePermissionRule {
        code: "SEC528",
        summary: "Claude settings permissions allow `Bash(gh api --method DELETE:*)` in a shared committed config",
        doc_title: "Claude settings: shared gh api DELETE permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGhApiPatchPermissionRule {
        code: "SEC530",
        summary: "Claude settings permissions allow `Bash(gh api --method PATCH:*)` in a shared committed config",
        doc_title: "Claude settings: shared gh api PATCH permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGhApiPutPermissionRule {
        code: "SEC531",
        summary: "Claude settings permissions allow `Bash(gh api --method PUT:*)` in a shared committed config",
        doc_title: "Claude settings: shared gh api PUT permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGhIssueCreatePermissionRule {
        code: "SEC503",
        summary: "Claude settings permissions allow `Bash(gh issue create:*)` in a shared committed config",
        doc_title: "Claude settings: shared gh issue create permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGhRepoCreatePermissionRule {
        code: "SEC504",
        summary: "Claude settings permissions allow `Bash(gh repo create:*)` in a shared committed config",
        doc_title: "Claude settings: shared gh repo create permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGhSecretSetPermissionRule {
        code: "SEC508",
        summary: "Claude settings permissions allow `Bash(gh secret set:*)` in a shared committed config",
        doc_title: "Claude settings: shared gh secret set permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGhRepoDeletePermissionRule {
        code: "SEC534",
        summary: "Claude settings permissions allow `Bash(gh repo delete:*)` in a shared committed config",
        doc_title: "Claude settings: shared gh repo delete permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGhRepoEditPermissionRule {
        code: "SEC538",
        summary: "Claude settings permissions allow `Bash(gh repo edit:*)` in a shared committed config",
        doc_title: "Claude settings: shared gh repo edit permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGhRepoTransferPermissionRule {
        code: "SEC542",
        summary: "Claude settings permissions allow `Bash(gh repo transfer:*)` in a shared committed config",
        doc_title: "Claude settings: shared gh repo transfer permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGhReleaseCreatePermissionRule {
        code: "SEC540",
        summary: "Claude settings permissions allow `Bash(gh release create:*)` in a shared committed config",
        doc_title: "Claude settings: shared gh release create permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGhReleaseUploadPermissionRule {
        code: "SEC544",
        summary: "Claude settings permissions allow `Bash(gh release upload:*)` in a shared committed config",
        doc_title: "Claude settings: shared gh release upload permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGhReleaseDeletePermissionRule {
        code: "SEC536",
        summary: "Claude settings permissions allow `Bash(gh release delete:*)` in a shared committed config",
        doc_title: "Claude settings: shared gh release delete permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGhVariableSetPermissionRule {
        code: "SEC509",
        summary: "Claude settings permissions allow `Bash(gh variable set:*)` in a shared committed config",
        doc_title: "Claude settings: shared gh variable set permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGhWorkflowRunPermissionRule {
        code: "SEC510",
        summary: "Claude settings permissions allow `Bash(gh workflow run:*)` in a shared committed config",
        doc_title: "Claude settings: shared gh workflow run permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGhSecretDeletePermissionRule {
        code: "SEC514",
        summary: "Claude settings permissions allow `Bash(gh secret delete:*)` in a shared committed config",
        doc_title: "Claude settings: shared gh secret delete permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGhVariableDeletePermissionRule {
        code: "SEC515",
        summary: "Claude settings permissions allow `Bash(gh variable delete:*)` in a shared committed config",
        doc_title: "Claude settings: shared gh variable delete permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGhWorkflowDisablePermissionRule {
        code: "SEC516",
        summary: "Claude settings permissions allow `Bash(gh workflow disable:*)` in a shared committed config",
        doc_title: "Claude settings: shared gh workflow disable permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitFetchPermissionRule {
        code: "SEC409",
        summary: "Claude settings permissions allow `Bash(git fetch:*)` in a shared committed config",
        doc_title: "Claude settings: shared git fetch permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitLsRemotePermissionRule {
        code: "SEC410",
        summary: "Claude settings permissions allow `Bash(git ls-remote:*)` in a shared committed config",
        doc_title: "Claude settings: shared git ls-remote permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsCurlPermissionRule {
        code: "SEC411",
        summary: "Claude settings permissions allow `Bash(curl:*)` in a shared committed config",
        doc_title: "Claude settings: shared curl permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsWgetPermissionRule {
        code: "SEC412",
        summary: "Claude settings permissions allow `Bash(wget:*)` in a shared committed config",
        doc_title: "Claude settings: shared wget permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitConfigPermissionRule {
        code: "SEC413",
        summary: "Claude settings permissions allow `Bash(git config:*)` in a shared committed config",
        doc_title: "Claude settings: shared git config permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitTagPermissionRule {
        code: "SEC414",
        summary: "Claude settings permissions allow `Bash(git tag:*)` in a shared committed config",
        doc_title: "Claude settings: shared git tag permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitBranchPermissionRule {
        code: "SEC415",
        summary: "Claude settings permissions allow `Bash(git branch:*)` in a shared committed config",
        doc_title: "Claude settings: shared git branch permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsEnabledMcpjsonServersRule {
        code: "SEC400",
        summary: "Claude settings enable `enabledMcpjsonServers` in a shared committed config",
        doc_title: "Claude settings: shared enabledMcpjsonServers",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsPackageInstallPermissionRule {
        code: "SEC405",
        summary: "Claude settings permissions allow package installation commands in a shared committed config",
        doc_title: "Claude settings: shared package install permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsNpxPermissionRule {
        code: "SEC399",
        summary: "Claude settings permissions allow `Bash(npx ...)` in a shared committed config",
        doc_title: "Claude settings: shared npx Bash permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsUvxPermissionRule {
        code: "SEC488",
        summary: "Claude settings permissions allow `Bash(uvx ...)` in a shared committed config",
        doc_title: "Claude settings: shared uvx Bash permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsNpmExecPermissionRule {
        code: "SEC492",
        summary: "Claude settings permissions allow `Bash(npm exec ...)` in a shared committed config",
        doc_title: "Claude settings: shared npm exec Bash permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsBunxPermissionRule {
        code: "SEC493",
        summary: "Claude settings permissions allow `Bash(bunx ...)` in a shared committed config",
        doc_title: "Claude settings: shared bunx Bash permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsPnpmDlxPermissionRule {
        code: "SEC489",
        summary: "Claude settings permissions allow `Bash(pnpm dlx ...)` in a shared committed config",
        doc_title: "Claude settings: shared pnpm dlx Bash permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsYarnDlxPermissionRule {
        code: "SEC490",
        summary: "Claude settings permissions allow `Bash(yarn dlx ...)` in a shared committed config",
        doc_title: "Claude settings: shared yarn dlx Bash permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsPipxRunPermissionRule {
        code: "SEC491",
        summary: "Claude settings permissions allow `Bash(pipx run ...)` in a shared committed config",
        doc_title: "Claude settings: shared pipx run Bash permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitCheckoutPermissionRule {
        code: "SEC386",
        summary: "Claude settings permissions allow `Bash(git checkout:*)` in a shared committed config",
        doc_title: "Claude settings: shared git checkout permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitCommitPermissionRule {
        code: "SEC387",
        summary: "Claude settings permissions allow `Bash(git commit:*)` in a shared committed config",
        doc_title: "Claude settings: shared git commit permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGitStashPermissionRule {
        code: "SEC388",
        summary: "Claude settings permissions allow `Bash(git stash:*)` in a shared committed config",
        doc_title: "Claude settings: shared git stash permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGlobWildcardRule {
        code: "SEC375",
        summary: "Claude settings permissions allow `Glob(*)` in a shared committed config",
        doc_title: "Claude settings: wildcard Glob permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsGrepWildcardRule {
        code: "SEC376",
        summary: "Claude settings permissions allow `Grep(*)` in a shared committed config",
        doc_title: "Claude settings: wildcard Grep permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsExternalAbsoluteHookCommandRule {
        code: "SEC368",
        summary: "Claude settings hook command uses a repo-external absolute path in a shared committed config",
        doc_title: "Claude settings: repo-external absolute hook path",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsWebFetchWildcardRule {
        code: "SEC367",
        summary: "Claude settings permissions allow `WebFetch(*)` in a shared committed config",
        doc_title: "Claude settings: wildcard WebFetch permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsDangerousHttpHookHostRule {
        code: "SEC366",
        summary: "Claude settings allow dangerous host literals in `allowedHttpHookUrls`",
        doc_title: "Claude settings: dangerous HTTP hook host literal",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsInsecureHttpHookUrlRule {
        code: "SEC365",
        summary: "Claude settings allow non-HTTPS HTTP hook URLs in a shared committed config",
        doc_title: "Claude settings: non-HTTPS allowed HTTP hook URL",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsBypassPermissionsRule {
        code: "SEC364",
        summary: "Claude settings set `permissions.defaultMode` to `bypassPermissions` in a shared committed config",
        doc_title: "Claude settings: bypassPermissions default mode",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsHomeDirectoryHookCommandRule {
        code: "SEC363",
        summary: "Claude settings hook command uses a home-directory path in a shared committed config",
        doc_title: "Claude settings: home-directory hook path",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsUnscopedBashRule {
        code: "SEC626",
        summary: "Claude settings permissions allow bare `Bash` in a shared committed config",
        doc_title: "Claude settings: bare Bash permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsUnscopedReadRule {
        code: "SEC627",
        summary: "Claude settings permissions allow bare `Read` in a shared committed config",
        doc_title: "Claude settings: bare Read permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsUnscopedWriteRule {
        code: "SEC628",
        summary: "Claude settings permissions allow bare `Write` in a shared committed config",
        doc_title: "Claude settings: bare Write permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsUnscopedEditRule {
        code: "SEC629",
        summary: "Claude settings permissions allow bare `Edit` in a shared committed config",
        doc_title: "Claude settings: bare Edit permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsUnscopedGlobRule {
        code: "SEC630",
        summary: "Claude settings permissions allow bare `Glob` in a shared committed config",
        doc_title: "Claude settings: bare Glob permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsUnscopedGrepRule {
        code: "SEC631",
        summary: "Claude settings permissions allow bare `Grep` in a shared committed config",
        doc_title: "Claude settings: bare Grep permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsUnscopedWebFetchRule {
        code: "SEC632",
        summary: "Claude settings permissions allow bare `WebFetch` in a shared committed config",
        doc_title: "Claude settings: bare WebFetch permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsBashWildcardRule {
        code: "SEC362",
        summary: "Claude settings permissions allow `Bash(*)` in a shared committed config",
        doc_title: "Claude settings: wildcard Bash permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsMissingSchemaRule {
        code: "SEC361",
        summary: "Claude settings file is missing a top-level `$schema` reference",
        doc_title: "Claude settings: missing `$schema`",
        category: Category::Quality,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
    }
}

declare_rule! {
    pub struct ClaudeSettingsMutableLauncherRule {
        code: "SEC340",
        summary: "Claude settings command hook uses a mutable package launcher",
        doc_title: "Claude hook: mutable package launcher",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsInlineDownloadExecRule {
        code: "SEC341",
        summary: "Claude settings command hook downloads remote content and pipes it into a shell",
        doc_title: "Claude hook: remote content piped to shell",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsNetworkTlsBypassRule {
        code: "SEC342",
        summary: "Claude settings command hook disables TLS verification in a network-capable execution path",
        doc_title: "Claude hook: TLS verification disabled",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsRootDeleteRule {
        code: "SEC641",
        summary: "Claude settings command hook attempts destructive root deletion",
        doc_title: "Claude settings: command hook root deletion",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsPasswordFileAccessRule {
        code: "SEC642",
        summary: "Claude settings command hook accesses a sensitive system password file",
        doc_title: "Claude settings: command hook password file access",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsShellProfileWriteRule {
        code: "SEC643",
        summary: "Claude settings command hook writes to a shell profile startup file",
        doc_title: "Claude settings: command hook shell profile write",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsAuthorizedKeysWriteRule {
        code: "SEC644",
        summary: "Claude settings command hook writes to SSH authorized_keys",
        doc_title: "Claude settings: command hook authorized_keys write",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsCronPersistenceRule {
        code: "SEC655",
        summary: "Claude settings command hook manipulates cron persistence",
        doc_title: "Claude settings: command hook cron persistence",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsSystemdServiceRegistrationRule {
        code: "SEC656",
        summary: "Claude settings command hook registers a systemd service or unit for persistence",
        doc_title: "Claude settings: command hook systemd persistence",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsLaunchdRegistrationRule {
        code: "SEC657",
        summary: "Claude settings command hook registers a launchd plist for persistence",
        doc_title: "Claude settings: command hook launchd persistence",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsInsecurePermissionChangeRule {
        code: "SEC667",
        summary: "Claude settings command hook performs an insecure permission change",
        doc_title: "Claude settings: command hook insecure chmod",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsSetuidSetgidRule {
        code: "SEC668",
        summary: "Claude settings command hook manipulates setuid or setgid permissions",
        doc_title: "Claude settings: command hook setuid or setgid manipulation",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsLinuxCapabilityManipulationRule {
        code: "SEC669",
        summary: "Claude settings command hook manipulates Linux capabilities",
        doc_title: "Claude settings: command hook Linux capability manipulation",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsSecretExfilRule {
        code: "SEC677",
        summary: "Claude settings command hook appears to send secret material over the network",
        doc_title: "Claude settings: secret exfiltration hook",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsPlainHttpSecretExfilRule {
        code: "SEC678",
        summary: "Claude settings command hook sends secret material to an insecure http:// endpoint",
        doc_title: "Claude settings: insecure HTTP secret send",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsWebhookSecretExfilRule {
        code: "SEC679",
        summary: "Claude settings command hook posts secret material to a webhook endpoint",
        doc_title: "Claude settings: webhook secret exfiltration",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsSensitiveFileExfilRule {
        code: "SEC685",
        summary: "Claude settings command hook transfers a sensitive credential file to a remote destination",
        doc_title: "Claude settings: sensitive file exfiltration hook",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsClipboardReadRule {
        code: "SEC691",
        summary: "Claude settings command hook reads local clipboard contents",
        doc_title: "Claude settings: clipboard read hook",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsBrowserSecretStoreAccessRule {
        code: "SEC692",
        summary: "Claude settings command hook accesses browser credential or cookie stores",
        doc_title: "Claude settings: browser credential store access hook",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsClipboardExfilRule {
        code: "SEC699",
        summary: "Claude settings command hook exfiltrates clipboard contents over the network",
        doc_title: "Claude settings: clipboard exfiltration hook",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsBrowserSecretStoreExfilRule {
        code: "SEC700",
        summary: "Claude settings command hook exfiltrates browser credential or cookie store data",
        doc_title: "Claude settings: browser credential store exfiltration hook",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsScreenCaptureRule {
        code: "SEC707",
        summary: "Claude settings command hook captures a screenshot or desktop image",
        doc_title: "Claude settings: screen capture hook",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsScreenCaptureExfilRule {
        code: "SEC708",
        summary: "Claude settings command hook captures and exfiltrates a screenshot or desktop image",
        doc_title: "Claude settings: screen capture exfiltration hook",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsCameraCaptureRule {
        code: "SEC719",
        summary: "Claude settings command hook captures a webcam or camera image",
        doc_title: "Claude settings: camera capture hook",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsMicrophoneCaptureRule {
        code: "SEC720",
        summary: "Claude settings command hook captures microphone audio",
        doc_title: "Claude settings: microphone capture hook",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsCameraCaptureExfilRule {
        code: "SEC721",
        summary: "Claude settings command hook captures and exfiltrates webcam or camera data",
        doc_title: "Claude settings: camera capture exfiltration hook",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsMicrophoneCaptureExfilRule {
        code: "SEC722",
        summary: "Claude settings command hook captures and exfiltrates microphone audio",
        doc_title: "Claude settings: microphone capture exfiltration hook",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsKeyloggingRule {
        code: "SEC731",
        summary: "Claude settings command hook captures keystrokes or keyboard input",
        doc_title: "Claude settings: keylogger capture hook",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsKeyloggingExfilRule {
        code: "SEC732",
        summary: "Claude settings command hook captures and exfiltrates keystrokes or keyboard input",
        doc_title: "Claude settings: keylogger exfiltration hook",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsEnvironmentDumpRule {
        code: "SEC739",
        summary: "Claude settings command hook dumps environment variables or shell state",
        doc_title: "Claude settings: environment dump hook",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct ClaudeSettingsEnvironmentDumpExfilRule {
        code: "SEC740",
        summary: "Claude settings command hook dumps and exfiltrates environment variables or shell state",
        doc_title: "Claude settings: environment dump exfiltration hook",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

pub(crate) static RULE_SPECS: [NativeRuleSpec; 111] = [
    NativeRuleSpec {
        metadata: ClaudeSettingsInvalidHookMatcherEventRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: COMPAT_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact use of `matcher` on unsupported hook events.",
            malicious_case_ids: &["claude-settings-matcher-on-stop-event"],
            benign_case_ids: &["claude-settings-matcher-pretooluse-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact hook-event and matcher presence detection in parsed Claude settings JSON.",
        },
        check: check_claude_settings_invalid_hook_matcher_event,
        safe_fix: None,
        suggestion_message: Some(
            "remove `matcher` from unsupported hook events or move the hook under a matcher-capable event like `PreToolUse` or `PostToolUse`",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsMissingRequiredHookMatcherRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: COMPAT_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact omission of `matcher` on matcher-capable hook events.",
            malicious_case_ids: &["claude-settings-missing-required-matcher"],
            benign_case_ids: &["claude-settings-required-matcher-present-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact hook-event and matcher absence detection in parsed Claude settings JSON.",
        },
        check: check_claude_settings_missing_required_hook_matcher,
        safe_fix: None,
        suggestion_message: Some(
            "add an explicit `matcher` to each shared `PreToolUse` or `PostToolUse` hook entry, or move the hook under a broader event if scoped matching is not intended",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsMissingHookTimeoutRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: COMPAT_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact omission of `timeout` on command hooks.",
            malicious_case_ids: &["claude-settings-missing-hook-timeout"],
            benign_case_ids: &["claude-settings-hook-timeout-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact command-hook timeout presence detection in parsed Claude settings JSON.",
        },
        check: check_claude_settings_missing_hook_timeout,
        safe_fix: None,
        suggestion_message: Some(
            "add an explicit `timeout` to each shared command hook so hook execution stays bounded and reviewable",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsWriteWildcardRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for explicit wildcard `Write(*)` grants.",
            malicious_case_ids: &["claude-settings-write-wildcard"],
            benign_case_ids: &["claude-settings-write-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Write(*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_write_wildcard,
        safe_fix: None,
        suggestion_message: Some(
            "replace `Write(*)` with a narrower allowlist of reviewed write patterns or remove broad write access from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsReadWildcardRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for explicit wildcard `Read(*)` grants.",
            malicious_case_ids: &["claude-settings-read-wildcard"],
            benign_case_ids: &["claude-settings-read-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Read(*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_read_wildcard,
        safe_fix: None,
        suggestion_message: Some(
            "replace `Read(*)` with a narrower allowlist of reviewed read patterns or remove broad read access from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsEditWildcardRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for explicit wildcard `Edit(*)` grants.",
            malicious_case_ids: &["claude-settings-edit-wildcard"],
            benign_case_ids: &["claude-settings-edit-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Edit(*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_edit_wildcard,
        safe_fix: None,
        suggestion_message: Some(
            "replace `Edit(*)` with a narrower allowlist of reviewed edit patterns or remove broad edit access from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsReadUnsafePathRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for exact unsafe-path `Read(...)` grants.",
            malicious_case_ids: &["claude-settings-unsafe-path-permissions"],
            benign_case_ids: &["claude-settings-unsafe-path-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission-scope detection for `Read(...)` entries that target absolute, home-relative, parent-traversing, or drive-qualified paths inside parsed Claude settings JSON.",
        },
        check: check_claude_settings_read_unsafe_path,
        safe_fix: None,
        suggestion_message: Some(
            "replace broad `Read(...)` path grants with repository-scoped allowlists or remove shared access to absolute, home-relative, or parent-traversing paths",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsWriteUnsafePathRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for exact unsafe-path `Write(...)` grants.",
            malicious_case_ids: &["claude-settings-unsafe-path-permissions"],
            benign_case_ids: &["claude-settings-unsafe-path-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission-scope detection for `Write(...)` entries that target absolute, home-relative, parent-traversing, or drive-qualified paths inside parsed Claude settings JSON.",
        },
        check: check_claude_settings_write_unsafe_path,
        safe_fix: None,
        suggestion_message: Some(
            "replace broad `Write(...)` path grants with repository-scoped allowlists or remove shared access to absolute, home-relative, or parent-traversing paths",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsEditUnsafePathRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for exact unsafe-path `Edit(...)` grants.",
            malicious_case_ids: &["claude-settings-unsafe-path-permissions"],
            benign_case_ids: &["claude-settings-unsafe-path-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission-scope detection for `Edit(...)` entries that target absolute, home-relative, parent-traversing, or drive-qualified paths inside parsed Claude settings JSON.",
        },
        check: check_claude_settings_edit_unsafe_path,
        safe_fix: None,
        suggestion_message: Some(
            "replace broad `Edit(...)` path grants with repository-scoped allowlists or remove shared access to absolute, home-relative, or parent-traversing paths",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGlobUnsafePathRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for exact unsafe-path `Glob(...)` grants.",
            malicious_case_ids: &["claude-settings-glob-grep-unsafe-path-permissions"],
            benign_case_ids: &["claude-settings-unsafe-path-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission-scope detection for `Glob(...)` entries that target absolute, home-relative, parent-traversing, or drive-qualified paths inside parsed Claude settings JSON.",
        },
        check: check_claude_settings_glob_unsafe_path,
        safe_fix: None,
        suggestion_message: Some(
            "replace broad `Glob(...)` path grants with repository-scoped allowlists, or remove shared access to absolute, home-relative, or parent-traversing glob scopes",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGrepUnsafePathRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for exact unsafe-path `Grep(...)` grants.",
            malicious_case_ids: &["claude-settings-glob-grep-unsafe-path-permissions"],
            benign_case_ids: &["claude-settings-unsafe-path-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission-scope detection for `Grep(...)` entries that target absolute, home-relative, parent-traversing, or drive-qualified paths inside parsed Claude settings JSON.",
        },
        check: check_claude_settings_grep_unsafe_path,
        safe_fix: None,
        suggestion_message: Some(
            "replace broad `Grep(...)` path grants with repository-scoped allowlists, or remove shared access to absolute, home-relative, or parent-traversing grep scopes",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsWebSearchWildcardRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for explicit wildcard `WebSearch(*)` grants.",
            malicious_case_ids: &["claude-settings-websearch-wildcard"],
            benign_case_ids: &["claude-settings-websearch-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `WebSearch(*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_websearch_wildcard,
        safe_fix: None,
        suggestion_message: Some(
            "replace `WebSearch(*)` with a narrower allowlist of reviewed search patterns or remove broad search access from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsUnscopedWebSearchRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for bare `WebSearch` grants without a reviewed scope.",
            malicious_case_ids: &["claude-settings-unscoped-websearch"],
            benign_case_ids: &["claude-settings-websearch-scoped-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for bare `WebSearch` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_unscoped_websearch,
        safe_fix: None,
        suggestion_message: Some(
            "replace bare `WebSearch` with a narrower reviewed permission pattern or remove broad search access from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsWebFetchRawGithubusercontentRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for explicit raw GitHub content fetch grants.",
            malicious_case_ids: &["claude-settings-webfetch-raw-github-permission"],
            benign_case_ids: &["claude-settings-webfetch-raw-github-fixture-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `WebFetch(domain:raw.githubusercontent.com)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_webfetch_raw_githubusercontent,
        safe_fix: None,
        suggestion_message: Some(
            "remove the raw-content fetch grant or replace it with a narrower reviewed content source",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitPushPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(git push)` authority.",
            malicious_case_ids: &["claude-settings-git-push-permission"],
            benign_case_ids: &["claude-settings-git-push-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(git push)` entries inside permissions.allow.",
        },
        check: check_claude_settings_git_push_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `Bash(git push)` permissions, or replace them with a narrower reviewed workflow that does not grant direct push authority by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitAddPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(git add:*)` authority.",
            malicious_case_ids: &["claude-settings-git-add-permission"],
            benign_case_ids: &["claude-settings-git-add-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(git add:*)` entries inside permissions.allow.",
        },
        check: check_claude_settings_git_add_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `git add` permissions or replace them with a narrower reviewed workflow that keeps repository staging under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitClonePermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(git clone:*)` authority.",
            malicious_case_ids: &["claude-settings-git-clone-permission"],
            benign_case_ids: &["claude-settings-git-clone-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(git clone:*)` entries inside permissions.allow.",
        },
        check: check_claude_settings_git_clone_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `git clone` permissions or replace them with a narrower reviewed workflow that keeps repository fetching under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGhPrPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(gh pr:*)` authority.",
            malicious_case_ids: &["claude-settings-gh-pr-permission"],
            benign_case_ids: &["claude-settings-gh-pr-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(gh pr:*)` entries inside permissions.allow.",
        },
        check: check_claude_settings_gh_pr_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh pr` permissions or replace them with narrower reviewed subcommands that keep pull-request operations under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGhApiPostPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings for exact GitHub API POST mutation authority through `permissions.allow`.",
            malicious_case_ids: &["claude-settings-gh-mutation-permissions"],
            benign_case_ids: &["claude-settings-gh-mutation-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(gh api --method POST:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_gh_api_post_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh api --method POST` permissions or replace them with narrower reviewed subcommands that keep remote GitHub mutations under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGhApiDeletePermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings for exact GitHub API DELETE mutation authority through `permissions.allow`.",
            malicious_case_ids: &["claude-settings-gh-api-delete-permission"],
            benign_case_ids: &["claude-settings-gh-api-delete-permission-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(gh api --method DELETE:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_gh_api_delete_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh api --method DELETE` permissions or replace them with narrower reviewed subcommands that keep destructive remote GitHub mutations under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGhApiPatchPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings for exact GitHub API PATCH mutation authority through `permissions.allow`.",
            malicious_case_ids: &["claude-settings-gh-api-patch-permission"],
            benign_case_ids: &["claude-settings-gh-api-patch-permission-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(gh api --method PATCH:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_gh_api_patch_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh api --method PATCH` permissions or replace them with narrower reviewed subcommands that keep remote GitHub mutations under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGhApiPutPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings for exact GitHub API PUT mutation authority through `permissions.allow`.",
            malicious_case_ids: &["claude-settings-gh-api-put-permission"],
            benign_case_ids: &["claude-settings-gh-api-put-permission-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(gh api --method PUT:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_gh_api_put_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh api --method PUT` permissions or replace them with narrower reviewed subcommands that keep remote GitHub mutations under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGhIssueCreatePermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings for exact GitHub issue creation authority through `permissions.allow`.",
            malicious_case_ids: &["claude-settings-gh-mutation-permissions"],
            benign_case_ids: &["claude-settings-gh-mutation-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(gh issue create:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_gh_issue_create_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh issue create` permissions or replace them with narrower reviewed subcommands that keep GitHub issue creation under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGhRepoCreatePermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings for exact GitHub repository creation authority through `permissions.allow`.",
            malicious_case_ids: &["claude-settings-gh-mutation-permissions"],
            benign_case_ids: &["claude-settings-gh-mutation-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(gh repo create:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_gh_repo_create_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh repo create` permissions or replace them with narrower reviewed subcommands that keep repository creation under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGhRepoDeletePermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings for exact GitHub repository deletion authority through `permissions.allow`.",
            malicious_case_ids: &["claude-settings-gh-repo-release-delete-permissions"],
            benign_case_ids: &["claude-settings-gh-repo-release-delete-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(gh repo delete:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_gh_repo_delete_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh repo delete` permissions or replace them with a narrower reviewed workflow that keeps repository deletion under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGhRepoEditPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings for exact GitHub repository settings mutation authority through `permissions.allow`.",
            malicious_case_ids: &["claude-settings-gh-repo-edit-release-create-permissions"],
            benign_case_ids: &["claude-settings-gh-repo-edit-release-create-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(gh repo edit:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_gh_repo_edit_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh repo edit` permissions or replace them with a narrower reviewed workflow that keeps repository settings mutation under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGhRepoTransferPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings for exact GitHub repository transfer authority through `permissions.allow`.",
            malicious_case_ids: &["claude-settings-gh-repo-transfer-release-upload-permissions"],
            benign_case_ids: &["claude-settings-gh-repo-transfer-release-upload-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(gh repo transfer:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_gh_repo_transfer_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh repo transfer` permissions or replace them with a narrower reviewed workflow that keeps repository transfer under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGhReleaseCreatePermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings for exact GitHub release creation authority through `permissions.allow`.",
            malicious_case_ids: &["claude-settings-gh-repo-edit-release-create-permissions"],
            benign_case_ids: &["claude-settings-gh-repo-edit-release-create-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(gh release create:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_gh_release_create_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh release create` permissions or replace them with a narrower reviewed workflow that keeps release publishing under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGhReleaseUploadPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings for exact GitHub release asset upload authority through `permissions.allow`.",
            malicious_case_ids: &["claude-settings-gh-repo-transfer-release-upload-permissions"],
            benign_case_ids: &["claude-settings-gh-repo-transfer-release-upload-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(gh release upload:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_gh_release_upload_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh release upload` permissions or replace them with a narrower reviewed workflow that keeps release asset mutation under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGhReleaseDeletePermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings for exact GitHub release deletion authority through `permissions.allow`.",
            malicious_case_ids: &["claude-settings-gh-repo-release-delete-permissions"],
            benign_case_ids: &["claude-settings-gh-repo-release-delete-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(gh release delete:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_gh_release_delete_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh release delete` permissions or replace them with a narrower reviewed workflow that keeps release deletion under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGhSecretSetPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings for exact GitHub secret mutation authority through `permissions.allow`.",
            malicious_case_ids: &["claude-settings-gh-secret-variable-workflow-permissions"],
            benign_case_ids: &["claude-settings-gh-secret-variable-workflow-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(gh secret set:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_gh_secret_set_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh secret set` permissions or replace them with narrower reviewed subcommands that keep GitHub secret mutation under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGhVariableSetPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings for exact GitHub variable mutation authority through `permissions.allow`.",
            malicious_case_ids: &["claude-settings-gh-secret-variable-workflow-permissions"],
            benign_case_ids: &["claude-settings-gh-secret-variable-workflow-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(gh variable set:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_gh_variable_set_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh variable set` permissions or replace them with narrower reviewed subcommands that keep GitHub variable mutation under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGhWorkflowRunPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings for exact GitHub workflow dispatch authority through `permissions.allow`.",
            malicious_case_ids: &["claude-settings-gh-secret-variable-workflow-permissions"],
            benign_case_ids: &["claude-settings-gh-secret-variable-workflow-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(gh workflow run:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_gh_workflow_run_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh workflow run` permissions or replace them with narrower reviewed subcommands that keep remote workflow dispatch under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGhSecretDeletePermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings for exact GitHub secret deletion authority through `permissions.allow`.",
            malicious_case_ids: &["claude-settings-gh-mutation-permissions"],
            benign_case_ids: &["claude-settings-gh-mutation-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(gh secret delete:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_gh_secret_delete_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh secret delete` permissions or replace them with narrower reviewed subcommands that keep GitHub secret deletion under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGhVariableDeletePermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings for exact GitHub variable deletion authority through `permissions.allow`.",
            malicious_case_ids: &["claude-settings-gh-mutation-permissions"],
            benign_case_ids: &["claude-settings-gh-mutation-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(gh variable delete:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_gh_variable_delete_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh variable delete` permissions or replace them with narrower reviewed subcommands that keep GitHub variable deletion under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGhWorkflowDisablePermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings for exact GitHub workflow disable authority through `permissions.allow`.",
            malicious_case_ids: &["claude-settings-gh-mutation-permissions"],
            benign_case_ids: &["claude-settings-gh-mutation-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(gh workflow disable:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_gh_workflow_disable_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh workflow disable` permissions or replace them with narrower reviewed subcommands that keep workflow disabling under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitFetchPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(git fetch:*)` authority.",
            malicious_case_ids: &["claude-settings-git-fetch-permission"],
            benign_case_ids: &["claude-settings-git-fetch-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(git fetch:*)` entries inside permissions.allow.",
        },
        check: check_claude_settings_git_fetch_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `git fetch` permissions or replace them with a narrower reviewed workflow that keeps repository synchronization under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitLsRemotePermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for wildcard remote repository inspection grants.",
            malicious_case_ids: &["claude-settings-git-ls-remote-permission"],
            benign_case_ids: &["claude-settings-git-ls-remote-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(git ls-remote:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_git_ls_remote_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `git ls-remote` permissions or replace them with a narrower reviewed workflow that keeps remote repository inspection under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsCurlPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for explicit wildcard curl execution grants.",
            malicious_case_ids: &["claude-settings-curl-permission"],
            benign_case_ids: &["claude-settings-curl-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(curl:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_curl_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `Bash(curl:*)` permissions or replace them with a narrower reviewed workflow that keeps direct network downloads under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsWgetPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for explicit wildcard wget execution grants.",
            malicious_case_ids: &["claude-settings-wget-permission"],
            benign_case_ids: &["claude-settings-wget-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(wget:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_wget_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `Bash(wget:*)` permissions or replace them with a narrower reviewed workflow that keeps direct network downloads under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitConfigPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for wildcard git config mutation grants.",
            malicious_case_ids: &["claude-settings-git-config-permission"],
            benign_case_ids: &["claude-settings-git-config-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(git config:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_git_config_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `Bash(git config:*)` permissions or replace them with a narrower reviewed workflow that keeps repository configuration changes under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitTagPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for wildcard git tag mutation grants.",
            malicious_case_ids: &["claude-settings-git-tag-permission"],
            benign_case_ids: &["claude-settings-git-tag-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(git tag:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_git_tag_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `Bash(git tag:*)` permissions or replace them with a narrower reviewed workflow that keeps repository tag mutation under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitBranchPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for wildcard git branch mutation grants.",
            malicious_case_ids: &["claude-settings-git-branch-permission"],
            benign_case_ids: &["claude-settings-git-branch-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(git branch:*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_git_branch_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `Bash(git branch:*)` permissions or replace them with a narrower reviewed workflow that keeps branch mutation under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsEnabledMcpjsonServersRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `enabledMcpjsonServers` enablement.",
            malicious_case_ids: &["claude-settings-enabled-mcpjson-servers"],
            benign_case_ids: &["claude-settings-empty-enabled-mcpjson-servers-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact non-empty `enabledMcpjsonServers` detection in parsed Claude settings JSON.",
        },
        check: check_claude_settings_enabled_mcpjson_servers,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `enabledMcpjsonServers` defaults or keep MCP server enablement as a locally reviewed opt-in step",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsPackageInstallPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for broad package installation authority.",
            malicious_case_ids: &["claude-settings-package-install-permission"],
            benign_case_ids: &["claude-settings-bash-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string-family detection for package installation permissions such as `Bash(pip install)` or `Bash(npm install)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_package_install_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared package installation permissions or replace them with a narrower reviewed wrapper that avoids blanket package-manager installs in default team config",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsNpxPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(npx ...)` mutable package-runner authority.",
            malicious_case_ids: &["claude-settings-npx-permission"],
            benign_case_ids: &["claude-settings-npx-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(npx ...)` entries inside permissions.allow.",
        },
        check: check_claude_settings_npx_permission,
        safe_fix: None,
        suggestion_message: Some(
            "replace shared `Bash(npx ...)` permissions with a pinned wrapper or a narrower reviewed command permission that does not grant mutable package execution by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsUvxPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(uvx ...)` mutable package-runner authority.",
            malicious_case_ids: &["claude-settings-mutable-runner-permissions"],
            benign_case_ids: &["claude-settings-package-runner-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(uvx ...)` entries inside permissions.allow.",
        },
        check: check_claude_settings_uvx_permission,
        safe_fix: None,
        suggestion_message: Some(
            "replace shared `Bash(uvx ...)` permissions with a pinned wrapper or a narrower reviewed command permission that does not grant mutable package execution by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsNpmExecPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(npm exec ...)` mutable package-runner authority.",
            malicious_case_ids: &["claude-settings-npm-exec-bunx-permissions"],
            benign_case_ids: &["claude-settings-npm-exec-bunx-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(npm exec ...)` entries inside permissions.allow.",
        },
        check: check_claude_settings_npm_exec_permission,
        safe_fix: None,
        suggestion_message: Some(
            "replace shared `Bash(npm exec ...)` permissions with a pinned wrapper or a narrower reviewed command permission that does not grant mutable package execution by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsBunxPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(bunx ...)` mutable package-runner authority.",
            malicious_case_ids: &["claude-settings-npm-exec-bunx-permissions"],
            benign_case_ids: &["claude-settings-npm-exec-bunx-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(bunx ...)` entries inside permissions.allow.",
        },
        check: check_claude_settings_bunx_permission,
        safe_fix: None,
        suggestion_message: Some(
            "replace shared `Bash(bunx ...)` permissions with a pinned wrapper or a narrower reviewed command permission that does not grant mutable package execution by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsPnpmDlxPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(pnpm dlx ...)` mutable package-runner authority.",
            malicious_case_ids: &["claude-settings-mutable-runner-permissions"],
            benign_case_ids: &["claude-settings-package-runner-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(pnpm dlx ...)` entries inside permissions.allow.",
        },
        check: check_claude_settings_pnpm_dlx_permission,
        safe_fix: None,
        suggestion_message: Some(
            "replace shared `Bash(pnpm dlx ...)` permissions with a pinned wrapper or a narrower reviewed command permission that does not grant mutable package execution by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsYarnDlxPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(yarn dlx ...)` mutable package-runner authority.",
            malicious_case_ids: &["claude-settings-mutable-runner-permissions"],
            benign_case_ids: &["claude-settings-package-runner-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(yarn dlx ...)` entries inside permissions.allow.",
        },
        check: check_claude_settings_yarn_dlx_permission,
        safe_fix: None,
        suggestion_message: Some(
            "replace shared `Bash(yarn dlx ...)` permissions with a pinned wrapper or a narrower reviewed command permission that does not grant mutable package execution by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsPipxRunPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(pipx run ...)` mutable package-runner authority.",
            malicious_case_ids: &["claude-settings-mutable-runner-permissions"],
            benign_case_ids: &["claude-settings-package-runner-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(pipx run ...)` entries inside permissions.allow.",
        },
        check: check_claude_settings_pipx_run_permission,
        safe_fix: None,
        suggestion_message: Some(
            "replace shared `Bash(pipx run ...)` permissions with a pinned wrapper or a narrower reviewed command permission that does not grant mutable package execution by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitCheckoutPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(git checkout:*)` authority.",
            malicious_case_ids: &["claude-settings-git-checkout-permission"],
            benign_case_ids: &["claude-settings-git-checkout-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(git checkout:*)` entries inside permissions.allow.",
        },
        check: check_claude_settings_git_checkout_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `Bash(git checkout:*)` permissions, or replace them with a narrower reviewed workflow that does not grant broad checkout authority by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitCommitPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(git commit:*)` authority.",
            malicious_case_ids: &["claude-settings-git-commit-permission"],
            benign_case_ids: &["claude-settings-git-commit-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(git commit:*)` entries inside permissions.allow.",
        },
        check: check_claude_settings_git_commit_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `Bash(git commit:*)` permissions, or replace them with a narrower reviewed workflow that does not grant broad commit authority by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitStashPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(git stash:*)` authority.",
            malicious_case_ids: &["claude-settings-git-stash-permission"],
            benign_case_ids: &["claude-settings-git-stash-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(git stash:*)` entries inside permissions.allow.",
        },
        check: check_claude_settings_git_stash_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `Bash(git stash:*)` permissions, or replace them with a narrower reviewed workflow that does not grant broad stash authority by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitResetPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(git reset:*)` authority.",
            malicious_case_ids: &["claude-settings-destructive-git-permissions"],
            benign_case_ids: &["claude-settings-destructive-git-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(git reset:*)` entries inside permissions.allow.",
        },
        check: check_claude_settings_git_reset_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `Bash(git reset:*)` permissions, or replace them with a narrower reviewed workflow that does not grant broad reset authority by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitCleanPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(git clean:*)` authority.",
            malicious_case_ids: &["claude-settings-destructive-git-permissions"],
            benign_case_ids: &["claude-settings-destructive-git-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(git clean:*)` entries inside permissions.allow.",
        },
        check: check_claude_settings_git_clean_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `Bash(git clean:*)` permissions, or replace them with a narrower reviewed workflow that does not grant broad cleanup authority by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitRestorePermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(git restore:*)` authority.",
            malicious_case_ids: &["claude-settings-destructive-git-permissions"],
            benign_case_ids: &["claude-settings-destructive-git-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(git restore:*)` entries inside permissions.allow.",
        },
        check: check_claude_settings_git_restore_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `Bash(git restore:*)` permissions, or replace them with a narrower reviewed workflow that does not grant broad restore authority by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitRebasePermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(git rebase:*)` authority.",
            malicious_case_ids: &["claude-settings-destructive-git-permissions"],
            benign_case_ids: &["claude-settings-destructive-git-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(git rebase:*)` entries inside permissions.allow.",
        },
        check: check_claude_settings_git_rebase_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `Bash(git rebase:*)` permissions, or replace them with a narrower reviewed workflow that does not grant broad history-rewrite authority by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitMergePermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(git merge:*)` authority.",
            malicious_case_ids: &["claude-settings-destructive-git-permissions"],
            benign_case_ids: &["claude-settings-destructive-git-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(git merge:*)` entries inside permissions.allow.",
        },
        check: check_claude_settings_git_merge_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `Bash(git merge:*)` permissions, or replace them with a narrower reviewed workflow that does not grant broad merge authority by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitCherryPickPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(git cherry-pick:*)` authority.",
            malicious_case_ids: &["claude-settings-destructive-git-permissions"],
            benign_case_ids: &["claude-settings-destructive-git-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(git cherry-pick:*)` entries inside permissions.allow.",
        },
        check: check_claude_settings_git_cherry_pick_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `Bash(git cherry-pick:*)` permissions, or replace them with a narrower reviewed workflow that does not grant broad cherry-pick authority by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitApplyPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(git apply:*)` authority.",
            malicious_case_ids: &["claude-settings-destructive-git-permissions"],
            benign_case_ids: &["claude-settings-destructive-git-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(git apply:*)` entries inside permissions.allow.",
        },
        check: check_claude_settings_git_apply_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `Bash(git apply:*)` permissions, or replace them with a narrower reviewed workflow that does not grant broad patch-application authority by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGitAmPermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for exact `Bash(git am:*)` authority.",
            malicious_case_ids: &["claude-settings-destructive-git-permissions"],
            benign_case_ids: &["claude-settings-destructive-git-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact permission detection for `Bash(git am:*)` entries inside permissions.allow.",
        },
        check: check_claude_settings_git_am_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `Bash(git am:*)` permissions, or replace them with a narrower reviewed workflow that does not grant broad mail-patch application authority by default",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGlobWildcardRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for explicit wildcard `Glob(*)` grants.",
            malicious_case_ids: &["claude-settings-glob-wildcard"],
            benign_case_ids: &["claude-settings-glob-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Glob(*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_glob_wildcard,
        safe_fix: None,
        suggestion_message: Some(
            "replace `Glob(*)` with a narrower allowlist of reviewed glob patterns or remove broad file-discovery access from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGrepWildcardRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for explicit wildcard `Grep(*)` grants.",
            malicious_case_ids: &["claude-settings-grep-wildcard"],
            benign_case_ids: &["claude-settings-grep-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Grep(*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_grep_wildcard,
        safe_fix: None,
        suggestion_message: Some(
            "replace `Grep(*)` with a narrower allowlist of reviewed grep patterns or remove broad content-search access from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsExternalAbsoluteHookCommandRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: COMPAT_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for repo-external absolute hook command paths.",
            malicious_case_ids: &["claude-settings-repo-external-absolute-hook-path"],
            benign_case_ids: &["claude-settings-repo-external-absolute-hook-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact command-path analysis for repo-external absolute hook commands in parsed Claude settings JSON.",
        },
        check: check_claude_settings_external_absolute_hook_command,
        safe_fix: None,
        suggestion_message: Some(
            "replace the repo-external absolute hook path with a project-scoped wrapper or a repo-relative path rooted in `$CLAUDE_PROJECT_DIR`",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsWebFetchWildcardRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for explicit wildcard `WebFetch(*)` grants.",
            malicious_case_ids: &["claude-settings-webfetch-wildcard"],
            benign_case_ids: &["claude-settings-webfetch-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `WebFetch(*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_webfetch_wildcard,
        safe_fix: None,
        suggestion_message: Some(
            "replace `WebFetch(*)` with a narrower allowlist of reviewed fetch patterns or remove broad network access from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsDangerousHttpHookHostRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: SUPPLY_CHAIN_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for dangerous host literals in `allowedHttpHookUrls`.",
            malicious_case_ids: &["claude-settings-dangerous-http-hook-host"],
            benign_case_ids: &["claude-settings-http-hook-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact host analysis over `allowedHttpHookUrls` entries in parsed Claude settings JSON.",
        },
        check: check_claude_settings_dangerous_http_hook_host,
        safe_fix: None,
        suggestion_message: Some(
            "remove metadata or private-network host literals from `allowedHttpHookUrls` and replace them with reviewed public endpoints",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsInsecureHttpHookUrlRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: SUPPLY_CHAIN_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for non-HTTPS `allowedHttpHookUrls` entries.",
            malicious_case_ids: &["claude-settings-http-hook-url"],
            benign_case_ids: &["claude-settings-http-hook-loopback-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact URL-scheme analysis over `allowedHttpHookUrls` entries in parsed Claude settings JSON.",
        },
        check: check_claude_settings_insecure_http_hook_url,
        safe_fix: None,
        suggestion_message: Some(
            "replace non-HTTPS `allowedHttpHookUrls` entries with reviewed `https://` endpoints or remove them from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsBypassPermissionsRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings for explicit `permissions.defaultMode = bypassPermissions`.",
            malicious_case_ids: &["claude-settings-bypass-permissions"],
            benign_case_ids: &["claude-settings-bypass-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `permissions.defaultMode = bypassPermissions` on parsed Claude settings JSON.",
        },
        check: check_claude_settings_bypass_permissions,
        safe_fix: None,
        suggestion_message: Some(
            "replace `permissions.defaultMode = bypassPermissions` with a narrower shared permissions mode and explicit reviewed allowlists",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsHomeDirectoryHookCommandRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: COMPAT_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for hook commands rooted in the home directory.",
            malicious_case_ids: &["claude-settings-home-directory-hook-path"],
            benign_case_ids: &["claude-settings-home-directory-safe-project-scoped"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact command-path analysis for home-directory rooted hook commands in parsed Claude settings JSON.",
        },
        check: check_claude_settings_home_directory_hook_command,
        safe_fix: None,
        suggestion_message: Some(
            "replace the home-directory hook path with a project-scoped wrapper or a repo-relative path rooted in `$CLAUDE_PROJECT_DIR`",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsUnscopedBashRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for exact bare `Bash` grants.",
            malicious_case_ids: &["claude-settings-bash-wildcard"],
            benign_case_ids: &["claude-settings-bash-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for bare `Bash` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_unscoped_bash,
        safe_fix: None,
        suggestion_message: Some(
            "replace bare `Bash` with a narrower allowlist of reviewed command patterns in the committed Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsUnscopedReadRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for exact bare `Read` grants.",
            malicious_case_ids: &["claude-settings-unscoped-tool-family"],
            benign_case_ids: &["claude-settings-unscoped-tool-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for bare `Read` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_unscoped_read,
        safe_fix: None,
        suggestion_message: Some(
            "replace bare `Read` with a narrower reviewed permission pattern or remove broad file-read access from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsUnscopedWriteRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for exact bare `Write` grants.",
            malicious_case_ids: &["claude-settings-unscoped-tool-family"],
            benign_case_ids: &["claude-settings-unscoped-tool-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for bare `Write` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_unscoped_write,
        safe_fix: None,
        suggestion_message: Some(
            "replace bare `Write` with a narrower reviewed permission pattern or remove broad file-write access from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsUnscopedEditRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for exact bare `Edit` grants.",
            malicious_case_ids: &["claude-settings-unscoped-tool-family"],
            benign_case_ids: &["claude-settings-unscoped-tool-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for bare `Edit` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_unscoped_edit,
        safe_fix: None,
        suggestion_message: Some(
            "replace bare `Edit` with a narrower reviewed permission pattern or remove broad edit access from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsUnscopedGlobRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for exact bare `Glob` grants.",
            malicious_case_ids: &["claude-settings-unscoped-tool-family"],
            benign_case_ids: &["claude-settings-unscoped-tool-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for bare `Glob` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_unscoped_glob,
        safe_fix: None,
        suggestion_message: Some(
            "replace bare `Glob` with a narrower reviewed permission pattern or remove broad file-discovery access from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsUnscopedGrepRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for exact bare `Grep` grants.",
            malicious_case_ids: &["claude-settings-unscoped-tool-family"],
            benign_case_ids: &["claude-settings-unscoped-tool-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for bare `Grep` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_unscoped_grep,
        safe_fix: None,
        suggestion_message: Some(
            "replace bare `Grep` with a narrower reviewed permission pattern or remove broad search access from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsUnscopedWebFetchRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for exact bare `WebFetch` grants.",
            malicious_case_ids: &["claude-settings-unscoped-tool-family"],
            benign_case_ids: &["claude-settings-unscoped-tool-family-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for bare `WebFetch` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_unscoped_webfetch,
        safe_fix: None,
        suggestion_message: Some(
            "replace bare `WebFetch` with a narrower reviewed permission pattern or remove broad fetch access from the shared Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsBashWildcardRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: GOVERNANCE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared Claude settings permissions for explicit wildcard `Bash(*)` grants.",
            malicious_case_ids: &["claude-settings-bash-wildcard"],
            benign_case_ids: &["claude-settings-bash-specific-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact string detection for `Bash(*)` inside permissions.allow on parsed Claude settings JSON.",
        },
        check: check_claude_settings_bash_wildcard,
        safe_fix: None,
        suggestion_message: Some(
            "replace `Bash(*)` with a narrower allowlist of reviewed command patterns in the committed Claude settings file",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsMissingSchemaRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: COMPAT_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks shared committed Claude settings for omission of a top-level `$schema` reference.",
            malicious_case_ids: &["claude-settings-missing-schema"],
            benign_case_ids: &["claude-settings-schema-present-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals exact top-level `$schema` presence detection in parsed Claude settings JSON.",
        },
        check: check_claude_settings_missing_schema,
        safe_fix: None,
        suggestion_message: Some(
            "add the Claude settings SchemaStore URL as top-level `$schema`, for example `https://json.schemastore.org/claude-code-settings.json`",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsMutableLauncherRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: RECOMMENDED_BASE_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for mutable package launcher forms such as npx, uvx, pnpm dlx, yarn dlx, and pipx run.",
            malicious_case_ids: &["claude-settings-mutable-launcher"],
            benign_case_ids: &["claude-settings-pinned-launcher-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook analysis over committed .claude/settings.json or claude/settings.json objects with type == command under hooks.",
        },
        check: check_claude_settings_mutable_launcher,
        safe_fix: None,
        suggestion_message: Some(
            "replace the mutable package launcher in the committed Claude hook with a vendored, pinned, or otherwise reproducible execution path",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsInlineDownloadExecRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: SUPPLY_CHAIN_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit curl|shell or wget|shell execution chains.",
            malicious_case_ids: &["claude-settings-inline-download-exec"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command, limited to explicit download-pipe-shell patterns.",
        },
        check: check_claude_settings_inline_download_exec,
        safe_fix: None,
        suggestion_message: Some(
            "remove the inline download-and-exec flow from the committed Claude hook command and pin or vendor the fetched content instead",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsNetworkTlsBypassRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: SUPPLY_CHAIN_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit TLS-bypass tokens in a network-capable execution context.",
            malicious_case_ids: &["claude-settings-command-tls-bypass"],
            benign_case_ids: &["claude-settings-network-tls-verified-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command, gated by network markers plus TLS-bypass tokens.",
        },
        check: check_claude_settings_network_tls_bypass,
        safe_fix: None,
        suggestion_message: Some(
            "remove TLS-bypass flags or NODE_TLS_REJECT_UNAUTHORIZED=0 from the network-capable Claude hook command",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsRootDeleteRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit `rm`-style destructive root deletion payloads.",
            malicious_case_ids: &["claude-settings-hook-persistence-escalation"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for `rm` with recursive+force flags targeting `/` or using `--no-preserve-root`.",
        },
        check: check_claude_settings_root_delete,
        safe_fix: None,
        suggestion_message: Some(
            "remove the destructive root deletion command from the committed Claude hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsPasswordFileAccessRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for direct access to sensitive password and sudo policy files.",
            malicious_case_ids: &["claude-settings-hook-persistence-escalation"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook path detection over committed hook entries with type == command for `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/etc/gshadow`, or `/etc/master.passwd`.",
        },
        check: check_claude_settings_password_file_access,
        safe_fix: None,
        suggestion_message: Some(
            "remove the sensitive password-file access from the committed Claude hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsShellProfileWriteRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit writes to shell startup profile files.",
            malicious_case_ids: &["claude-settings-hook-persistence-escalation"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook analysis over committed hook entries with type == command using redirection-or-tee targeting of `.bashrc`, `.bash_profile`, `.zshrc`, or `.profile`.",
        },
        check: check_claude_settings_shell_profile_write,
        safe_fix: None,
        suggestion_message: Some(
            "remove the shell profile write and keep startup-file persistence out of the committed Claude hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsAuthorizedKeysWriteRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit writes to SSH `authorized_keys`.",
            malicious_case_ids: &["claude-settings-hook-persistence-escalation"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook analysis over committed hook entries with type == command using redirection-or-tee targeting of `authorized_keys`.",
        },
        check: check_claude_settings_authorized_keys_write,
        safe_fix: None,
        suggestion_message: Some(
            "remove the `authorized_keys` modification from the committed Claude hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsCronPersistenceRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit cron persistence setup.",
            malicious_case_ids: &["claude-settings-hook-service-persistence"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for `crontab` mutation or writes to cron persistence paths.",
        },
        check: check_claude_settings_cron_persistence,
        safe_fix: None,
        suggestion_message: Some(
            "remove cron persistence from the committed Claude hook and keep scheduled-task changes under explicit review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsSystemdServiceRegistrationRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit systemd service registration or unit-file writes.",
            malicious_case_ids: &["claude-settings-hook-service-persistence"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for `systemctl enable|link` or writes to systemd unit paths.",
        },
        check: check_claude_settings_systemd_service_registration,
        safe_fix: None,
        suggestion_message: Some(
            "remove systemd persistence from the committed Claude hook and keep service registration out of shared hooks",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsLaunchdRegistrationRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit launchd registration or LaunchAgents/LaunchDaemons plist writes.",
            malicious_case_ids: &["claude-settings-hook-service-persistence"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for `launchctl load|bootstrap` or writes to LaunchAgents/LaunchDaemons plist paths.",
        },
        check: check_claude_settings_launchd_registration,
        safe_fix: None,
        suggestion_message: Some(
            "remove launchd persistence from the committed Claude hook and keep plist registration out of shared hooks",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsInsecurePermissionChangeRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit insecure chmod payloads.",
            malicious_case_ids: &["claude-settings-hook-privilege-escalation-payloads"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for `chmod 777`, `chmod 0777`, or symbolic world-writable modes such as `a+rwx`.",
        },
        check: check_claude_settings_insecure_permission_change,
        safe_fix: None,
        suggestion_message: Some(
            "remove the insecure chmod change from the committed Claude hook and use the minimum required permissions",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsSetuidSetgidRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit setuid or setgid chmod payloads.",
            malicious_case_ids: &["claude-settings-hook-privilege-escalation-payloads"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for chmod octal modes with setuid/setgid bits or symbolic modes such as `u+s` and `g+s`.",
        },
        check: check_claude_settings_setuid_setgid,
        safe_fix: None,
        suggestion_message: Some(
            "remove setuid or setgid manipulation from the committed Claude hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsLinuxCapabilityManipulationRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit Linux capability manipulation payloads.",
            malicious_case_ids: &["claude-settings-hook-privilege-escalation-payloads"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for `setcap` or dangerous Linux capability tokens such as `cap_setuid` and `cap_sys_admin`.",
        },
        check: check_claude_settings_linux_capability_manipulation,
        safe_fix: None,
        suggestion_message: Some(
            "remove Linux capability manipulation from the committed Claude hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsSecretExfilRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit secret-bearing network exfil payloads.",
            malicious_case_ids: &["claude-settings-hook-secret-exfil-payloads"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for secret markers combined with network-capable command context.",
        },
        check: check_claude_settings_secret_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove the secret-bearing network send from the committed Claude hook and keep secret access local",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsPlainHttpSecretExfilRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for secret-bearing exfil over insecure HTTP.",
            malicious_case_ids: &["claude-settings-hook-secret-exfil-payloads"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for `http://` endpoints gated by concurrent secret markers in a network-capable command path.",
        },
        check: check_claude_settings_plain_http_secret_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove the insecure secret-bearing HTTP send from the committed Claude hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsWebhookSecretExfilRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for secret-bearing posts to webhook endpoints.",
            malicious_case_ids: &["claude-settings-hook-secret-exfil-payloads"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for secret markers plus webhook endpoint markers such as `hooks.slack.com/services/` or `discord.com/api/webhooks/`.",
        },
        check: check_claude_settings_webhook_secret_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove the secret-bearing webhook post from the committed Claude hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsSensitiveFileExfilRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit transfer of sensitive credential files to remote destinations.",
            malicious_case_ids: &[
                "claude-settings-hook-sensitive-file-exfil",
                "claude-settings-hook-sensitive-file-rclone-exfil",
            ],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for sensitive file paths such as `.env`, `.aws/credentials`, `.ssh/id_rsa`, or `.kube/config` combined with transfer commands like `scp`, `sftp`, `rsync`, `curl`, `aws s3 cp`, `gsutil cp`, or `rclone copy`.",
        },
        check: check_claude_settings_sensitive_file_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove the remote transfer of sensitive credential files from the committed Claude hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsClipboardReadRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for clipboard-reading behavior that can extract local user data.",
            malicious_case_ids: &["claude-settings-hook-local-data-theft"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for clipboard read utilities such as `pbpaste`, `wl-paste`, `xclip -o`, `xsel --output`, or PowerShell `Get-Clipboard`.",
        },
        check: check_claude_settings_clipboard_read,
        safe_fix: None,
        suggestion_message: Some("remove clipboard reads from the committed Claude hook"),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsBrowserSecretStoreAccessRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for direct access to browser credential or cookie storage files.",
            malicious_case_ids: &["claude-settings-hook-local-data-theft"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for browser profile paths such as Chrome or Firefox state directories paired with secret-store files like `Cookies`, `Login Data`, `logins.json`, `key4.db`, `Web Data`, or `Local State`.",
        },
        check: check_claude_settings_browser_secret_store_access,
        safe_fix: None,
        suggestion_message: Some(
            "remove browser credential or cookie store access from the committed Claude hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsClipboardExfilRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for clipboard-reading behavior that also transmits captured data to remote destinations.",
            malicious_case_ids: &["claude-settings-hook-local-data-exfil"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for clipboard read utilities such as `pbpaste`, `wl-paste`, `xclip -o`, `xsel --output`, or PowerShell `Get-Clipboard` combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_claude_settings_clipboard_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove network exfiltration of clipboard contents from the committed Claude hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsBrowserSecretStoreExfilRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for direct access to browser credential or cookie storage files combined with remote transfer behavior.",
            malicious_case_ids: &["claude-settings-hook-local-data-exfil"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for browser profile paths such as Chrome or Firefox state directories paired with secret-store files like `Cookies`, `Login Data`, `logins.json`, `key4.db`, `Web Data`, or `Local State`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_claude_settings_browser_secret_store_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove network exfiltration of browser credential or cookie store data from the committed Claude hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsScreenCaptureRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit screen capture utilities.",
            malicious_case_ids: &[
                "claude-settings-hook-screen-capture",
                "claude-settings-hook-screen-capture-exfil",
            ],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for explicit screen capture utilities such as `screencapture`, `scrot`, `gnome-screenshot`, `grim`, `maim`, `grimshot`, ImageMagick `import -window root`, or PowerShell `CopyFromScreen`.",
        },
        check: check_claude_settings_screen_capture,
        safe_fix: None,
        suggestion_message: Some(
            "remove screenshot capture behavior from the committed Claude hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsScreenCaptureExfilRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit screen capture utilities combined with remote transfer behavior.",
            malicious_case_ids: &["claude-settings-hook-screen-capture-exfil"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for explicit screen capture utilities such as `screencapture`, `scrot`, `gnome-screenshot`, `grim`, `maim`, `grimshot`, ImageMagick `import -window root`, or PowerShell `CopyFromScreen`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_claude_settings_screen_capture_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove screenshot capture and remote transfer behavior from the committed Claude hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsCameraCaptureRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit webcam or camera capture utilities.",
            malicious_case_ids: &[
                "claude-settings-hook-device-capture",
                "claude-settings-hook-device-capture-exfil",
            ],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for explicit camera capture utilities such as `imagesnap`, `fswebcam`, or `ffmpeg` with camera-oriented selectors like `video=`, `/dev/video`, `-f v4l2`, `-f video4linux2`, `webcam`, or `camera`.",
        },
        check: check_claude_settings_camera_capture,
        safe_fix: None,
        suggestion_message: Some(
            "remove webcam or camera capture behavior from the committed Claude hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsMicrophoneCaptureRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit microphone recording utilities.",
            malicious_case_ids: &[
                "claude-settings-hook-device-capture",
                "claude-settings-hook-device-capture-exfil",
            ],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for explicit microphone capture utilities such as `arecord`, `parecord`, `parec`, `rec`, `sox -d`, or `ffmpeg` with audio-oriented selectors like `audio=`, `-f alsa`, `-f pulse`, `microphone`, or ` mic`.",
        },
        check: check_claude_settings_microphone_capture,
        safe_fix: None,
        suggestion_message: Some(
            "remove microphone capture behavior from the committed Claude hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsCameraCaptureExfilRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit webcam or camera capture utilities combined with remote transfer behavior.",
            malicious_case_ids: &["claude-settings-hook-device-capture-exfil"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for explicit camera capture utilities such as `imagesnap`, `fswebcam`, or `ffmpeg` with camera-oriented selectors like `video=`, `/dev/video`, `-f v4l2`, `-f video4linux2`, `webcam`, or `camera`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_claude_settings_camera_capture_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove webcam or camera capture and remote transfer behavior from the committed Claude hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsMicrophoneCaptureExfilRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit microphone recording utilities combined with remote transfer behavior.",
            malicious_case_ids: &["claude-settings-hook-device-capture-exfil"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for explicit microphone capture utilities such as `arecord`, `parecord`, `parec`, `rec`, `sox -d`, or `ffmpeg` with audio-oriented selectors like `audio=`, `-f alsa`, `-f pulse`, `microphone`, or ` mic`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_claude_settings_microphone_capture_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove microphone capture and remote transfer behavior from the committed Claude hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsKeyloggingRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit keystroke capture utilities or keylogger markers.",
            malicious_case_ids: &[
                "claude-settings-hook-keylogger",
                "claude-settings-hook-keylogger-exfil",
            ],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for explicit keylogger primitives such as `logkeys`, `xinput test`, `evtest`, `showkey`, PowerShell `GetAsyncKeyState`, or inline Python listener markers like `pynput.keyboard.Listener`.",
        },
        check: check_claude_settings_keylogging,
        safe_fix: None,
        suggestion_message: Some(
            "remove keystroke capture or keylogger behavior from the committed Claude hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsKeyloggingExfilRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit keystroke capture utilities or keylogger markers combined with remote transfer behavior.",
            malicious_case_ids: &["claude-settings-hook-keylogger-exfil"],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for explicit keylogger primitives such as `logkeys`, `xinput test`, `evtest`, `showkey`, PowerShell `GetAsyncKeyState`, or inline Python listener markers like `pynput.keyboard.Listener`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_claude_settings_keylogging_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove keystroke capture and remote transfer behavior from the committed Claude hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsEnvironmentDumpRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit environment or shell-state enumeration commands.",
            malicious_case_ids: &[
                "claude-settings-hook-env-dump",
                "claude-settings-hook-env-dump-exfil",
                "claude-settings-hook-env-dump-cloud-exfil",
            ],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for explicit environment enumeration primitives such as `printenv`, `env` used as a dump, `export -p`, `declare -xp`, or `compgen -v`.",
        },
        check: check_claude_settings_environment_dump,
        safe_fix: None,
        suggestion_message: Some(
            "remove environment dumping behavior from the committed Claude hook",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsEnvironmentDumpExfilRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: THREAT_REVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks committed Claude settings command hooks for explicit environment or shell-state enumeration commands combined with remote transfer behavior.",
            malicious_case_ids: &[
                "claude-settings-hook-env-dump-exfil",
                "claude-settings-hook-env-dump-cloud-exfil",
            ],
            benign_case_ids: &["claude-settings-network-command-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "ClaudeSettingsSignals command-hook string analysis over committed hook entries with type == command for explicit environment enumeration primitives such as `printenv`, `env` used as a dump, `export -p`, `declare -xp`, or `compgen -v`, combined with remote sinks such as `curl`, `wget`, `scp`, `sftp`, `rsync`, `nc`, `aws s3 cp`, `gsutil cp`, `rclone copy`, or HTTP(S) endpoints.",
        },
        check: check_claude_settings_environment_dump_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove environment dumping and remote transfer behavior from the committed Claude hook",
        ),
        suggestion_fix: None,
    },
];

pub(crate) fn rule_specs() -> &'static [NativeRuleSpec] {
    &RULE_SPECS
}
