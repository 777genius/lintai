use lintai_api::{Category, Confidence, RuleTier, Severity, declare_rule};

use super::*;
use crate::claude_settings_rules::{
    check_claude_settings_bash_wildcard, check_claude_settings_bunx_permission,
    check_claude_settings_bypass_permissions, check_claude_settings_curl_permission,
    check_claude_settings_dangerous_http_hook_host, check_claude_settings_edit_unsafe_path,
    check_claude_settings_edit_wildcard, check_claude_settings_enabled_mcpjson_servers,
    check_claude_settings_external_absolute_hook_command,
    check_claude_settings_gh_api_delete_permission, check_claude_settings_gh_api_patch_permission,
    check_claude_settings_gh_api_post_permission, check_claude_settings_gh_api_put_permission,
    check_claude_settings_gh_issue_create_permission, check_claude_settings_gh_pr_permission,
    check_claude_settings_gh_release_create_permission,
    check_claude_settings_gh_release_delete_permission,
    check_claude_settings_gh_repo_create_permission,
    check_claude_settings_gh_repo_delete_permission, check_claude_settings_gh_repo_edit_permission,
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
    check_claude_settings_insecure_http_hook_url, check_claude_settings_invalid_hook_matcher_event,
    check_claude_settings_missing_hook_timeout,
    check_claude_settings_missing_required_hook_matcher, check_claude_settings_missing_schema,
    check_claude_settings_mutable_launcher, check_claude_settings_network_tls_bypass,
    check_claude_settings_npm_exec_permission, check_claude_settings_npx_permission,
    check_claude_settings_package_install_permission, check_claude_settings_pipx_run_permission,
    check_claude_settings_pnpm_dlx_permission, check_claude_settings_read_unsafe_path,
    check_claude_settings_read_wildcard, check_claude_settings_unscoped_websearch,
    check_claude_settings_uvx_permission, check_claude_settings_webfetch_raw_githubusercontent,
    check_claude_settings_webfetch_wildcard, check_claude_settings_websearch_wildcard,
    check_claude_settings_wget_permission, check_claude_settings_write_unsafe_path,
    check_claude_settings_write_wildcard, check_claude_settings_yarn_dlx_permission,
};
use crate::registry::presets::PREVIEW_CLAUDE_PRESETS;

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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
        tier: RuleTier::Preview,
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
    pub struct ClaudeSettingsBashWildcardRule {
        code: "SEC362",
        summary: "Claude settings permissions allow `Bash(*)` in a shared committed config",
        doc_title: "Claude settings: wildcard Bash permissions",
        category: Category::Security,
        default_severity: Severity::Warn,
        default_confidence: Confidence::High,
        tier: RuleTier::Preview,
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

pub(crate) const RULE_SPECS: [NativeRuleSpec; 74] = [
    NativeRuleSpec {
        metadata: ClaudeSettingsInvalidHookMatcherEventRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Unsupported hook-event matchers in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Missing matchers on matcher-capable Claude hook events are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Missing command-hook timeouts in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Wildcard Write grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Wildcard Read grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Wildcard Edit grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Unsafe Read path grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Unsafe Write path grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Unsafe Edit path grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Unsafe Glob path grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Unsafe Grep path grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Wildcard WebSearch grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Bare WebSearch grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared git push permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `git add` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `git clone` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `gh pr` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `gh api --method POST` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `gh api --method DELETE` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `gh api --method PATCH` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `gh api --method PUT` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `gh issue create` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `gh repo create` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `gh repo delete` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `gh repo edit` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_gh_repo_edit_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh repo edit` permissions or replace them with a narrower reviewed workflow that keeps repository settings mutation under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGhReleaseCreatePermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `gh release create` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_gh_release_create_permission,
        safe_fix: None,
        suggestion_message: Some(
            "remove shared `gh release create` permissions or replace them with a narrower reviewed workflow that keeps release publishing under explicit user control",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsGhReleaseDeletePermissionRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `gh release delete` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `gh secret set` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `gh variable set` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `gh workflow run` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `gh secret delete` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `gh variable delete` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `gh workflow disable` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `git fetch` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `git ls-remote` permissions in committed Claude settings are deterministic, but the first release stays guidance-only until ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `enabledMcpjsonServers` in committed Claude settings is deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared package installation permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `Bash(npx ...)` permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `Bash(uvx ...)` permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `Bash(npm exec ...)` permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `Bash(bunx ...)` permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `Bash(pnpm dlx ...)` permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `Bash(yarn dlx ...)` permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared `Bash(pipx run ...)` permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared git checkout permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared git commit permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared git stash permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared git reset permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared git clean permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared git restore permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared git rebase permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared git merge permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared git cherry-pick permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared git apply permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Shared git am permissions in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Wildcard Glob grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Wildcard Grep grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Repo-external absolute hook paths in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Wildcard WebFetch grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Committed Claude settings with dangerous host literals in `allowedHttpHookUrls` are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Committed Claude settings with non-HTTPS `allowedHttpHookUrls` entries are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Committed Claude settings with `permissions.defaultMode = bypassPermissions` are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Home-directory hook paths in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
        },
        check: check_claude_settings_home_directory_hook_command,
        safe_fix: None,
        suggestion_message: Some(
            "replace the home-directory hook path with a project-scoped wrapper or a repo-relative path rooted in `$CLAUDE_PROJECT_DIR`",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: ClaudeSettingsBashWildcardRule::METADATA,
        surface: Surface::ClaudeSettings,
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Wildcard Bash grants in shared Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: PREVIEW_CLAUDE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Preview {
            blocker: "Schema references in committed Claude settings are deterministic, but the first release stays guidance-only while ecosystem usefulness is measured.",
            promotion_requirements: STRUCTURAL_PREVIEW_REQUIREMENTS,
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
        default_presets: BASE_CLAUDE_PRESETS,
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
        default_presets: BASE_CLAUDE_PRESETS,
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
        default_presets: BASE_CLAUDE_PRESETS,
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
];
