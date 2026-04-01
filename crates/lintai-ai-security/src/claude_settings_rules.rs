use lintai_api::{Finding, RuleMetadata, ScanContext, Span};

use crate::helpers::finding_for_region;
use crate::signals::ArtifactSignals;

pub(crate) fn check_claude_settings_mutable_launcher(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.mutable_launcher_span.clone()),
        "Claude settings command hook uses a mutable package launcher",
    )
}

pub(crate) fn check_claude_settings_missing_schema(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.missing_schema_span.clone()),
        "Claude settings file is missing a top-level `$schema` reference",
    )
}

pub(crate) fn check_claude_settings_missing_hook_timeout(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.missing_hook_timeout_span.clone()),
        "Claude settings command hook is missing an explicit `timeout` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_invalid_hook_matcher_event(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.invalid_hook_matcher_event_span.clone()),
        "Claude settings use `matcher` on a hook event that does not support it",
    )
}

pub(crate) fn check_claude_settings_missing_required_hook_matcher(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.missing_required_hook_matcher_span.clone()),
        "Claude settings omit `matcher` on a hook event that expects scoped matching",
    )
}

pub(crate) fn check_claude_settings_bypass_permissions(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.bypass_permissions_span.clone()),
        "Claude settings set `permissions.defaultMode` to `bypassPermissions` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_insecure_http_hook_url(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.insecure_http_hook_url_span.clone()),
        "Claude settings allow non-HTTPS HTTP hook URLs in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_dangerous_http_hook_host(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.dangerous_http_hook_host_span.clone()),
        "Claude settings allow dangerous host literals in `allowedHttpHookUrls`",
    )
}

pub(crate) fn check_claude_settings_bash_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.bash_wildcard_span.clone()),
        "Claude settings permissions allow `Bash(*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_webfetch_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.webfetch_wildcard_span.clone()),
        "Claude settings permissions allow `WebFetch(*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_write_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.write_wildcard_span.clone()),
        "Claude settings permissions allow `Write(*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_webfetch_raw_githubusercontent(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.webfetch_raw_githubusercontent_span.clone()),
        "Claude settings permissions allow `WebFetch(domain:raw.githubusercontent.com)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_read_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.read_wildcard_span.clone()),
        "Claude settings permissions allow `Read(*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_edit_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.edit_wildcard_span.clone()),
        "Claude settings permissions allow `Edit(*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_read_unsafe_path(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.read_unsafe_path_span.clone()),
        "Claude settings permissions allow `Read(...)` over an unsafe path in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_write_unsafe_path(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.write_unsafe_path_span.clone()),
        "Claude settings permissions allow `Write(...)` over an unsafe path in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_edit_unsafe_path(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.edit_unsafe_path_span.clone()),
        "Claude settings permissions allow `Edit(...)` over an unsafe path in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_glob_unsafe_path(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.glob_unsafe_path_span.clone()),
        "Claude settings permissions allow `Glob(...)` over an unsafe path in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_grep_unsafe_path(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.grep_unsafe_path_span.clone()),
        "Claude settings permissions allow `Grep(...)` over an unsafe path in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_websearch_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.websearch_wildcard_span.clone()),
        "Claude settings permissions allow `WebSearch(*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_unscoped_websearch(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.unscoped_websearch_span.clone()),
        "Claude settings permissions allow bare `WebSearch` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_git_push_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.git_push_permission_span.clone()),
        "Claude settings permissions allow `Bash(git push)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_git_add_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.git_add_permission_span.clone()),
        "Claude settings permissions allow `Bash(git add:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_git_clone_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.git_clone_permission_span.clone()),
        "Claude settings permissions allow `Bash(git clone:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_gh_pr_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.gh_pr_permission_span.clone()),
        "Claude settings permissions allow `Bash(gh pr:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_gh_api_post_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.gh_api_post_permission_span.clone()),
        "Claude settings permissions allow `Bash(gh api --method POST:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_gh_issue_create_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.gh_issue_create_permission_span.clone()),
        "Claude settings permissions allow `Bash(gh issue create:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_gh_api_delete_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.gh_api_delete_permission_span.clone()),
        "Claude settings permissions allow `Bash(gh api --method DELETE:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_gh_repo_create_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.gh_repo_create_permission_span.clone()),
        "Claude settings permissions allow `Bash(gh repo create:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_gh_secret_set_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.gh_secret_set_permission_span.clone()),
        "Claude settings permissions allow `Bash(gh secret set:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_gh_variable_set_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.gh_variable_set_permission_span.clone()),
        "Claude settings permissions allow `Bash(gh variable set:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_gh_workflow_run_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.gh_workflow_run_permission_span.clone()),
        "Claude settings permissions allow `Bash(gh workflow run:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_gh_secret_delete_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.gh_secret_delete_permission_span.clone()),
        "Claude settings permissions allow `Bash(gh secret delete:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_gh_variable_delete_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.gh_variable_delete_permission_span.clone()),
        "Claude settings permissions allow `Bash(gh variable delete:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_gh_workflow_disable_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.gh_workflow_disable_permission_span.clone()),
        "Claude settings permissions allow `Bash(gh workflow disable:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_git_fetch_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.git_fetch_permission_span.clone()),
        "Claude settings permissions allow `Bash(git fetch:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_git_ls_remote_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.git_ls_remote_permission_span.clone()),
        "Claude settings permissions allow `Bash(git ls-remote:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_npx_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.npx_permission_span.clone()),
        "Claude settings permissions allow `Bash(npx ...)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_uvx_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.uvx_permission_span.clone()),
        "Claude settings permissions allow `Bash(uvx ...)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_npm_exec_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.npm_exec_permission_span.clone()),
        "Claude settings permissions allow `Bash(npm exec ...)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_bunx_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.bunx_permission_span.clone()),
        "Claude settings permissions allow `Bash(bunx ...)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_pnpm_dlx_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.pnpm_dlx_permission_span.clone()),
        "Claude settings permissions allow `Bash(pnpm dlx ...)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_yarn_dlx_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.yarn_dlx_permission_span.clone()),
        "Claude settings permissions allow `Bash(yarn dlx ...)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_pipx_run_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.pipx_run_permission_span.clone()),
        "Claude settings permissions allow `Bash(pipx run ...)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_curl_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.curl_permission_span.clone()),
        "Claude settings permissions allow `Bash(curl:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_wget_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.wget_permission_span.clone()),
        "Claude settings permissions allow `Bash(wget:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_git_config_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.git_config_permission_span.clone()),
        "Claude settings permissions allow `Bash(git config:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_git_tag_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.git_tag_permission_span.clone()),
        "Claude settings permissions allow `Bash(git tag:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_git_branch_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.git_branch_permission_span.clone()),
        "Claude settings permissions allow `Bash(git branch:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_enabled_mcpjson_servers(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.enabled_mcpjson_servers_span.clone()),
        "Claude settings enable `enabledMcpjsonServers` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_package_install_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.package_install_permission_span.clone()),
        "Claude settings permissions allow package installation commands in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_git_checkout_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.git_checkout_permission_span.clone()),
        "Claude settings permissions allow `Bash(git checkout:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_git_commit_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.git_commit_permission_span.clone()),
        "Claude settings permissions allow `Bash(git commit:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_git_stash_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.git_stash_permission_span.clone()),
        "Claude settings permissions allow `Bash(git stash:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_git_reset_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.git_reset_permission_span.clone()),
        "Claude settings permissions allow `Bash(git reset:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_git_clean_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.git_clean_permission_span.clone()),
        "Claude settings permissions allow `Bash(git clean:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_git_restore_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.git_restore_permission_span.clone()),
        "Claude settings permissions allow `Bash(git restore:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_git_rebase_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.git_rebase_permission_span.clone()),
        "Claude settings permissions allow `Bash(git rebase:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_git_merge_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.git_merge_permission_span.clone()),
        "Claude settings permissions allow `Bash(git merge:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_git_cherry_pick_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.git_cherry_pick_permission_span.clone()),
        "Claude settings permissions allow `Bash(git cherry-pick:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_git_apply_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.git_apply_permission_span.clone()),
        "Claude settings permissions allow `Bash(git apply:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_git_am_permission(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.git_am_permission_span.clone()),
        "Claude settings permissions allow `Bash(git am:*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_glob_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.glob_wildcard_span.clone()),
        "Claude settings permissions allow `Glob(*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_grep_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.grep_wildcard_span.clone()),
        "Claude settings permissions allow `Grep(*)` in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_home_directory_hook_command(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.home_directory_hook_command_span.clone()),
        "Claude settings hook command uses a home-directory path in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_external_absolute_hook_command(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.external_absolute_hook_command_span.clone()),
        "Claude settings hook command uses a repo-external absolute path in a shared committed config",
    )
}

pub(crate) fn check_claude_settings_inline_download_exec(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.inline_download_exec_span.clone()),
        "Claude settings command hook downloads remote content and pipes it directly into a shell",
    )
}

pub(crate) fn check_claude_settings_network_tls_bypass(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .claude_settings()
            .and_then(|signals| signals.network_tls_bypass_span.clone()),
        "Claude settings command hook disables TLS verification in a network-capable execution path",
    )
}

fn finding_from_span(
    ctx: &ScanContext,
    meta: RuleMetadata,
    span: Option<Span>,
    message: &'static str,
) -> Vec<Finding> {
    span.into_iter()
        .map(|span| finding_for_region(&meta, ctx, &span, message))
        .collect()
}
