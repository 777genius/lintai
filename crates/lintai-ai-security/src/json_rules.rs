use lintai_api::{Finding, RuleMetadata, ScanContext, Span};

use crate::helpers::finding_for_region;
use crate::signals::ArtifactSignals;

pub(crate) fn check_mcp_shell_wrapper(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.shell_wrapper_span.clone()),
        "MCP configuration shells out through sh -c or bash -c",
    )
}

pub(crate) fn check_mcp_mutable_launcher(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.mutable_mcp_launcher_span.clone()),
        "MCP configuration uses a mutable package launcher in committed config",
    )
}

pub(crate) fn check_mcp_inline_download_exec(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.inline_download_exec_command_span.clone()),
        "MCP configuration command downloads remote content and pipes it directly into a shell",
    )
}

pub(crate) fn check_mcp_network_tls_bypass_command(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.network_tls_bypass_command_span.clone()),
        "MCP configuration command disables TLS verification in a network-capable execution path",
    )
}

pub(crate) fn check_mcp_broad_env_file(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.broad_env_file_span.clone()),
        "repo-local MCP client config loads a broad dotenv-style envFile value",
    )
}

pub(crate) fn check_mcp_autoapprove_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_wildcard_span.clone()),
        "MCP configuration auto-approves all tools with `autoApprove: [\"*\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_bash_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_bash_wildcard_span.clone()),
        "MCP configuration auto-approves blanket shell execution with `autoApprove: [\"Bash(*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_curl(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_curl_span.clone()),
        "MCP configuration auto-approves network download execution with `autoApprove: [\"Bash(curl:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_wget(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_wget_span.clone()),
        "MCP configuration auto-approves network download execution with `autoApprove: [\"Bash(wget:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_sudo(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_sudo_span.clone()),
        "MCP configuration auto-approves `sudo` shell execution with `autoApprove: [\"Bash(sudo:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_rm(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_rm_span.clone()),
        "MCP configuration auto-approves `rm` shell execution with `autoApprove: [\"Bash(rm:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_git_push(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_git_push_span.clone()),
        "MCP configuration auto-approves `git push` with `autoApprove: [\"Bash(git push)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_gh_api_post(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_gh_api_post_span.clone()),
        "MCP configuration auto-approves GitHub API mutation calls with `autoApprove: [\"Bash(gh api --method POST:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_git_checkout(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_git_checkout_span.clone()),
        "MCP configuration auto-approves `git checkout` with `autoApprove: [\"Bash(git checkout:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_git_commit(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_git_commit_span.clone()),
        "MCP configuration auto-approves `git commit` with `autoApprove: [\"Bash(git commit:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_git_reset(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_git_reset_span.clone()),
        "MCP configuration auto-approves `git reset` with `autoApprove: [\"Bash(git reset:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_git_clean(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_git_clean_span.clone()),
        "MCP configuration auto-approves `git clean` with `autoApprove: [\"Bash(git clean:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_gh_api_delete(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_gh_api_delete_span.clone()),
        "MCP configuration auto-approves GitHub API DELETE mutation calls with `autoApprove: [\"Bash(gh api --method DELETE:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_gh_api_patch(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_gh_api_patch_span.clone()),
        "MCP configuration auto-approves GitHub API PATCH mutation calls with `autoApprove: [\"Bash(gh api --method PATCH:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_gh_api_put(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_gh_api_put_span.clone()),
        "MCP configuration auto-approves GitHub API PUT mutation calls with `autoApprove: [\"Bash(gh api --method PUT:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_gh_issue_create(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_gh_issue_create_span.clone()),
        "MCP configuration auto-approves `gh issue create` with `autoApprove: [\"Bash(gh issue create:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_gh_repo_create(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_gh_repo_create_span.clone()),
        "MCP configuration auto-approves `gh repo create` with `autoApprove: [\"Bash(gh repo create:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_gh_repo_delete(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_gh_repo_delete_span.clone()),
        "MCP configuration auto-approves `gh repo delete` with `autoApprove: [\"Bash(gh repo delete:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_gh_repo_edit(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_gh_repo_edit_span.clone()),
        "MCP configuration auto-approves `gh repo edit` with `autoApprove: [\"Bash(gh repo edit:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_gh_secret_set(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_gh_secret_set_span.clone()),
        "MCP configuration auto-approves `gh secret set` with `autoApprove: [\"Bash(gh secret set:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_gh_variable_set(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_gh_variable_set_span.clone()),
        "MCP configuration auto-approves `gh variable set` with `autoApprove: [\"Bash(gh variable set:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_gh_workflow_run(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_gh_workflow_run_span.clone()),
        "MCP configuration auto-approves `gh workflow run` with `autoApprove: [\"Bash(gh workflow run:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_gh_secret_delete(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_gh_secret_delete_span.clone()),
        "MCP configuration auto-approves `gh secret delete` with `autoApprove: [\"Bash(gh secret delete:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_gh_variable_delete(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_gh_variable_delete_span.clone()),
        "MCP configuration auto-approves `gh variable delete` with `autoApprove: [\"Bash(gh variable delete:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_gh_workflow_disable(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_gh_workflow_disable_span.clone()),
        "MCP configuration auto-approves `gh workflow disable` with `autoApprove: [\"Bash(gh workflow disable:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_gh_repo_transfer(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_gh_repo_transfer_span.clone()),
        "MCP configuration auto-approves `gh repo transfer` with `autoApprove: [\"Bash(gh repo transfer:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_gh_release_create(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_gh_release_create_span.clone()),
        "MCP configuration auto-approves `gh release create` with `autoApprove: [\"Bash(gh release create:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_gh_release_delete(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_gh_release_delete_span.clone()),
        "MCP configuration auto-approves `gh release delete` with `autoApprove: [\"Bash(gh release delete:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_gh_release_upload(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_gh_release_upload_span.clone()),
        "MCP configuration auto-approves `gh release upload` with `autoApprove: [\"Bash(gh release upload:*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_npx(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_npx_span.clone()),
        "MCP configuration auto-approves `Bash(npx ...)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_uvx(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_uvx_span.clone()),
        "MCP configuration auto-approves `Bash(uvx ...)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_npm_exec(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_npm_exec_span.clone()),
        "MCP configuration auto-approves `Bash(npm exec ...)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_bunx(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_bunx_span.clone()),
        "MCP configuration auto-approves `Bash(bunx ...)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_pnpm_dlx(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_pnpm_dlx_span.clone()),
        "MCP configuration auto-approves `Bash(pnpm dlx ...)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_yarn_dlx(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_yarn_dlx_span.clone()),
        "MCP configuration auto-approves `Bash(yarn dlx ...)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_pipx_run(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_pipx_run_span.clone()),
        "MCP configuration auto-approves `Bash(pipx run ...)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_package_install(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_package_install_span.clone()),
        "MCP configuration auto-approves package installation commands through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_git_clone(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_git_clone_span.clone()),
        "MCP configuration auto-approves `Bash(git clone:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_git_fetch(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_git_fetch_span.clone()),
        "MCP configuration auto-approves `Bash(git fetch:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_git_ls_remote(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_git_ls_remote_span.clone()),
        "MCP configuration auto-approves `Bash(git ls-remote:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_git_add(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_git_add_span.clone()),
        "MCP configuration auto-approves `Bash(git add:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_git_config(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_git_config_span.clone()),
        "MCP configuration auto-approves `Bash(git config:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_git_tag(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_git_tag_span.clone()),
        "MCP configuration auto-approves `Bash(git tag:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_git_branch(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_git_branch_span.clone()),
        "MCP configuration auto-approves `Bash(git branch:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_git_stash(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_git_stash_span.clone()),
        "MCP configuration auto-approves `Bash(git stash:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_git_restore(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_git_restore_span.clone()),
        "MCP configuration auto-approves `Bash(git restore:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_git_rebase(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_git_rebase_span.clone()),
        "MCP configuration auto-approves `Bash(git rebase:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_git_merge(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_git_merge_span.clone()),
        "MCP configuration auto-approves `Bash(git merge:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_git_cherry_pick(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_git_cherry_pick_span.clone()),
        "MCP configuration auto-approves `Bash(git cherry-pick:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_git_apply(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_git_apply_span.clone()),
        "MCP configuration auto-approves `Bash(git apply:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_git_am(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_git_am_span.clone()),
        "MCP configuration auto-approves `Bash(git am:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_gh_pr(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_gh_pr_span.clone()),
        "MCP configuration auto-approves `Bash(gh pr:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_crontab(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_crontab_span.clone()),
        "MCP configuration auto-approves `Bash(crontab:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_systemctl_enable(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_systemctl_enable_span.clone()),
        "MCP configuration auto-approves `Bash(systemctl enable:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_launchctl_load(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_launchctl_load_span.clone()),
        "MCP configuration auto-approves `Bash(launchctl load:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_launchctl_bootstrap(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_launchctl_bootstrap_span.clone()),
        "MCP configuration auto-approves `Bash(launchctl bootstrap:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_chmod(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_chmod_span.clone()),
        "MCP configuration auto-approves `Bash(chmod:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_chown(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_chown_span.clone()),
        "MCP configuration auto-approves `Bash(chown:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_chgrp(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_chgrp_span.clone()),
        "MCP configuration auto-approves `Bash(chgrp:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_su(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_su_span.clone()),
        "MCP configuration auto-approves `Bash(su:*)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_read_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_read_wildcard_span.clone()),
        "MCP configuration auto-approves blanket read access with `autoApprove: [\"Read(*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_write_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_write_wildcard_span.clone()),
        "MCP configuration auto-approves blanket write access with `autoApprove: [\"Write(*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_edit_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_edit_wildcard_span.clone()),
        "MCP configuration auto-approves blanket edit access with `autoApprove: [\"Edit(*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_glob_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_glob_wildcard_span.clone()),
        "MCP configuration auto-approves blanket file discovery with `autoApprove: [\"Glob(*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_grep_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_grep_wildcard_span.clone()),
        "MCP configuration auto-approves blanket content search with `autoApprove: [\"Grep(*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_webfetch_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_webfetch_wildcard_span.clone()),
        "MCP configuration auto-approves blanket remote fetch with `autoApprove: [\"WebFetch(*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_webfetch_raw_githubusercontent(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals.json().and_then(|signals| {
            signals
                .autoapprove_webfetch_raw_githubusercontent_span
                .clone()
        }),
        "MCP configuration auto-approves `WebFetch(domain:raw.githubusercontent.com)` through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_websearch_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_websearch_wildcard_span.clone()),
        "MCP configuration auto-approves blanket remote search with `autoApprove: [\"WebSearch(*)\"]`",
    )
}

pub(crate) fn check_mcp_autoapprove_read_unsafe_path(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_read_unsafe_path_span.clone()),
        "MCP configuration auto-approves `Read(...)` over an unsafe path through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_write_unsafe_path(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_write_unsafe_path_span.clone()),
        "MCP configuration auto-approves `Write(...)` over an unsafe path through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_edit_unsafe_path(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_edit_unsafe_path_span.clone()),
        "MCP configuration auto-approves `Edit(...)` over an unsafe path through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_glob_unsafe_path(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_glob_unsafe_path_span.clone()),
        "MCP configuration auto-approves `Glob(...)` over an unsafe path through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_grep_unsafe_path(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_grep_unsafe_path_span.clone()),
        "MCP configuration auto-approves `Grep(...)` over an unsafe path through `autoApprove`",
    )
}

pub(crate) fn check_mcp_autoapprove_tools_true(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.autoapprove_tools_true_span.clone()),
        "MCP configuration auto-approves all tools with `autoApproveTools: true`",
    )
}

pub(crate) fn check_mcp_trust_tools_true(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.trust_tools_true_span.clone()),
        "MCP configuration fully trusts tools with `trustTools: true`",
    )
}

pub(crate) fn check_mcp_sandbox_disabled(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.sandbox_disabled_span.clone()),
        "MCP configuration disables sandboxing with `sandbox: false` or `disableSandbox: true`",
    )
}

pub(crate) fn check_mcp_capabilities_wildcard(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.capabilities_wildcard_span.clone()),
        "MCP configuration grants all capabilities with `capabilities: [\"*\"]` or `capabilities: \"*\"`",
    )
}

pub(crate) fn check_mcp_sudo_command(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.sudo_command_span.clone()),
        "MCP configuration launches the server through `sudo`",
    )
}

pub(crate) fn check_mcp_sudo_args0(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.sudo_args0_span.clone()),
        "MCP configuration passes `sudo` as the first argument in the launch path",
    )
}

pub(crate) fn check_mcp_unpinned_docker_image(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.mutable_docker_image_span.clone()),
        "MCP configuration launches Docker with an image reference that is not digest-pinned",
    )
}

pub(crate) fn check_mcp_sensitive_docker_mount(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.sensitive_docker_mount_span.clone()),
        "MCP configuration launches Docker with a bind mount of sensitive host material",
    )
}

pub(crate) fn check_mcp_mutable_docker_pull(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.mutable_docker_pull_span.clone()),
        "MCP configuration launches Docker with a forced mutable pull policy",
    )
}

pub(crate) fn check_mcp_dangerous_docker_flag(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.dangerous_docker_flag_span.clone()),
        "MCP configuration launches Docker with a host-escape or privileged runtime flag",
    )
}

pub(crate) fn check_plugin_hook_mutable_launcher(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.mutable_plugin_hook_launcher_span.clone()),
        "plugin hook command uses a mutable package launcher in committed hooks.json",
    )
}

pub(crate) fn check_plugin_hook_inline_download_exec(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.inline_download_exec_plugin_hook_span.clone()),
        "plugin hook command downloads remote content and pipes it directly into a shell",
    )
}

pub(crate) fn check_plugin_hook_network_tls_bypass(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.network_tls_bypass_plugin_hook_span.clone()),
        "plugin hook command disables TLS verification in a network-capable execution path",
    )
}

pub(crate) fn check_plain_http_config(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.plain_http_endpoint_span.clone()),
        "configuration contains an insecure http:// endpoint",
    )
}

pub(crate) fn check_mcp_credential_env_passthrough(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.credential_env_passthrough_span.clone()),
        "MCP configuration passes through credential environment variables",
    )
}

pub(crate) fn check_json_hidden_instruction(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.hidden_instruction_span.clone()),
        "configuration description contains override-style hidden instructions",
    )
}

pub(crate) fn check_json_sensitive_env_reference(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.sensitive_env_reference_span.clone()),
        "configuration forwards a sensitive environment variable reference",
    )
}

pub(crate) fn check_json_suspicious_remote_endpoint(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.suspicious_remote_endpoint_span.clone()),
        "configuration points at a suspicious remote endpoint",
    )
}

pub(crate) fn check_json_literal_secret(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.literal_secret_span.clone()),
        "configuration commits literal secret material in env, auth, or header values",
    )
}

pub(crate) fn check_json_dangerous_endpoint_host(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.dangerous_endpoint_host_span.clone()),
        "configuration endpoint targets a metadata or private-network host literal",
    )
}

pub(crate) fn check_json_unsafe_plugin_path(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.unsafe_plugin_path_span.clone()),
        "cursor plugin manifest contains an unsafe absolute or parent-traversing path",
    )
}

pub(crate) fn check_trust_verification_disabled_config(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.trust_verification_disabled_span.clone()),
        "configuration disables TLS or certificate verification",
    )
}

pub(crate) fn check_static_auth_exposure_config(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals
            .json()
            .and_then(|signals| signals.static_auth_exposure_span.clone()),
        "configuration embeds static authentication material in a connection or auth value",
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
