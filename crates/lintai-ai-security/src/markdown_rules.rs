use lintai_api::{Finding, RuleMetadata, ScanContext, Span};

use crate::helpers::finding_for_region;
use crate::signals::ArtifactSignals;

macro_rules! markdown_spans_rule {
    ($name:ident, $field:ident, $message:literal) => {
        pub(crate) fn $name(
            ctx: &ScanContext,
            signals: &ArtifactSignals,
            meta: RuleMetadata,
        ) -> Vec<Finding> {
            findings_for_spans(
                ctx,
                meta,
                signals
                    .markdown()
                    .map(|signals| signals.$field.as_slice())
                    .unwrap_or(&[]),
                $message,
            )
        }
    };
}

markdown_spans_rule!(
    check_html_comment_directive,
    directive_comment_spans,
    "dangerous hidden instructions in HTML comment"
);
markdown_spans_rule!(
    check_markdown_download_exec,
    prose_download_exec_spans,
    "remote download-and-execute instruction outside a code block"
);
markdown_spans_rule!(
    check_markdown_base64_exec,
    prose_base64_exec_spans,
    "base64-decoded payload is executed outside a code block"
);
markdown_spans_rule!(
    check_markdown_path_traversal,
    prose_path_traversal_spans,
    "instruction references parent-directory traversal for file access"
);
markdown_spans_rule!(
    check_html_comment_download_exec,
    comment_download_exec_spans,
    "hidden HTML comment contains a download-and-execute instruction"
);
markdown_spans_rule!(
    check_markdown_private_key_pem,
    private_key_spans,
    "markdown contains committed private key material"
);
markdown_spans_rule!(
    check_markdown_fenced_pipe_shell,
    fenced_pipe_shell_spans,
    "fenced shell example pipes remote content directly into a shell"
);
markdown_spans_rule!(
    check_markdown_metadata_service_access,
    metadata_service_access_spans,
    "markdown example targets a cloud metadata service literal"
);
markdown_spans_rule!(
    check_markdown_mutable_mcp_launcher,
    mutable_mcp_launcher_spans,
    "markdown example launches MCP through a mutable package runner"
);
markdown_spans_rule!(
    check_markdown_claude_bare_pip_install,
    claude_bare_pip_install_spans,
    "AI-native markdown models Claude package installation with bare `pip install` despite explicit `uv` preference guidance"
);
markdown_spans_rule!(
    check_markdown_unpinned_pip_git_install,
    unpinned_pip_git_install_spans,
    "AI-native markdown installs Python packages from an unpinned `git+https://` source"
);
markdown_spans_rule!(
    check_markdown_pip_http_git_install,
    pip_http_git_install_spans,
    "AI-native markdown installs Python packages from an insecure `git+http://` source"
);
markdown_spans_rule!(
    check_markdown_pip_trusted_host,
    pip_trusted_host_spans,
    "AI-native markdown installs Python packages with `--trusted-host`"
);
markdown_spans_rule!(
    check_markdown_pip_http_index,
    pip_http_index_spans,
    "AI-native markdown installs Python packages from an insecure `http://` package index"
);
markdown_spans_rule!(
    check_markdown_pip_http_find_links,
    pip_http_find_links_spans,
    "AI-native markdown installs Python packages with insecure `http://` find-links"
);
markdown_spans_rule!(
    check_markdown_pip_config_http_index,
    pip_config_http_index_spans,
    "AI-native markdown configures Python package resolution with an insecure `http://` package index"
);
markdown_spans_rule!(
    check_markdown_pip_config_http_find_links,
    pip_config_http_find_links_spans,
    "AI-native markdown configures Python package discovery with insecure `http://` find-links"
);
markdown_spans_rule!(
    check_markdown_pip_config_trusted_host,
    pip_config_trusted_host_spans,
    "AI-native markdown configures Python package resolution with `trusted-host`"
);
markdown_spans_rule!(
    check_markdown_network_tls_bypass,
    network_tls_bypass_spans,
    "AI-native markdown disables TLS verification for a network-capable command"
);
markdown_spans_rule!(
    check_markdown_pip_http_source,
    pip_http_source_spans,
    "AI-native markdown installs Python packages from an insecure direct `http://` source"
);
markdown_spans_rule!(
    check_markdown_js_package_config_http_registry,
    js_package_config_http_registry_spans,
    "AI-native markdown configures a JavaScript package manager with an insecure `http://` registry"
);
markdown_spans_rule!(
    check_markdown_npm_http_registry,
    npm_http_registry_spans,
    "AI-native markdown installs JavaScript packages from an insecure `http://` registry"
);
markdown_spans_rule!(
    check_markdown_js_package_strict_ssl_false,
    js_package_strict_ssl_false_spans,
    "AI-native markdown disables strict SSL verification for JavaScript package manager config"
);
markdown_spans_rule!(
    check_markdown_npm_http_source,
    npm_http_source_spans,
    "AI-native markdown installs JavaScript packages from an insecure direct `http://` source"
);
markdown_spans_rule!(
    check_markdown_cargo_http_git_install,
    cargo_http_git_install_spans,
    "AI-native markdown installs Rust packages from an insecure `http://` git source"
);
markdown_spans_rule!(
    check_markdown_cargo_http_index,
    cargo_http_index_spans,
    "AI-native markdown installs Rust packages from an insecure `http://` index"
);
markdown_spans_rule!(
    check_markdown_git_http_clone,
    git_http_clone_spans,
    "AI-native markdown clones a Git repository from an insecure `http://` source"
);
markdown_spans_rule!(
    check_markdown_git_http_remote,
    git_http_remote_spans,
    "AI-native markdown configures a Git remote with an insecure `http://` source"
);
markdown_spans_rule!(
    check_markdown_git_sslverify_false,
    git_sslverify_false_spans,
    "AI-native markdown disables Git TLS verification with `http.sslVerify false`"
);
markdown_spans_rule!(
    check_markdown_git_ssl_no_verify,
    git_ssl_no_verify_spans,
    "AI-native markdown disables Git TLS verification with `GIT_SSL_NO_VERIFY`"
);
markdown_spans_rule!(
    check_markdown_git_inline_sslverify_false,
    git_inline_sslverify_false_spans,
    "AI-native markdown disables Git TLS verification with `git -c http.sslVerify=false`"
);
markdown_spans_rule!(
    check_markdown_mutable_docker_image,
    mutable_docker_image_spans,
    "markdown docker example uses a mutable registry image"
);
markdown_spans_rule!(
    check_markdown_docker_host_escape,
    docker_host_escape_spans,
    "markdown docker example uses a host-escape or privileged runtime pattern"
);
markdown_spans_rule!(
    check_untrusted_instruction_promotion,
    untrusted_instruction_promotion_spans,
    "instruction markdown promotes untrusted external content to developer/system-level instructions"
);
markdown_spans_rule!(
    check_approval_bypass_instruction,
    approval_bypass_instruction_spans,
    "instruction markdown explicitly disables user approval or confirmation"
);
markdown_spans_rule!(
    check_copilot_instruction_wrong_suffix,
    copilot_instruction_wrong_suffix_spans,
    "path-specific GitHub Copilot instruction markdown under `.github/instructions/` must end with `.instructions.md`"
);

pub(crate) fn check_copilot_instruction_invalid_apply_to(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| {
                signals
                    .copilot_instruction_invalid_apply_to_spans
                    .as_slice()
            })
            .unwrap_or(&[]),
        "path-specific GitHub Copilot instruction markdown `applyTo` must be a non-empty string or sequence of non-empty strings",
    )
}

pub(crate) fn check_copilot_instruction_invalid_apply_to_glob(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| {
                signals
                    .copilot_instruction_invalid_apply_to_glob_spans
                    .as_slice()
            })
            .unwrap_or(&[]),
        "path-specific GitHub Copilot instruction markdown `applyTo` must use valid glob patterns",
    )
}

markdown_spans_rule!(
    check_unscoped_bash_allowed_tools,
    unscoped_bash_allowed_tools_spans,
    "frontmatter grants unscoped Bash tool access"
);
markdown_spans_rule!(
    check_wildcard_bash_allowed_tools,
    wildcard_bash_allowed_tools_spans,
    "frontmatter grants `Bash(*)` wildcard access"
);
markdown_spans_rule!(
    check_unscoped_websearch_allowed_tools,
    unscoped_websearch_allowed_tools_spans,
    "frontmatter grants bare WebSearch tool access"
);
markdown_spans_rule!(
    check_unscoped_webfetch_allowed_tools,
    unscoped_webfetch_allowed_tools_spans,
    "frontmatter grants bare WebFetch tool access"
);
markdown_spans_rule!(
    check_git_push_allowed_tools,
    git_push_allowed_tools_spans,
    "frontmatter grants `Bash(git push)` tool access"
);
markdown_spans_rule!(
    check_git_checkout_allowed_tools,
    git_checkout_allowed_tools_spans,
    "frontmatter grants `Bash(git checkout:*)` tool access"
);
markdown_spans_rule!(
    check_git_commit_allowed_tools,
    git_commit_allowed_tools_spans,
    "frontmatter grants `Bash(git commit:*)` tool access"
);
markdown_spans_rule!(
    check_git_stash_allowed_tools,
    git_stash_allowed_tools_spans,
    "frontmatter grants `Bash(git stash:*)` tool access"
);
markdown_spans_rule!(
    check_gh_pr_allowed_tools,
    gh_pr_allowed_tools_spans,
    "frontmatter grants `Bash(gh pr:*)` tool access"
);
markdown_spans_rule!(
    check_gh_api_post_allowed_tools,
    gh_api_post_allowed_tools_spans,
    "frontmatter grants `Bash(gh api --method POST:*)` tool access"
);
markdown_spans_rule!(
    check_gh_issue_create_allowed_tools,
    gh_issue_create_allowed_tools_spans,
    "frontmatter grants `Bash(gh issue create:*)` tool access"
);
markdown_spans_rule!(
    check_gh_api_delete_allowed_tools,
    gh_api_delete_allowed_tools_spans,
    "frontmatter grants `Bash(gh api --method DELETE:*)` tool access"
);
markdown_spans_rule!(
    check_gh_api_patch_allowed_tools,
    gh_api_patch_allowed_tools_spans,
    "frontmatter grants `Bash(gh api --method PATCH:*)` tool access"
);
markdown_spans_rule!(
    check_gh_api_put_allowed_tools,
    gh_api_put_allowed_tools_spans,
    "frontmatter grants `Bash(gh api --method PUT:*)` tool access"
);
markdown_spans_rule!(
    check_gh_repo_create_allowed_tools,
    gh_repo_create_allowed_tools_spans,
    "frontmatter grants `Bash(gh repo create:*)` tool access"
);
markdown_spans_rule!(
    check_gh_repo_delete_allowed_tools,
    gh_repo_delete_allowed_tools_spans,
    "frontmatter grants `Bash(gh repo delete:*)` tool access"
);
markdown_spans_rule!(
    check_gh_repo_edit_allowed_tools,
    gh_repo_edit_allowed_tools_spans,
    "frontmatter grants `Bash(gh repo edit:*)` tool access"
);
markdown_spans_rule!(
    check_gh_repo_transfer_allowed_tools,
    gh_repo_transfer_allowed_tools_spans,
    "frontmatter grants `Bash(gh repo transfer:*)` tool access"
);
markdown_spans_rule!(
    check_gh_release_create_allowed_tools,
    gh_release_create_allowed_tools_spans,
    "frontmatter grants `Bash(gh release create:*)` tool access"
);
markdown_spans_rule!(
    check_gh_release_delete_allowed_tools,
    gh_release_delete_allowed_tools_spans,
    "frontmatter grants `Bash(gh release delete:*)` tool access"
);
markdown_spans_rule!(
    check_gh_release_upload_allowed_tools,
    gh_release_upload_allowed_tools_spans,
    "frontmatter grants `Bash(gh release upload:*)` tool access"
);
markdown_spans_rule!(
    check_gh_secret_set_allowed_tools,
    gh_secret_set_allowed_tools_spans,
    "frontmatter grants `Bash(gh secret set:*)` tool access"
);
markdown_spans_rule!(
    check_gh_variable_set_allowed_tools,
    gh_variable_set_allowed_tools_spans,
    "frontmatter grants `Bash(gh variable set:*)` tool access"
);
markdown_spans_rule!(
    check_gh_workflow_run_allowed_tools,
    gh_workflow_run_allowed_tools_spans,
    "frontmatter grants `Bash(gh workflow run:*)` tool access"
);
markdown_spans_rule!(
    check_gh_secret_delete_allowed_tools,
    gh_secret_delete_allowed_tools_spans,
    "frontmatter grants `Bash(gh secret delete:*)` tool access"
);
markdown_spans_rule!(
    check_gh_variable_delete_allowed_tools,
    gh_variable_delete_allowed_tools_spans,
    "frontmatter grants `Bash(gh variable delete:*)` tool access"
);
markdown_spans_rule!(
    check_gh_workflow_disable_allowed_tools,
    gh_workflow_disable_allowed_tools_spans,
    "frontmatter grants `Bash(gh workflow disable:*)` tool access"
);
markdown_spans_rule!(
    check_npm_exec_allowed_tools,
    npm_exec_allowed_tools_spans,
    "frontmatter grants `Bash(npm exec:*)` tool access"
);
markdown_spans_rule!(
    check_bunx_allowed_tools,
    bunx_allowed_tools_spans,
    "frontmatter grants `Bash(bunx:*)` tool access"
);
markdown_spans_rule!(
    check_uvx_allowed_tools,
    uvx_allowed_tools_spans,
    "frontmatter grants `Bash(uvx:*)` tool access"
);
markdown_spans_rule!(
    check_pnpm_dlx_allowed_tools,
    pnpm_dlx_allowed_tools_spans,
    "frontmatter grants `Bash(pnpm dlx:*)` tool access"
);
markdown_spans_rule!(
    check_yarn_dlx_allowed_tools,
    yarn_dlx_allowed_tools_spans,
    "frontmatter grants `Bash(yarn dlx:*)` tool access"
);
markdown_spans_rule!(
    check_pipx_run_allowed_tools,
    pipx_run_allowed_tools_spans,
    "frontmatter grants `Bash(pipx run:*)` tool access"
);
markdown_spans_rule!(
    check_npx_allowed_tools,
    npx_allowed_tools_spans,
    "frontmatter grants `Bash(npx:*)` tool access"
);
markdown_spans_rule!(
    check_git_ls_remote_allowed_tools,
    git_ls_remote_allowed_tools_spans,
    "frontmatter grants `Bash(git ls-remote:*)` tool access"
);
markdown_spans_rule!(
    check_curl_allowed_tools,
    curl_allowed_tools_spans,
    "frontmatter grants `Bash(curl:*)` authority"
);
markdown_spans_rule!(
    check_wget_allowed_tools,
    wget_allowed_tools_spans,
    "frontmatter grants `Bash(wget:*)` authority"
);
markdown_spans_rule!(
    check_sudo_allowed_tools,
    sudo_allowed_tools_spans,
    "frontmatter grants `Bash(sudo:*)` authority"
);
markdown_spans_rule!(
    check_rm_allowed_tools,
    rm_allowed_tools_spans,
    "frontmatter grants `Bash(rm:*)` authority"
);
markdown_spans_rule!(
    check_chmod_allowed_tools,
    chmod_allowed_tools_spans,
    "frontmatter grants `Bash(chmod:*)` authority"
);
markdown_spans_rule!(
    check_chown_allowed_tools,
    chown_allowed_tools_spans,
    "frontmatter grants `Bash(chown:*)` authority"
);
markdown_spans_rule!(
    check_chgrp_allowed_tools,
    chgrp_allowed_tools_spans,
    "frontmatter grants `Bash(chgrp:*)` authority"
);
markdown_spans_rule!(
    check_su_allowed_tools,
    su_allowed_tools_spans,
    "frontmatter grants `Bash(su:*)` authority"
);
markdown_spans_rule!(
    check_git_clone_allowed_tools,
    git_clone_allowed_tools_spans,
    "frontmatter grants `Bash(git clone:*)` authority"
);
markdown_spans_rule!(
    check_git_add_allowed_tools,
    git_add_allowed_tools_spans,
    "frontmatter grants `Bash(git add:*)` authority"
);
markdown_spans_rule!(
    check_git_fetch_allowed_tools,
    git_fetch_allowed_tools_spans,
    "frontmatter grants `Bash(git fetch:*)` authority"
);
markdown_spans_rule!(
    check_webfetch_raw_github_allowed_tools,
    webfetch_raw_github_allowed_tools_spans,
    "frontmatter grants `WebFetch(domain:raw.githubusercontent.com)` authority"
);
markdown_spans_rule!(
    check_git_config_allowed_tools,
    git_config_allowed_tools_spans,
    "frontmatter grants `Bash(git config:*)` authority"
);
markdown_spans_rule!(
    check_git_tag_allowed_tools,
    git_tag_allowed_tools_spans,
    "frontmatter grants `Bash(git tag:*)` authority"
);
markdown_spans_rule!(
    check_git_branch_allowed_tools,
    git_branch_allowed_tools_spans,
    "frontmatter grants `Bash(git branch:*)` authority"
);
markdown_spans_rule!(
    check_git_reset_allowed_tools,
    git_reset_allowed_tools_spans,
    "frontmatter grants `Bash(git reset:*)` authority"
);
markdown_spans_rule!(
    check_git_clean_allowed_tools,
    git_clean_allowed_tools_spans,
    "frontmatter grants `Bash(git clean:*)` authority"
);
markdown_spans_rule!(
    check_git_restore_allowed_tools,
    git_restore_allowed_tools_spans,
    "frontmatter grants `Bash(git restore:*)` authority"
);
markdown_spans_rule!(
    check_git_rebase_allowed_tools,
    git_rebase_allowed_tools_spans,
    "frontmatter grants `Bash(git rebase:*)` authority"
);
markdown_spans_rule!(
    check_git_merge_allowed_tools,
    git_merge_allowed_tools_spans,
    "frontmatter grants `Bash(git merge:*)` authority"
);
markdown_spans_rule!(
    check_git_cherry_pick_allowed_tools,
    git_cherry_pick_allowed_tools_spans,
    "frontmatter grants `Bash(git cherry-pick:*)` authority"
);
markdown_spans_rule!(
    check_git_apply_allowed_tools,
    git_apply_allowed_tools_spans,
    "frontmatter grants `Bash(git apply:*)` authority"
);
markdown_spans_rule!(
    check_git_am_allowed_tools,
    git_am_allowed_tools_spans,
    "frontmatter grants `Bash(git am:*)` authority"
);
markdown_spans_rule!(
    check_package_install_allowed_tools,
    package_install_allowed_tools_spans,
    "frontmatter grants package installation authority"
);
markdown_spans_rule!(
    check_unscoped_read_allowed_tools,
    unscoped_read_allowed_tools_spans,
    "frontmatter grants bare Read tool access"
);
markdown_spans_rule!(
    check_unscoped_write_allowed_tools,
    unscoped_write_allowed_tools_spans,
    "frontmatter grants bare Write tool access"
);
markdown_spans_rule!(
    check_unscoped_edit_allowed_tools,
    unscoped_edit_allowed_tools_spans,
    "frontmatter grants bare Edit tool access"
);
markdown_spans_rule!(
    check_unscoped_glob_allowed_tools,
    unscoped_glob_allowed_tools_spans,
    "frontmatter grants bare Glob tool access"
);
markdown_spans_rule!(
    check_unscoped_grep_allowed_tools,
    unscoped_grep_allowed_tools_spans,
    "frontmatter grants bare Grep tool access"
);
markdown_spans_rule!(
    check_wildcard_read_allowed_tools,
    wildcard_read_allowed_tools_spans,
    "frontmatter grants `Read(*)` wildcard access"
);
markdown_spans_rule!(
    check_wildcard_write_allowed_tools,
    wildcard_write_allowed_tools_spans,
    "frontmatter grants `Write(*)` wildcard access"
);
markdown_spans_rule!(
    check_wildcard_edit_allowed_tools,
    wildcard_edit_allowed_tools_spans,
    "frontmatter grants `Edit(*)` wildcard access"
);
markdown_spans_rule!(
    check_wildcard_glob_allowed_tools,
    wildcard_glob_allowed_tools_spans,
    "frontmatter grants `Glob(*)` wildcard access"
);
markdown_spans_rule!(
    check_wildcard_grep_allowed_tools,
    wildcard_grep_allowed_tools_spans,
    "frontmatter grants `Grep(*)` wildcard access"
);
markdown_spans_rule!(
    check_wildcard_webfetch_allowed_tools,
    wildcard_webfetch_allowed_tools_spans,
    "frontmatter grants `WebFetch(*)` wildcard access"
);
markdown_spans_rule!(
    check_wildcard_websearch_allowed_tools,
    wildcard_websearch_allowed_tools_spans,
    "frontmatter grants `WebSearch(*)` wildcard access"
);
markdown_spans_rule!(
    check_read_unsafe_path_allowed_tools,
    read_unsafe_path_allowed_tools_spans,
    "frontmatter grants `Read(...)` over an unsafe absolute, home-relative, or parent-traversing path"
);
markdown_spans_rule!(
    check_write_unsafe_path_allowed_tools,
    write_unsafe_path_allowed_tools_spans,
    "frontmatter grants `Write(...)` over an unsafe absolute, home-relative, or parent-traversing path"
);
markdown_spans_rule!(
    check_edit_unsafe_path_allowed_tools,
    edit_unsafe_path_allowed_tools_spans,
    "frontmatter grants `Edit(...)` over an unsafe absolute, home-relative, or parent-traversing path"
);
markdown_spans_rule!(
    check_glob_unsafe_path_allowed_tools,
    glob_unsafe_path_allowed_tools_spans,
    "frontmatter grants `Glob(...)` over an unsafe absolute, home-relative, or parent-traversing path"
);
markdown_spans_rule!(
    check_wildcard_tool_access,
    wildcard_tool_access_spans,
    "frontmatter grants wildcard tool access"
);
markdown_spans_rule!(
    check_plugin_agent_permission_mode,
    plugin_agent_permission_mode_spans,
    "plugin agent frontmatter sets `permissionMode`"
);
markdown_spans_rule!(
    check_plugin_agent_hooks_frontmatter,
    plugin_agent_hooks_spans,
    "plugin agent frontmatter sets `hooks`"
);
markdown_spans_rule!(
    check_plugin_agent_mcp_servers_frontmatter,
    plugin_agent_mcp_servers_spans,
    "plugin agent frontmatter sets `mcpServers`"
);
markdown_spans_rule!(
    check_cursor_rule_always_apply_type,
    cursor_rule_always_apply_type_spans,
    "Cursor rule frontmatter `alwaysApply` must be boolean"
);
markdown_spans_rule!(
    check_cursor_rule_globs_type,
    cursor_rule_globs_type_spans,
    "Cursor rule frontmatter `globs` must be a sequence of patterns"
);
markdown_spans_rule!(
    check_cursor_rule_redundant_globs,
    cursor_rule_redundant_globs_spans,
    "Cursor rule frontmatter should not set `globs` when `alwaysApply` is `true`"
);
markdown_spans_rule!(
    check_cursor_rule_unknown_frontmatter_key,
    cursor_rule_unknown_frontmatter_key_spans,
    "Cursor rule frontmatter contains an unknown key"
);
markdown_spans_rule!(
    check_cursor_rule_missing_description,
    cursor_rule_missing_description_spans,
    "Cursor rule frontmatter should include `description`"
);
markdown_spans_rule!(
    check_copilot_instruction_too_long,
    copilot_instruction_too_long_spans,
    "GitHub Copilot instruction markdown exceeds the 4000-character guidance limit"
);

pub(crate) fn check_copilot_instruction_missing_apply_to(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    findings_for_spans(
        ctx,
        meta,
        signals
            .markdown()
            .map(|signals| {
                signals
                    .copilot_instruction_missing_apply_to_spans
                    .as_slice()
            })
            .unwrap_or(&[]),
        "path-specific GitHub Copilot instruction markdown is missing `applyTo` frontmatter",
    )
}

fn findings_for_spans(
    ctx: &ScanContext,
    meta: RuleMetadata,
    spans: &[Span],
    message: &'static str,
) -> Vec<Finding> {
    spans
        .iter()
        .map(|span| finding_for_region(&meta, ctx, span, message))
        .collect()
}
