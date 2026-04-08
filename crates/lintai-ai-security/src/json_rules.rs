use lintai_api::{Finding, RuleMetadata, ScanContext, Span};

use crate::helpers::finding_for_region;
use crate::signals::ArtifactSignals;

macro_rules! json_span_rule {
    ($name:ident, $field:ident, $message:literal) => {
        pub(crate) fn $name(
            ctx: &ScanContext,
            signals: &ArtifactSignals,
            meta: RuleMetadata,
        ) -> Vec<Finding> {
            finding_from_span(
                ctx,
                meta,
                signals.json().and_then(|signals| signals.$field.clone()),
                $message,
            )
        }
    };
}

json_span_rule!(
    check_mcp_shell_wrapper,
    shell_wrapper_span,
    "MCP configuration shells out through sh -c or bash -c"
);
json_span_rule!(
    check_mcp_mutable_launcher,
    mutable_mcp_launcher_span,
    "MCP configuration uses a mutable package launcher in committed config"
);
json_span_rule!(
    check_mcp_inline_download_exec,
    inline_download_exec_command_span,
    "MCP configuration command downloads remote content and pipes it directly into a shell"
);
json_span_rule!(
    check_mcp_network_tls_bypass_command,
    network_tls_bypass_command_span,
    "MCP configuration command disables TLS verification in a network-capable execution path"
);
json_span_rule!(
    check_mcp_broad_env_file,
    broad_env_file_span,
    "repo-local MCP client config loads a broad dotenv-style envFile value"
);
json_span_rule!(
    check_package_manifest_dangerous_lifecycle_script,
    dangerous_lifecycle_script_span,
    "package manifest defines an install-time lifecycle script with download-exec, eval, or npm explore shell behavior"
);
json_span_rule!(
    check_package_manifest_git_dependency,
    git_dependency_span,
    "package manifest installs a dependency from a git or forge shortcut source instead of the registry"
);
json_span_rule!(
    check_package_manifest_unbounded_dependency,
    unbounded_dependency_span,
    "package manifest uses an unbounded dependency spec such as `*` or `latest`"
);
json_span_rule!(
    check_package_manifest_direct_url_dependency,
    direct_url_dependency_span,
    "package manifest installs a dependency from a direct archive URL instead of a published registry release"
);
json_span_rule!(
    check_mcp_autoapprove_wildcard,
    autoapprove_wildcard_span,
    "MCP configuration auto-approves all tools with `autoApprove: [\"*\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_bash_wildcard,
    autoapprove_bash_wildcard_span,
    "MCP configuration auto-approves blanket shell execution with `autoApprove: [\"Bash(*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_bash_unscoped,
    autoapprove_bash_unscoped_span,
    "MCP configuration auto-approves bare `Bash` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_curl,
    autoapprove_curl_span,
    "MCP configuration auto-approves network download execution with `autoApprove: [\"Bash(curl:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_wget,
    autoapprove_wget_span,
    "MCP configuration auto-approves network download execution with `autoApprove: [\"Bash(wget:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_sudo,
    autoapprove_sudo_span,
    "MCP configuration auto-approves `sudo` shell execution with `autoApprove: [\"Bash(sudo:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_rm,
    autoapprove_rm_span,
    "MCP configuration auto-approves `rm` shell execution with `autoApprove: [\"Bash(rm:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_git_push,
    autoapprove_git_push_span,
    "MCP configuration auto-approves `git push` with `autoApprove: [\"Bash(git push)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_gh_api_post,
    autoapprove_gh_api_post_span,
    "MCP configuration auto-approves GitHub API mutation calls with `autoApprove: [\"Bash(gh api --method POST:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_git_checkout,
    autoapprove_git_checkout_span,
    "MCP configuration auto-approves `git checkout` with `autoApprove: [\"Bash(git checkout:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_git_commit,
    autoapprove_git_commit_span,
    "MCP configuration auto-approves `git commit` with `autoApprove: [\"Bash(git commit:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_git_reset,
    autoapprove_git_reset_span,
    "MCP configuration auto-approves `git reset` with `autoApprove: [\"Bash(git reset:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_git_clean,
    autoapprove_git_clean_span,
    "MCP configuration auto-approves `git clean` with `autoApprove: [\"Bash(git clean:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_gh_api_delete,
    autoapprove_gh_api_delete_span,
    "MCP configuration auto-approves GitHub API DELETE mutation calls with `autoApprove: [\"Bash(gh api --method DELETE:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_gh_api_patch,
    autoapprove_gh_api_patch_span,
    "MCP configuration auto-approves GitHub API PATCH mutation calls with `autoApprove: [\"Bash(gh api --method PATCH:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_gh_api_put,
    autoapprove_gh_api_put_span,
    "MCP configuration auto-approves GitHub API PUT mutation calls with `autoApprove: [\"Bash(gh api --method PUT:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_gh_issue_create,
    autoapprove_gh_issue_create_span,
    "MCP configuration auto-approves `gh issue create` with `autoApprove: [\"Bash(gh issue create:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_gh_repo_create,
    autoapprove_gh_repo_create_span,
    "MCP configuration auto-approves `gh repo create` with `autoApprove: [\"Bash(gh repo create:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_gh_repo_delete,
    autoapprove_gh_repo_delete_span,
    "MCP configuration auto-approves `gh repo delete` with `autoApprove: [\"Bash(gh repo delete:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_gh_repo_edit,
    autoapprove_gh_repo_edit_span,
    "MCP configuration auto-approves `gh repo edit` with `autoApprove: [\"Bash(gh repo edit:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_gh_secret_set,
    autoapprove_gh_secret_set_span,
    "MCP configuration auto-approves `gh secret set` with `autoApprove: [\"Bash(gh secret set:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_gh_variable_set,
    autoapprove_gh_variable_set_span,
    "MCP configuration auto-approves `gh variable set` with `autoApprove: [\"Bash(gh variable set:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_gh_workflow_run,
    autoapprove_gh_workflow_run_span,
    "MCP configuration auto-approves `gh workflow run` with `autoApprove: [\"Bash(gh workflow run:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_gh_secret_delete,
    autoapprove_gh_secret_delete_span,
    "MCP configuration auto-approves `gh secret delete` with `autoApprove: [\"Bash(gh secret delete:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_gh_variable_delete,
    autoapprove_gh_variable_delete_span,
    "MCP configuration auto-approves `gh variable delete` with `autoApprove: [\"Bash(gh variable delete:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_gh_workflow_disable,
    autoapprove_gh_workflow_disable_span,
    "MCP configuration auto-approves `gh workflow disable` with `autoApprove: [\"Bash(gh workflow disable:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_gh_repo_transfer,
    autoapprove_gh_repo_transfer_span,
    "MCP configuration auto-approves `gh repo transfer` with `autoApprove: [\"Bash(gh repo transfer:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_gh_release_create,
    autoapprove_gh_release_create_span,
    "MCP configuration auto-approves `gh release create` with `autoApprove: [\"Bash(gh release create:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_gh_release_delete,
    autoapprove_gh_release_delete_span,
    "MCP configuration auto-approves `gh release delete` with `autoApprove: [\"Bash(gh release delete:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_gh_release_upload,
    autoapprove_gh_release_upload_span,
    "MCP configuration auto-approves `gh release upload` with `autoApprove: [\"Bash(gh release upload:*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_npx,
    autoapprove_npx_span,
    "MCP configuration auto-approves `Bash(npx ...)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_uvx,
    autoapprove_uvx_span,
    "MCP configuration auto-approves `Bash(uvx ...)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_npm_exec,
    autoapprove_npm_exec_span,
    "MCP configuration auto-approves `Bash(npm exec ...)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_bunx,
    autoapprove_bunx_span,
    "MCP configuration auto-approves `Bash(bunx ...)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_pnpm_dlx,
    autoapprove_pnpm_dlx_span,
    "MCP configuration auto-approves `Bash(pnpm dlx ...)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_yarn_dlx,
    autoapprove_yarn_dlx_span,
    "MCP configuration auto-approves `Bash(yarn dlx ...)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_pipx_run,
    autoapprove_pipx_run_span,
    "MCP configuration auto-approves `Bash(pipx run ...)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_package_install,
    autoapprove_package_install_span,
    "MCP configuration auto-approves package installation commands through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_git_clone,
    autoapprove_git_clone_span,
    "MCP configuration auto-approves `Bash(git clone:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_git_fetch,
    autoapprove_git_fetch_span,
    "MCP configuration auto-approves `Bash(git fetch:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_git_ls_remote,
    autoapprove_git_ls_remote_span,
    "MCP configuration auto-approves `Bash(git ls-remote:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_git_add,
    autoapprove_git_add_span,
    "MCP configuration auto-approves `Bash(git add:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_git_config,
    autoapprove_git_config_span,
    "MCP configuration auto-approves `Bash(git config:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_git_tag,
    autoapprove_git_tag_span,
    "MCP configuration auto-approves `Bash(git tag:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_git_branch,
    autoapprove_git_branch_span,
    "MCP configuration auto-approves `Bash(git branch:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_git_stash,
    autoapprove_git_stash_span,
    "MCP configuration auto-approves `Bash(git stash:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_git_restore,
    autoapprove_git_restore_span,
    "MCP configuration auto-approves `Bash(git restore:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_git_rebase,
    autoapprove_git_rebase_span,
    "MCP configuration auto-approves `Bash(git rebase:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_git_merge,
    autoapprove_git_merge_span,
    "MCP configuration auto-approves `Bash(git merge:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_git_cherry_pick,
    autoapprove_git_cherry_pick_span,
    "MCP configuration auto-approves `Bash(git cherry-pick:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_git_apply,
    autoapprove_git_apply_span,
    "MCP configuration auto-approves `Bash(git apply:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_git_am,
    autoapprove_git_am_span,
    "MCP configuration auto-approves `Bash(git am:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_gh_pr,
    autoapprove_gh_pr_span,
    "MCP configuration auto-approves `Bash(gh pr:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_crontab,
    autoapprove_crontab_span,
    "MCP configuration auto-approves `Bash(crontab:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_systemctl_enable,
    autoapprove_systemctl_enable_span,
    "MCP configuration auto-approves `Bash(systemctl enable:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_launchctl_load,
    autoapprove_launchctl_load_span,
    "MCP configuration auto-approves `Bash(launchctl load:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_launchctl_bootstrap,
    autoapprove_launchctl_bootstrap_span,
    "MCP configuration auto-approves `Bash(launchctl bootstrap:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_chmod,
    autoapprove_chmod_span,
    "MCP configuration auto-approves `Bash(chmod:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_chown,
    autoapprove_chown_span,
    "MCP configuration auto-approves `Bash(chown:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_chgrp,
    autoapprove_chgrp_span,
    "MCP configuration auto-approves `Bash(chgrp:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_su,
    autoapprove_su_span,
    "MCP configuration auto-approves `Bash(su:*)` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_read_wildcard,
    autoapprove_read_wildcard_span,
    "MCP configuration auto-approves blanket read access with `autoApprove: [\"Read(*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_write_wildcard,
    autoapprove_write_wildcard_span,
    "MCP configuration auto-approves blanket write access with `autoApprove: [\"Write(*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_edit_wildcard,
    autoapprove_edit_wildcard_span,
    "MCP configuration auto-approves blanket edit access with `autoApprove: [\"Edit(*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_glob_wildcard,
    autoapprove_glob_wildcard_span,
    "MCP configuration auto-approves blanket file discovery with `autoApprove: [\"Glob(*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_grep_wildcard,
    autoapprove_grep_wildcard_span,
    "MCP configuration auto-approves blanket content search with `autoApprove: [\"Grep(*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_webfetch_wildcard,
    autoapprove_webfetch_wildcard_span,
    "MCP configuration auto-approves blanket remote fetch with `autoApprove: [\"WebFetch(*)\"]`"
);

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

json_span_rule!(
    check_mcp_autoapprove_websearch_wildcard,
    autoapprove_websearch_wildcard_span,
    "MCP configuration auto-approves blanket remote search with `autoApprove: [\"WebSearch(*)\"]`"
);
json_span_rule!(
    check_mcp_autoapprove_read_unscoped,
    autoapprove_read_unscoped_span,
    "MCP configuration auto-approves bare `Read` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_write_unscoped,
    autoapprove_write_unscoped_span,
    "MCP configuration auto-approves bare `Write` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_edit_unscoped,
    autoapprove_edit_unscoped_span,
    "MCP configuration auto-approves bare `Edit` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_glob_unscoped,
    autoapprove_glob_unscoped_span,
    "MCP configuration auto-approves bare `Glob` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_grep_unscoped,
    autoapprove_grep_unscoped_span,
    "MCP configuration auto-approves bare `Grep` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_webfetch_unscoped,
    autoapprove_webfetch_unscoped_span,
    "MCP configuration auto-approves bare `WebFetch` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_websearch_unscoped,
    autoapprove_websearch_unscoped_span,
    "MCP configuration auto-approves bare `WebSearch` through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_read_unsafe_path,
    autoapprove_read_unsafe_path_span,
    "MCP configuration auto-approves `Read(...)` over an unsafe path through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_write_unsafe_path,
    autoapprove_write_unsafe_path_span,
    "MCP configuration auto-approves `Write(...)` over an unsafe path through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_edit_unsafe_path,
    autoapprove_edit_unsafe_path_span,
    "MCP configuration auto-approves `Edit(...)` over an unsafe path through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_glob_unsafe_path,
    autoapprove_glob_unsafe_path_span,
    "MCP configuration auto-approves `Glob(...)` over an unsafe path through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_grep_unsafe_path,
    autoapprove_grep_unsafe_path_span,
    "MCP configuration auto-approves `Grep(...)` over an unsafe path through `autoApprove`"
);
json_span_rule!(
    check_mcp_autoapprove_tools_true,
    autoapprove_tools_true_span,
    "MCP configuration auto-approves all tools with `autoApproveTools: true`"
);
json_span_rule!(
    check_mcp_trust_tools_true,
    trust_tools_true_span,
    "MCP configuration fully trusts tools with `trustTools: true`"
);
json_span_rule!(
    check_mcp_sandbox_disabled,
    sandbox_disabled_span,
    "MCP configuration disables sandboxing with `sandbox: false` or `disableSandbox: true`"
);
json_span_rule!(
    check_mcp_capabilities_wildcard,
    capabilities_wildcard_span,
    "MCP configuration grants all capabilities with `capabilities: [\"*\"]` or `capabilities: \"*\"`"
);
json_span_rule!(
    check_mcp_sudo_command,
    sudo_command_span,
    "MCP configuration launches the server through `sudo`"
);
json_span_rule!(
    check_mcp_sudo_args0,
    sudo_args0_span,
    "MCP configuration passes `sudo` as the first argument in the launch path"
);
json_span_rule!(
    check_mcp_unpinned_docker_image,
    mutable_docker_image_span,
    "MCP configuration launches Docker with an image reference that is not digest-pinned"
);
json_span_rule!(
    check_mcp_sensitive_docker_mount,
    sensitive_docker_mount_span,
    "MCP configuration launches Docker with a bind mount of sensitive host material"
);
json_span_rule!(
    check_mcp_mutable_docker_pull,
    mutable_docker_pull_span,
    "MCP configuration launches Docker with a forced mutable pull policy"
);
json_span_rule!(
    check_mcp_dangerous_docker_flag,
    dangerous_docker_flag_span,
    "MCP configuration launches Docker with a host-escape or privileged runtime flag"
);
json_span_rule!(
    check_plugin_hook_mutable_launcher,
    mutable_plugin_hook_launcher_span,
    "plugin hook command uses a mutable package launcher in committed hooks.json"
);
json_span_rule!(
    check_plugin_hook_inline_download_exec,
    inline_download_exec_plugin_hook_span,
    "plugin hook command downloads remote content and pipes it directly into a shell"
);
json_span_rule!(
    check_plugin_hook_network_tls_bypass,
    network_tls_bypass_plugin_hook_span,
    "plugin hook command disables TLS verification in a network-capable execution path"
);
json_span_rule!(
    check_mcp_root_delete,
    root_delete_command_span,
    "MCP configuration command attempts destructive root deletion"
);
json_span_rule!(
    check_mcp_password_file_access,
    password_file_access_command_span,
    "MCP configuration command accesses a sensitive system password file"
);
json_span_rule!(
    check_mcp_shell_profile_write,
    shell_profile_write_command_span,
    "MCP configuration command writes to a shell profile startup file"
);
json_span_rule!(
    check_mcp_authorized_keys_write,
    authorized_keys_write_command_span,
    "MCP configuration command writes to SSH authorized_keys"
);
json_span_rule!(
    check_plugin_hook_root_delete,
    root_delete_plugin_hook_span,
    "plugin hook command attempts destructive root deletion"
);
json_span_rule!(
    check_plugin_hook_password_file_access,
    password_file_access_plugin_hook_span,
    "plugin hook command accesses a sensitive system password file"
);
json_span_rule!(
    check_plugin_hook_shell_profile_write,
    shell_profile_write_plugin_hook_span,
    "plugin hook command writes to a shell profile startup file"
);
json_span_rule!(
    check_plugin_hook_authorized_keys_write,
    authorized_keys_write_plugin_hook_span,
    "plugin hook command writes to SSH authorized_keys"
);
json_span_rule!(
    check_mcp_sensitive_file_exfil,
    sensitive_file_exfil_command_span,
    "MCP configuration command transfers a sensitive credential file to a remote destination"
);
json_span_rule!(
    check_plugin_hook_sensitive_file_exfil,
    sensitive_file_exfil_plugin_hook_span,
    "plugin hook command transfers a sensitive credential file to a remote destination"
);
json_span_rule!(
    check_mcp_clipboard_read,
    clipboard_read_command_span,
    "MCP configuration command reads clipboard contents"
);
json_span_rule!(
    check_mcp_browser_secret_store_access,
    browser_secret_store_access_command_span,
    "MCP configuration command accesses browser credential or cookie store data"
);
json_span_rule!(
    check_plugin_hook_clipboard_read,
    clipboard_read_plugin_hook_span,
    "plugin hook command reads clipboard contents"
);
json_span_rule!(
    check_plugin_hook_browser_secret_store_access,
    browser_secret_store_access_plugin_hook_span,
    "plugin hook command accesses browser credential or cookie store data"
);
json_span_rule!(
    check_mcp_clipboard_exfil,
    clipboard_exfil_command_span,
    "MCP configuration command exfiltrates clipboard contents over the network"
);
json_span_rule!(
    check_mcp_browser_secret_store_exfil,
    browser_secret_store_exfil_command_span,
    "MCP configuration command exfiltrates browser credential or cookie store data"
);
json_span_rule!(
    check_plugin_hook_clipboard_exfil,
    clipboard_exfil_plugin_hook_span,
    "plugin hook command exfiltrates clipboard contents over the network"
);
json_span_rule!(
    check_plugin_hook_browser_secret_store_exfil,
    browser_secret_store_exfil_plugin_hook_span,
    "plugin hook command exfiltrates browser credential or cookie store data"
);
json_span_rule!(
    check_mcp_screen_capture,
    screen_capture_command_span,
    "MCP configuration command captures a screenshot or desktop image"
);
json_span_rule!(
    check_mcp_screen_capture_exfil,
    screen_capture_exfil_command_span,
    "MCP configuration command captures and exfiltrates a screenshot or desktop image"
);
json_span_rule!(
    check_plugin_hook_screen_capture,
    screen_capture_plugin_hook_span,
    "plugin hook command captures a screenshot or desktop image"
);
json_span_rule!(
    check_plugin_hook_screen_capture_exfil,
    screen_capture_exfil_plugin_hook_span,
    "plugin hook command captures and exfiltrates a screenshot or desktop image"
);
json_span_rule!(
    check_mcp_camera_capture,
    camera_capture_command_span,
    "MCP configuration command captures a camera image or webcam stream"
);
json_span_rule!(
    check_mcp_microphone_capture,
    microphone_capture_command_span,
    "MCP configuration command records microphone or audio input"
);
json_span_rule!(
    check_mcp_camera_capture_exfil,
    camera_capture_exfil_command_span,
    "MCP configuration command captures and exfiltrates camera or webcam data"
);
json_span_rule!(
    check_mcp_microphone_capture_exfil,
    microphone_capture_exfil_command_span,
    "MCP configuration command records and exfiltrates microphone or audio input"
);
json_span_rule!(
    check_plugin_hook_camera_capture,
    camera_capture_plugin_hook_span,
    "plugin hook command captures a camera image or webcam stream"
);
json_span_rule!(
    check_plugin_hook_microphone_capture,
    microphone_capture_plugin_hook_span,
    "plugin hook command records microphone or audio input"
);
json_span_rule!(
    check_plugin_hook_camera_capture_exfil,
    camera_capture_exfil_plugin_hook_span,
    "plugin hook command captures and exfiltrates camera or webcam data"
);
json_span_rule!(
    check_plugin_hook_microphone_capture_exfil,
    microphone_capture_exfil_plugin_hook_span,
    "plugin hook command records and exfiltrates microphone or audio input"
);
json_span_rule!(
    check_mcp_keylogging,
    keylogging_command_span,
    "MCP configuration command captures keystrokes or keyboard input"
);
json_span_rule!(
    check_mcp_keylogging_exfil,
    keylogging_exfil_command_span,
    "MCP configuration command captures and exfiltrates keystrokes or keyboard input"
);
json_span_rule!(
    check_plugin_hook_keylogging,
    keylogging_plugin_hook_span,
    "plugin hook command captures keystrokes or keyboard input"
);
json_span_rule!(
    check_plugin_hook_keylogging_exfil,
    keylogging_exfil_plugin_hook_span,
    "plugin hook command captures and exfiltrates keystrokes or keyboard input"
);
json_span_rule!(
    check_mcp_environment_dump,
    environment_dump_command_span,
    "MCP configuration command dumps environment variables or shell state"
);
json_span_rule!(
    check_mcp_environment_dump_exfil,
    environment_dump_exfil_command_span,
    "MCP configuration command dumps and exfiltrates environment variables or shell state"
);
json_span_rule!(
    check_plugin_hook_environment_dump,
    environment_dump_plugin_hook_span,
    "plugin hook command dumps environment variables or shell state"
);
json_span_rule!(
    check_plugin_hook_environment_dump_exfil,
    environment_dump_exfil_plugin_hook_span,
    "plugin hook command dumps and exfiltrates environment variables or shell state"
);
json_span_rule!(
    check_mcp_secret_exfil,
    secret_exfil_command_span,
    "MCP configuration command appears to send secret material over the network"
);
json_span_rule!(
    check_mcp_plain_http_secret_exfil,
    plain_http_secret_exfil_command_span,
    "MCP configuration command sends secret material to an insecure http:// endpoint"
);
json_span_rule!(
    check_mcp_webhook_secret_exfil,
    webhook_secret_exfil_command_span,
    "MCP configuration command posts secret material to a webhook endpoint"
);
json_span_rule!(
    check_plugin_hook_secret_exfil,
    secret_exfil_plugin_hook_span,
    "plugin hook command appears to send secret material over the network"
);
json_span_rule!(
    check_plugin_hook_plain_http_secret_exfil,
    plain_http_secret_exfil_plugin_hook_span,
    "plugin hook command sends secret material to an insecure http:// endpoint"
);
json_span_rule!(
    check_plugin_hook_webhook_secret_exfil,
    webhook_secret_exfil_plugin_hook_span,
    "plugin hook command posts secret material to a webhook endpoint"
);
json_span_rule!(
    check_mcp_cron_persistence,
    cron_persistence_command_span,
    "MCP configuration command manipulates cron persistence"
);
json_span_rule!(
    check_mcp_systemd_service_registration,
    systemd_service_registration_command_span,
    "MCP configuration command registers a systemd service or unit for persistence"
);
json_span_rule!(
    check_mcp_launchd_registration,
    launchd_registration_command_span,
    "MCP configuration command registers a launchd plist for persistence"
);
json_span_rule!(
    check_plugin_hook_cron_persistence,
    cron_persistence_plugin_hook_span,
    "plugin hook command manipulates cron persistence"
);

pub(crate) fn check_plugin_hook_systemd_service_registration(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals.json().and_then(|signals| {
            signals
                .systemd_service_registration_plugin_hook_span
                .clone()
        }),
        "plugin hook command registers a systemd service or unit for persistence",
    )
}

json_span_rule!(
    check_plugin_hook_launchd_registration,
    launchd_registration_plugin_hook_span,
    "plugin hook command registers a launchd plist for persistence"
);
json_span_rule!(
    check_mcp_insecure_permission_change,
    insecure_permission_change_command_span,
    "MCP configuration command performs an insecure permission change"
);
json_span_rule!(
    check_mcp_setuid_setgid,
    setuid_setgid_command_span,
    "MCP configuration command manipulates setuid or setgid permissions"
);
json_span_rule!(
    check_mcp_linux_capability_manipulation,
    linux_capability_manipulation_command_span,
    "MCP configuration command manipulates Linux capabilities"
);
json_span_rule!(
    check_plugin_hook_insecure_permission_change,
    insecure_permission_change_plugin_hook_span,
    "plugin hook command performs an insecure permission change"
);
json_span_rule!(
    check_plugin_hook_setuid_setgid,
    setuid_setgid_plugin_hook_span,
    "plugin hook command manipulates setuid or setgid permissions"
);

pub(crate) fn check_plugin_hook_linux_capability_manipulation(
    ctx: &ScanContext,
    signals: &ArtifactSignals,
    meta: RuleMetadata,
) -> Vec<Finding> {
    finding_from_span(
        ctx,
        meta,
        signals.json().and_then(|signals| {
            signals
                .linux_capability_manipulation_plugin_hook_span
                .clone()
        }),
        "plugin hook command manipulates Linux capabilities",
    )
}

json_span_rule!(
    check_plain_http_config,
    plain_http_endpoint_span,
    "configuration contains an insecure http:// endpoint"
);
json_span_rule!(
    check_mcp_credential_env_passthrough,
    credential_env_passthrough_span,
    "MCP configuration passes through credential environment variables"
);
json_span_rule!(
    check_json_hidden_instruction,
    hidden_instruction_span,
    "configuration description contains override-style hidden instructions"
);
json_span_rule!(
    check_json_sensitive_env_reference,
    sensitive_env_reference_span,
    "configuration forwards a sensitive environment variable reference"
);
json_span_rule!(
    check_json_suspicious_remote_endpoint,
    suspicious_remote_endpoint_span,
    "configuration points at a suspicious remote endpoint"
);
json_span_rule!(
    check_json_literal_secret,
    literal_secret_span,
    "configuration commits literal secret material in env, auth, or header values"
);
json_span_rule!(
    check_json_dangerous_endpoint_host,
    dangerous_endpoint_host_span,
    "configuration endpoint targets a metadata or private-network host literal"
);
json_span_rule!(
    check_json_unsafe_plugin_path,
    unsafe_plugin_path_span,
    "cursor plugin manifest contains an unsafe absolute or parent-traversing path"
);
json_span_rule!(
    check_trust_verification_disabled_config,
    trust_verification_disabled_span,
    "configuration disables TLS or certificate verification"
);
json_span_rule!(
    check_static_auth_exposure_config,
    static_auth_exposure_span,
    "configuration embeds static authentication material in a connection or auth value"
);

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
