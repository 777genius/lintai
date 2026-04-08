use lintai_api::{Finding, RuleMetadata, ScanContext, Span};

use crate::helpers::finding_for_region;
use crate::signals::ArtifactSignals;

macro_rules! claude_settings_span_rule {
    ($fn_name:ident, $field:ident, $message:literal) => {
        pub(crate) fn $fn_name(
            ctx: &ScanContext,
            signals: &ArtifactSignals,
            meta: RuleMetadata,
        ) -> Vec<Finding> {
            finding_from_span(
                ctx,
                meta,
                signals
                    .claude_settings()
                    .and_then(|signals| signals.$field.clone()),
                $message,
            )
        }
    };
}

claude_settings_span_rule!(
    check_claude_settings_mutable_launcher,
    mutable_launcher_span,
    "Claude settings command hook uses a mutable package launcher"
);
claude_settings_span_rule!(
    check_claude_settings_missing_schema,
    missing_schema_span,
    "Claude settings file is missing a top-level `$schema` reference"
);
claude_settings_span_rule!(
    check_claude_settings_missing_hook_timeout,
    missing_hook_timeout_span,
    "Claude settings command hook is missing an explicit `timeout` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_invalid_hook_matcher_event,
    invalid_hook_matcher_event_span,
    "Claude settings use `matcher` on a hook event that does not support it"
);
claude_settings_span_rule!(
    check_claude_settings_missing_required_hook_matcher,
    missing_required_hook_matcher_span,
    "Claude settings omit `matcher` on a hook event that expects scoped matching"
);
claude_settings_span_rule!(
    check_claude_settings_bypass_permissions,
    bypass_permissions_span,
    "Claude settings set `permissions.defaultMode` to `bypassPermissions` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_insecure_http_hook_url,
    insecure_http_hook_url_span,
    "Claude settings allow non-HTTPS HTTP hook URLs in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_dangerous_http_hook_host,
    dangerous_http_hook_host_span,
    "Claude settings allow dangerous host literals in `allowedHttpHookUrls`"
);
claude_settings_span_rule!(
    check_claude_settings_bash_wildcard,
    bash_wildcard_span,
    "Claude settings permissions allow `Bash(*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_unscoped_bash,
    unscoped_bash_span,
    "Claude settings permissions allow bare `Bash` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_unscoped_read,
    unscoped_read_span,
    "Claude settings permissions allow bare `Read` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_unscoped_write,
    unscoped_write_span,
    "Claude settings permissions allow bare `Write` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_unscoped_edit,
    unscoped_edit_span,
    "Claude settings permissions allow bare `Edit` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_unscoped_glob,
    unscoped_glob_span,
    "Claude settings permissions allow bare `Glob` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_unscoped_grep,
    unscoped_grep_span,
    "Claude settings permissions allow bare `Grep` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_unscoped_webfetch,
    unscoped_webfetch_span,
    "Claude settings permissions allow bare `WebFetch` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_webfetch_wildcard,
    webfetch_wildcard_span,
    "Claude settings permissions allow `WebFetch(*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_write_wildcard,
    write_wildcard_span,
    "Claude settings permissions allow `Write(*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_webfetch_raw_githubusercontent,
    webfetch_raw_githubusercontent_span,
    "Claude settings permissions allow `WebFetch(domain:raw.githubusercontent.com)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_read_wildcard,
    read_wildcard_span,
    "Claude settings permissions allow `Read(*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_edit_wildcard,
    edit_wildcard_span,
    "Claude settings permissions allow `Edit(*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_read_unsafe_path,
    read_unsafe_path_span,
    "Claude settings permissions allow `Read(...)` over an unsafe path in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_write_unsafe_path,
    write_unsafe_path_span,
    "Claude settings permissions allow `Write(...)` over an unsafe path in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_edit_unsafe_path,
    edit_unsafe_path_span,
    "Claude settings permissions allow `Edit(...)` over an unsafe path in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_glob_unsafe_path,
    glob_unsafe_path_span,
    "Claude settings permissions allow `Glob(...)` over an unsafe path in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_grep_unsafe_path,
    grep_unsafe_path_span,
    "Claude settings permissions allow `Grep(...)` over an unsafe path in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_websearch_wildcard,
    websearch_wildcard_span,
    "Claude settings permissions allow `WebSearch(*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_unscoped_websearch,
    unscoped_websearch_span,
    "Claude settings permissions allow bare `WebSearch` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_git_push_permission,
    git_push_permission_span,
    "Claude settings permissions allow `Bash(git push)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_git_add_permission,
    git_add_permission_span,
    "Claude settings permissions allow `Bash(git add:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_git_clone_permission,
    git_clone_permission_span,
    "Claude settings permissions allow `Bash(git clone:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_gh_pr_permission,
    gh_pr_permission_span,
    "Claude settings permissions allow `Bash(gh pr:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_gh_api_post_permission,
    gh_api_post_permission_span,
    "Claude settings permissions allow `Bash(gh api --method POST:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_gh_issue_create_permission,
    gh_issue_create_permission_span,
    "Claude settings permissions allow `Bash(gh issue create:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_gh_api_delete_permission,
    gh_api_delete_permission_span,
    "Claude settings permissions allow `Bash(gh api --method DELETE:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_gh_api_patch_permission,
    gh_api_patch_permission_span,
    "Claude settings permissions allow `Bash(gh api --method PATCH:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_gh_api_put_permission,
    gh_api_put_permission_span,
    "Claude settings permissions allow `Bash(gh api --method PUT:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_gh_repo_create_permission,
    gh_repo_create_permission_span,
    "Claude settings permissions allow `Bash(gh repo create:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_gh_repo_delete_permission,
    gh_repo_delete_permission_span,
    "Claude settings permissions allow `Bash(gh repo delete:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_gh_repo_edit_permission,
    gh_repo_edit_permission_span,
    "Claude settings permissions allow `Bash(gh repo edit:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_gh_repo_transfer_permission,
    gh_repo_transfer_permission_span,
    "Claude settings permissions allow `Bash(gh repo transfer:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_gh_release_create_permission,
    gh_release_create_permission_span,
    "Claude settings permissions allow `Bash(gh release create:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_gh_release_delete_permission,
    gh_release_delete_permission_span,
    "Claude settings permissions allow `Bash(gh release delete:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_gh_release_upload_permission,
    gh_release_upload_permission_span,
    "Claude settings permissions allow `Bash(gh release upload:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_gh_secret_set_permission,
    gh_secret_set_permission_span,
    "Claude settings permissions allow `Bash(gh secret set:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_gh_variable_set_permission,
    gh_variable_set_permission_span,
    "Claude settings permissions allow `Bash(gh variable set:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_gh_workflow_run_permission,
    gh_workflow_run_permission_span,
    "Claude settings permissions allow `Bash(gh workflow run:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_gh_secret_delete_permission,
    gh_secret_delete_permission_span,
    "Claude settings permissions allow `Bash(gh secret delete:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_gh_variable_delete_permission,
    gh_variable_delete_permission_span,
    "Claude settings permissions allow `Bash(gh variable delete:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_gh_workflow_disable_permission,
    gh_workflow_disable_permission_span,
    "Claude settings permissions allow `Bash(gh workflow disable:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_git_fetch_permission,
    git_fetch_permission_span,
    "Claude settings permissions allow `Bash(git fetch:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_git_ls_remote_permission,
    git_ls_remote_permission_span,
    "Claude settings permissions allow `Bash(git ls-remote:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_npx_permission,
    npx_permission_span,
    "Claude settings permissions allow `Bash(npx ...)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_uvx_permission,
    uvx_permission_span,
    "Claude settings permissions allow `Bash(uvx ...)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_npm_exec_permission,
    npm_exec_permission_span,
    "Claude settings permissions allow `Bash(npm exec ...)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_bunx_permission,
    bunx_permission_span,
    "Claude settings permissions allow `Bash(bunx ...)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_pnpm_dlx_permission,
    pnpm_dlx_permission_span,
    "Claude settings permissions allow `Bash(pnpm dlx ...)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_yarn_dlx_permission,
    yarn_dlx_permission_span,
    "Claude settings permissions allow `Bash(yarn dlx ...)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_pipx_run_permission,
    pipx_run_permission_span,
    "Claude settings permissions allow `Bash(pipx run ...)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_curl_permission,
    curl_permission_span,
    "Claude settings permissions allow `Bash(curl:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_wget_permission,
    wget_permission_span,
    "Claude settings permissions allow `Bash(wget:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_git_config_permission,
    git_config_permission_span,
    "Claude settings permissions allow `Bash(git config:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_git_tag_permission,
    git_tag_permission_span,
    "Claude settings permissions allow `Bash(git tag:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_git_branch_permission,
    git_branch_permission_span,
    "Claude settings permissions allow `Bash(git branch:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_enabled_mcpjson_servers,
    enabled_mcpjson_servers_span,
    "Claude settings enable `enabledMcpjsonServers` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_package_install_permission,
    package_install_permission_span,
    "Claude settings permissions allow package installation commands in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_git_checkout_permission,
    git_checkout_permission_span,
    "Claude settings permissions allow `Bash(git checkout:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_git_commit_permission,
    git_commit_permission_span,
    "Claude settings permissions allow `Bash(git commit:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_git_stash_permission,
    git_stash_permission_span,
    "Claude settings permissions allow `Bash(git stash:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_git_reset_permission,
    git_reset_permission_span,
    "Claude settings permissions allow `Bash(git reset:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_git_clean_permission,
    git_clean_permission_span,
    "Claude settings permissions allow `Bash(git clean:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_git_restore_permission,
    git_restore_permission_span,
    "Claude settings permissions allow `Bash(git restore:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_git_rebase_permission,
    git_rebase_permission_span,
    "Claude settings permissions allow `Bash(git rebase:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_git_merge_permission,
    git_merge_permission_span,
    "Claude settings permissions allow `Bash(git merge:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_git_cherry_pick_permission,
    git_cherry_pick_permission_span,
    "Claude settings permissions allow `Bash(git cherry-pick:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_git_apply_permission,
    git_apply_permission_span,
    "Claude settings permissions allow `Bash(git apply:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_git_am_permission,
    git_am_permission_span,
    "Claude settings permissions allow `Bash(git am:*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_glob_wildcard,
    glob_wildcard_span,
    "Claude settings permissions allow `Glob(*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_grep_wildcard,
    grep_wildcard_span,
    "Claude settings permissions allow `Grep(*)` in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_home_directory_hook_command,
    home_directory_hook_command_span,
    "Claude settings hook command uses a home-directory path in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_external_absolute_hook_command,
    external_absolute_hook_command_span,
    "Claude settings hook command uses a repo-external absolute path in a shared committed config"
);
claude_settings_span_rule!(
    check_claude_settings_inline_download_exec,
    inline_download_exec_span,
    "Claude settings command hook downloads remote content and pipes it directly into a shell"
);
claude_settings_span_rule!(
    check_claude_settings_network_tls_bypass,
    network_tls_bypass_span,
    "Claude settings command hook disables TLS verification in a network-capable execution path"
);
claude_settings_span_rule!(
    check_claude_settings_root_delete,
    root_delete_span,
    "Claude settings command hook attempts destructive root deletion"
);
claude_settings_span_rule!(
    check_claude_settings_password_file_access,
    password_file_access_span,
    "Claude settings command hook accesses a sensitive system password file"
);
claude_settings_span_rule!(
    check_claude_settings_shell_profile_write,
    shell_profile_write_span,
    "Claude settings command hook writes to a shell profile startup file"
);
claude_settings_span_rule!(
    check_claude_settings_authorized_keys_write,
    authorized_keys_write_span,
    "Claude settings command hook writes to SSH authorized_keys"
);
claude_settings_span_rule!(
    check_claude_settings_sensitive_file_exfil,
    sensitive_file_exfil_span,
    "Claude settings command hook transfers a sensitive credential file to a remote destination"
);
claude_settings_span_rule!(
    check_claude_settings_clipboard_read,
    clipboard_read_span,
    "Claude settings command hook reads clipboard contents"
);
claude_settings_span_rule!(
    check_claude_settings_browser_secret_store_access,
    browser_secret_store_access_span,
    "Claude settings command hook accesses browser credential or cookie store data"
);
claude_settings_span_rule!(
    check_claude_settings_clipboard_exfil,
    clipboard_exfil_span,
    "Claude settings command hook exfiltrates clipboard contents over the network"
);
claude_settings_span_rule!(
    check_claude_settings_browser_secret_store_exfil,
    browser_secret_store_exfil_span,
    "Claude settings command hook exfiltrates browser credential or cookie store data"
);
claude_settings_span_rule!(
    check_claude_settings_screen_capture,
    screen_capture_span,
    "Claude settings command hook captures a screenshot or desktop image"
);
claude_settings_span_rule!(
    check_claude_settings_screen_capture_exfil,
    screen_capture_exfil_span,
    "Claude settings command hook captures and exfiltrates a screenshot or desktop image"
);
claude_settings_span_rule!(
    check_claude_settings_camera_capture,
    camera_capture_span,
    "Claude settings command hook captures a camera image or webcam stream"
);
claude_settings_span_rule!(
    check_claude_settings_microphone_capture,
    microphone_capture_span,
    "Claude settings command hook records microphone or audio input"
);
claude_settings_span_rule!(
    check_claude_settings_camera_capture_exfil,
    camera_capture_exfil_span,
    "Claude settings command hook captures and exfiltrates camera or webcam data"
);
claude_settings_span_rule!(
    check_claude_settings_microphone_capture_exfil,
    microphone_capture_exfil_span,
    "Claude settings command hook records and exfiltrates microphone or audio input"
);
claude_settings_span_rule!(
    check_claude_settings_keylogging,
    keylogging_span,
    "Claude settings command hook captures keystrokes or keyboard input"
);
claude_settings_span_rule!(
    check_claude_settings_keylogging_exfil,
    keylogging_exfil_span,
    "Claude settings command hook captures and exfiltrates keystrokes or keyboard input"
);
claude_settings_span_rule!(
    check_claude_settings_environment_dump,
    environment_dump_span,
    "Claude settings command hook dumps environment variables or shell state"
);
claude_settings_span_rule!(
    check_claude_settings_environment_dump_exfil,
    environment_dump_exfil_span,
    "Claude settings command hook dumps and exfiltrates environment variables or shell state"
);
claude_settings_span_rule!(
    check_claude_settings_secret_exfil,
    secret_exfil_span,
    "Claude settings command hook appears to send secret material over the network"
);
claude_settings_span_rule!(
    check_claude_settings_plain_http_secret_exfil,
    plain_http_secret_exfil_span,
    "Claude settings command hook sends secret material to an insecure http:// endpoint"
);
claude_settings_span_rule!(
    check_claude_settings_webhook_secret_exfil,
    webhook_secret_exfil_span,
    "Claude settings command hook posts secret material to a webhook endpoint"
);
claude_settings_span_rule!(
    check_claude_settings_cron_persistence,
    cron_persistence_span,
    "Claude settings command hook manipulates cron persistence"
);
claude_settings_span_rule!(
    check_claude_settings_systemd_service_registration,
    systemd_service_registration_span,
    "Claude settings command hook registers a systemd service or unit for persistence"
);
claude_settings_span_rule!(
    check_claude_settings_launchd_registration,
    launchd_registration_span,
    "Claude settings command hook registers a launchd plist for persistence"
);
claude_settings_span_rule!(
    check_claude_settings_insecure_permission_change,
    insecure_permission_change_span,
    "Claude settings command hook performs an insecure permission change"
);
claude_settings_span_rule!(
    check_claude_settings_setuid_setgid,
    setuid_setgid_span,
    "Claude settings command hook manipulates setuid or setgid permissions"
);
claude_settings_span_rule!(
    check_claude_settings_linux_capability_manipulation,
    linux_capability_manipulation_span,
    "Claude settings command hook manipulates Linux capabilities"
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
