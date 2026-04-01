use lintai_api::{ArtifactKind, Span};
use serde_json::{Map, Value};

use crate::json_locator::{JsonLocationMap, JsonPathSegment};
use crate::signals::JsonSignals;

use super::super::auth_env::*;
use super::super::spans::*;
use super::super::tool_descriptor::{
    is_broad_dotenv_env_file, is_plugin_manifest_path_key, is_unsafe_plugin_manifest_path,
};

pub(super) struct JsonObjectCommandShape<'a> {
    pub(super) shell_command_key: Option<&'a str>,
    pub(super) shell_has_dash_c: bool,
    pub(super) command: Option<&'a str>,
    pub(super) args: Option<&'a Vec<Value>>,
}

pub(super) fn analyze_json_object<'a>(
    map: &'a Map<String, Value>,
    path: &[JsonPathSegment],
    locator: Option<&JsonLocationMap>,
    fallback_len: usize,
    artifact_kind: ArtifactKind,
    signals: &mut JsonSignals,
) -> JsonObjectCommandShape<'a> {
    let mut shell_command_key = None;
    let mut shell_has_dash_c = false;
    let command = map.get("command").and_then(Value::as_str);
    let args = map.get("args").and_then(Value::as_array);

    for (key, nested) in map {
        if signals.shell_wrapper_span.is_none() {
            if key == "command" {
                if nested
                    .as_str()
                    .is_some_and(|command| command == "sh" || command == "bash")
                {
                    shell_command_key = Some(key.as_str());
                }
            } else if key == "args" {
                shell_has_dash_c = nested
                    .as_array()
                    .is_some_and(|items| items.iter().any(|item| item.as_str() == Some("-c")));
            }
        }

        if is_env_container_key(key)
            && let Some(env_map) = nested.as_object()
        {
            for (env_key, env_value) in env_map {
                if signals.literal_secret_span.is_none()
                    && is_sensitive_env_var_name(env_key)
                    && let Some(text) = env_value.as_str()
                    && is_literal_secret_value(text)
                {
                    signals.literal_secret_span = Some(resolve_child_relative_value_span(
                        path,
                        key,
                        env_key,
                        Span::new(0, text.len()),
                        locator,
                        fallback_len,
                    ));
                }

                if signals.credential_env_passthrough_span.is_none()
                    && JSON_SECRET_ENV_KEYS
                        .iter()
                        .any(|secret| env_key.eq_ignore_ascii_case(secret))
                {
                    signals.credential_env_passthrough_span = Some(resolve_child_key_span(
                        path,
                        key,
                        env_key,
                        locator,
                        fallback_len,
                    ));
                }

                if signals.sensitive_env_reference_span.is_none()
                    && !is_sensitive_env_var_name(env_key)
                    && let Some(text) = env_value.as_str()
                    && let Some(relative) = find_sensitive_env_reference_relative_span(text)
                {
                    signals.sensitive_env_reference_span = Some(resolve_child_relative_value_span(
                        path,
                        key,
                        env_key,
                        relative,
                        locator,
                        fallback_len,
                    ));
                }

                if signals.credential_env_passthrough_span.is_some()
                    && signals.sensitive_env_reference_span.is_some()
                {
                    break;
                }
            }
        }

        if signals.literal_secret_span.is_none()
            && is_header_container_key(key)
            && let Some(header_map) = nested.as_object()
        {
            for (header_key, header_value) in header_map {
                if is_sensitive_header_name(header_key)
                    && let Some(text) = header_value.as_str()
                    && is_literal_secret_value(text)
                    && !is_static_authorization_literal(header_key, text)
                {
                    signals.literal_secret_span = Some(resolve_child_relative_value_span(
                        path,
                        key,
                        header_key,
                        Span::new(0, text.len()),
                        locator,
                        fallback_len,
                    ));
                    break;
                }
            }
        }

        if signals.trust_verification_disabled_span.is_none()
            && is_trust_verification_disabled_key_value(key, nested)
        {
            signals.trust_verification_disabled_span = Some(resolve_child_value_or_key_span(
                path,
                key,
                locator,
                fallback_len,
            ));
        }

        if signals.static_auth_exposure_span.is_none()
            && key.eq_ignore_ascii_case("authorization")
            && let Some(text) = nested.as_str()
            && let Some(relative) =
                find_literal_value_after_prefixes_case_insensitive(text, &["Bearer ", "Basic "])
        {
            signals.static_auth_exposure_span = Some(resolve_child_relative_value_span(
                path,
                key,
                key,
                relative,
                locator,
                fallback_len,
            ));
        }

        if signals.literal_secret_span.is_none()
            && is_secretish_json_key(key)
            && let Some(text) = nested.as_str()
            && is_literal_secret_value(text)
            && !is_static_authorization_literal(key, text)
        {
            signals.literal_secret_span =
                Some(resolve_child_value_span(path, key, locator, fallback_len));
        }

        if signals.unsafe_plugin_path_span.is_none()
            && artifact_kind == ArtifactKind::CursorPluginManifest
            && is_plugin_manifest_path_key(key)
            && let Some(text) = nested.as_str()
            && is_unsafe_plugin_manifest_path(text)
        {
            signals.unsafe_plugin_path_span =
                Some(resolve_child_value_span(path, key, locator, fallback_len));
        }

        if signals.broad_env_file_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && signals.expanded_mcp_client_variant
            && key == "envFile"
            && let Some(text) = nested.as_str()
            && is_broad_dotenv_env_file(text)
        {
            signals.broad_env_file_span =
                Some(resolve_child_value_span(path, key, locator, fallback_len));
        }

        if signals.autoapprove_wildcard_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "*")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_wildcard_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_bash_wildcard_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_bash_wildcard_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_curl_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(curl:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_curl_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_wget_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(wget:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_wget_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_sudo_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(sudo:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_sudo_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_rm_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(rm:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_rm_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_git_push_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(git push)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_git_push_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_gh_api_post_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) =
                find_string_array_item_index(nested, "Bash(gh api --method POST:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_gh_api_post_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_git_checkout_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(git checkout:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_git_checkout_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_git_commit_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(git commit:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_git_commit_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_git_reset_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(git reset:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_git_reset_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_git_clean_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(git clean:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_git_clean_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_gh_api_delete_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) =
                find_string_array_item_index(nested, "Bash(gh api --method DELETE:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_gh_api_delete_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_gh_api_patch_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) =
                find_string_array_item_index(nested, "Bash(gh api --method PATCH:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_gh_api_patch_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_gh_api_put_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(gh api --method PUT:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_gh_api_put_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_gh_issue_create_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(gh issue create:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_gh_issue_create_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_gh_repo_create_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(gh repo create:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_gh_repo_create_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_gh_repo_delete_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(gh repo delete:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_gh_repo_delete_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_gh_repo_edit_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(gh repo edit:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_gh_repo_edit_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_gh_secret_set_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(gh secret set:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_gh_secret_set_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_gh_variable_set_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(gh variable set:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_gh_variable_set_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_gh_workflow_run_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(gh workflow run:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_gh_workflow_run_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_gh_secret_delete_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(gh secret delete:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_gh_secret_delete_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_gh_variable_delete_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(gh variable delete:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_gh_variable_delete_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_gh_workflow_disable_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(gh workflow disable:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_gh_workflow_disable_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_gh_repo_transfer_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(gh repo transfer:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_gh_repo_transfer_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_gh_release_create_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(gh release create:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_gh_release_create_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_gh_release_delete_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(gh release delete:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_gh_release_delete_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_gh_release_upload_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(gh release upload:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_gh_release_upload_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_npx_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_prefixed_string_array_item_index(nested, "Bash(npx ")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_npx_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_uvx_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_prefixed_string_array_item_index(nested, "Bash(uvx ")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_uvx_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_npm_exec_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_prefixed_string_array_item_index(nested, "Bash(npm exec ")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_npm_exec_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_bunx_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_prefixed_string_array_item_index(nested, "Bash(bunx ")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_bunx_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_pnpm_dlx_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_prefixed_string_array_item_index(nested, "Bash(pnpm dlx ")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_pnpm_dlx_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_yarn_dlx_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_prefixed_string_array_item_index(nested, "Bash(yarn dlx ")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_yarn_dlx_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_pipx_run_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_prefixed_string_array_item_index(nested, "Bash(pipx run ")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_pipx_run_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_package_install_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_matching_index(nested, |text| {
                matches!(
                    text,
                    "Bash(pip install)"
                        | "Bash(pip3 install)"
                        | "Bash(python -m pip install)"
                        | "Bash(yarn install)"
                        | "Bash(npm install)"
                        | "Bash(pnpm install)"
                        | "Bash(bun install)"
                )
            })
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_package_install_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_git_clone_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(git clone:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_git_clone_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_git_fetch_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(git fetch:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_git_fetch_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_git_ls_remote_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(git ls-remote:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_git_ls_remote_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_git_add_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(git add:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_git_add_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_git_config_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(git config:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_git_config_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_git_tag_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(git tag:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_git_tag_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_git_branch_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(git branch:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_git_branch_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_git_stash_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(git stash:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_git_stash_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_git_restore_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(git restore:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_git_restore_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_git_rebase_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(git rebase:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_git_rebase_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_git_merge_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(git merge:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_git_merge_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_git_cherry_pick_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(git cherry-pick:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_git_cherry_pick_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_git_apply_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(git apply:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_git_apply_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_git_am_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(git am:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_git_am_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_gh_pr_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(gh pr:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_gh_pr_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_crontab_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(crontab:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_crontab_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_systemctl_enable_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(systemctl enable:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_systemctl_enable_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_launchctl_load_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(launchctl load:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_launchctl_load_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_launchctl_bootstrap_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(launchctl bootstrap:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_launchctl_bootstrap_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_chmod_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(chmod:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_chmod_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_chown_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(chown:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_chown_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_chgrp_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(chgrp:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_chgrp_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_su_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Bash(su:*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_su_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_read_wildcard_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Read(*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_read_wildcard_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_write_wildcard_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Write(*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_write_wildcard_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_edit_wildcard_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Edit(*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_edit_wildcard_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_glob_wildcard_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Glob(*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_glob_wildcard_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_grep_wildcard_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "Grep(*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_grep_wildcard_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_webfetch_wildcard_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "WebFetch(*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_webfetch_wildcard_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals
            .autoapprove_webfetch_raw_githubusercontent_span
            .is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) =
                find_string_array_item_index(nested, "WebFetch(domain:raw.githubusercontent.com)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_webfetch_raw_githubusercontent_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_websearch_wildcard_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_index(nested, "WebSearch(*)")
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_websearch_wildcard_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_read_unsafe_path_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_matching_index(nested, |item| {
                tool_has_unsafe_path_scope(item, "Read")
            })
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_read_unsafe_path_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_write_unsafe_path_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_matching_index(nested, |item| {
                tool_has_unsafe_path_scope(item, "Write")
            })
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_write_unsafe_path_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_edit_unsafe_path_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_matching_index(nested, |item| {
                tool_has_unsafe_path_scope(item, "Edit")
            })
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_edit_unsafe_path_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_glob_unsafe_path_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_matching_index(nested, |item| {
                tool_has_unsafe_path_scope(item, "Glob")
            })
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_glob_unsafe_path_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_grep_unsafe_path_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApprove"
            && let Some(index) = find_string_array_item_matching_index(nested, |item| {
                tool_has_unsafe_path_scope(item, "Grep")
            })
        {
            let key_path = with_child_key(path, key);
            let item_path = with_child_index(&key_path, index);
            signals.autoapprove_grep_unsafe_path_span =
                Some(resolve_value_span(&item_path, locator, fallback_len));
        }

        if signals.autoapprove_tools_true_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "autoApproveTools"
            && nested.as_bool() == Some(true)
        {
            signals.autoapprove_tools_true_span =
                Some(resolve_child_value_span(path, key, locator, fallback_len));
        }

        if signals.trust_tools_true_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "trustTools"
            && nested.as_bool() == Some(true)
        {
            signals.trust_tools_true_span =
                Some(resolve_child_value_span(path, key, locator, fallback_len));
        }

        if signals.sandbox_disabled_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && ((key == "sandbox" && nested.as_bool() == Some(false))
                || (key == "disableSandbox" && nested.as_bool() == Some(true)))
        {
            signals.sandbox_disabled_span =
                Some(resolve_child_value_span(path, key, locator, fallback_len));
        }

        if signals.capabilities_wildcard_span.is_none()
            && artifact_kind == ArtifactKind::McpConfig
            && key == "capabilities"
        {
            if let Some(index) = find_string_array_item_index(nested, "*") {
                let key_path = with_child_key(path, key);
                let item_path = with_child_index(&key_path, index);
                signals.capabilities_wildcard_span =
                    Some(resolve_value_span(&item_path, locator, fallback_len));
            } else if nested.as_str() == Some("*") {
                signals.capabilities_wildcard_span =
                    Some(resolve_child_value_span(path, key, locator, fallback_len));
            }
        }
    }

    JsonObjectCommandShape {
        shell_command_key,
        shell_has_dash_c,
        command,
        args,
    }
}

fn find_string_array_item_index(value: &Value, wanted: &str) -> Option<usize> {
    value
        .as_array()
        .and_then(|items| items.iter().position(|item| item.as_str() == Some(wanted)))
}

fn find_prefixed_string_array_item_index(value: &Value, prefix: &str) -> Option<usize> {
    value.as_array().and_then(|items| {
        items
            .iter()
            .position(|item| item.as_str().is_some_and(|text| text.starts_with(prefix)))
    })
}

fn find_string_array_item_matching_index(
    value: &Value,
    matcher: impl Fn(&str) -> bool,
) -> Option<usize> {
    value.as_array().and_then(|items| {
        items
            .iter()
            .position(|item| item.as_str().is_some_and(&matcher))
    })
}

fn is_unsafe_tool_scope_path(value: &str) -> bool {
    let normalized = value.trim();
    normalized.starts_with('/')
        || normalized.starts_with("~/")
        || normalized.starts_with("~\\")
        || normalized.contains("../")
        || normalized.contains("..\\")
        || normalized
            .as_bytes()
            .get(1)
            .is_some_and(|byte| *byte == b':')
}

fn tool_has_unsafe_path_scope(token: &str, tool_name: &str) -> bool {
    let trimmed = token.trim();
    let Some(inner) = trimmed
        .strip_prefix(tool_name)
        .and_then(|remainder| remainder.strip_prefix('('))
        .and_then(|remainder| remainder.strip_suffix(')'))
    else {
        return false;
    };

    is_unsafe_tool_scope_path(inner)
}
