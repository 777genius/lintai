use lintai_api::{ArtifactKind, ScanContext, Span};
use serde_json::Value;

use crate::helpers::json_semantics;
use crate::json_locator::{JsonLocationMap, JsonPathSegment};

use super::shared::{
    json::{
        find_dangerous_endpoint_host_relative_span, find_non_loopback_http_relative_span,
        visit_claude_settings_value,
    },
    markdown::is_fixture_like_claude_settings_path,
};
use super::{ClaudeSettingsSignals, SignalWorkBudget};

fn leading_json_file_relative_span(content: &str) -> Option<Span> {
    content
        .char_indices()
        .find(|(_, ch)| !ch.is_whitespace())
        .map(|(index, ch)| Span::new(index, index + ch.len_utf8()))
}

fn resolve_permissions_allow_exact_span(
    value: &serde_json::Value,
    locator: Option<&JsonLocationMap>,
    permission: &str,
) -> Option<Span> {
    let allow = value
        .get("permissions")
        .and_then(|permissions| permissions.get("allow"))
        .and_then(serde_json::Value::as_array)?;
    let index = allow
        .iter()
        .position(|entry| entry.as_str() == Some(permission))?;
    let path = vec![
        JsonPathSegment::Key("permissions".to_owned()),
        JsonPathSegment::Key("allow".to_owned()),
        JsonPathSegment::Index(index),
    ];
    locator.and_then(|locator| locator.value_span(&path).cloned())
}

fn resolve_permissions_allow_prefix_span(
    value: &serde_json::Value,
    locator: Option<&JsonLocationMap>,
    prefix: &str,
) -> Option<Span> {
    let allow = value
        .get("permissions")
        .and_then(|permissions| permissions.get("allow"))
        .and_then(serde_json::Value::as_array)?;
    let index = allow.iter().position(|entry| {
        entry
            .as_str()
            .is_some_and(|permission| permission.starts_with(prefix))
    })?;
    let path = vec![
        JsonPathSegment::Key("permissions".to_owned()),
        JsonPathSegment::Key("allow".to_owned()),
        JsonPathSegment::Index(index),
    ];
    locator.and_then(|locator| locator.value_span(&path).cloned())
}

fn resolve_permissions_allow_any_exact_span(
    value: &serde_json::Value,
    locator: Option<&JsonLocationMap>,
    permissions: &[&str],
) -> Option<Span> {
    let allow = value
        .get("permissions")
        .and_then(|permissions| permissions.get("allow"))
        .and_then(serde_json::Value::as_array)?;
    let index = allow.iter().position(|entry| {
        entry
            .as_str()
            .is_some_and(|permission| permissions.contains(&permission))
    })?;
    let path = vec![
        JsonPathSegment::Key("permissions".to_owned()),
        JsonPathSegment::Key("allow".to_owned()),
        JsonPathSegment::Index(index),
    ];
    locator.and_then(|locator| locator.value_span(&path).cloned())
}

fn is_unsafe_permission_scope_path(value: &str) -> bool {
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

fn permission_has_unsafe_path_scope(permission: &str, tool_name: &str) -> bool {
    let trimmed = permission.trim();
    let Some(inner) = trimmed
        .strip_prefix(tool_name)
        .and_then(|remainder| remainder.strip_prefix('('))
        .and_then(|remainder| remainder.strip_suffix(')'))
    else {
        return false;
    };

    is_unsafe_permission_scope_path(inner)
}

fn resolve_permissions_allow_matching_span(
    value: &serde_json::Value,
    locator: Option<&JsonLocationMap>,
    matcher: impl Fn(&str) -> bool,
) -> Option<Span> {
    let allow = value
        .get("permissions")
        .and_then(|permissions| permissions.get("allow"))
        .and_then(serde_json::Value::as_array)?;
    let index = allow
        .iter()
        .position(|entry| entry.as_str().is_some_and(&matcher))?;
    let path = vec![
        JsonPathSegment::Key("permissions".to_owned()),
        JsonPathSegment::Key("allow".to_owned()),
        JsonPathSegment::Index(index),
    ];
    locator.and_then(|locator| locator.value_span(&path).cloned())
}

fn resolve_bypass_permissions_span(
    value: &serde_json::Value,
    locator: Option<&JsonLocationMap>,
) -> Option<Span> {
    let mode = value
        .get("permissions")
        .and_then(|permissions| permissions.get("defaultMode"))
        .and_then(serde_json::Value::as_str)?;
    if mode != "bypassPermissions" {
        return None;
    }
    let path = vec![
        JsonPathSegment::Key("permissions".to_owned()),
        JsonPathSegment::Key("defaultMode".to_owned()),
    ];
    locator.and_then(|locator| locator.value_span(&path).cloned())
}

fn resolve_enabled_mcpjson_servers_span(
    value: &serde_json::Value,
    locator: Option<&JsonLocationMap>,
) -> Option<Span> {
    let entry = value.get("enabledMcpjsonServers")?;
    let is_enabled = match entry {
        Value::Array(values) => !values.is_empty(),
        Value::String(value) => !value.trim().is_empty(),
        _ => false,
    };
    if !is_enabled {
        return None;
    }
    let path = vec![JsonPathSegment::Key("enabledMcpjsonServers".to_owned())];
    locator.and_then(|locator| locator.key_span(&path).cloned())
}

fn resolve_insecure_http_hook_url_span(
    value: &serde_json::Value,
    locator: Option<&JsonLocationMap>,
) -> Option<Span> {
    let urls = value.get("allowedHttpHookUrls").and_then(Value::as_array)?;
    let (index, relative) = urls.iter().enumerate().find_map(|(index, entry)| {
        let url = entry.as_str()?;
        let relative = find_non_loopback_http_relative_span(url)?;
        Some((index, relative))
    })?;
    let path = vec![
        JsonPathSegment::Key("allowedHttpHookUrls".to_owned()),
        JsonPathSegment::Index(index),
    ];
    locator
        .and_then(|locator| locator.value_span(&path).cloned())
        .map(|span| {
            Span::new(
                span.start_byte + relative.start_byte,
                span.start_byte + relative.end_byte,
            )
        })
}

fn resolve_dangerous_http_hook_host_span(
    value: &serde_json::Value,
    locator: Option<&JsonLocationMap>,
) -> Option<Span> {
    let urls = value.get("allowedHttpHookUrls").and_then(Value::as_array)?;
    let (index, relative) = urls.iter().enumerate().find_map(|(index, entry)| {
        let url = entry.as_str()?;
        let relative = find_dangerous_endpoint_host_relative_span(url)?;
        Some((index, relative))
    })?;
    let path = vec![
        JsonPathSegment::Key("allowedHttpHookUrls".to_owned()),
        JsonPathSegment::Index(index),
    ];
    locator
        .and_then(|locator| locator.value_span(&path).cloned())
        .map(|span| {
            Span::new(
                span.start_byte + relative.start_byte,
                span.start_byte + relative.end_byte,
            )
        })
}

fn resolve_missing_hook_timeout_span(
    value: &serde_json::Value,
    locator: Option<&JsonLocationMap>,
) -> Option<Span> {
    let hooks = value.get("hooks")?.as_object()?;

    for (event_name, event_entries) in hooks {
        let Some(event_entries) = event_entries.as_array() else {
            continue;
        };

        for (entry_index, entry) in event_entries.iter().enumerate() {
            let Some(entry_hooks) = entry.get("hooks").and_then(Value::as_array) else {
                continue;
            };

            for (hook_index, hook) in entry_hooks.iter().enumerate() {
                if hook.get("type").and_then(Value::as_str) != Some("command") {
                    continue;
                }
                if hook.get("timeout").is_some() {
                    continue;
                }
                if hook.get("command").and_then(Value::as_str).is_none() {
                    continue;
                }

                let path = vec![
                    JsonPathSegment::Key("hooks".to_owned()),
                    JsonPathSegment::Key(event_name.clone()),
                    JsonPathSegment::Index(entry_index),
                    JsonPathSegment::Key("hooks".to_owned()),
                    JsonPathSegment::Index(hook_index),
                    JsonPathSegment::Key("command".to_owned()),
                ];
                return locator.and_then(|locator| locator.value_span(&path).cloned());
            }
        }
    }

    None
}

fn resolve_invalid_hook_matcher_event_span(
    value: &serde_json::Value,
    locator: Option<&JsonLocationMap>,
) -> Option<Span> {
    let hooks = value.get("hooks")?.as_object()?;

    for (event_name, event_entries) in hooks {
        if matches!(event_name.as_str(), "PreToolUse" | "PostToolUse") {
            continue;
        }

        let Some(event_entries) = event_entries.as_array() else {
            continue;
        };

        for (entry_index, entry) in event_entries.iter().enumerate() {
            if entry.get("matcher").is_none() {
                continue;
            }

            let path = vec![
                JsonPathSegment::Key("hooks".to_owned()),
                JsonPathSegment::Key(event_name.clone()),
                JsonPathSegment::Index(entry_index),
                JsonPathSegment::Key("matcher".to_owned()),
            ];
            return locator.and_then(|locator| locator.value_span(&path).cloned());
        }
    }

    None
}

fn resolve_missing_required_hook_matcher_span(
    value: &serde_json::Value,
    locator: Option<&JsonLocationMap>,
) -> Option<Span> {
    let hooks = value.get("hooks")?.as_object()?;

    for event_name in ["PreToolUse", "PostToolUse"] {
        let Some(event_entries) = hooks.get(event_name).and_then(Value::as_array) else {
            continue;
        };

        for (entry_index, entry) in event_entries.iter().enumerate() {
            let Some(entry_hooks) = entry.get("hooks").and_then(Value::as_array) else {
                continue;
            };
            if entry.get("matcher").is_some() || entry_hooks.is_empty() {
                continue;
            }

            let path = vec![
                JsonPathSegment::Key("hooks".to_owned()),
                JsonPathSegment::Key(event_name.to_owned()),
                JsonPathSegment::Index(entry_index),
                JsonPathSegment::Key("hooks".to_owned()),
            ];
            return locator.and_then(|locator| locator.key_span(&path).cloned());
        }
    }

    None
}

impl ClaudeSettingsSignals {
    pub(super) fn from_context(ctx: &ScanContext, metrics: &mut SignalWorkBudget) -> Option<Self> {
        if ctx.artifact.kind != ArtifactKind::ClaudeSettings {
            return None;
        }

        let value = &json_semantics(ctx)?.value;
        let locator = JsonLocationMap::parse(&ctx.content);
        if locator.is_some() {
            metrics.json_locator_builds += 1;
        }
        let fallback_len = ctx.content.len();
        let locator_ref = locator.clone();
        let mut signals = Self {
            locator,
            fixture_like_path: is_fixture_like_claude_settings_path(&ctx.artifact.normalized_path),
            ..Self::default()
        };
        if signals.fixture_like_path {
            return Some(signals);
        }
        signals.insecure_http_hook_url_span =
            resolve_insecure_http_hook_url_span(value, locator_ref.as_ref());
        signals.dangerous_http_hook_host_span =
            resolve_dangerous_http_hook_host_span(value, locator_ref.as_ref());
        signals.bypass_permissions_span =
            resolve_bypass_permissions_span(value, locator_ref.as_ref());
        signals.enabled_mcpjson_servers_span =
            resolve_enabled_mcpjson_servers_span(value, locator_ref.as_ref());
        signals.missing_hook_timeout_span =
            resolve_missing_hook_timeout_span(value, locator_ref.as_ref());
        signals.invalid_hook_matcher_event_span =
            resolve_invalid_hook_matcher_event_span(value, locator_ref.as_ref());
        signals.missing_required_hook_matcher_span =
            resolve_missing_required_hook_matcher_span(value, locator_ref.as_ref());
        if value.is_object() && !value.get("$schema").is_some() {
            signals.missing_schema_span = leading_json_file_relative_span(&ctx.content);
        }
        signals.bash_wildcard_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Bash(*)");
        signals.webfetch_wildcard_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "WebFetch(*)");
        signals.webfetch_raw_githubusercontent_span = resolve_permissions_allow_exact_span(
            value,
            locator_ref.as_ref(),
            "WebFetch(domain:raw.githubusercontent.com)",
        );
        signals.write_wildcard_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Write(*)");
        signals.read_wildcard_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Read(*)");
        signals.edit_wildcard_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Edit(*)");
        signals.read_unsafe_path_span =
            resolve_permissions_allow_matching_span(value, locator_ref.as_ref(), |permission| {
                permission_has_unsafe_path_scope(permission, "Read")
            });
        signals.write_unsafe_path_span =
            resolve_permissions_allow_matching_span(value, locator_ref.as_ref(), |permission| {
                permission_has_unsafe_path_scope(permission, "Write")
            });
        signals.edit_unsafe_path_span =
            resolve_permissions_allow_matching_span(value, locator_ref.as_ref(), |permission| {
                permission_has_unsafe_path_scope(permission, "Edit")
            });
        signals.glob_unsafe_path_span =
            resolve_permissions_allow_matching_span(value, locator_ref.as_ref(), |permission| {
                permission_has_unsafe_path_scope(permission, "Glob")
            });
        signals.grep_unsafe_path_span =
            resolve_permissions_allow_matching_span(value, locator_ref.as_ref(), |permission| {
                permission_has_unsafe_path_scope(permission, "Grep")
            });
        signals.websearch_wildcard_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "WebSearch(*)");
        signals.unscoped_websearch_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "WebSearch");
        signals.git_push_permission_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Bash(git push)");
        signals.git_add_permission_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Bash(git add:*)");
        signals.git_clone_permission_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Bash(git clone:*)");
        signals.gh_pr_permission_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Bash(gh pr:*)");
        signals.gh_api_post_permission_span = resolve_permissions_allow_exact_span(
            value,
            locator_ref.as_ref(),
            "Bash(gh api --method POST:*)",
        );
        signals.gh_api_delete_permission_span = resolve_permissions_allow_exact_span(
            value,
            locator_ref.as_ref(),
            "Bash(gh api --method DELETE:*)",
        );
        signals.gh_issue_create_permission_span = resolve_permissions_allow_exact_span(
            value,
            locator_ref.as_ref(),
            "Bash(gh issue create:*)",
        );
        signals.gh_repo_create_permission_span = resolve_permissions_allow_exact_span(
            value,
            locator_ref.as_ref(),
            "Bash(gh repo create:*)",
        );
        signals.gh_secret_set_permission_span = resolve_permissions_allow_exact_span(
            value,
            locator_ref.as_ref(),
            "Bash(gh secret set:*)",
        );
        signals.gh_variable_set_permission_span = resolve_permissions_allow_exact_span(
            value,
            locator_ref.as_ref(),
            "Bash(gh variable set:*)",
        );
        signals.gh_workflow_run_permission_span = resolve_permissions_allow_exact_span(
            value,
            locator_ref.as_ref(),
            "Bash(gh workflow run:*)",
        );
        signals.gh_secret_delete_permission_span = resolve_permissions_allow_exact_span(
            value,
            locator_ref.as_ref(),
            "Bash(gh secret delete:*)",
        );
        signals.gh_variable_delete_permission_span = resolve_permissions_allow_exact_span(
            value,
            locator_ref.as_ref(),
            "Bash(gh variable delete:*)",
        );
        signals.gh_workflow_disable_permission_span = resolve_permissions_allow_exact_span(
            value,
            locator_ref.as_ref(),
            "Bash(gh workflow disable:*)",
        );
        signals.git_fetch_permission_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Bash(git fetch:*)");
        signals.git_ls_remote_permission_span = resolve_permissions_allow_exact_span(
            value,
            locator_ref.as_ref(),
            "Bash(git ls-remote:*)",
        );
        signals.curl_permission_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Bash(curl:*)");
        signals.wget_permission_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Bash(wget:*)");
        signals.git_config_permission_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Bash(git config:*)");
        signals.git_tag_permission_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Bash(git tag:*)");
        signals.git_branch_permission_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Bash(git branch:*)");
        signals.npx_permission_span =
            resolve_permissions_allow_prefix_span(value, locator_ref.as_ref(), "Bash(npx ");
        signals.uvx_permission_span =
            resolve_permissions_allow_prefix_span(value, locator_ref.as_ref(), "Bash(uvx ");
        signals.npm_exec_permission_span =
            resolve_permissions_allow_prefix_span(value, locator_ref.as_ref(), "Bash(npm exec ");
        signals.bunx_permission_span =
            resolve_permissions_allow_prefix_span(value, locator_ref.as_ref(), "Bash(bunx ");
        signals.pnpm_dlx_permission_span =
            resolve_permissions_allow_prefix_span(value, locator_ref.as_ref(), "Bash(pnpm dlx ");
        signals.yarn_dlx_permission_span =
            resolve_permissions_allow_prefix_span(value, locator_ref.as_ref(), "Bash(yarn dlx ");
        signals.pipx_run_permission_span =
            resolve_permissions_allow_prefix_span(value, locator_ref.as_ref(), "Bash(pipx run ");
        signals.package_install_permission_span = resolve_permissions_allow_any_exact_span(
            value,
            locator_ref.as_ref(),
            &[
                "Bash(pip install)",
                "Bash(pip3 install)",
                "Bash(python -m pip install)",
                "Bash(yarn install)",
                "Bash(npm install)",
                "Bash(pnpm install)",
                "Bash(bun install)",
            ],
        );
        signals.git_checkout_permission_span = resolve_permissions_allow_exact_span(
            value,
            locator_ref.as_ref(),
            "Bash(git checkout:*)",
        );
        signals.git_commit_permission_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Bash(git commit:*)");
        signals.git_stash_permission_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Bash(git stash:*)");
        signals.git_reset_permission_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Bash(git reset:*)");
        signals.git_clean_permission_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Bash(git clean:*)");
        signals.git_restore_permission_span = resolve_permissions_allow_exact_span(
            value,
            locator_ref.as_ref(),
            "Bash(git restore:*)",
        );
        signals.git_rebase_permission_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Bash(git rebase:*)");
        signals.git_merge_permission_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Bash(git merge:*)");
        signals.git_cherry_pick_permission_span = resolve_permissions_allow_exact_span(
            value,
            locator_ref.as_ref(),
            "Bash(git cherry-pick:*)",
        );
        signals.git_apply_permission_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Bash(git apply:*)");
        signals.git_am_permission_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Bash(git am:*)");
        signals.glob_wildcard_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Glob(*)");
        signals.grep_wildcard_span =
            resolve_permissions_allow_exact_span(value, locator_ref.as_ref(), "Grep(*)");
        let mut path = Vec::new();
        visit_claude_settings_value(
            value,
            &mut path,
            locator_ref.as_ref(),
            fallback_len,
            &mut signals,
            metrics,
        );
        Some(signals)
    }
}
