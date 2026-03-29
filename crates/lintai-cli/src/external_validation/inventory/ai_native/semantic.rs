use super::super::super::*;
use super::super::common::json_descendants;

pub(crate) fn contains_semantic_docker_mcp_launch(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    json_descendants(&value).any(|candidate| {
        let Some(object) = candidate.as_object() else {
            return false;
        };
        let Some(command) = object.get("command").and_then(Value::as_str) else {
            return false;
        };
        if !command.eq_ignore_ascii_case("docker") {
            return false;
        }
        object
            .get("args")
            .and_then(Value::as_array)
            .and_then(|args| args.first())
            .and_then(Value::as_str)
            .is_some_and(|arg| arg.eq_ignore_ascii_case("run"))
    })
}

pub(crate) fn contains_semantic_gemini_mcp_config(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    object
        .get("mcpServers")
        .and_then(Value::as_object)
        .is_some_and(|servers| {
            servers.values().any(|server| {
                server
                    .as_object()
                    .and_then(|entry| entry.get("command"))
                    .and_then(Value::as_str)
                    .is_some()
            })
        })
}

pub(crate) fn contains_semantic_claude_command_settings(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    json_descendants(&value).any(|candidate| {
        let Some(object) = candidate.as_object() else {
            return false;
        };
        let Some(kind) = object.get("type").and_then(Value::as_str) else {
            return false;
        };
        kind.eq_ignore_ascii_case("command")
            && object.get("command").and_then(Value::as_str).is_some()
    })
}

pub(crate) fn contains_semantic_plugin_hook_commands(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    object
        .get("hooks")
        .and_then(Value::as_object)
        .is_some_and(|hooks| {
            hooks.values().any(|entries| {
                entries.as_array().is_some_and(|entries| {
                    entries.iter().any(|entry| {
                        entry
                            .as_object()
                            .and_then(|entry| entry.get("command"))
                            .and_then(Value::as_str)
                            .is_some()
                    })
                })
            })
        })
}
