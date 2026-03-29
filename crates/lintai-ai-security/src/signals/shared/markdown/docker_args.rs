use serde_json::Value;

use crate::helpers::contains_dynamic_reference;

use super::super::json::contains_template_placeholder;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DockerRunAnalysis {
    pub(crate) mutable_image_arg_index: Option<usize>,
    pub(crate) mutable_pull_arg_index: Option<usize>,
    pub(crate) sensitive_mount_arg_index: Option<usize>,
    pub(crate) dangerous_flag_arg_index: Option<usize>,
}

pub(crate) fn analyze_docker_run_args(args: &Vec<Value>) -> Option<DockerRunAnalysis> {
    let first_arg = args.first().and_then(Value::as_str)?;
    if !first_arg.eq_ignore_ascii_case("run") {
        return None;
    }

    let mut analysis = DockerRunAnalysis::default();
    let mut index = 1usize;
    while index < args.len() {
        let Some(text) = args[index].as_str() else {
            index += 1;
            continue;
        };

        if analysis.dangerous_flag_arg_index.is_none()
            && is_dangerous_docker_flag(text, args, index)
        {
            analysis.dangerous_flag_arg_index = Some(index);
        }

        if analysis.mutable_pull_arg_index.is_none()
            && is_mutable_docker_pull_flag(text, args, index)
        {
            analysis.mutable_pull_arg_index = Some(index);
        }

        if analysis.sensitive_mount_arg_index.is_none() {
            if matches!(text, "-v" | "--volume")
                && let Some(spec) = args.get(index + 1).and_then(Value::as_str)
                && is_sensitive_docker_volume_spec(spec)
            {
                analysis.sensitive_mount_arg_index = Some(index + 1);
            } else if text.starts_with("--volume=")
                && is_sensitive_docker_volume_spec(
                    text.split_once('=')
                        .map(|(_, value)| value)
                        .unwrap_or_default(),
                )
            {
                analysis.sensitive_mount_arg_index = Some(index);
            } else if text.starts_with("-v")
                && text.len() > 2
                && is_sensitive_docker_volume_spec(&text[2..])
            {
                analysis.sensitive_mount_arg_index = Some(index);
            } else if matches!(text, "--mount")
                && let Some(spec) = args.get(index + 1).and_then(Value::as_str)
                && is_sensitive_docker_mount_spec(spec)
            {
                analysis.sensitive_mount_arg_index = Some(index + 1);
            } else if text.starts_with("--mount=")
                && is_sensitive_docker_mount_spec(
                    text.split_once('=')
                        .map(|(_, value)| value)
                        .unwrap_or_default(),
                )
            {
                analysis.sensitive_mount_arg_index = Some(index);
            }
        }

        if !text.starts_with('-') {
            if analysis.mutable_image_arg_index.is_none()
                && !contains_dynamic_reference(text)
                && !contains_template_placeholder(text)
                && !is_digest_pinned_docker_image(text)
            {
                analysis.mutable_image_arg_index = Some(index);
            }
            break;
        }

        index += docker_option_consumed_len(text, args, index);
    }

    Some(analysis)
}

pub(crate) fn docker_option_consumed_len(text: &str, args: &[Value], index: usize) -> usize {
    if text.starts_with("--volume=")
        || text.starts_with("--mount=")
        || text.starts_with("--network=")
        || text.starts_with("--pid=")
        || text.starts_with("--ipc=")
        || (text.starts_with("-v") && text.len() > 2)
    {
        return 1;
    }

    if matches!(
        text,
        "-v" | "--volume"
            | "--mount"
            | "-e"
            | "--env"
            | "--env-file"
            | "-p"
            | "--publish"
            | "--network"
            | "--pid"
            | "--ipc"
            | "--name"
            | "-w"
            | "--workdir"
            | "-u"
            | "--user"
            | "--entrypoint"
            | "--platform"
    ) && args.get(index + 1).and_then(Value::as_str).is_some()
    {
        return 2;
    }

    1
}

pub(crate) fn is_dangerous_docker_flag(text: &str, args: &[Value], index: usize) -> bool {
    text == "--privileged"
        || matches!(text, "--network=host" | "--pid=host" | "--ipc=host")
        || matches!(text, "--network" | "--pid" | "--ipc")
            && args
                .get(index + 1)
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("host"))
}

pub(crate) fn is_mutable_docker_pull_flag(text: &str, args: &[Value], index: usize) -> bool {
    text.eq_ignore_ascii_case("--pull=always")
        || text.eq_ignore_ascii_case("--pull")
            && args
                .get(index + 1)
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("always"))
}

pub(crate) fn is_digest_pinned_docker_image(text: &str) -> bool {
    text.to_ascii_lowercase().contains("@sha256:")
}

pub(crate) fn is_sensitive_docker_volume_spec(spec: &str) -> bool {
    let source = spec.split(':').next().unwrap_or_default();
    is_sensitive_host_path(source)
}

pub(crate) fn is_sensitive_docker_mount_spec(spec: &str) -> bool {
    let mut is_bind = false;
    let mut source = None;
    for part in spec.split(',') {
        let trimmed = part.trim();
        if let Some((key, value)) = trimmed.split_once('=') {
            let lowered_key = key.trim().to_ascii_lowercase();
            let trimmed_value = value.trim();
            match lowered_key.as_str() {
                "type" => is_bind = trimmed_value.eq_ignore_ascii_case("bind"),
                "source" | "src" => source = Some(trimmed_value),
                _ => {}
            }
        }
    }
    is_bind && source.is_some_and(is_sensitive_host_path)
}

pub(crate) fn is_sensitive_host_path(source: &str) -> bool {
    let normalized = source.trim().replace('\\', "/").to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }

    if normalized.contains("/var/run/docker.sock") {
        return true;
    }

    let path_like = normalized.starts_with('/')
        || normalized.starts_with('~')
        || normalized.starts_with('.')
        || normalized.starts_with("$home")
        || normalized.starts_with("${home}")
        || normalized.contains('/');
    path_like
        && (normalized.contains(".ssh")
            || normalized.contains(".aws")
            || normalized.contains(".kube")
            || normalized.contains(".config/gcloud"))
}
