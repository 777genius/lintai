use lintai_api::Span;
use serde_json::Value;

use super::hook::shell_tokens;
use crate::helpers::contains_dynamic_reference;
pub(crate) const HTML_COMMENT_DIRECTIVE_MARKERS: &[&str] = &[
    "ignore previous",
    "ignore all previous",
    "system prompt",
    "you are now",
    "send secrets",
    "exfiltrate",
];

pub(crate) fn has_download_exec(lowered: &str) -> bool {
    let has_download = lowered.contains("curl ") || lowered.contains("wget ");
    let has_pipe_exec = lowered.contains("| sh") || lowered.contains("| bash");
    let has_chmod_exec = lowered.contains("chmod +x") && lowered.contains("./");
    has_download && (has_pipe_exec || has_chmod_exec)
}

pub(crate) fn has_inline_download_pipe_exec(lowered: &str) -> bool {
    let has_download = lowered.contains("curl ") || lowered.contains("wget ");
    let has_pipe_exec =
        lowered.contains("| sh") || lowered.contains("| bash") || lowered.contains("| zsh");
    has_download && has_pipe_exec
}

pub(crate) fn looks_like_dangerous_lifecycle_script(script: &str) -> bool {
    let lowered = script.to_ascii_lowercase();
    let has_download_to_exec = has_download_exec(&lowered)
        || (has_inline_download_pipe_exec(&lowered)
            && (lowered.contains("| node") || lowered.contains("node -e")));
    let has_eval = lowered.contains("eval ")
        || lowered.contains(" eval ")
        || lowered.starts_with("eval ")
        || lowered.contains("eval(");
    let has_npm_explore_exec = lowered.contains("npm explore ")
        && (lowered.contains(" sh ")
            || lowered.contains(" bash ")
            || lowered.contains(" zsh ")
            || lowered.contains(" -c "));

    has_download_to_exec || has_eval || has_npm_explore_exec
}

pub(crate) fn looks_like_git_dependency_spec(spec: &str) -> bool {
    let lowered = spec.trim().to_ascii_lowercase();
    lowered.starts_with("git://")
        || lowered.starts_with("git+https://")
        || lowered.starts_with("git+ssh://")
        || lowered.starts_with("github:")
        || lowered.starts_with("gitlab:")
        || lowered.starts_with("bitbucket:")
}

pub(crate) fn looks_like_unbounded_dependency_spec(spec: &str) -> bool {
    let trimmed = spec.trim();
    trimmed == "*" || trimmed.eq_ignore_ascii_case("latest")
}

pub(crate) fn is_mutable_mcp_launcher(command: &str, args: Option<&Vec<Value>>) -> bool {
    if command.eq_ignore_ascii_case("npx") || command.eq_ignore_ascii_case("uvx") {
        return true;
    }

    let first_arg = args
        .and_then(|items| items.first())
        .and_then(Value::as_str)
        .unwrap_or_default();

    ((command.eq_ignore_ascii_case("pnpm") || command.eq_ignore_ascii_case("yarn"))
        && first_arg.eq_ignore_ascii_case("dlx"))
        || (command.eq_ignore_ascii_case("pipx") && first_arg.eq_ignore_ascii_case("run"))
}

pub(crate) fn find_mutable_launcher_relative_span(command: &str) -> Option<Span> {
    let tokens = shell_tokens(command);
    for index in 0..tokens.len() {
        let text = tokens[index].text;
        if text.eq_ignore_ascii_case("npx") || text.eq_ignore_ascii_case("uvx") {
            return Some(Span::new(tokens[index].start, tokens[index].end));
        }
        if (text.eq_ignore_ascii_case("pnpm") || text.eq_ignore_ascii_case("yarn"))
            && tokens
                .get(index + 1)
                .is_some_and(|next| next.text.eq_ignore_ascii_case("dlx"))
        {
            return Some(Span::new(tokens[index].start, tokens[index].end));
        }
        if text.eq_ignore_ascii_case("pipx")
            && tokens
                .get(index + 1)
                .is_some_and(|next| next.text.eq_ignore_ascii_case("run"))
        {
            return Some(Span::new(tokens[index].start, tokens[index].end));
        }
    }
    None
}

pub(crate) fn looks_like_network_capable_command(lowered: &str) -> bool {
    lowered.contains("curl")
        || lowered.contains("wget")
        || lowered.contains("http://")
        || lowered.contains("https://")
}

const SECRET_EXFIL_MARKERS: &[&str] = &[
    "openai_api_key",
    "anthropic_api_key",
    "aws_secret_access_key",
    "aws_access_key_id",
    "aws_session_token",
    "github_token",
    "gh_token",
    "authorization:",
    "bearer ",
    "cookie:",
    "x-api-key:",
];

const WEBHOOK_ENDPOINT_MARKERS: &[&str] = &[
    "hooks.slack.com/services/",
    "discord.com/api/webhooks/",
    "discordapp.com/api/webhooks/",
    "webhook.site/",
    "/webhook",
    "/webhooks/",
];

const SENSITIVE_SECRET_FILE_SUFFIXES: &[&str] = &[
    ".aws/credentials",
    ".aws/config",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/config",
    ".kube/config",
    ".docker/config.json",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "application_default_credentials.json",
];

const BROWSER_SECRET_STORE_FILENAMES: &[&str] = &[
    "Login Data",
    "Cookies",
    "logins.json",
    "key4.db",
    "Web Data",
    "Local State",
];

const BROWSER_SECRET_STORE_PREFIXES: &[&str] = &[
    ".config/google-chrome/",
    ".config/chromium/",
    ".config/microsoft-edge/",
    ".mozilla/firefox/",
    "Library/Application Support/Google/Chrome/",
    "Library/Application Support/Chromium/",
    "Library/Application Support/Microsoft Edge/",
    "Library/Application Support/Firefox/",
];

pub(crate) fn looks_like_exfil_network_command(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    if lowered.contains("http://") || lowered.contains("https://") {
        return true;
    }

    if looks_like_sensitive_file_transfer_command(text) {
        return true;
    }

    shell_tokens(text).iter().any(|token| {
        command_name_eq(token.text, "curl")
            || command_name_eq(token.text, "wget")
            || command_name_eq(token.text, "nc")
            || command_name_eq(token.text, "netcat")
            || command_name_eq(token.text, "scp")
            || command_name_eq(token.text, "rsync")
            || command_name_eq(token.text, "sftp")
            || command_name_eq(token.text, "ftp")
    })
}

pub(crate) fn find_secret_reference_relative_span(text: &str) -> Option<Span> {
    find_first_ascii_case_insensitive_span(text, SECRET_EXFIL_MARKERS)
}

pub(crate) fn find_plain_http_relative_span(text: &str) -> Option<Span> {
    find_ascii_case_insensitive(text, "http://").map(|start| Span::new(start, start + 7))
}

pub(crate) fn find_webhook_endpoint_relative_span(text: &str) -> Option<Span> {
    find_first_ascii_case_insensitive_span(text, WEBHOOK_ENDPOINT_MARKERS)
}

pub(crate) fn find_sensitive_secret_file_relative_span(text: &str) -> Option<Span> {
    let tokens = shell_tokens(text);
    let mut best: Option<Span> = None;

    for token in tokens {
        let trimmed = trim_shell_token(token.text);
        let candidate = trimmed.trim_start_matches('@');
        let basename = candidate.rsplit('/').next().unwrap_or(candidate);

        let matches_env = basename.eq_ignore_ascii_case(".env")
            || basename.to_ascii_lowercase().starts_with(".env.");
        let matches_suffix = SENSITIVE_SECRET_FILE_SUFFIXES
            .iter()
            .any(|suffix| ends_with_ascii_case_insensitive(candidate, suffix));

        if matches_env || matches_suffix {
            let start_offset = trimmed.len().saturating_sub(candidate.len());
            let candidate_start = token.start + start_offset;
            let candidate_end = candidate_start + candidate.len();
            let span = Span::new(candidate_start, candidate_end);
            match best {
                Some(ref existing) if existing.start_byte <= span.start_byte => {}
                _ => best = Some(span),
            }
        }
    }

    best
}

pub(crate) fn find_clipboard_read_relative_span(text: &str) -> Option<Span> {
    let tokens = shell_tokens(text);
    let lowered = text.to_ascii_lowercase();

    for token in &tokens {
        if command_name_eq(token.text, "pbpaste") || command_name_eq(token.text, "wl-paste") {
            return Some(Span::new(token.start, token.end));
        }

        if (command_name_eq(token.text, "powershell") || command_name_eq(token.text, "pwsh"))
            && let Some(start) = find_ascii_case_insensitive(text, "Get-Clipboard")
        {
            return Some(Span::new(start, start + "Get-Clipboard".len()));
        }

        if command_name_eq(token.text, "xclip")
            && (lowered.contains(" -o") || lowered.contains(" --out"))
        {
            return Some(Span::new(token.start, token.end));
        }

        if command_name_eq(token.text, "xsel")
            && (lowered.contains(" --output")
                || lowered.contains(" -o")
                || lowered.contains(" --clipboard"))
        {
            return Some(Span::new(token.start, token.end));
        }
    }

    None
}

pub(crate) fn find_browser_secret_store_access_relative_span(text: &str) -> Option<Span> {
    let tokens = shell_tokens(text);
    let mut best: Option<Span> = None;

    for token in tokens {
        let candidate = trim_shell_token(token.text).trim_start_matches('@');
        let lowered = candidate.to_ascii_lowercase();
        let has_browser_prefix = BROWSER_SECRET_STORE_PREFIXES
            .iter()
            .any(|prefix| lowered.contains(&prefix.to_ascii_lowercase()));
        let has_secret_filename = BROWSER_SECRET_STORE_FILENAMES
            .iter()
            .any(|suffix| ends_with_ascii_case_insensitive(candidate, suffix));

        if has_browser_prefix && has_secret_filename {
            let span = Span::new(token.start, token.start + candidate.len());
            match best {
                Some(ref existing) if existing.start_byte <= span.start_byte => {}
                _ => best = Some(span),
            }
        }
    }

    best
}

pub(crate) fn find_clipboard_exfil_relative_span(text: &str) -> Option<Span> {
    if !looks_like_exfil_network_command(text) {
        return None;
    }
    find_clipboard_read_relative_span(text)
}

pub(crate) fn find_browser_secret_store_exfil_relative_span(text: &str) -> Option<Span> {
    if !looks_like_exfil_network_command(text) {
        return None;
    }
    find_browser_secret_store_access_relative_span(text)
}

pub(crate) fn find_screen_capture_relative_span(text: &str) -> Option<Span> {
    let tokens = shell_tokens(text);
    let lowered = text.to_ascii_lowercase();

    for token in &tokens {
        if command_name_eq(token.text, "screencapture")
            || command_name_eq(token.text, "scrot")
            || command_name_eq(token.text, "gnome-screenshot")
            || command_name_eq(token.text, "grim")
            || command_name_eq(token.text, "grimshot")
            || command_name_eq(token.text, "maim")
        {
            return Some(Span::new(token.start, token.end));
        }

        if command_name_eq(token.text, "import")
            && (lowered.contains("-window root") || lowered.contains("-window desktop"))
        {
            return Some(Span::new(token.start, token.end));
        }

        if (command_name_eq(token.text, "powershell") || command_name_eq(token.text, "pwsh"))
            && let Some(start) = find_ascii_case_insensitive(text, "CopyFromScreen")
        {
            return Some(Span::new(start, start + "CopyFromScreen".len()));
        }
    }

    None
}

pub(crate) fn find_screen_capture_exfil_relative_span(text: &str) -> Option<Span> {
    if !looks_like_exfil_network_command(text) {
        return None;
    }
    find_screen_capture_relative_span(text)
}

pub(crate) fn find_camera_capture_relative_span(text: &str) -> Option<Span> {
    let tokens = shell_tokens(text);
    let lowered = text.to_ascii_lowercase();

    for token in &tokens {
        if command_name_eq(token.text, "imagesnap") || command_name_eq(token.text, "fswebcam") {
            return Some(Span::new(token.start, token.end));
        }

        if command_name_eq(token.text, "ffmpeg")
            && (lowered.contains("video=")
                || lowered.contains("/dev/video")
                || lowered.contains(" -f v4l2")
                || lowered.contains(" -f video4linux2")
                || lowered.contains("webcam")
                || lowered.contains("camera"))
        {
            return Some(Span::new(token.start, token.end));
        }
    }

    None
}

pub(crate) fn find_microphone_capture_relative_span(text: &str) -> Option<Span> {
    let tokens = shell_tokens(text);
    let lowered = text.to_ascii_lowercase();

    for token in &tokens {
        if command_name_eq(token.text, "arecord")
            || command_name_eq(token.text, "parecord")
            || command_name_eq(token.text, "parec")
        {
            return Some(Span::new(token.start, token.end));
        }

        if command_name_eq(token.text, "rec")
            || (command_name_eq(token.text, "sox")
                && (lowered.contains(" -d ") || lowered.contains(" --default-device")))
        {
            return Some(Span::new(token.start, token.end));
        }

        if command_name_eq(token.text, "ffmpeg")
            && (lowered.contains("audio=")
                || lowered.contains(" -f alsa")
                || lowered.contains(" -f pulse")
                || lowered.contains("microphone")
                || lowered.contains(" mic"))
        {
            return Some(Span::new(token.start, token.end));
        }
    }

    None
}

pub(crate) fn find_keylogging_relative_span(text: &str) -> Option<Span> {
    let tokens = shell_tokens(text);
    let lowered = text.to_ascii_lowercase();

    for token in &tokens {
        if command_name_eq(token.text, "logkeys")
            || command_name_eq(token.text, "evtest")
            || command_name_eq(token.text, "showkey")
        {
            return Some(Span::new(token.start, token.end));
        }

        if command_name_eq(token.text, "xinput")
            && (lowered.contains(" test ")
                || lowered.contains(" test-xi2 ")
                || lowered.ends_with(" test")
                || lowered.ends_with(" test-xi2"))
        {
            return Some(Span::new(token.start, token.end));
        }

        if (command_name_eq(token.text, "powershell") || command_name_eq(token.text, "pwsh"))
            && let Some(start) = find_ascii_case_insensitive(text, "GetAsyncKeyState")
        {
            return Some(Span::new(start, start + "GetAsyncKeyState".len()));
        }
    }

    if let Some(start) = find_ascii_case_insensitive(text, "pynput.keyboard.Listener") {
        return Some(Span::new(start, start + "pynput.keyboard.Listener".len()));
    }

    if let Some(start) = find_ascii_case_insensitive(text, "keyboard.on_press") {
        return Some(Span::new(start, start + "keyboard.on_press".len()));
    }

    if let Some(start) = find_ascii_case_insensitive(text, "keyboard.record(") {
        return Some(Span::new(start, start + "keyboard.record(".len()));
    }

    if let Some(start) = find_ascii_case_insensitive(text, "keyboard.read_event(") {
        return Some(Span::new(start, start + "keyboard.read_event(".len()));
    }

    None
}

pub(crate) fn find_camera_capture_exfil_relative_span(text: &str) -> Option<Span> {
    if !looks_like_exfil_network_command(text) {
        return None;
    }
    find_camera_capture_relative_span(text)
}

pub(crate) fn find_microphone_capture_exfil_relative_span(text: &str) -> Option<Span> {
    if !looks_like_exfil_network_command(text) {
        return None;
    }
    find_microphone_capture_relative_span(text)
}

pub(crate) fn find_keylogging_exfil_relative_span(text: &str) -> Option<Span> {
    if !looks_like_exfil_network_command(text) {
        return None;
    }
    find_keylogging_relative_span(text)
}

pub(crate) fn find_environment_dump_relative_span(text: &str) -> Option<Span> {
    let tokens = shell_tokens(text);
    let lowered = text.to_ascii_lowercase();

    for (index, token) in tokens.iter().enumerate() {
        if command_name_eq(token.text, "printenv") {
            return Some(Span::new(token.start, token.end));
        }

        if command_name_eq(token.text, "env")
            && (lowered.ends_with("env")
                || lowered.contains("env |")
                || lowered.contains("env >")
                || lowered.contains("env >>")
                || tokens
                    .get(index + 1)
                    .is_some_and(|next| next.text == "|" || next.text.starts_with('>')))
        {
            return Some(Span::new(token.start, token.end));
        }

        if command_name_eq(token.text, "export")
            && tokens
                .get(index + 1)
                .is_some_and(|next| next.text.eq_ignore_ascii_case("-p"))
        {
            return Some(Span::new(token.start, token.end));
        }

        if command_name_eq(token.text, "declare")
            && tokens
                .get(index + 1)
                .is_some_and(|next| next.text.eq_ignore_ascii_case("-xp"))
        {
            return Some(Span::new(token.start, token.end));
        }

        if command_name_eq(token.text, "compgen")
            && tokens
                .get(index + 1)
                .is_some_and(|next| next.text.eq_ignore_ascii_case("-v"))
        {
            return Some(Span::new(token.start, token.end));
        }
    }

    None
}

pub(crate) fn find_environment_dump_exfil_relative_span(text: &str) -> Option<Span> {
    if !looks_like_exfil_network_command(text) {
        return None;
    }
    find_environment_dump_relative_span(text)
}

pub(crate) fn looks_like_sensitive_file_transfer_command(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    let tokens = shell_tokens(text);

    let has_http_upload = (lowered.contains("http://") || lowered.contains("https://"))
        && (lowered.contains("curl") || lowered.contains("wget"))
        && (lowered.contains("-t ")
            || lowered.contains("--upload-file")
            || lowered.contains("--post-file")
            || lowered.contains("--data-binary")
            || lowered.contains(" -f ")
            || lowered.contains("-f "));
    if has_http_upload {
        return true;
    }

    let has_scp = tokens
        .iter()
        .any(|token| command_name_eq(token.text, "scp"))
        && tokens.iter().any(|token| token.text.contains(':'));
    if has_scp {
        return true;
    }

    let has_rsync = tokens
        .iter()
        .any(|token| command_name_eq(token.text, "rsync"))
        && tokens.iter().any(|token| token.text.contains(':'));
    if has_rsync {
        return true;
    }

    let has_sftp = tokens
        .iter()
        .any(|token| command_name_eq(token.text, "sftp"));
    if has_sftp {
        return true;
    }

    let has_nc = tokens
        .iter()
        .any(|token| command_name_eq(token.text, "nc") || command_name_eq(token.text, "netcat"));
    if has_nc {
        return true;
    }

    let has_aws_s3 = tokens
        .iter()
        .any(|token| command_name_eq(token.text, "aws"))
        && tokens
            .iter()
            .any(|token| token.text.eq_ignore_ascii_case("s3"))
        && tokens.iter().any(|token| {
            token.text.eq_ignore_ascii_case("cp")
                || token.text.eq_ignore_ascii_case("mv")
                || token.text.eq_ignore_ascii_case("sync")
        })
        && tokens
            .iter()
            .any(|token| starts_with_ascii_case_insensitive(token.text, "s3://"));
    if has_aws_s3 {
        return true;
    }

    let has_gsutil = tokens
        .iter()
        .any(|token| command_name_eq(token.text, "gsutil"))
        && tokens.iter().any(|token| {
            token.text.eq_ignore_ascii_case("cp")
                || token.text.eq_ignore_ascii_case("mv")
                || token.text.eq_ignore_ascii_case("rsync")
        })
        && tokens
            .iter()
            .any(|token| starts_with_ascii_case_insensitive(token.text, "gs://"));
    if has_gsutil {
        return true;
    }

    let has_rclone = tokens
        .iter()
        .any(|token| command_name_eq(token.text, "rclone"))
        && tokens.iter().any(|token| {
            token.text.eq_ignore_ascii_case("copy")
                || token.text.eq_ignore_ascii_case("move")
                || token.text.eq_ignore_ascii_case("sync")
        })
        && tokens.iter().any(|token| token.text.contains(':'));
    if has_rclone {
        return true;
    }

    false
}

pub(crate) fn find_command_tls_bypass_relative_span(text: &str) -> Option<Span> {
    if let Some(start) = text.find("NODE_TLS_REJECT_UNAUTHORIZED=0") {
        return Some(Span::new(
            start,
            start + "NODE_TLS_REJECT_UNAUTHORIZED=0".len(),
        ));
    }

    if let Some(start) = text.find("--insecure") {
        return Some(Span::new(start, start + "--insecure".len()));
    }

    find_standalone_short_flag(text, "-k").map(|start| Span::new(start, start + 2))
}

pub(crate) fn find_destructive_root_delete_relative_span(text: &str) -> Option<Span> {
    let tokens = shell_tokens(text);
    let rm_index = tokens
        .iter()
        .position(|token| command_name_eq(token.text, "rm"))?;

    let mut has_recursive = false;
    let mut has_force = false;
    let mut root_target = None;

    for token in tokens.iter().skip(rm_index + 1) {
        let lowered = token.text.to_ascii_lowercase();
        if lowered == "--no-preserve-root" {
            return Some(Span::new(token.start, token.end));
        }
        if lowered == "--recursive" {
            has_recursive = true;
            continue;
        }
        if lowered == "--force" {
            has_force = true;
            continue;
        }
        if lowered.starts_with('-') && !lowered.starts_with("--") {
            for flag in lowered[1..].chars() {
                if flag == 'r' {
                    has_recursive = true;
                }
                if flag == 'f' {
                    has_force = true;
                }
            }
            continue;
        }
        if token.text == "/" || token.text == "/*" {
            root_target = Some(Span::new(token.start, token.end));
        }
    }

    if has_recursive && has_force {
        return root_target;
    }

    None
}

pub(crate) fn find_sensitive_password_file_relative_span(text: &str) -> Option<Span> {
    find_first_ascii_case_insensitive_span(
        text,
        &[
            "/etc/shadow",
            "/etc/passwd",
            "/etc/sudoers",
            "/etc/gshadow",
            "/etc/master.passwd",
        ],
    )
}

pub(crate) fn find_shell_profile_write_relative_span(text: &str) -> Option<Span> {
    find_write_target_relative_span(text, &[".bashrc", ".bash_profile", ".zshrc", ".profile"])
}

pub(crate) fn find_authorized_keys_write_relative_span(text: &str) -> Option<Span> {
    find_write_target_relative_span(text, &["authorized_keys"])
}

pub(crate) fn find_crontab_persistence_relative_span(text: &str) -> Option<Span> {
    let tokens = shell_tokens(text);
    for (index, token) in tokens.iter().enumerate() {
        if !command_name_eq(token.text, "crontab") {
            continue;
        }

        let mut saw_list_only = false;
        for next in tokens.iter().skip(index + 1) {
            if next.text.eq_ignore_ascii_case("-l") || next.text.eq_ignore_ascii_case("--list") {
                saw_list_only = true;
                continue;
            }
            return Some(Span::new(next.start, next.end));
        }

        if !saw_list_only {
            return Some(Span::new(token.start, token.end));
        }
    }

    find_write_target_path_relative_span(text, is_cron_persistence_path)
}

pub(crate) fn find_systemd_service_registration_relative_span(text: &str) -> Option<Span> {
    if let Some(span) = find_subcommand_relative_span(text, "systemctl", &["enable", "link"]) {
        return Some(span);
    }

    find_write_target_path_relative_span(text, is_systemd_unit_path)
}

pub(crate) fn find_launchd_registration_relative_span(text: &str) -> Option<Span> {
    if let Some(span) = find_subcommand_relative_span(text, "launchctl", &["load", "bootstrap"]) {
        return Some(span);
    }

    find_write_target_path_relative_span(text, is_launchd_plist_path)
}

pub(crate) fn find_insecure_permission_change_relative_span(text: &str) -> Option<Span> {
    let tokens = shell_tokens(text);
    let chmod_index = tokens
        .iter()
        .position(|token| command_name_eq(token.text, "chmod"))?;

    for token in tokens.iter().skip(chmod_index + 1) {
        if token.text.starts_with('-') {
            continue;
        }
        if is_insecure_chmod_mode(token.text) {
            return Some(Span::new(token.start, token.end));
        }
    }

    None
}

pub(crate) fn find_setuid_setgid_relative_span(text: &str) -> Option<Span> {
    let tokens = shell_tokens(text);
    let chmod_index = tokens
        .iter()
        .position(|token| command_name_eq(token.text, "chmod"))?;

    for token in tokens.iter().skip(chmod_index + 1) {
        if token.text.starts_with('-') {
            continue;
        }
        if is_setuid_setgid_mode(token.text) {
            return Some(Span::new(token.start, token.end));
        }
    }

    None
}

pub(crate) fn find_linux_capability_manipulation_relative_span(text: &str) -> Option<Span> {
    let tokens = shell_tokens(text);
    for (index, token) in tokens.iter().enumerate() {
        if command_name_eq(token.text, "setcap") {
            for next in tokens.iter().skip(index + 1) {
                if is_linux_capability_token(next.text) {
                    return Some(Span::new(next.start, next.end));
                }
            }
            return Some(Span::new(token.start, token.end));
        }

        if command_name_eq(token.text, "capsh")
            && tokens.iter().any(|t| is_linux_capability_token(t.text))
        {
            if let Some(cap_token) = tokens.iter().find(|t| is_linux_capability_token(t.text)) {
                return Some(Span::new(cap_token.start, cap_token.end));
            }
        }
    }

    find_first_ascii_case_insensitive_span(text, DANGEROUS_LINUX_CAPABILITY_TOKENS)
}

pub(crate) fn find_standalone_short_flag(text: &str, flag: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let flag_bytes = flag.as_bytes();
    if flag_bytes.is_empty() || bytes.len() < flag_bytes.len() {
        return None;
    }

    for index in 0..=bytes.len() - flag_bytes.len() {
        if &bytes[index..index + flag_bytes.len()] != flag_bytes {
            continue;
        }
        let before_ok = index == 0 || bytes[index - 1].is_ascii_whitespace();
        let after_index = index + flag_bytes.len();
        let after_ok = after_index == bytes.len() || bytes[after_index].is_ascii_whitespace();
        if before_ok && after_ok {
            return Some(index);
        }
    }

    None
}

pub(crate) fn find_literal_value_after_prefixes_case_insensitive(
    text: &str,
    prefixes: &[&str],
) -> Option<Span> {
    for prefix in prefixes {
        let mut search_start = 0usize;
        while let Some(relative) = find_ascii_case_insensitive(&text[search_start..], prefix) {
            let value_start = search_start + relative + prefix.len();
            let value_end = text[value_start..]
                .char_indices()
                .find_map(|(index, ch)| match ch {
                    '"' | '\'' | ' ' | '\t' | '\r' | '\n' => Some(value_start + index),
                    _ => None,
                })
                .unwrap_or(text.len());
            if value_end > value_start {
                let value = &text[value_start..value_end];
                if !contains_dynamic_reference(value) {
                    return Some(Span::new(value_start, value_end));
                }
            }
            search_start = value_start;
        }
    }

    None
}

pub(crate) fn starts_with_ascii_case_insensitive(text: &str, prefix: &str) -> bool {
    text.as_bytes()
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix.as_bytes()))
}

pub(crate) fn ends_with_ascii_case_insensitive(text: &str, suffix: &str) -> bool {
    text.as_bytes()
        .get(text.len().saturating_sub(suffix.len())..)
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(suffix.as_bytes()))
}

pub(crate) fn contains_ascii_case_insensitive(text: &str, needle: &str) -> bool {
    find_ascii_case_insensitive(text, needle).is_some()
}

pub(crate) fn find_ascii_case_insensitive(text: &str, needle: &str) -> Option<usize> {
    let needle_bytes = needle.as_bytes();
    if needle_bytes.is_empty() {
        return Some(0);
    }

    text.as_bytes()
        .windows(needle_bytes.len())
        .position(|window| window.eq_ignore_ascii_case(needle_bytes))
}

fn find_first_ascii_case_insensitive_span(text: &str, needles: &[&str]) -> Option<Span> {
    let mut best: Option<Span> = None;

    for needle in needles {
        if let Some(start) = find_ascii_case_insensitive(text, needle) {
            let candidate = Span::new(start, start + needle.len());
            match best {
                Some(ref existing) if existing.start_byte <= candidate.start_byte => {}
                _ => best = Some(candidate),
            }
        }
    }

    best
}

fn find_write_target_relative_span(text: &str, suffixes: &[&str]) -> Option<Span> {
    let mut best: Option<Span> = None;

    for suffix in suffixes {
        if let Some(span) = find_redirection_target_relative_span(text, suffix)
            .or_else(|| find_tee_target_relative_span(text, suffix))
        {
            match best {
                Some(ref existing) if existing.start_byte <= span.start_byte => {}
                _ => best = Some(span),
            }
        }
    }

    best
}

fn find_write_target_path_relative_span(text: &str, predicate: fn(&str) -> bool) -> Option<Span> {
    let tokens = shell_tokens(text);
    for (index, token) in tokens.iter().enumerate() {
        if !is_shell_redirection_operator(token.text) && !command_name_eq(token.text, "tee") {
            continue;
        }

        let mut lookahead = index + 1;
        while let Some(next) = tokens.get(lookahead) {
            if command_name_eq(token.text, "tee") && next.text.starts_with('-') {
                lookahead += 1;
                continue;
            }
            if predicate(trim_shell_token(next.text)) {
                return Some(Span::new(next.start, next.end));
            }
            break;
        }
    }

    None
}

fn find_redirection_target_relative_span(text: &str, suffix: &str) -> Option<Span> {
    let tokens = shell_tokens(text);
    for (index, token) in tokens.iter().enumerate() {
        if !is_shell_redirection_operator(token.text) {
            continue;
        }
        if let Some(target) = tokens.get(index + 1)
            && ends_with_ascii_case_insensitive(target.text, suffix)
        {
            return Some(Span::new(target.start, target.end));
        }
    }

    let start = find_ascii_case_insensitive(text, suffix)?;
    let bytes = text.as_bytes();
    let mut token_start = start;
    while token_start > 0 {
        let previous = bytes[token_start - 1];
        if previous.is_ascii_whitespace() || matches!(previous, b'"' | b'\'' | b';' | b'|') {
            break;
        }
        if previous == b'>' {
            break;
        }
        token_start -= 1;
    }

    let mut cursor = token_start;
    while cursor > 0 && bytes[cursor - 1].is_ascii_whitespace() {
        cursor -= 1;
    }

    if cursor == 0 || bytes[cursor - 1] != b'>' {
        return None;
    }

    let end = text[token_start..]
        .char_indices()
        .find_map(|(index, ch)| {
            if ch.is_whitespace() || matches!(ch, '"' | '\'' | ';' | '|') {
                Some(token_start + index)
            } else {
                None
            }
        })
        .unwrap_or(text.len());

    Some(Span::new(token_start, end))
}

fn find_tee_target_relative_span(text: &str, suffix: &str) -> Option<Span> {
    let tokens = shell_tokens(text);
    for (index, token) in tokens.iter().enumerate() {
        if !command_name_eq(token.text, "tee") {
            continue;
        }

        let mut lookahead = index + 1;
        while let Some(next) = tokens.get(lookahead) {
            if next.text.starts_with('-') {
                lookahead += 1;
                continue;
            }
            if ends_with_ascii_case_insensitive(next.text, suffix) {
                return Some(Span::new(next.start, next.end));
            }
            break;
        }
    }

    None
}

fn command_name_eq(text: &str, name: &str) -> bool {
    text.eq_ignore_ascii_case(name)
        || text
            .rsplit('/')
            .next()
            .is_some_and(|component| component.eq_ignore_ascii_case(name))
}

fn find_subcommand_relative_span(
    text: &str,
    command_name: &str,
    subcommands: &[&str],
) -> Option<Span> {
    let tokens = shell_tokens(text);
    for (index, token) in tokens.iter().enumerate() {
        if !command_name_eq(token.text, command_name) {
            continue;
        }

        for next in tokens.iter().skip(index + 1) {
            if next.text.starts_with('-') {
                continue;
            }
            if subcommands
                .iter()
                .any(|expected| next.text.eq_ignore_ascii_case(expected))
            {
                return Some(Span::new(next.start, next.end));
            }
            break;
        }
    }

    None
}

fn is_shell_redirection_operator(text: &str) -> bool {
    matches!(text, ">" | ">>" | "1>" | "1>>" | "2>" | "2>>")
}

fn trim_shell_token(text: &str) -> &str {
    text.trim_matches(|ch| matches!(ch, '"' | '\'' | ';'))
}

fn is_cron_persistence_path(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    lowered == "/etc/crontab"
        || lowered.contains("/etc/cron")
        || lowered.contains("/var/spool/cron")
}

fn is_systemd_unit_path(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    let is_systemd_path = lowered.contains("/etc/systemd/system/")
        || lowered.contains("/lib/systemd/system/")
        || lowered.contains("/usr/lib/systemd/system/")
        || lowered.contains("/run/systemd/system/")
        || lowered.contains("/.config/systemd/user/")
        || lowered.contains("/systemd/user/");
    let is_unit_file = lowered.ends_with(".service")
        || lowered.ends_with(".timer")
        || lowered.ends_with(".socket")
        || lowered.ends_with(".path");

    is_systemd_path && is_unit_file
}

fn is_launchd_plist_path(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    (lowered.contains("/library/launchagents/") || lowered.contains("/library/launchdaemons/"))
        && lowered.ends_with(".plist")
}

const DANGEROUS_LINUX_CAPABILITY_TOKENS: &[&str] = &[
    "cap_setuid",
    "cap_setgid",
    "cap_sys_admin",
    "cap_sys_ptrace",
    "cap_net_admin",
    "cap_net_raw",
    "cap_dac_override",
    "cap_chown",
];

fn is_insecure_chmod_mode(text: &str) -> bool {
    let trimmed = trim_shell_token(text);
    matches!(trimmed, "777" | "0777")
        || trimmed.eq_ignore_ascii_case("a+rwx")
        || trimmed.eq_ignore_ascii_case("ugo+rwx")
}

fn is_setuid_setgid_mode(text: &str) -> bool {
    let trimmed = trim_shell_token(text);
    if trimmed.eq_ignore_ascii_case("u+s")
        || trimmed.eq_ignore_ascii_case("g+s")
        || trimmed.eq_ignore_ascii_case("ug+s")
        || trimmed.eq_ignore_ascii_case("u=xs")
        || trimmed.eq_ignore_ascii_case("g=xs")
    {
        return true;
    }

    let octal = trimmed.strip_prefix('0').unwrap_or(trimmed);
    octal.len() == 4
        && octal.as_bytes().iter().all(u8::is_ascii_digit)
        && matches!(octal.as_bytes()[0], b'2' | b'4' | b'6')
        && octal
            .as_bytes()
            .iter()
            .all(|digit| matches!(digit, b'0'..=b'7'))
}

fn is_linux_capability_token(text: &str) -> bool {
    let lowered = trim_shell_token(text).to_ascii_lowercase();
    lowered.starts_with("cap_")
        && DANGEROUS_LINUX_CAPABILITY_TOKENS
            .iter()
            .any(|cap| lowered.contains(cap))
}
