use ignore::WalkBuilder;
use lintai_api::{ArtifactKind, RegionKind};
use lintai_engine::FileTypeDetector;
use lintai_parse::parse;
use std::fs;
use std::path::Path;

use crate::external_validation::{ExternalValidationLedger, repo_dir_name};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Sec347SubtypeCounts {
    pub(crate) cli_form_repos: usize,
    pub(crate) config_snippet_repos: usize,
}

pub(crate) fn sec347_subtype_counts(
    workspace_root: &Path,
    ledger: &ExternalValidationLedger,
) -> Sec347SubtypeCounts {
    let detector = FileTypeDetector::default();
    let repo_root = workspace_root.join("target/external-validation/repos");
    let mut counts = Sec347SubtypeCounts::default();

    for entry in &ledger.evaluations {
        if !entry.preview_rule_codes.iter().any(|rule| rule == "SEC347") {
            continue;
        }

        let repo_dir = repo_root.join(repo_dir_name(&entry.repo));
        if !repo_dir.is_dir() {
            continue;
        }

        let mut repo_has_cli_form = false;
        let mut repo_has_config_snippet_form = false;

        let mut walk = WalkBuilder::new(&repo_dir);
        walk.hidden(false)
            .git_ignore(false)
            .git_exclude(false)
            .git_global(false);

        for result in walk.build() {
            let Ok(entry) = result else {
                continue;
            };
            if !entry
                .file_type()
                .map(|kind| kind.is_file())
                .unwrap_or(false)
            {
                continue;
            }
            let Ok(relative_path) = entry.path().strip_prefix(&repo_dir) else {
                continue;
            };
            let normalized_path = relative_path
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/");
            let Some(artifact) = detector.detect(relative_path, &normalized_path) else {
                continue;
            };
            if !matches!(
                artifact.kind,
                ArtifactKind::Skill
                    | ArtifactKind::Instructions
                    | ArtifactKind::CursorRules
                    | ArtifactKind::CursorPluginAgent
                    | ArtifactKind::CursorPluginCommand
            ) {
                continue;
            }

            let Ok(content) = fs::read_to_string(entry.path()) else {
                continue;
            };
            let Ok(parsed) = parse::markdown::parse(&content) else {
                continue;
            };

            for region in &parsed.document.regions {
                let Some(snippet) = content.get(region.span.start_byte..region.span.end_byte)
                else {
                    continue;
                };
                match region.kind {
                    RegionKind::Normal
                    | RegionKind::Heading
                    | RegionKind::CodeBlock
                    | RegionKind::Blockquote => {
                        repo_has_cli_form |= has_sec347_cli_form(snippet);
                        repo_has_config_snippet_form |= has_sec347_config_snippet_form(snippet);
                    }
                    _ => {}
                }
                if repo_has_cli_form && repo_has_config_snippet_form {
                    break;
                }
            }

            if repo_has_cli_form && repo_has_config_snippet_form {
                break;
            }
        }

        if repo_has_cli_form {
            counts.cli_form_repos += 1;
        }
        if repo_has_config_snippet_form {
            counts.config_snippet_repos += 1;
        }
    }

    counts
}

pub(crate) fn sec347_primary_driver_label(counts: Sec347SubtypeCounts) -> &'static str {
    match counts.cli_form_repos.cmp(&counts.config_snippet_repos) {
        std::cmp::Ordering::Greater => "command-line onboarding examples",
        std::cmp::Ordering::Less => "MCP config snippets",
        std::cmp::Ordering::Equal => {
            if counts.cli_form_repos == 0 {
                "no current subtype evidence"
            } else {
                "a split mix of command-line onboarding examples and MCP config snippets"
            }
        }
    }
}

fn has_sec347_cli_form(region: &str) -> bool {
    for line in region.lines() {
        if line.contains("claude mcp add") {
            if let Some((start, token_len)) = sec347_mutable_launcher_token(line) {
                if !has_sec347_safety_context(line, start, token_len) {
                    return true;
                }
            }
        }
    }

    false
}

fn has_sec347_config_snippet_form(region: &str) -> bool {
    for launcher in ["npx", "uvx", "pnpm dlx", "yarn dlx", "pipx run"] {
        let Some(launcher_start) = region.find(launcher) else {
            continue;
        };
        if launcher_start > 0 && region.as_bytes()[launcher_start - 1].is_ascii_alphanumeric() {
            continue;
        }
        if has_sec347_safety_context(region, launcher_start, launcher.len()) {
            continue;
        }
        if sec347_has_mutable_args(region, launcher_start, launcher) {
            return true;
        }
    }

    false
}

fn sec347_mutable_launcher_token(text: &str) -> Option<(usize, usize)> {
    ["npx", "uvx", "pnpm", "yarn", "pipx"]
        .into_iter()
        .filter_map(|marker| text.find(marker).map(|start| (start, marker.len())))
        .find(|(start, marker_len)| {
            text[*start..]
                .chars()
                .nth(*marker_len)
                .is_none_or(|ch| ch.is_whitespace())
        })
}

fn has_sec347_safety_context(text: &str, marker_start: usize, marker_len: usize) -> bool {
    let prefix = &text[..marker_start];
    let suffix = &text[marker_start + marker_len..];
    let context = format!("{prefix} {suffix}").to_ascii_lowercase();
    [
        "do not use",
        "don't use",
        "avoid",
        "replace with",
        "instead of",
    ]
    .iter()
    .any(|marker| context.contains(marker))
}

fn sec347_has_mutable_args(region: &str, launcher_start: usize, launcher: &str) -> bool {
    let args_window = &region[launcher_start + launcher.len()..];
    match launcher {
        "npx" | "uvx" => sec347_contains_package_like_arg(args_window, &["-y", "--yes"]),
        "pnpm dlx" | "yarn dlx" => {
            sec347_contains_package_like_arg(args_window, &["dlx", "-y", "--yes"])
        }
        "pipx run" => sec347_contains_package_like_arg(args_window, &["run", "-y", "--yes"]),
        _ => false,
    }
}

fn sec347_contains_package_like_arg(args_window: &str, excluded_tokens: &[&str]) -> bool {
    let mut current = String::new();
    for ch in args_window.chars() {
        if ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | ']' | '[') {
            let token = current.trim();
            if !token.is_empty() && sec347_is_package_like_token(token, excluded_tokens) {
                return true;
            }
            current.clear();
            continue;
        }
        current.push(ch);
    }

    let token = current.trim();
    sec347_is_package_like_token(token, excluded_tokens)
}

fn sec347_is_package_like_token(token: &str, excluded_tokens: &[&str]) -> bool {
    if token.is_empty()
        || excluded_tokens
            .iter()
            .any(|excluded| token.eq_ignore_ascii_case(excluded))
        || token.starts_with('-')
    {
        return false;
    }

    token.contains('/') || token.contains('@') || token.contains(':')
}
