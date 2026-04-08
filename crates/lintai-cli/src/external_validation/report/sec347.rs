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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_validation::{repo_dir_name, ExternalValidationLedger, EvaluationEntry};
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_workspace_root() -> PathBuf {
        let unique_id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|time| time.as_nanos())
            .unwrap_or(0);
        let workspace = env::temp_dir().join(format!("lintai-sec347-tests-{unique_id}-{}", std::process::id()));
        fs::create_dir_all(&workspace).unwrap();
        workspace
    }

    fn cleanup(workspace: &PathBuf) {
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn primary_driver_label_reports_mix_when_equal_but_nonzero() {
        let counts = Sec347SubtypeCounts {
            cli_form_repos: 2,
            config_snippet_repos: 2,
        };
        assert_eq!(
            sec347_primary_driver_label(counts),
            "a split mix of command-line onboarding examples and MCP config snippets"
        );
    }

    #[test]
    fn primary_driver_label_reports_cli_when_cli_has_majority() {
        let counts = Sec347SubtypeCounts {
            cli_form_repos: 3,
            config_snippet_repos: 1,
        };
        assert_eq!(
            sec347_primary_driver_label(counts),
            "command-line onboarding examples"
        );
    }

    #[test]
    fn primary_driver_label_reports_config_when_config_has_majority() {
        let counts = Sec347SubtypeCounts {
            cli_form_repos: 1,
            config_snippet_repos: 3,
        };
        assert_eq!(
            sec347_primary_driver_label(counts),
            "MCP config snippets"
        );
    }

    #[test]
    fn primary_driver_label_reports_no_current_evidence_when_empty() {
        let counts = Sec347SubtypeCounts::default();
        assert_eq!(
            sec347_primary_driver_label(counts),
            "no current subtype evidence"
        );
    }

    #[test]
    fn sec347_cli_form_requires_nonsafety_context_token() {
        let with_safety = "Instead of claude mcp add npx tool@1";
        let without_safety = "Use this flow: claude mcp add npx tool@1";
        assert!(!has_sec347_cli_form(with_safety));
        assert!(has_sec347_cli_form(without_safety));
    }

    #[test]
    fn sec347_config_snippet_form_detects_mutable_launcher() {
        let with_safety = "Use uvx instead of --safe-mode\n";
        let with_mutable = "uvx -y mypkg@1.0\n";
        assert!(!has_sec347_config_snippet_form(with_safety));
        assert!(has_sec347_config_snippet_form(with_mutable));
    }

    #[test]
    fn sec347_mutable_launcher_token_matches_markers_with_word_boundary() {
        assert!(sec347_mutable_launcher_token("uvx --help").is_some());
        assert!(sec347_mutable_launcher_token("this string contains pipx run cmd").is_some());
        assert!(sec347_mutable_launcher_token("unrelated text").is_none());
    }

    #[test]
    fn sec347_contains_package_like_args_skips_negated_tokens() {
        assert!(sec347_contains_package_like_arg(" -y demo@1", &["-y", "--yes"]));
        assert!(!sec347_contains_package_like_arg(" -y --yes", &["-y", "--yes"]));
        assert!(!sec347_contains_package_like_arg(" -y -d", &["-y", "--yes"]));
    }

    #[test]
    fn sec347_subtype_counts_distinguish_cli_and_config_repos() {
        let workspace_root = make_workspace_root();
        let repos_root = workspace_root
            .join("target")
            .join("external-validation")
            .join("repos");

        let cli_repo = "owner/cli-workflow";
        let config_repo = "owner/config-workflow";
        let other_repo = "owner/no-sec347";

        let cli_repo_dir = repos_root.join(repo_dir_name(cli_repo));
        let config_repo_dir = repos_root.join(repo_dir_name(config_repo));
        let other_repo_dir = repos_root.join(repo_dir_name(other_repo));
        fs::create_dir_all(&cli_repo_dir).unwrap();
        fs::create_dir_all(&config_repo_dir).unwrap();
        fs::create_dir_all(&other_repo_dir).unwrap();

        fs::create_dir_all(cli_repo_dir.join(".github").join("instructions")).unwrap();
        fs::create_dir_all(config_repo_dir.join(".github").join("instructions")).unwrap();
        fs::create_dir_all(other_repo_dir.join(".github").join("instructions")).unwrap();

        fs::write(
            cli_repo_dir
                .join(".github")
                .join("instructions")
                .join("guide.md"),
            "Notes\nclaude mcp add npx --help\n",
        )
        .unwrap();
        fs::write(
            config_repo_dir
                .join(".github")
                .join("instructions")
                .join("guide.md"),
            "Run this example:\nuvx -y my-team/runner\n",
        )
        .unwrap();
        fs::write(
            other_repo_dir
                .join(".github")
                .join("instructions")
                .join("guide.md"),
            "No match text.\n",
        )
        .unwrap();

        let ledger = ExternalValidationLedger {
            evaluations: vec![
                EvaluationEntry {
                    repo: cli_repo.to_owned(),
                    preview_rule_codes: vec!["SEC347".to_owned()],
                    ..Default::default()
                },
                EvaluationEntry {
                    repo: config_repo.to_owned(),
                    preview_rule_codes: vec!["SEC347".to_owned()],
                    ..Default::default()
                },
                EvaluationEntry {
                    repo: other_repo.to_owned(),
                    preview_rule_codes: vec!["SEC346".to_owned()],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        let counts = sec347_subtype_counts(&workspace_root, &ledger);
        assert_eq!(counts.cli_form_repos, 1);
        assert_eq!(counts.config_snippet_repos, 1);
        cleanup(&workspace_root);
    }
}
