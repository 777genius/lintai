use crate::external_validation::{
    ExternalValidationLedger, RepoShortlist, repo_dir_name, template_map,
};
use ignore::WalkBuilder;
use lintai_api::{ArtifactKind, RegionKind};
use lintai_engine::FileTypeDetector;
use lintai_parse::parse;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

pub(crate) fn preview_signal_repos(
    ledger: &ExternalValidationLedger,
) -> Vec<(String, usize, Vec<String>)> {
    ledger
        .evaluations
        .iter()
        .filter(|entry| entry.preview_findings > 0)
        .map(|entry| {
            (
                entry.repo.clone(),
                entry.preview_findings,
                entry.preview_rule_codes.clone(),
            )
        })
        .collect()
}

pub(crate) fn unique_rule_codes_from_hits(hits: &[(String, usize, Vec<String>)]) -> Vec<String> {
    let mut codes = Vec::new();
    for (_, _, hit_codes) in hits {
        for code in hit_codes {
            if !codes.contains(code) {
                codes.push(code.clone());
            }
        }
    }
    codes
}

pub(crate) fn missing_rule_codes(expected: &[&str], observed: &[String]) -> Vec<String> {
    expected
        .iter()
        .filter(|code| !observed.iter().any(|observed| observed == **code))
        .map(|code| (*code).to_owned())
        .collect()
}

pub(crate) fn format_rule_codes(rule_codes: &[String]) -> String {
    if rule_codes.is_empty() {
        "`unspecified`".to_owned()
    } else {
        rule_codes
            .iter()
            .map(|rule_code| format!("`{rule_code}`"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

pub(crate) fn render_clusters(output: &mut String, clusters: &[(String, usize)], label: &str) {
    for index in 0..3 {
        if let Some((rule_code, count)) = clusters.get(index) {
            output.push_str(&format!(
                "{}. `{}` observed in `{}` repo(s).\n",
                index + 1,
                rule_code,
                count
            ));
        } else {
            output.push_str(&format!(
                "{}. No {} cluster observed in this wave.\n",
                index + 1,
                label
            ));
        }
    }
}

pub(crate) fn category_counts(ledger: &ExternalValidationLedger) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for entry in &ledger.evaluations {
        *counts.entry(entry.category.clone()).or_insert(0usize) += 1;
    }
    counts
}

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

pub(crate) struct ExpandedSurfaceCounts {
    pub(crate) top_level_mcp: usize,
    pub(crate) dot_mcp: usize,
    pub(crate) cursor_mcp: usize,
    pub(crate) vscode_mcp: usize,
    pub(crate) roo_mcp: usize,
    pub(crate) kiro_mcp: usize,
    pub(crate) gemini_extension: usize,
    pub(crate) gemini_settings: usize,
    pub(crate) dot_gemini_settings: usize,
    pub(crate) vscode_settings: usize,
    pub(crate) claude_mcp: usize,
    pub(crate) fixture_only_client_variants: usize,
    pub(crate) docker_mcp_launch: usize,
    pub(crate) fixture_only_docker_client_variants: usize,
    pub(crate) tool_descriptor_json: usize,
}

pub(crate) fn expanded_surface_counts(ledger: &ExternalValidationLedger) -> ExpandedSurfaceCounts {
    ExpandedSurfaceCounts {
        top_level_mcp: count_any_surface_presence(ledger, &["mcp.json"]),
        dot_mcp: count_surface_presence(ledger, ".mcp.json"),
        cursor_mcp: count_any_surface_presence(
            ledger,
            &[".cursor/mcp.json", ".cursor/mcp.json (fixture-like)"],
        ),
        vscode_mcp: count_any_surface_presence(
            ledger,
            &[".vscode/mcp.json", ".vscode/mcp.json (fixture-like)"],
        ),
        roo_mcp: count_any_surface_presence(
            ledger,
            &[".roo/mcp.json", ".roo/mcp.json (fixture-like)"],
        ),
        kiro_mcp: count_any_surface_presence(
            ledger,
            &[
                ".kiro/settings/mcp.json",
                ".kiro/settings/mcp.json (fixture-like)",
            ],
        ),
        gemini_extension: count_any_surface_presence(
            ledger,
            &[
                "gemini-extension.json",
                "gemini-extension.json (fixture-like)",
            ],
        ),
        gemini_settings: count_any_surface_presence(
            ledger,
            &[
                "gemini.settings.json",
                "gemini.settings.json (fixture-like)",
            ],
        ),
        dot_gemini_settings: count_any_surface_presence(
            ledger,
            &[
                ".gemini/settings.json",
                ".gemini/settings.json (fixture-like)",
            ],
        ),
        vscode_settings: count_any_surface_presence(
            ledger,
            &[
                "vscode.settings.json",
                "vscode.settings.json (fixture-like)",
            ],
        ),
        claude_mcp: count_surface_presence(ledger, ".claude/mcp/*.json"),
        fixture_only_client_variants: count_surface_presence(
            ledger,
            "expanded_mcp_client_variant_fixture_only",
        ),
        docker_mcp_launch: count_any_surface_presence(
            ledger,
            &["docker_mcp_launch", "docker_mcp_launch (fixture-like)"],
        ),
        fixture_only_docker_client_variants: count_surface_presence(
            ledger,
            "docker_mcp_launch_fixture_only",
        ),
        tool_descriptor_json: count_surface_presence(ledger, "tool_descriptor_json"),
    }
}

const SEC347_CONTEXT_MARKERS: &[&str] = &[
    "mcpservers",
    "\"mcpservers\"",
    "claude mcp",
    "cursor mcp",
    "model context protocol",
    "mcp server",
];

const SEC347_SAFETY_MARKERS: &[&str] = &[
    "do not use",
    "don't use",
    "avoid",
    "replace with",
    "instead of",
];

fn has_sec347_cli_form(region: &str) -> bool {
    for line in region.split_inclusive('\n') {
        let lowered = line.to_ascii_lowercase();
        if lowered.contains("claude mcp add")
            && let Some((start, token_len)) = sec347_mutable_launcher_token(line)
        {
            if !has_sec347_safety_context(line, start, token_len) {
                return true;
            }
        }
    }

    if !region.ends_with('\n') {
        let lowered = region.to_ascii_lowercase();
        if lowered.contains("claude mcp add")
            && let Some((start, token_len)) = sec347_mutable_launcher_token(region)
        {
            return !has_sec347_safety_context(region, start, token_len);
        }
    }

    false
}

fn has_sec347_config_snippet_form(region: &str) -> bool {
    let lowered = region.to_ascii_lowercase();
    if !SEC347_CONTEXT_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return false;
    }

    for launcher in ["npx", "uvx", "pnpm", "yarn", "pipx"] {
        for prefix in [
            format!("\"command\": \"{launcher}\""),
            format!("command: {launcher}"),
        ] {
            if let Some(start) = lowered.find(&prefix) {
                let launcher_start = start + prefix.rfind(launcher).unwrap_or(0);
                if has_sec347_safety_context(region, launcher_start, launcher.len()) {
                    continue;
                }
                if sec347_has_mutable_args(region, launcher_start, launcher) {
                    return true;
                }
            }
        }
    }

    false
}

fn sec347_mutable_launcher_token(text: &str) -> Option<(usize, usize)> {
    for marker in ["npx", "uvx", "pnpm dlx", "yarn dlx", "pipx run"] {
        let lowered = text.to_ascii_lowercase();
        if let Some(start) = lowered.find(marker) {
            let token_len = marker.split_whitespace().next().unwrap_or(marker).len();
            return Some((start, token_len));
        }
    }
    None
}

fn has_sec347_safety_context(text: &str, marker_start: usize, marker_len: usize) -> bool {
    let lowered = text.to_ascii_lowercase();
    let start = marker_start.saturating_sub(96);
    let end = (marker_start + marker_len + 96).min(lowered.len());
    let window = &lowered[start..end];
    SEC347_SAFETY_MARKERS
        .iter()
        .any(|marker| window.contains(marker))
}

fn sec347_has_mutable_args(region: &str, launcher_start: usize, launcher: &str) -> bool {
    let lowered = region.to_ascii_lowercase();
    let window_start = launcher_start.saturating_sub(48);
    let window_end = (launcher_start + launcher.len() + 220).min(lowered.len());
    let window = &lowered[window_start..window_end];

    let Some(args_index) = window.find("\"args\"").or_else(|| window.find("args:")) else {
        return false;
    };
    let args_window = &window[args_index..];

    match launcher {
        "npx" | "uvx" => sec347_contains_package_like_arg(args_window, &["-y", "--yes"]),
        "pnpm" | "yarn" => {
            args_window.contains("dlx")
                && sec347_contains_package_like_arg(args_window, &["dlx", "-y", "--yes"])
        }
        "pipx" => {
            args_window.contains("run")
                && sec347_contains_package_like_arg(args_window, &["run", "-y", "--yes"])
        }
        _ => false,
    }
}

fn sec347_contains_package_like_arg(args_window: &str, excluded_tokens: &[&str]) -> bool {
    let mut token = String::new();
    for ch in args_window.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '@' | '/' | '.' | '-' | '_') {
            token.push(ch);
            continue;
        }
        if sec347_is_package_like_token(&token, excluded_tokens) {
            return true;
        }
        token.clear();
    }

    sec347_is_package_like_token(&token, excluded_tokens)
}

fn sec347_is_package_like_token(token: &str, excluded_tokens: &[&str]) -> bool {
    !token.is_empty()
        && token != "args"
        && !excluded_tokens.iter().any(|excluded| token == *excluded)
        && token.chars().any(|ch| ch.is_ascii_alphabetic())
}

pub(crate) fn count_surface_presence(ledger: &ExternalValidationLedger, surface: &str) -> usize {
    count_any_surface_presence(ledger, &[surface])
}

pub(crate) fn count_any_surface_presence(
    ledger: &ExternalValidationLedger,
    surfaces: &[&str],
) -> usize {
    let wanted = surfaces.iter().copied().collect::<BTreeSet<_>>();
    ledger
        .evaluations
        .iter()
        .filter(|entry| {
            entry
                .surfaces_present
                .iter()
                .any(|present| wanted.contains(present.as_str()))
        })
        .count()
}

pub(crate) fn rule_count(ledger: &ExternalValidationLedger, rules: &[&str]) -> usize {
    let wanted = rules.iter().copied().collect::<BTreeSet<_>>();
    ledger
        .evaluations
        .iter()
        .map(|entry| {
            entry
                .stable_rule_codes
                .iter()
                .chain(entry.preview_rule_codes.iter())
                .filter(|rule_code| wanted.contains(rule_code.as_str()))
                .count()
        })
        .sum()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PhaseTargetKind {
    DatadogSec105,
    InvalidYamlRecovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PhaseTargetStatus {
    Improved,
    Unchanged,
    Regressed,
}

pub(crate) fn target_status_label(status: PhaseTargetStatus) -> &'static str {
    match status {
        PhaseTargetStatus::Improved => "improved",
        PhaseTargetStatus::Unchanged => "stayed unchanged",
        PhaseTargetStatus::Regressed => "regressed",
    }
}

pub(crate) fn phase_target_status(
    baseline: &ExternalValidationLedger,
    current: &ExternalValidationLedger,
    repo: &str,
    kind: PhaseTargetKind,
) -> PhaseTargetStatus {
    let baseline = baseline.evaluations.iter().find(|entry| entry.repo == repo);
    let current = current.evaluations.iter().find(|entry| entry.repo == repo);
    let Some((baseline, current)) = baseline.zip(current) else {
        return PhaseTargetStatus::Unchanged;
    };

    match kind {
        PhaseTargetKind::DatadogSec105 => {
            compare_counts(baseline.preview_findings, current.preview_findings)
        }
        PhaseTargetKind::InvalidYamlRecovery => {
            compare_counts(baseline.runtime_errors.len(), current.runtime_errors.len())
        }
    }
}

pub(crate) fn compare_counts(before: usize, after: usize) -> PhaseTargetStatus {
    match after.cmp(&before) {
        std::cmp::Ordering::Less => PhaseTargetStatus::Improved,
        std::cmp::Ordering::Equal => PhaseTargetStatus::Unchanged,
        std::cmp::Ordering::Greater => PhaseTargetStatus::Regressed,
    }
}

pub(crate) struct RepoVerdictChange {
    pub(crate) repo: String,
    pub(crate) from: String,
    pub(crate) to: String,
}

pub(crate) fn repo_verdict_changes(
    baseline: &ExternalValidationLedger,
    current: &ExternalValidationLedger,
) -> Vec<RepoVerdictChange> {
    let baseline_map = template_map(baseline);
    current
        .evaluations
        .iter()
        .filter_map(|entry| {
            baseline_map.get(&entry.repo).and_then(|prior| {
                (prior.repo_verdict != entry.repo_verdict).then(|| RepoVerdictChange {
                    repo: entry.repo.clone(),
                    from: prior.repo_verdict.clone(),
                    to: entry.repo_verdict.clone(),
                })
            })
        })
        .collect()
}

#[derive(Clone, Copy)]
pub(crate) enum ClusterKind {
    FalsePositive,
    FalseNegative,
}

pub(crate) fn top_clusters(
    ledger: &ExternalValidationLedger,
    kind: ClusterKind,
) -> Vec<(String, usize)> {
    let mut counts = BTreeMap::new();
    for entry in &ledger.evaluations {
        let notes = match kind {
            ClusterKind::FalsePositive => &entry.false_positive_notes,
            ClusterKind::FalseNegative => &entry.possible_false_negative_notes,
        };
        for note in notes {
            let key = note
                .rule_code
                .clone()
                .unwrap_or_else(|| "unspecified".to_owned());
            *counts.entry(key).or_insert(0usize) += 1;
        }
    }
    let mut pairs = counts.into_iter().collect::<Vec<_>>();
    pairs.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    pairs
}

pub(crate) struct AggregateCounts {
    pub(crate) stable_findings: usize,
    pub(crate) preview_findings: usize,
    pub(crate) runtime_errors: usize,
    pub(crate) diagnostics: usize,
}

pub(crate) fn aggregate_counts(ledger: &ExternalValidationLedger) -> AggregateCounts {
    AggregateCounts {
        stable_findings: ledger
            .evaluations
            .iter()
            .map(|entry| entry.stable_findings)
            .sum(),
        preview_findings: ledger
            .evaluations
            .iter()
            .map(|entry| entry.preview_findings)
            .sum(),
        runtime_errors: ledger
            .evaluations
            .iter()
            .map(|entry| entry.runtime_errors.len())
            .sum(),
        diagnostics: ledger
            .evaluations
            .iter()
            .map(|entry| entry.diagnostics.len())
            .sum(),
    }
}

pub(crate) fn repos_with_rule_hits(
    ledger: &ExternalValidationLedger,
    wanted_rules: &[&str],
    stable: bool,
) -> Vec<(String, usize, Vec<String>)> {
    let wanted = wanted_rules.iter().copied().collect::<BTreeSet<_>>();
    ledger
        .evaluations
        .iter()
        .filter_map(|entry| {
            let matching_codes = if stable {
                entry
                    .stable_rule_codes
                    .iter()
                    .filter(|code| wanted.contains(code.as_str()))
                    .cloned()
                    .collect::<Vec<_>>()
            } else {
                entry
                    .preview_rule_codes
                    .iter()
                    .filter(|code| wanted.contains(code.as_str()))
                    .cloned()
                    .collect::<Vec<_>>()
            };
            if matching_codes.is_empty() {
                return None;
            }
            let count = if stable {
                entry
                    .stable_rule_codes
                    .iter()
                    .filter(|code| wanted.contains(code.as_str()))
                    .count()
            } else {
                entry
                    .preview_rule_codes
                    .iter()
                    .filter(|code| wanted.contains(code.as_str()))
                    .count()
            };
            Some((entry.repo.clone(), count, matching_codes))
        })
        .collect()
}

pub(crate) fn repos_with_runtime_issues(
    ledger: &ExternalValidationLedger,
    shortlist: &RepoShortlist,
) -> Vec<(String, usize, usize, Vec<String>)> {
    let admission_map = shortlist
        .repos
        .iter()
        .map(|repo| (repo.repo.as_str(), repo.admission_paths.as_slice()))
        .collect::<BTreeMap<_, _>>();
    ledger
        .evaluations
        .iter()
        .filter_map(|entry| {
            let runtime_count = entry.runtime_errors.len();
            let diagnostic_count = entry.diagnostics.len();
            ((runtime_count + diagnostic_count) > 0).then(|| {
                let admission_paths = admission_map
                    .get(entry.repo.as_str())
                    .copied()
                    .unwrap_or(&[]);
                let mut labels = Vec::new();
                labels.extend(
                    entry
                        .runtime_errors
                        .iter()
                        .map(|error| issue_scope_label(&error.path, admission_paths)),
                );
                labels.extend(
                    entry
                        .diagnostics
                        .iter()
                        .map(|diagnostic| issue_scope_label(&diagnostic.path, admission_paths)),
                );
                labels.sort();
                labels.dedup();
                (entry.repo.clone(), runtime_count, diagnostic_count, labels)
            })
        })
        .collect()
}

pub(crate) fn issue_scope_label(path: &str, admission_paths: &[String]) -> String {
    if admission_paths.iter().any(|candidate| candidate == path) {
        "admission-path issue".to_owned()
    } else {
        "non-admission-path issue".to_owned()
    }
}

pub(crate) fn admitted_repo_set_changes(
    shortlist: &RepoShortlist,
    baseline: &ExternalValidationLedger,
) -> Vec<String> {
    let current = shortlist
        .repos
        .iter()
        .map(|repo| repo.repo.as_str())
        .collect::<BTreeSet<_>>();
    let previous = baseline
        .evaluations
        .iter()
        .map(|entry| entry.repo.as_str())
        .collect::<BTreeSet<_>>();
    let mut changes = Vec::new();
    for repo in current.difference(&previous) {
        changes.push(format!("added `{repo}`"));
    }
    for repo in previous.difference(&current) {
        changes.push(format!("removed `{repo}`"));
    }
    changes
}
