use crate::external_validation::{ExternalValidationLedger, RepoShortlist, template_map};
use std::collections::{BTreeMap, BTreeSet};

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
