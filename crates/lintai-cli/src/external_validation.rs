use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use ignore::WalkBuilder;
use lintai_ai_security::{AiSecurityProvider, PolicyMismatchProvider};
use lintai_api::{RuleProvider, RuleTier};
use serde::{Deserialize, Serialize};

use crate::internal_bin::resolve_lintai_driver_path;

const SHORTLIST_PATH: &str = "validation/external-repos/repo-shortlist.toml";
const LEDGER_PATH: &str = "validation/external-repos/ledger.toml";
const ARCHIVED_WAVE1_LEDGER_PATH: &str = "validation/external-repos/archive/wave1-ledger.toml";

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct RepoShortlist {
    #[allow(dead_code)]
    pub version: u32,
    pub repos: Vec<ShortlistRepo>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct ShortlistRepo {
    pub repo: String,
    pub url: String,
    pub pinned_ref: String,
    pub category: String,
    pub subtype: String,
    pub status: String,
    pub surfaces_present: Vec<String>,
    #[allow(dead_code)]
    pub rationale: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct ExternalValidationLedger {
    pub version: u32,
    #[serde(default)]
    pub wave: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<String>,
    #[serde(default)]
    pub evaluations: Vec<EvaluationEntry>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct EvaluationEntry {
    pub repo: String,
    pub url: String,
    pub pinned_ref: String,
    pub category: String,
    pub subtype: String,
    pub status: String,
    pub surfaces_present: Vec<String>,
    pub stable_findings: usize,
    pub preview_findings: usize,
    pub stable_rule_codes: Vec<String>,
    pub preview_rule_codes: Vec<String>,
    pub repo_verdict: String,
    pub stable_precision_notes: String,
    pub preview_signal_notes: String,
    pub false_positive_notes: Vec<FindingNote>,
    pub possible_false_negative_notes: Vec<FindingNote>,
    pub follow_up_action: String,
    #[serde(default)]
    pub runtime_errors: Vec<RuntimeErrorRecord>,
    #[serde(default)]
    pub diagnostics: Vec<DiagnosticRecord>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct FindingNote {
    #[serde(default)]
    pub rule_code: Option<String>,
    #[serde(default)]
    pub verdict: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub problem: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct RuntimeErrorRecord {
    pub path: String,
    pub kind: String,
    pub message: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct DiagnosticRecord {
    pub path: String,
    pub severity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize)]
struct JsonScanEnvelope {
    findings: Vec<JsonFinding>,
    #[serde(default)]
    diagnostics: Vec<JsonDiagnostic>,
    #[serde(default)]
    runtime_errors: Vec<JsonRuntimeError>,
}

#[derive(Clone, Debug, Deserialize)]
struct JsonFinding {
    rule_code: String,
}

#[derive(Clone, Debug, Deserialize)]
struct JsonDiagnostic {
    normalized_path: String,
    severity: String,
    code: Option<String>,
    message: String,
}

#[derive(Clone, Debug, Deserialize)]
struct JsonRuntimeError {
    normalized_path: String,
    kind: String,
    message: String,
}

#[derive(Clone, Debug)]
pub(crate) struct RerunOptions {
    pub workspace_root: PathBuf,
    pub lintai_bin: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub(crate) struct RenderReportOptions {
    pub workspace_root: PathBuf,
}

pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<(), String> {
    let args = args.collect::<Vec<_>>();
    let Some(command) = args.first().map(String::as_str) else {
        return Err("expected one of: rerun, render-report".to_owned());
    };
    match command {
        "rerun" => {
            if args.len() > 1 {
                return Err("rerun does not accept extra positional arguments".to_owned());
            }
            rerun(RerunOptions {
                workspace_root: workspace_root()?,
                lintai_bin: None,
            })?;
            Ok(())
        }
        "render-report" => {
            if args.len() > 1 {
                return Err("render-report does not accept extra positional arguments".to_owned());
            }
            let markdown = render_report(RenderReportOptions {
                workspace_root: workspace_root()?,
            })?;
            print!("{markdown}");
            Ok(())
        }
        _ => Err(format!("unknown external validation command `{command}`")),
    }
}

pub(crate) fn rerun(options: RerunOptions) -> Result<(), String> {
    let shortlist = load_shortlist(&options.workspace_root)?;
    let template = load_ledger(&options.workspace_root.join(LEDGER_PATH))?;
    let repo_root = options
        .workspace_root
        .join("target/external-validation/repos");
    let raw_root = options
        .workspace_root
        .join("target/external-validation/wave2/raw");
    fs::create_dir_all(&repo_root).map_err(|error| {
        format!(
            "failed to create repo cache root {}: {error}",
            repo_root.display()
        )
    })?;
    fs::create_dir_all(&raw_root).map_err(|error| {
        format!(
            "failed to create raw output root {}: {error}",
            raw_root.display()
        )
    })?;

    let lintai_bin = options
        .lintai_bin
        .unwrap_or(resolve_lintai_driver_path().map_err(|error| {
            format!("failed to resolve lintai binary for external validation rerun: {error}")
        })?);
    let tier_map = current_rule_tiers();
    let template_entries = template_map(&template);

    let mut candidate = ExternalValidationLedger {
        version: 1,
        wave: 2,
        baseline: Some("archive/wave1-ledger.toml".to_owned()),
        evaluations: Vec::new(),
    };

    for repo in &shortlist.repos {
        let local_dir = repo_root.join(repo_dir_name(&repo.repo));
        materialize_repo(repo, &local_dir)?;
        let inventory = inventory_surfaces(&local_dir)?;
        let repo_raw_root = raw_root.join(repo_dir_name(&repo.repo));
        fs::create_dir_all(&repo_raw_root).map_err(|error| {
            format!(
                "failed to create raw output dir {}: {error}",
                repo_raw_root.display()
            )
        })?;

        let text = run_scan(&lintai_bin, &local_dir, false)?;
        let json = run_scan(&lintai_bin, &local_dir, true)?;
        fs::write(repo_raw_root.join("scan.txt"), &text)
            .map_err(|error| format!("failed to write text scan artifact: {error}"))?;
        fs::write(repo_raw_root.join("scan.json"), &json)
            .map_err(|error| format!("failed to write JSON scan artifact: {error}"))?;
        let inventory_text = toml::to_string_pretty(&inventory)
            .map_err(|error| format!("failed to serialize inventory artifact: {error}"))?;
        fs::write(repo_raw_root.join("inventory.toml"), inventory_text)
            .map_err(|error| format!("failed to write inventory artifact: {error}"))?;

        let parsed: JsonScanEnvelope = serde_json::from_str(&json)
            .map_err(|error| format!("failed to parse scan JSON for {}: {error}", repo.repo))?;
        let mut entry = template_entries
            .get(&repo.repo)
            .cloned()
            .unwrap_or_else(|| default_entry_from_shortlist(repo));
        fill_auto_fields(
            &mut entry,
            repo,
            inventory.surfaces_present.clone(),
            &parsed,
            &tier_map,
        )?;
        candidate.evaluations.push(entry);
    }

    let candidate_path = options
        .workspace_root
        .join("target/external-validation/wave2/candidate-ledger.toml");
    let text = toml::to_string_pretty(&candidate)
        .map_err(|error| format!("failed to serialize candidate ledger: {error}"))?;
    fs::create_dir_all(
        candidate_path
            .parent()
            .ok_or_else(|| "candidate ledger path should have a parent".to_owned())?,
    )
    .map_err(|error| format!("failed to create candidate ledger directory: {error}"))?;
    fs::write(&candidate_path, text)
        .map_err(|error| format!("failed to write candidate ledger: {error}"))?;

    Ok(())
}

pub(crate) fn render_report(options: RenderReportOptions) -> Result<String, String> {
    let baseline = load_ledger(&options.workspace_root.join(ARCHIVED_WAVE1_LEDGER_PATH))?;
    let current = load_ledger(&options.workspace_root.join(LEDGER_PATH))?;
    Ok(render_report_from_ledgers(&baseline, &current))
}

fn render_report_from_ledgers(
    baseline: &ExternalValidationLedger,
    current: &ExternalValidationLedger,
) -> String {
    let baseline_counts = aggregate_counts(baseline);
    let current_counts = aggregate_counts(current);
    let verdict_changes = repo_verdict_changes(baseline, current);
    let fp_clusters = top_clusters(current, ClusterKind::FalsePositive);
    let fn_clusters = top_clusters(current, ClusterKind::FalseNegative);
    let preview_signal_repos = preview_signal_repos(current);

    let datadog_status = phase_target_status(
        baseline,
        current,
        "datadog-labs/cursor-plugin",
        PhaseTargetKind::DatadogSec105,
    );
    let cursor_plugins_status = phase_target_status(
        baseline,
        current,
        "cursor/plugins",
        PhaseTargetKind::InvalidYamlRecovery,
    );
    let emmraan_status = phase_target_status(
        baseline,
        current,
        "Emmraan/agent-skills",
        PhaseTargetKind::InvalidYamlRecovery,
    );

    let mut output = String::new();
    output.push_str("# External Validation Report\n\n");
    output.push_str("> Second checked-in external validation summary for `lintai` after Phase 1 precision hardening.\n");
    output.push_str("> Cohort source of truth lives in [validation/external-repos/repo-shortlist.toml](../validation/external-repos/repo-shortlist.toml), current results in [validation/external-repos/ledger.toml](../validation/external-repos/ledger.toml), and wave 1 baseline in [validation/external-repos/archive/wave1-ledger.toml](../validation/external-repos/archive/wave1-ledger.toml).\n\n");
    output.push_str("## Cohort Composition\n\n");
    output.push_str(&format!(
        "The current cohort still contains `{}` public repositories:\n\n",
        current.evaluations.len()
    ));
    let category_counts = category_counts(current);
    output.push_str(&format!(
        "- `{}` `mcp`-focused repos\n",
        category_counts.get("mcp").copied().unwrap_or(0)
    ));
    output.push_str(&format!(
        "- `{}` `cursor_plugin`-focused repos\n",
        category_counts.get("cursor_plugin").copied().unwrap_or(0)
    ));
    output.push_str(&format!(
        "- `{}` `skills`-focused repos\n\n",
        category_counts.get("skills").copied().unwrap_or(0)
    ));

    output.push_str("## Overall Counts\n\n");
    output.push_str("Current checked-in wave 2 results:\n\n");
    output.push_str(&format!(
        "- `{}` repos evaluated\n",
        current.evaluations.len()
    ));
    output.push_str(&format!(
        "- `{}` total findings\n",
        current_counts.stable_findings + current_counts.preview_findings
    ));
    output.push_str(&format!(
        "- `{}` stable findings\n",
        current_counts.stable_findings
    ));
    output.push_str(&format!(
        "- `{}` preview findings\n",
        current_counts.preview_findings
    ));
    output.push_str(&format!(
        "- `{}` runtime parser errors\n",
        current_counts.runtime_errors
    ));
    output.push_str(&format!(
        "- `{}` diagnostics\n\n",
        current_counts.diagnostics
    ));

    output.push_str("## Delta From Previous Wave\n\n");
    output.push_str(&format!(
        "- stable findings: `{}` -> `{}`\n",
        baseline_counts.stable_findings, current_counts.stable_findings
    ));
    output.push_str(&format!(
        "- preview findings: `{}` -> `{}`\n",
        baseline_counts.preview_findings, current_counts.preview_findings
    ));
    output.push_str(&format!(
        "- runtime parser errors: `{}` -> `{}`\n",
        baseline_counts.runtime_errors, current_counts.runtime_errors
    ));
    output.push_str(&format!(
        "- diagnostics: `{}` -> `{}`\n",
        baseline_counts.diagnostics, current_counts.diagnostics
    ));
    if verdict_changes.is_empty() {
        output.push_str("- repo verdict changes: none\n\n");
    } else {
        output.push_str("- repo verdict changes:\n");
        for change in &verdict_changes {
            output.push_str(&format!(
                "  - `{}`: `{}` -> `{}`\n",
                change.repo, change.from, change.to
            ));
        }
        output.push('\n');
    }

    output.push_str("## Stable Precision Summary\n\n");
    if current_counts.stable_findings == 0 {
        output.push_str("The current `Stable` layer remains clean across wave 2:\n\n");
        output.push_str("- no `Stable` findings were emitted\n");
        output.push_str("- no `Stable` false-positive cluster was observed\n");
        output
            .push_str("- no new `Stable` release-blocking noise signal surfaced in this wave\n\n");
    } else {
        output.push_str("Wave 2 surfaced `Stable` findings and requires another precision pass before beta.\n\n");
    }

    output.push_str("## Preview Usefulness Summary\n\n");
    output.push_str(&format!(
        "Wave 2 produced `{}` preview finding(s).\n\n",
        current_counts.preview_findings
    ));
    output.push_str(&format!(
        "- `datadog-labs/cursor-plugin`: `{}`\n",
        target_status_label(datadog_status)
    ));
    for (repo, count, rule_codes) in preview_signal_repos {
        output.push_str(&format!(
            "- `{repo}`: `{count}` preview finding(s) via {}\n",
            format_rule_codes(&rule_codes)
        ));
    }
    output.push('\n');

    output.push_str("## Runtime / Diagnostic Notes\n\n");
    output.push_str(&format!(
        "- `cursor/plugins`: `{}`\n",
        target_status_label(cursor_plugins_status)
    ));
    output.push_str(&format!(
        "- `Emmraan/agent-skills`: `{}`\n\n",
        target_status_label(emmraan_status)
    ));

    output.push_str("## Top FP Clusters\n\n");
    render_clusters(&mut output, &fp_clusters, "false-positive");
    output.push('\n');

    output.push_str("## Top FN Clusters\n\n");
    render_clusters(&mut output, &fn_clusters, "false-negative");
    output.push('\n');

    output.push_str("## Recommended Next Step\n\n");
    let next_step = if current_counts.stable_findings == 0
        && datadog_status != PhaseTargetStatus::Regressed
        && cursor_plugins_status != PhaseTargetStatus::Regressed
        && emmraan_status != PhaseTargetStatus::Regressed
    {
        "public beta"
    } else {
        "precision hardening"
    };
    output.push_str(&format!("`{next_step}`\n\n"));
    output.push_str("Rationale:\n\n");
    output.push_str("- this report is grounded in the current checked-in wave 2 ledger and archived wave 1 baseline\n");
    output.push_str("- the known Phase 1 follow-up repos are called out explicitly above\n");
    if next_step == "public beta" {
        output.push_str("- the current results do not show a new `Stable` precision regression\n");
    } else {
        output.push_str(
            "- one or more wave 2 signals still require another precision pass before beta\n",
        );
    }

    output
}

fn preview_signal_repos(ledger: &ExternalValidationLedger) -> Vec<(String, usize, Vec<String>)> {
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

fn format_rule_codes(rule_codes: &[String]) -> String {
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

fn render_clusters(output: &mut String, clusters: &[(String, usize)], label: &str) {
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

fn category_counts(ledger: &ExternalValidationLedger) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for entry in &ledger.evaluations {
        *counts.entry(entry.category.clone()).or_insert(0usize) += 1;
    }
    counts
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PhaseTargetKind {
    DatadogSec105,
    InvalidYamlRecovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PhaseTargetStatus {
    Improved,
    Unchanged,
    Regressed,
}

fn target_status_label(status: PhaseTargetStatus) -> &'static str {
    match status {
        PhaseTargetStatus::Improved => "improved",
        PhaseTargetStatus::Unchanged => "stayed unchanged",
        PhaseTargetStatus::Regressed => "regressed",
    }
}

fn phase_target_status(
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

fn compare_counts(before: usize, after: usize) -> PhaseTargetStatus {
    match after.cmp(&before) {
        std::cmp::Ordering::Less => PhaseTargetStatus::Improved,
        std::cmp::Ordering::Equal => PhaseTargetStatus::Unchanged,
        std::cmp::Ordering::Greater => PhaseTargetStatus::Regressed,
    }
}

struct RepoVerdictChange {
    repo: String,
    from: String,
    to: String,
}

fn repo_verdict_changes(
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
enum ClusterKind {
    FalsePositive,
    FalseNegative,
}

fn top_clusters(ledger: &ExternalValidationLedger, kind: ClusterKind) -> Vec<(String, usize)> {
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

struct AggregateCounts {
    stable_findings: usize,
    preview_findings: usize,
    runtime_errors: usize,
    diagnostics: usize,
}

fn aggregate_counts(ledger: &ExternalValidationLedger) -> AggregateCounts {
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

#[derive(Clone, Debug, Default, Serialize)]
struct InventoryArtifact {
    surfaces_present: Vec<String>,
}

fn inventory_surfaces(repo_root: &Path) -> Result<InventoryArtifact, String> {
    let mut surfaces = BTreeSet::new();
    let mut builder = WalkBuilder::new(repo_root);
    builder
        .hidden(false)
        .git_ignore(false)
        .git_exclude(false)
        .parents(false);
    for result in builder.build() {
        let entry = result.map_err(|error| format!("inventory walk failed: {error}"))?;
        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(repo_root)
            .map_err(|error| format!("failed to relativize inventory path: {error}"))?;
        let normalized = normalize_rel_path(relative);
        if normalized.ends_with("SKILL.md") {
            surfaces.insert("SKILL.md".to_owned());
        }
        if normalized.ends_with("CLAUDE.md") {
            surfaces.insert("CLAUDE.md".to_owned());
        }
        if normalized.ends_with(".mdc") {
            surfaces.insert(".mdc".to_owned());
        }
        if normalized.ends_with(".cursorrules") {
            surfaces.insert(".cursorrules".to_owned());
        }
        if normalized.ends_with("mcp.json") {
            surfaces.insert("mcp.json".to_owned());
        }
        if normalized.ends_with(".cursor-plugin/plugin.json") {
            surfaces.insert(".cursor-plugin/plugin.json".to_owned());
        }
        if normalized.ends_with(".cursor-plugin/hooks.json") {
            surfaces.insert(".cursor-plugin/hooks.json".to_owned());
        }
        if normalized.contains(".cursor-plugin/hooks/") && normalized.ends_with(".sh") {
            surfaces.insert(".cursor-plugin/hooks/**/*.sh".to_owned());
        }
        if normalized.contains(".cursor-plugin/commands/") && normalized.ends_with(".md") {
            surfaces.insert(".cursor-plugin/commands/**/*.md".to_owned());
        }
        if normalized.contains(".cursor-plugin/agents/") && normalized.ends_with(".md") {
            surfaces.insert(".cursor-plugin/agents/**/*.md".to_owned());
        }
    }

    Ok(InventoryArtifact {
        surfaces_present: surfaces.into_iter().collect(),
    })
}

fn run_scan(lintai_bin: &Path, repo_dir: &Path, json: bool) -> Result<String, String> {
    let mut command = Command::new(lintai_bin);
    command.current_dir(repo_dir).arg("scan").arg(".");
    if json {
        command.arg("--format=json");
    }
    let output = command
        .output()
        .map_err(|error| format!("failed to run lintai in {}: {error}", repo_dir.display()))?;
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| format!("lintai stdout was not valid UTF-8: {error}"))?;
    if matches!(output.status.code(), Some(0 | 1)) {
        return Ok(stdout);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(format!(
        "lintai scan failed in {} with exit {:?}: {}",
        repo_dir.display(),
        output.status.code(),
        stderr.trim()
    ))
}

fn materialize_repo(repo: &ShortlistRepo, local_dir: &Path) -> Result<(), String> {
    let marker_path = local_dir.join(".lintai-external-validation-ref");
    if marker_path.exists()
        && fs::read_to_string(&marker_path)
            .map(|value| value.trim().to_owned())
            .unwrap_or_default()
            == repo.pinned_ref
    {
        return Ok(());
    }

    if local_dir.exists() {
        fs::remove_dir_all(local_dir).map_err(|error| {
            format!(
                "failed to remove stale repo cache dir {}: {error}",
                local_dir.display()
            )
        })?;
    }
    fs::create_dir_all(local_dir).map_err(|error| {
        format!(
            "failed to create repo cache dir {}: {error}",
            local_dir.display()
        )
    })?;

    let archive_path = local_dir.with_extension("tar.gz");
    let download_url = format!(
        "https://codeload.github.com/{}/tar.gz/{}",
        repo.repo, repo.pinned_ref
    );
    let curl_output = Command::new("curl")
        .args(["-L", "--fail", "-o"])
        .arg(&archive_path)
        .arg(&download_url)
        .output()
        .map_err(|error| format!("failed to download {download_url}: {error}"))?;
    if !curl_output.status.success() {
        return Err(format!(
            "failed to download {download_url}: {}",
            String::from_utf8_lossy(&curl_output.stderr).trim()
        ));
    }

    let tar_output = Command::new("tar")
        .arg("-xzf")
        .arg(&archive_path)
        .arg("--strip-components=1")
        .arg("-C")
        .arg(local_dir)
        .output()
        .map_err(|error| {
            format!(
                "failed to extract archive {}: {error}",
                archive_path.display()
            )
        })?;
    if !tar_output.status.success() {
        return Err(format!(
            "failed to extract archive {}: {}",
            archive_path.display(),
            String::from_utf8_lossy(&tar_output.stderr).trim()
        ));
    }

    let _ = fs::remove_file(&archive_path);
    fs::write(&marker_path, format!("{}\n", repo.pinned_ref)).map_err(|error| {
        format!(
            "failed to write repo materialization marker {}: {error}",
            marker_path.display()
        )
    })?;

    Ok(())
}

fn fill_auto_fields(
    entry: &mut EvaluationEntry,
    repo: &ShortlistRepo,
    surfaces_present: Vec<String>,
    parsed: &JsonScanEnvelope,
    tier_map: &BTreeMap<String, RuleTier>,
) -> Result<(), String> {
    let mut stable = BTreeSet::new();
    let mut preview = BTreeSet::new();

    for finding in &parsed.findings {
        match tier_map.get(&finding.rule_code) {
            Some(RuleTier::Stable) => {
                stable.insert(finding.rule_code.clone());
            }
            Some(RuleTier::Preview) => {
                preview.insert(finding.rule_code.clone());
            }
            None => {
                return Err(format!(
                    "unknown rule code `{}` observed during external validation rerun",
                    finding.rule_code
                ));
            }
        }
    }

    entry.repo = repo.repo.clone();
    entry.url = repo.url.clone();
    entry.pinned_ref = repo.pinned_ref.clone();
    entry.category = repo.category.clone();
    entry.subtype = repo.subtype.clone();
    entry.status = "evaluated".to_owned();
    entry.surfaces_present = surfaces_present;
    entry.stable_findings = parsed
        .findings
        .iter()
        .filter(|finding| tier_map.get(&finding.rule_code) == Some(&RuleTier::Stable))
        .count();
    entry.preview_findings = parsed
        .findings
        .iter()
        .filter(|finding| tier_map.get(&finding.rule_code) == Some(&RuleTier::Preview))
        .count();
    entry.stable_rule_codes = stable.into_iter().collect();
    entry.preview_rule_codes = preview.into_iter().collect();
    entry.runtime_errors = parsed
        .runtime_errors
        .iter()
        .map(|error| RuntimeErrorRecord {
            path: error.normalized_path.clone(),
            kind: error.kind.clone(),
            message: error.message.clone(),
        })
        .collect();
    entry.diagnostics = parsed
        .diagnostics
        .iter()
        .map(|diagnostic| DiagnosticRecord {
            path: diagnostic.normalized_path.clone(),
            severity: diagnostic.severity.clone(),
            code: diagnostic.code.clone(),
            message: diagnostic.message.clone(),
        })
        .collect();
    Ok(())
}

fn current_rule_tiers() -> BTreeMap<String, RuleTier> {
    let mut rules = BTreeMap::new();
    for meta in AiSecurityProvider::default().rules() {
        rules.insert(meta.code.to_owned(), meta.tier);
    }
    for meta in PolicyMismatchProvider.rules() {
        rules.insert(meta.code.to_owned(), meta.tier);
    }
    rules
}

fn default_entry_from_shortlist(repo: &ShortlistRepo) -> EvaluationEntry {
    EvaluationEntry {
        repo: repo.repo.clone(),
        url: repo.url.clone(),
        pinned_ref: repo.pinned_ref.clone(),
        category: repo.category.clone(),
        subtype: repo.subtype.clone(),
        status: repo.status.clone(),
        surfaces_present: repo.surfaces_present.clone(),
        stable_findings: 0,
        preview_findings: 0,
        stable_rule_codes: Vec::new(),
        preview_rule_codes: Vec::new(),
        repo_verdict: "strong_fit".to_owned(),
        stable_precision_notes: String::new(),
        preview_signal_notes: String::new(),
        false_positive_notes: Vec::new(),
        possible_false_negative_notes: Vec::new(),
        follow_up_action: "no_action".to_owned(),
        runtime_errors: Vec::new(),
        diagnostics: Vec::new(),
    }
}

fn template_map(ledger: &ExternalValidationLedger) -> BTreeMap<String, EvaluationEntry> {
    ledger
        .evaluations
        .iter()
        .cloned()
        .map(|entry| (entry.repo.clone(), entry))
        .collect()
}

fn load_shortlist(workspace_root: &Path) -> Result<RepoShortlist, String> {
    let text = fs::read_to_string(workspace_root.join(SHORTLIST_PATH))
        .map_err(|error| format!("failed to read shortlist: {error}"))?;
    toml::from_str(&text).map_err(|error| format!("failed to parse shortlist TOML: {error}"))
}

fn load_ledger(path: &Path) -> Result<ExternalValidationLedger, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("failed to read ledger {}: {error}", path.display()))?;
    toml::from_str(&text)
        .map_err(|error| format!("failed to parse ledger {}: {error}", path.display()))
}

fn repo_dir_name(repo: &str) -> String {
    repo.replace('/', "__")
}

fn normalize_rel_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn workspace_root() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|parent| parent.parent())
        .map(Path::to_path_buf)
        .ok_or_else(|| "failed to resolve lintai workspace root".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_shortlist() -> RepoShortlist {
        RepoShortlist {
            version: 1,
            repos: vec![ShortlistRepo {
                repo: "owner/repo".to_owned(),
                url: "https://github.com/owner/repo".to_owned(),
                pinned_ref: "abc123".to_owned(),
                category: "skills".to_owned(),
                subtype: "control".to_owned(),
                status: "evaluated".to_owned(),
                surfaces_present: vec!["SKILL.md".to_owned()],
                rationale: "demo".to_owned(),
            }],
        }
    }

    #[test]
    fn shortlist_parser_shape_is_expected() {
        let shortlist: RepoShortlist = toml::from_str(
            r#"
version = 1

[[repos]]
repo = "owner/repo"
url = "https://github.com/owner/repo"
pinned_ref = "abc123"
category = "skills"
subtype = "control"
status = "evaluated"
surfaces_present = ["SKILL.md"]
rationale = "demo"
"#,
        )
        .unwrap();

        assert_eq!(shortlist.version, 1);
        assert_eq!(shortlist.repos.len(), 1);
        assert_eq!(shortlist.repos[0].repo, "owner/repo");
    }

    #[test]
    fn fill_auto_fields_separates_stable_preview_diagnostics_and_runtime_errors() {
        let repo = &sample_shortlist().repos[0];
        let mut entry = default_entry_from_shortlist(repo);
        let parsed = JsonScanEnvelope {
            findings: vec![
                JsonFinding {
                    rule_code: "SEC201".to_owned(),
                },
                JsonFinding {
                    rule_code: "SEC105".to_owned(),
                },
            ],
            diagnostics: vec![JsonDiagnostic {
                normalized_path: "SKILL.md".to_owned(),
                severity: "warn".to_owned(),
                code: Some("parse_recovery".to_owned()),
                message: "frontmatter ignored".to_owned(),
            }],
            runtime_errors: vec![JsonRuntimeError {
                normalized_path: "SKILL.md".to_owned(),
                kind: "parse".to_owned(),
                message: "fatal".to_owned(),
            }],
        };

        fill_auto_fields(
            &mut entry,
            repo,
            vec!["SKILL.md".to_owned()],
            &parsed,
            &current_rule_tiers(),
        )
        .unwrap();

        assert_eq!(entry.stable_findings, 1);
        assert_eq!(entry.preview_findings, 1);
        assert_eq!(entry.stable_rule_codes, vec!["SEC201"]);
        assert_eq!(entry.preview_rule_codes, vec!["SEC105"]);
        assert_eq!(entry.diagnostics.len(), 1);
        assert_eq!(entry.runtime_errors.len(), 1);
    }

    #[test]
    fn template_map_preserves_manual_fields() {
        let repo = &sample_shortlist().repos[0];
        let mut prior = default_entry_from_shortlist(repo);
        prior.repo_verdict = "useful_but_noisy".to_owned();
        prior.preview_signal_notes = "carry".to_owned();
        let ledger = ExternalValidationLedger {
            version: 1,
            wave: 1,
            baseline: None,
            evaluations: vec![prior.clone()],
        };

        let mapped = template_map(&ledger);
        assert_eq!(mapped["owner/repo"].repo_verdict, "useful_but_noisy");
        assert_eq!(mapped["owner/repo"].preview_signal_notes, "carry");
    }

    #[test]
    fn report_renderer_emits_delta_and_phase_targets() {
        let mut baseline_entry = default_entry_from_shortlist(&sample_shortlist().repos[0]);
        baseline_entry.repo = "datadog-labs/cursor-plugin".to_owned();
        baseline_entry.preview_findings = 1;
        baseline_entry.preview_rule_codes = vec!["SEC105".to_owned()];
        let baseline = ExternalValidationLedger {
            version: 1,
            wave: 1,
            baseline: None,
            evaluations: vec![
                baseline_entry,
                EvaluationEntry {
                    repo: "cursor/plugins".to_owned(),
                    runtime_errors: vec![RuntimeErrorRecord {
                        path: "a".to_owned(),
                        kind: "parse".to_owned(),
                        message: "bad".to_owned(),
                    }],
                    ..default_entry_from_shortlist(&sample_shortlist().repos[0])
                },
                EvaluationEntry {
                    repo: "Emmraan/agent-skills".to_owned(),
                    runtime_errors: vec![RuntimeErrorRecord {
                        path: "b".to_owned(),
                        kind: "parse".to_owned(),
                        message: "bad".to_owned(),
                    }],
                    ..default_entry_from_shortlist(&sample_shortlist().repos[0])
                },
            ],
        };
        let current = ExternalValidationLedger {
            version: 1,
            wave: 2,
            baseline: Some("archive/wave1-ledger.toml".to_owned()),
            evaluations: vec![
                EvaluationEntry {
                    repo: "datadog-labs/cursor-plugin".to_owned(),
                    ..default_entry_from_shortlist(&sample_shortlist().repos[0])
                },
                EvaluationEntry {
                    repo: "zebbern/claude-code-guide".to_owned(),
                    preview_findings: 2,
                    preview_rule_codes: vec!["SEC313".to_owned()],
                    ..default_entry_from_shortlist(&sample_shortlist().repos[0])
                },
                EvaluationEntry {
                    repo: "cursor/plugins".to_owned(),
                    diagnostics: vec![DiagnosticRecord {
                        path: "a".to_owned(),
                        severity: "warn".to_owned(),
                        code: Some("parse_recovery".to_owned()),
                        message: "recovered".to_owned(),
                    }],
                    ..default_entry_from_shortlist(&sample_shortlist().repos[0])
                },
                EvaluationEntry {
                    repo: "Emmraan/agent-skills".to_owned(),
                    diagnostics: vec![DiagnosticRecord {
                        path: "b".to_owned(),
                        severity: "warn".to_owned(),
                        code: Some("parse_recovery".to_owned()),
                        message: "recovered".to_owned(),
                    }],
                    ..default_entry_from_shortlist(&sample_shortlist().repos[0])
                },
            ],
        };

        let markdown = render_report_from_ledgers(&baseline, &current);
        assert!(markdown.contains("## Delta From Previous Wave"));
        assert!(markdown.contains("`datadog-labs/cursor-plugin`: `improved`"));
        assert!(markdown.contains("`zebbern/claude-code-guide`: `2` preview finding(s) via `SEC313`"));
        assert!(markdown.contains("`cursor/plugins`: `improved`"));
        assert!(markdown.contains("`Emmraan/agent-skills`: `improved`"));
    }
}
