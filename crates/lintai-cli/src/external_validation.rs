use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use ignore::WalkBuilder;
use lintai_ai_security::{AiSecurityProvider, PolicyMismatchProvider};
use lintai_api::{ArtifactKind, RuleProvider, RuleTier};
use lintai_engine::FileTypeDetector;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::internal_bin::resolve_lintai_driver_path;

const SHORTLIST_PATH: &str = "validation/external-repos/repo-shortlist.toml";
const LEDGER_PATH: &str = "validation/external-repos/ledger.toml";
const ARCHIVED_WAVE1_LEDGER_PATH: &str = "validation/external-repos/archive/wave1-ledger.toml";
const TOOL_JSON_EXTENSION_SHORTLIST_PATH: &str =
    "validation/external-repos-tool-json/repo-shortlist.toml";
const TOOL_JSON_EXTENSION_LEDGER_PATH: &str = "validation/external-repos-tool-json/ledger.toml";
const TOOL_JSON_EXTENSION_ARCHIVED_WAVE3_LEDGER_PATH: &str =
    "validation/external-repos-tool-json/archive/wave3-ledger.toml";
const SERVER_JSON_EXTENSION_SHORTLIST_PATH: &str =
    "validation/external-repos-server-json/repo-shortlist.toml";
const SERVER_JSON_EXTENSION_LEDGER_PATH: &str = "validation/external-repos-server-json/ledger.toml";
const SERVER_JSON_EXTENSION_ARCHIVED_WAVE1_LEDGER_PATH: &str =
    "validation/external-repos-server-json/archive/wave1-ledger.toml";
const GITHUB_ACTIONS_EXTENSION_SHORTLIST_PATH: &str =
    "validation/external-repos-github-actions/repo-shortlist.toml";
const GITHUB_ACTIONS_EXTENSION_LEDGER_PATH: &str =
    "validation/external-repos-github-actions/ledger.toml";
const AI_NATIVE_DISCOVERY_SHORTLIST_PATH: &str =
    "validation/external-repos-ai-native/repo-shortlist.toml";
const AI_NATIVE_DISCOVERY_LEDGER_PATH: &str = "validation/external-repos-ai-native/ledger.toml";
const FIXTURE_PATH_SEGMENTS: &[&str] = &[
    "test", "tests", "testdata", "fixture", "fixtures", "example", "examples", "sample", "samples",
];
const DOCISH_PATH_SEGMENTS: &[&str] = &[
    "doc",
    "docs",
    "schema",
    "schemas",
    "spec",
    "specs",
    "contract",
    "contracts",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ValidationPackage {
    Canonical,
    ToolJsonExtension,
    ServerJsonExtension,
    GithubActionsExtension,
    AiNativeDiscovery,
}

impl ValidationPackage {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "canonical" => Ok(Self::Canonical),
            "tool-json-extension" => Ok(Self::ToolJsonExtension),
            "server-json-extension" => Ok(Self::ServerJsonExtension),
            "github-actions-extension" => Ok(Self::GithubActionsExtension),
            "ai-native-discovery" => Ok(Self::AiNativeDiscovery),
            _ => Err(format!("unknown external validation package `{value}`")),
        }
    }

    fn shortlist_path(self) -> &'static str {
        match self {
            Self::Canonical => SHORTLIST_PATH,
            Self::ToolJsonExtension => TOOL_JSON_EXTENSION_SHORTLIST_PATH,
            Self::ServerJsonExtension => SERVER_JSON_EXTENSION_SHORTLIST_PATH,
            Self::GithubActionsExtension => GITHUB_ACTIONS_EXTENSION_SHORTLIST_PATH,
            Self::AiNativeDiscovery => AI_NATIVE_DISCOVERY_SHORTLIST_PATH,
        }
    }

    fn ledger_path(self) -> &'static str {
        match self {
            Self::Canonical => LEDGER_PATH,
            Self::ToolJsonExtension => TOOL_JSON_EXTENSION_LEDGER_PATH,
            Self::ServerJsonExtension => SERVER_JSON_EXTENSION_LEDGER_PATH,
            Self::GithubActionsExtension => GITHUB_ACTIONS_EXTENSION_LEDGER_PATH,
            Self::AiNativeDiscovery => AI_NATIVE_DISCOVERY_LEDGER_PATH,
        }
    }

    fn baseline_reference(self) -> Option<&'static str> {
        match self {
            Self::Canonical => Some("archive/wave1-ledger.toml"),
            Self::ToolJsonExtension => Some("archive/wave3-ledger.toml"),
            Self::ServerJsonExtension => Some("archive/wave1-ledger.toml"),
            Self::GithubActionsExtension => None,
            Self::AiNativeDiscovery => None,
        }
    }

    fn candidate_ledger_path(self) -> &'static str {
        match self {
            Self::Canonical => "target/external-validation/wave2/candidate-ledger.toml",
            Self::ToolJsonExtension => {
                "target/external-validation/tool-json-extension/candidate-ledger.toml"
            }
            Self::ServerJsonExtension => {
                "target/external-validation/server-json-extension/candidate-ledger.toml"
            }
            Self::GithubActionsExtension => {
                "target/external-validation/github-actions-extension/candidate-ledger.toml"
            }
            Self::AiNativeDiscovery => {
                "target/external-validation/ai-native-discovery/candidate-ledger.toml"
            }
        }
    }

    fn raw_output_root(self) -> &'static str {
        match self {
            Self::Canonical => "target/external-validation/wave2/raw",
            Self::ToolJsonExtension => "target/external-validation/tool-json-extension/raw",
            Self::ServerJsonExtension => "target/external-validation/server-json-extension/raw",
            Self::GithubActionsExtension => {
                "target/external-validation/github-actions-extension/raw"
            }
            Self::AiNativeDiscovery => "target/external-validation/ai-native-discovery/raw",
        }
    }
    fn default_wave(self) -> u32 {
        match self {
            Self::Canonical => 2,
            Self::ToolJsonExtension => 4,
            Self::ServerJsonExtension => 2,
            Self::GithubActionsExtension => 1,
            Self::AiNativeDiscovery => 1,
        }
    }
}

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
    #[serde(default)]
    pub admission_paths: Vec<String>,
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
    pub package: ValidationPackage,
    pub lintai_bin: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub(crate) struct RenderReportOptions {
    pub workspace_root: PathBuf,
    pub package: ValidationPackage,
}

pub(crate) fn run(args: impl Iterator<Item = String>) -> Result<(), String> {
    let raw_args = args.collect::<Vec<_>>();
    let Some(command) = raw_args.first().map(String::as_str) else {
        return Err("expected one of: rerun, render-report".to_owned());
    };
    let package = parse_package_flag(&raw_args[1..])?;
    match command {
        "rerun" => {
            rerun(RerunOptions {
                workspace_root: workspace_root()?,
                package,
                lintai_bin: None,
            })?;
            Ok(())
        }
        "render-report" => {
            let markdown = render_report(RenderReportOptions {
                workspace_root: workspace_root()?,
                package,
            })?;
            print!("{markdown}");
            Ok(())
        }
        _ => Err(format!("unknown external validation command `{command}`")),
    }
}

pub(crate) fn rerun(options: RerunOptions) -> Result<(), String> {
    let package = options.package;
    let shortlist = load_shortlist(&options.workspace_root, package)?;
    let template = load_ledger(&options.workspace_root.join(package.ledger_path()))?;
    let repo_root = options
        .workspace_root
        .join("target/external-validation/repos");
    let raw_root = options.workspace_root.join(package.raw_output_root());
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
        wave: package.default_wave(),
        baseline: package.baseline_reference().map(str::to_owned),
        evaluations: Vec::new(),
    };

    for repo in &shortlist.repos {
        let local_dir = repo_root.join(repo_dir_name(&repo.repo));
        materialize_repo(repo, &local_dir)?;
        verify_repo_admission(package, repo, &local_dir)?;
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

    let candidate_path = options.workspace_root.join(package.candidate_ledger_path());
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
    match options.package {
        ValidationPackage::Canonical => {
            let baseline = load_ledger(&options.workspace_root.join(ARCHIVED_WAVE1_LEDGER_PATH))?;
            let current = load_ledger(&options.workspace_root.join(LEDGER_PATH))?;
            Ok(render_report_from_ledgers(&baseline, &current))
        }
        ValidationPackage::ToolJsonExtension => {
            let shortlist = load_shortlist(&options.workspace_root, options.package)?;
            let baseline = load_ledger(
                &options
                    .workspace_root
                    .join(TOOL_JSON_EXTENSION_ARCHIVED_WAVE3_LEDGER_PATH),
            )?;
            let current = load_ledger(&options.workspace_root.join(options.package.ledger_path()))?;
            Ok(render_tool_json_extension_report(
                &shortlist, &baseline, &current,
            ))
        }
        ValidationPackage::ServerJsonExtension => {
            let shortlist = load_shortlist(&options.workspace_root, options.package)?;
            let baseline = load_ledger(
                &options
                    .workspace_root
                    .join(SERVER_JSON_EXTENSION_ARCHIVED_WAVE1_LEDGER_PATH),
            )?;
            let current = load_ledger(&options.workspace_root.join(options.package.ledger_path()))?;
            Ok(render_server_json_extension_report(
                &shortlist, &baseline, &current,
            ))
        }
        ValidationPackage::GithubActionsExtension => {
            let shortlist = load_shortlist(&options.workspace_root, options.package)?;
            let current = load_ledger(&options.workspace_root.join(options.package.ledger_path()))?;
            Ok(render_github_actions_extension_report(&shortlist, &current))
        }
        ValidationPackage::AiNativeDiscovery => {
            let shortlist = load_shortlist(&options.workspace_root, options.package)?;
            let current = load_ledger(&options.workspace_root.join(options.package.ledger_path()))?;
            Ok(render_ai_native_discovery_report(&shortlist, &current))
        }
    }
}

fn parse_package_flag(args: &[String]) -> Result<ValidationPackage, String> {
    let mut package = ValidationPackage::Canonical;
    for arg in args {
        let Some(value) = arg.strip_prefix("--package=") else {
            return Err(format!(
                "unexpected external validation argument `{arg}`; expected only --package=<name>"
            ));
        };
        package = ValidationPackage::parse(value)?;
    }
    Ok(package)
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
    let expanded_surface_counts = expanded_surface_counts(current);
    let tool_rule_hits = rule_count(current, &["SEC314", "SEC315", "SEC316", "SEC317", "SEC318"]);
    let mcp_rule_hits = rule_count(
        current,
        &[
            "SEC301", "SEC302", "SEC303", "SEC304", "SEC305", "SEC306", "SEC307", "SEC308",
            "SEC309", "SEC310", "SEC329", "SEC330", "SEC331", "SEC337", "SEC338", "SEC339",
        ],
    );
    let env_file_hits = rule_count(current, &["SEC336"]);
    let docker_rule_hits = rule_count(current, &["SEC337", "SEC338", "SEC339"]);

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

    output.push_str("## Hybrid Scope Expansion Results\n\n");
    output.push_str("Current wave inventory for the newly expanded JSON lanes:\n\n");
    output.push_str(&format!(
        "- repos with root `mcp.json`: `{}`\n",
        expanded_surface_counts.top_level_mcp
    ));
    output.push_str(&format!(
        "- repos with `.mcp.json`: `{}`\n",
        expanded_surface_counts.dot_mcp
    ));
    output.push_str(&format!(
        "- repos with `.cursor/mcp.json`: `{}`\n",
        expanded_surface_counts.cursor_mcp
    ));
    output.push_str(&format!(
        "- repos with `.vscode/mcp.json`: `{}`\n",
        expanded_surface_counts.vscode_mcp
    ));
    output.push_str(&format!(
        "- repos with `.roo/mcp.json`: `{}`\n",
        expanded_surface_counts.roo_mcp
    ));
    output.push_str(&format!(
        "- repos with `.kiro/settings/mcp.json`: `{}`\n",
        expanded_surface_counts.kiro_mcp
    ));
    output.push_str(&format!(
        "- repos with `.claude/mcp/*.json`: `{}`\n",
        expanded_surface_counts.claude_mcp
    ));
    output.push_str(&format!(
        "- repos with Docker-based MCP launch configs: `{}`\n",
        expanded_surface_counts.docker_mcp_launch
    ));
    output.push_str(&format!(
        "- MCP findings from expanded client-config coverage (`SEC301`-`SEC331`, `SEC337`-`SEC339`): `{}`\n",
        mcp_rule_hits
    ));
    output.push_str(&format!("- findings from `SEC336`: `{}`\n", env_file_hits));
    output.push_str(&format!(
        "- findings from `SEC337`-`SEC339`: `{}`\n",
        docker_rule_hits
    ));
    output.push_str(&format!(
        "- repos with `tool_descriptor_json`: `{}`\n",
        expanded_surface_counts.tool_descriptor_json
    ));
    output.push_str(&format!(
        "- findings from `SEC314`-`SEC318`: `{}`\n",
        tool_rule_hits
    ));
    output.push_str(&format!(
        "- repos where new MCP client-config variants existed only under fixture-like paths: `{}`\n",
        expanded_surface_counts.fixture_only_client_variants
    ));
    output.push_str(&format!(
        "- repos where Docker-based MCP launch existed only under fixture-like client-config variants: `{}`\n",
        expanded_surface_counts.fixture_only_docker_client_variants
    ));
    if env_file_hits == 0 && mcp_rule_hits == 0 {
        output.push_str(
            "- expanded MCP client-config coverage produced no external MCP hits on the canonical cohort yet\n",
        );
    }
    if docker_rule_hits == 0 {
        output.push_str(
            "- no external hits were produced yet from Docker-based MCP launch hardening on the canonical cohort\n",
        );
    }
    if tool_rule_hits == 0 {
        output.push_str(
            "- no non-fixture external `Stable` hits were produced yet on committed tool-descriptor JSON\n",
        );
    }
    output.push_str(
        "- fixture/testdata/example suppression stayed active for the newly added MCP client-config variants and did not create a fake usefulness signal from fixture-like paths\n\n",
    );

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

fn render_tool_json_extension_report(
    shortlist: &RepoShortlist,
    baseline: &ExternalValidationLedger,
    ledger: &ExternalValidationLedger,
) -> String {
    let baseline_counts = aggregate_counts(baseline);
    let counts = aggregate_counts(ledger);
    let admitted_paths = shortlist
        .repos
        .iter()
        .map(|repo| repo.admission_paths.len())
        .sum::<usize>();
    let admitted_repo_changes = admitted_repo_set_changes(shortlist, baseline);
    let stable_hit_repos = repos_with_rule_hits(
        ledger,
        &["SEC314", "SEC315", "SEC316", "SEC317", "SEC318"],
        true,
    );
    let preview_hit_repos = repos_with_rule_hits(
        ledger,
        &["SEC314", "SEC315", "SEC316", "SEC317", "SEC318"],
        false,
    );
    let runtime_issue_repos = repos_with_runtime_issues(ledger, shortlist);
    let fixture_safe = shortlist.repos.iter().all(|repo| {
        repo.admission_paths
            .iter()
            .all(|path| !is_tool_json_excluded_path(path))
    });
    let scarcity = shortlist.repos.len() < 18;
    let tool_rule_hit_count =
        rule_count(ledger, &["SEC314", "SEC315", "SEC316", "SEC317", "SEC318"]);
    let recommend_promotion = tool_rule_hit_count > 0 && counts.runtime_errors == 0;

    let mut output = String::new();
    output.push_str("# External Validation Tool JSON Extension Report\n\n");
    output.push_str("> Wave 4 extension report for `ToolDescriptorJson` usefulness proof after broader deterministic discovery and the stricter operational-only admission gate.\n");
    output.push_str("> Source of truth lives in [validation/external-repos-tool-json/repo-shortlist.toml](../validation/external-repos-tool-json/repo-shortlist.toml), current results in [validation/external-repos-tool-json/ledger.toml](../validation/external-repos-tool-json/ledger.toml), and archived wave 3 baseline in [validation/external-repos-tool-json/archive/wave3-ledger.toml](../validation/external-repos-tool-json/archive/wave3-ledger.toml).\n\n");

    output.push_str("## Cohort Composition\n\n");
    output.push_str(&format!(
        "The extension cohort contains `{}` public repositories focused on committed non-fixture tool-descriptor JSON.\n\n",
        shortlist.repos.len()
    ));
    let stress = shortlist
        .repos
        .iter()
        .filter(|repo| repo.subtype == "stress")
        .count();
    let control = shortlist
        .repos
        .iter()
        .filter(|repo| repo.subtype == "control")
        .count();
    output.push_str(&format!(
        "- `{}` `tool_json` repos total\n",
        shortlist.repos.len()
    ));
    output.push_str(&format!("- `{}` `stress` repos\n", stress));
    output.push_str(&format!("- `{}` `control` repos\n\n", control));
    if scarcity {
        output.push_str(
        "Broader discovery was attempted, but the target of `18` admitted repos was not reached under the stricter operational-only gate.\n\n",
        );
    }

    output.push_str("## Admission Results\n\n");
    output.push_str(
        "Admitted repos and their semantic-confirmed non-fixture `ToolDescriptorJson` paths:\n\n",
    );
    for repo in &shortlist.repos {
        output.push_str(&format!(
            "- `{}` via {}. {}\n",
            repo.repo,
            format_rule_codes(&repo.admission_paths),
            repo.rationale
        ));
    }
    output.push('\n');

    output.push_str("## Overall Counts\n\n");
    output.push_str(&format!(
        "- `{}` repos evaluated\n",
        ledger.evaluations.len()
    ));
    output.push_str(&format!(
        "- `{}` admitted tool-descriptor paths\n",
        admitted_paths
    ));
    output.push_str(&format!("- `{}` stable findings\n", counts.stable_findings));
    output.push_str(&format!(
        "- `{}` preview findings\n",
        counts.preview_findings
    ));
    output.push_str(&format!(
        "- `{}` runtime parser errors\n",
        counts.runtime_errors
    ));
    output.push_str(&format!("- `{}` diagnostics\n\n", counts.diagnostics));

    output.push_str("## Delta From Previous Wave\n\n");
    output.push_str(&format!(
        "- stable findings: `{}` -> `{}`\n",
        baseline_counts.stable_findings, counts.stable_findings
    ));
    output.push_str(&format!(
        "- preview findings: `{}` -> `{}`\n",
        baseline_counts.preview_findings, counts.preview_findings
    ));
    output.push_str(&format!(
        "- runtime parser errors: `{}` -> `{}`\n",
        baseline_counts.runtime_errors, counts.runtime_errors
    ));
    output.push_str(&format!(
        "- diagnostics: `{}` -> `{}`\n",
        baseline_counts.diagnostics, counts.diagnostics
    ));
    if admitted_repo_changes.is_empty() {
        output.push_str("- admitted repo set changes: none\n\n");
    } else {
        output.push_str("- admitted repo set changes:\n");
        for change in admitted_repo_changes {
            output.push_str(&format!("- {change}\n"));
        }
        output.push('\n');
    }
    if scarcity {
        output.push_str(&format!(
            "- scarcity note: discovery exhausted before reaching the target cohort size of `18`; current admitted count is `{}`\n\n",
            shortlist.repos.len()
        ));
    }

    output.push_str("## Stable Hits\n\n");
    if stable_hit_repos.is_empty() {
        output.push_str(
            "- no non-fixture external `Stable` hits were observed from `SEC314`-`SEC318`\n",
        );
    } else {
        for (repo, count, rule_codes) in &stable_hit_repos {
            output.push_str(&format!(
                "- `{repo}`: `{count}` stable finding(s) via {}\n",
                format_rule_codes(&rule_codes)
            ));
        }
    }
    output.push('\n');

    output.push_str("## Preview Hits\n\n");
    if preview_hit_repos.is_empty() {
        output.push_str("- no preview hits were observed in the extension wave\n\n");
    } else {
        for (repo, count, rule_codes) in preview_hit_repos {
            output.push_str(&format!(
                "- `{repo}`: `{count}` preview finding(s) via {}\n",
                format_rule_codes(&rule_codes)
            ));
        }
        output.push('\n');
    }

    output.push_str("## Runtime / Diagnostic Notes\n\n");
    output.push_str(
        "- label legend: `admission-path issue` means the problem occurred on an admitted `ToolDescriptorJson` path; `non-admission-path issue` means the problem occurred on sibling material outside the admitted path set\n\n",
    );
    if runtime_issue_repos.is_empty() {
        output.push_str(
            "- no runtime parser errors or diagnostics were emitted in this extension wave\n\n",
        );
    } else {
        for (repo, runtime_count, diagnostic_count, labels) in runtime_issue_repos {
            output.push_str(&format!(
                "- `{repo}`: `{}` runtime parser errors, `{}` diagnostics ({})\n",
                runtime_count,
                diagnostic_count,
                labels.join(", ")
            ));
        }
        output.push('\n');
    }

    output.push_str("## Fixture Suppression Check\n\n");
    if fixture_safe {
        output.push_str("- all admitted repos passed the non-fixture path gate\n");
        output.push_str("- no admitted repo would have been excluded for `tests/fixtures/testdata/examples/samples`\n");
        output.push_str("- no admitted repo used tokenized path segments reserved for `docs/schema/spec/contracts`-only material\n");
        output.push_str("- no fake `Stable` usefulness signal was introduced from fixture or documentation-only paths\n\n");
    } else {
        output.push_str("- one or more admitted repos violated the fixture suppression boundary and this wave is invalid\n\n");
    }

    output.push_str("## Recommended Next Step\n\n");
    if recommend_promotion {
        output.push_str("Extension evidence is strong enough to consider promoting some of these repos into the main canonical cohort later.\n");
    } else {
        output.push_str("Extension evidence is not strong enough yet to justify promoting repos into the main canonical cohort; continue broader discovery or add more structural rules.\n");
    }

    output
}

fn render_server_json_extension_report(
    shortlist: &RepoShortlist,
    baseline: &ExternalValidationLedger,
    ledger: &ExternalValidationLedger,
) -> String {
    let baseline_counts = aggregate_counts(baseline);
    let counts = aggregate_counts(ledger);
    let stable_hit_repos = repos_with_rule_hits(
        ledger,
        &["SEC319", "SEC320", "SEC321", "SEC322", "SEC323"],
        true,
    );
    let preview_hit_repos = repos_with_rule_hits(
        ledger,
        &["SEC319", "SEC320", "SEC321", "SEC322", "SEC323"],
        false,
    );
    let runtime_issue_repos = repos_with_runtime_issues(ledger, shortlist);
    let admitted_repo_changes = admitted_repo_set_changes(shortlist, baseline);
    let remote_enabled = shortlist
        .repos
        .iter()
        .filter(|repo| repo.subtype == "stress")
        .count();
    let controls = shortlist.repos.len().saturating_sub(remote_enabled);
    let scarcity = shortlist.repos.len() < 18;

    let mut output = String::new();
    output.push_str("# External Validation Server JSON Report\n\n");
    output.push_str("> Wave 2 extension report for semantically confirmed MCP Registry `server.json` surfaces.\n");
    output.push_str("> Source of truth lives in [validation/external-repos-server-json/repo-shortlist.toml](../validation/external-repos-server-json/repo-shortlist.toml), current results in [validation/external-repos-server-json/ledger.toml](../validation/external-repos-server-json/ledger.toml), and archived wave 1 baseline in [validation/external-repos-server-json/archive/wave1-ledger.toml](../validation/external-repos-server-json/archive/wave1-ledger.toml).\n\n");

    output.push_str("## Cohort Composition\n\n");
    output.push_str(&format!(
        "- `{}` repos evaluated\n- `{}` remote-enabled repos\n- `{}` control repos\n\n",
        shortlist.repos.len(),
        remote_enabled,
        controls
    ));
    if scarcity {
        output.push_str(&format!(
            "Discovery exhausted before reaching the target cohort size of `18`; current admitted count is `{}`.\n\n",
            shortlist.repos.len()
        ));
    }

    output.push_str("## Admission Results\n\n");
    for repo in &shortlist.repos {
        output.push_str(&format!(
            "- `{}` via {}. {}\n",
            repo.repo,
            format_rule_codes(&repo.admission_paths),
            repo.rationale
        ));
    }
    output.push('\n');

    output.push_str("## Overall Counts\n\n");
    output.push_str(&format!(
        "- `{}` stable findings\n- `{}` preview findings\n- `{}` runtime parser errors\n- `{}` diagnostics\n\n",
        counts.stable_findings,
        counts.preview_findings,
        counts.runtime_errors,
        counts.diagnostics
    ));

    output.push_str("## Delta From Previous Wave\n\n");
    output.push_str(&format!(
        "- stable findings: `{}` -> `{}`\n",
        baseline_counts.stable_findings, counts.stable_findings
    ));
    output.push_str(&format!(
        "- preview findings: `{}` -> `{}`\n",
        baseline_counts.preview_findings, counts.preview_findings
    ));
    output.push_str(&format!(
        "- runtime parser errors: `{}` -> `{}`\n",
        baseline_counts.runtime_errors, counts.runtime_errors
    ));
    output.push_str(&format!(
        "- diagnostics: `{}` -> `{}`\n",
        baseline_counts.diagnostics, counts.diagnostics
    ));
    if admitted_repo_changes.is_empty() {
        output.push_str("- admitted repo set changes: none\n\n");
    } else {
        output.push_str("- admitted repo set changes:\n");
        for change in admitted_repo_changes {
            output.push_str(&format!("- {change}\n"));
        }
        output.push('\n');
    }
    if scarcity {
        output.push_str(&format!(
            "- scarcity note: discovery exhausted before reaching the target cohort size of `18`; current admitted count is `{}`\n\n",
            shortlist.repos.len()
        ));
    }

    output.push_str("## Stable Hits\n\n");
    if stable_hit_repos.is_empty() {
        output.push_str("- no external `Stable` hits were observed from `SEC319`-`SEC323`\n\n");
    } else {
        for (repo, count, rule_codes) in &stable_hit_repos {
            output.push_str(&format!(
                "- `{repo}`: `{count}` stable finding(s) via {}\n",
                format_rule_codes(rule_codes)
            ));
        }
        output.push('\n');
    }

    output.push_str("## Preview Hits\n\n");
    if preview_hit_repos.is_empty() {
        output.push_str("- no preview hits were observed in the server-json extension wave\n\n");
    } else {
        for (repo, count, rule_codes) in preview_hit_repos {
            output.push_str(&format!(
                "- `{repo}`: `{count}` preview finding(s) via {}\n",
                format_rule_codes(&rule_codes)
            ));
        }
        output.push('\n');
    }

    output.push_str("## Runtime / Diagnostic Notes\n\n");
    if runtime_issue_repos.is_empty() {
        output.push_str(
            "- no runtime parser errors or diagnostics were emitted in this extension wave\n\n",
        );
    } else {
        for (repo, runtime_count, diagnostic_count, labels) in runtime_issue_repos {
            output.push_str(&format!(
                "- `{repo}`: `{}` runtime parser errors, `{}` diagnostics ({})\n",
                runtime_count,
                diagnostic_count,
                labels.join(", ")
            ));
        }
        output.push('\n');
    }

    output.push_str("## Recommended Next Step\n\n");
    if stable_hit_repos.is_empty() {
        output.push_str("Keep the `server.json` surface and continue discovery; do not weaken `SEC319`-`SEC323` if this wave stays clean but sparse.\n");
    } else {
        output.push_str("Promote the highest-signal server-json repos into future canonical evidence sets and expand the server-json rule batch conservatively.\n");
    }

    output
}

fn render_github_actions_extension_report(
    shortlist: &RepoShortlist,
    ledger: &ExternalValidationLedger,
) -> String {
    let counts = aggregate_counts(ledger);
    let stable_hit_repos = repos_with_rule_hits(ledger, &["SEC324", "SEC326", "SEC327"], true);
    let preview_hit_repos = repos_with_rule_hits(ledger, &["SEC325", "SEC328"], false);
    let runtime_issue_repos = repos_with_runtime_issues(ledger, shortlist);
    let stress = shortlist
        .repos
        .iter()
        .filter(|repo| repo.subtype == "stress")
        .count();
    let control = shortlist.repos.len().saturating_sub(stress);

    let mut output = String::new();
    output.push_str("# External Validation GitHub Actions Report\n\n");
    output.push_str(
        "> Wave 1 extension report for semantically confirmed GitHub Actions workflow surfaces.\n",
    );
    output.push_str("> Source of truth lives in [validation/external-repos-github-actions/repo-shortlist.toml](../validation/external-repos-github-actions/repo-shortlist.toml) and [validation/external-repos-github-actions/ledger.toml](../validation/external-repos-github-actions/ledger.toml).\n\n");

    output.push_str("## Cohort Composition\n\n");
    output.push_str(&format!(
        "- `{}` repos evaluated\n- `{}` stress repos\n- `{}` control repos\n\n",
        shortlist.repos.len(),
        stress,
        control
    ));
    if shortlist.repos.len() < 18 {
        output.push_str(&format!(
            "Discovery exhausted before reaching the target cohort size of `18`; current admitted count is `{}`.\n\n",
            shortlist.repos.len()
        ));
    }

    output.push_str("## Admission Results\n\n");
    for repo in &shortlist.repos {
        output.push_str(&format!(
            "- `{}` via {}. {}\n",
            repo.repo,
            format_rule_codes(&repo.admission_paths),
            repo.rationale
        ));
    }
    output.push('\n');

    output.push_str("## Overall Counts\n\n");
    output.push_str(&format!(
        "- `{}` stable findings\n- `{}` preview findings\n- `{}` runtime parser errors\n- `{}` diagnostics\n\n",
        counts.stable_findings,
        counts.preview_findings,
        counts.runtime_errors,
        counts.diagnostics
    ));

    output.push_str("## Stable Hits\n\n");
    if stable_hit_repos.is_empty() {
        output.push_str("- no external `Stable` hits were observed from `SEC324`-`SEC327`\n\n");
    } else {
        for (repo, count, rule_codes) in &stable_hit_repos {
            output.push_str(&format!(
                "- `{repo}`: `{count}` stable finding(s) via {}\n",
                format_rule_codes(&rule_codes)
            ));
        }
        let observed_stable_rules = unique_rule_codes_from_hits(&stable_hit_repos);
        let missing_stable_rules =
            missing_rule_codes(&["SEC324", "SEC326", "SEC327"], &observed_stable_rules);
        if !missing_stable_rules.is_empty() {
            output.push_str(&format!(
                "\nWithin this batch, no external stable hits were observed from {}.\n",
                format_rule_codes(&missing_stable_rules)
            ));
        }
        output.push('\n');
    }

    output.push_str("## Preview Hits\n\n");
    if preview_hit_repos.is_empty() {
        output.push_str("- no preview hits were observed from `SEC325` or `SEC328`\n\n");
    } else {
        for (repo, count, rule_codes) in preview_hit_repos {
            output.push_str(&format!(
                "- `{repo}`: `{count}` preview finding(s) via {}\n",
                format_rule_codes(&rule_codes)
            ));
        }
        output.push('\n');
    }

    output.push_str("## Runtime / Diagnostic Notes\n\n");
    if runtime_issue_repos.is_empty() {
        output.push_str(
            "- no runtime parser errors or diagnostics were emitted in this extension wave\n\n",
        );
    } else {
        for (repo, runtime_count, diagnostic_count, labels) in runtime_issue_repos {
            output.push_str(&format!(
                "- `{repo}`: `{}` runtime parser errors, `{}` diagnostics ({})\n",
                runtime_count,
                diagnostic_count,
                labels.join(", ")
            ));
        }
        output.push('\n');
    }

    output.push_str("## Recommended Next Step\n\n");
    if stable_hit_repos.is_empty() {
        output.push_str("Keep the GitHub Actions surface and expand the workflow rule batch conservatively if this first wave stays clean but sparse.\n");
    } else {
        output.push_str("Promote the highest-signal GitHub Actions repos into future usefulness evidence sets and expand workflow checks conservatively.\n");
    }

    output
}

fn render_ai_native_discovery_report(
    shortlist: &RepoShortlist,
    ledger: &ExternalValidationLedger,
) -> String {
    const AI_NATIVE_RULE_CODES: &[&str] = &[
        "SEC301", "SEC302", "SEC303", "SEC304", "SEC305", "SEC309", "SEC310", "SEC329", "SEC330",
        "SEC331", "SEC336", "SEC337", "SEC338", "SEC339", "SEC340", "SEC341", "SEC342",
    ];
    let counts = aggregate_counts(ledger);
    let subtype_counts = shortlist
        .repos
        .iter()
        .fold(BTreeMap::new(), |mut counts, repo| {
            *counts.entry(repo.subtype.as_str()).or_insert(0usize) += 1;
            counts
        });
    let coverage = ai_native_coverage_summary(shortlist);
    let runtime_issue_repos = repos_with_runtime_issues(ledger, shortlist);
    let ai_native_rule_hits = rule_count(ledger, AI_NATIVE_RULE_CODES);

    let mut output = String::new();
    output.push_str("# External Validation AI-Native Discovery Report\n\n");
    output.push_str("> Wave 1 discovery report for real AI-native execution surfaces that are only partially covered by the current shipped detector.\n");
    output.push_str("> Source of truth lives in [validation/external-repos-ai-native/repo-shortlist.toml](../validation/external-repos-ai-native/repo-shortlist.toml) and [validation/external-repos-ai-native/ledger.toml](../validation/external-repos-ai-native/ledger.toml).\n\n");

    output.push_str("## Cohort Composition\n\n");
    output.push_str(&format!("- `{}` repos evaluated\n", shortlist.repos.len()));
    output.push_str(&format!(
        "- `{}` `mcp_docker` repos\n",
        subtype_counts.get("mcp_docker").copied().unwrap_or(0)
    ));
    output.push_str(&format!(
        "- `{}` `claude_settings_command` repos\n",
        subtype_counts
            .get("claude_settings_command")
            .copied()
            .unwrap_or(0)
    ));
    output.push_str(&format!(
        "- `{}` `plugin_execution_reference` repos\n\n",
        subtype_counts
            .get("plugin_execution_reference")
            .copied()
            .unwrap_or(0)
    ));

    output.push_str("## Admission Results\n\n");
    for repo in &shortlist.repos {
        output.push_str(&format!(
            "- `{}` via {}. {}\n",
            repo.repo,
            format_rule_codes(&repo.admission_paths),
            repo.rationale
        ));
    }
    output.push('\n');

    output.push_str("## Coverage Status\n\n");
    output.push_str(&format!(
        "- `{}` total admitted paths\n",
        coverage.total_admission_paths
    ));
    output.push_str(&format!(
        "- `{}` admitted paths are currently covered by shipped detector kinds\n",
        coverage.covered_admission_paths
    ));
    output.push_str(&format!(
        "- `{}` admitted paths are discovery-only and not directly scanned by current detector kinds\n",
        coverage.discovery_only_admission_paths
    ));
    output.push_str(&format!(
        "- `{}` repos have at least one currently covered admission path\n",
        coverage.covered_repos.len()
    ));
    output.push_str(&format!(
        "- `{}` repos are discovery-only under current detector coverage\n\n",
        coverage.discovery_only_repos.len()
    ));
    if !coverage.covered_repos.is_empty() {
        output.push_str("Currently covered admission paths:\n\n");
        for (repo, paths) in &coverage.covered_repos {
            output.push_str(&format!("- `{repo}`: {}\n", format_rule_codes(paths)));
        }
        output.push('\n');
    }
    if !coverage.discovery_only_repos.is_empty() {
        output.push_str("Discovery-only admission paths:\n\n");
        for (repo, paths) in &coverage.discovery_only_repos {
            output.push_str(&format!("- `{repo}`: {}\n", format_rule_codes(paths)));
        }
        output.push('\n');
    }

    output.push_str("## Overall Counts\n\n");
    output.push_str(&format!(
        "- `{}` stable findings across whole-repo scans\n",
        counts.stable_findings
    ));
    output.push_str(&format!(
        "- `{}` preview findings across whole-repo scans\n",
        counts.preview_findings
    ));
    output.push_str(&format!(
        "- `{}` runtime parser errors\n",
        counts.runtime_errors
    ));
    output.push_str(&format!("- `{}` diagnostics\n\n", counts.diagnostics));

    output.push_str("## Stable Hits\n\n");
    output.push_str(&format!(
        "- current AI-native MCP rule families produced `{}` repo-level rule-code hits in this discovery wave\n",
        ai_native_rule_hits
    ));
    if ai_native_rule_hits == 0 {
        output.push_str(
            "- no new current-rule hits were observed on the admitted AI-native execution paths in this wave\n\n",
        );
    } else {
        output.push_str(
            "- some repo-level hits were observed, but current scan output still needs path-attribution work before claiming they came from discovery-only admission paths rather than sibling scanned surfaces\n\n",
        );
    }

    output.push_str("## Preview Hits\n\n");
    if counts.preview_findings == 0 {
        output.push_str("- no preview hits were observed in this discovery wave\n\n");
    } else {
        output.push_str(&format!(
            "- `{}` preview hit(s) were observed at repo scope; these should not yet be interpreted as proof on discovery-only admission paths\n\n",
            counts.preview_findings
        ));
    }

    output.push_str("## Runtime / Diagnostic Notes\n\n");
    if runtime_issue_repos.is_empty() {
        output.push_str(
            "- no runtime parser errors or diagnostics were emitted in this discovery wave\n\n",
        );
    } else {
        for (repo, runtime_count, diagnostic_count, labels) in runtime_issue_repos {
            output.push_str(&format!(
                "- `{repo}`: `{}` runtime parser errors, `{}` diagnostics ({})\n",
                runtime_count,
                diagnostic_count,
                labels.join(", ")
            ));
        }
        output.push('\n');
    }

    output.push_str("## Recommended Next Step\n\n");
    output.push_str("Use this package as discovery evidence for the next detector expansion. The immediate product work should target currently uncovered `.claude/settings.json`, plugin-root `hooks.json` / `agents/*.md`, and committed Docker-oriented client config files before widening non-AI-native surfaces.\n");

    output
}

#[derive(Clone, Debug, Default)]
struct AiNativeCoverageSummary {
    total_admission_paths: usize,
    covered_admission_paths: usize,
    discovery_only_admission_paths: usize,
    covered_repos: Vec<(String, Vec<String>)>,
    discovery_only_repos: Vec<(String, Vec<String>)>,
}

fn ai_native_coverage_summary(shortlist: &RepoShortlist) -> AiNativeCoverageSummary {
    let detector = FileTypeDetector::default();
    let mut summary = AiNativeCoverageSummary::default();
    for repo in &shortlist.repos {
        let mut covered = Vec::new();
        let mut discovery_only = Vec::new();
        for path in &repo.admission_paths {
            summary.total_admission_paths += 1;
            if detector.detect(Path::new(path), path).is_some() {
                summary.covered_admission_paths += 1;
                covered.push(path.clone());
            } else {
                summary.discovery_only_admission_paths += 1;
                discovery_only.push(path.clone());
            }
        }
        if !covered.is_empty() {
            summary.covered_repos.push((repo.repo.clone(), covered));
        }
        if !discovery_only.is_empty() {
            summary
                .discovery_only_repos
                .push((repo.repo.clone(), discovery_only));
        }
    }
    summary
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

fn unique_rule_codes_from_hits(hits: &[(String, usize, Vec<String>)]) -> Vec<String> {
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

fn missing_rule_codes(expected: &[&str], observed: &[String]) -> Vec<String> {
    expected
        .iter()
        .filter(|code| !observed.iter().any(|observed| observed == **code))
        .map(|code| (*code).to_owned())
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

struct ExpandedSurfaceCounts {
    top_level_mcp: usize,
    dot_mcp: usize,
    cursor_mcp: usize,
    vscode_mcp: usize,
    roo_mcp: usize,
    kiro_mcp: usize,
    claude_mcp: usize,
    fixture_only_client_variants: usize,
    docker_mcp_launch: usize,
    fixture_only_docker_client_variants: usize,
    tool_descriptor_json: usize,
}

fn expanded_surface_counts(ledger: &ExternalValidationLedger) -> ExpandedSurfaceCounts {
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

fn count_surface_presence(ledger: &ExternalValidationLedger, surface: &str) -> usize {
    count_any_surface_presence(ledger, &[surface])
}

fn count_any_surface_presence(ledger: &ExternalValidationLedger, surfaces: &[&str]) -> usize {
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

fn rule_count(ledger: &ExternalValidationLedger, rules: &[&str]) -> usize {
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

fn repos_with_rule_hits(
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

fn repos_with_runtime_issues(
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

fn issue_scope_label(path: &str, admission_paths: &[String]) -> String {
    if admission_paths.iter().any(|candidate| candidate == path) {
        "admission-path issue".to_owned()
    } else {
        "non-admission-path issue".to_owned()
    }
}

fn admitted_repo_set_changes(
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
        if normalized == "mcp.json" {
            surfaces.insert("mcp.json".to_owned());
        }
        if normalized.ends_with(".mcp.json") {
            surfaces.insert(".mcp.json".to_owned());
        }
        if normalized.ends_with(".cursor/mcp.json") {
            insert_expanded_mcp_variant_surface(&mut surfaces, &normalized, ".cursor/mcp.json");
        }
        if normalized.ends_with(".vscode/mcp.json") {
            insert_expanded_mcp_variant_surface(&mut surfaces, &normalized, ".vscode/mcp.json");
        }
        if normalized.ends_with(".roo/mcp.json") {
            insert_expanded_mcp_variant_surface(&mut surfaces, &normalized, ".roo/mcp.json");
        }
        if normalized.ends_with(".kiro/settings/mcp.json") {
            insert_expanded_mcp_variant_surface(
                &mut surfaces,
                &normalized,
                ".kiro/settings/mcp.json",
            );
        }
        if normalized.contains(".claude/mcp/") && normalized.ends_with(".json") {
            surfaces.insert(".claude/mcp/*.json".to_owned());
        }
        if normalized == ".claude/settings.json" {
            surfaces.insert(".claude/settings.json".to_owned());
        }
        if normalized == "claude/settings.json" {
            surfaces.insert("claude/settings.json".to_owned());
        }
        if is_mcp_config_path(&normalized)
            && let Ok(text) = std::fs::read_to_string(entry.path())
            && contains_semantic_docker_mcp_launch(&text)
        {
            insert_docker_mcp_launch_surface(&mut surfaces, &normalized);
        }
        if normalized.ends_with("server.json") {
            surfaces.insert("server.json".to_owned());
        }
        if normalized.contains(".github/workflows/")
            && (normalized.ends_with(".yml") || normalized.ends_with(".yaml"))
        {
            surfaces.insert(".github/workflows/*.yml".to_owned());
        }
        if normalized.ends_with("tools.json")
            || normalized.ends_with(".tool.json")
            || normalized.ends_with(".tools.json")
            || normalized.rsplit('/').next().is_some_and(|file_name| {
                file_name.ends_with(".json") && file_name.contains("tools")
            })
        {
            surfaces.insert("tool_descriptor_json".to_owned());
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

fn insert_expanded_mcp_variant_surface(
    surfaces: &mut BTreeSet<String>,
    normalized_path: &str,
    label: &str,
) {
    if normalized_path
        .split('/')
        .any(|segment| FIXTURE_PATH_SEGMENTS.contains(&segment.to_ascii_lowercase().as_str()))
    {
        surfaces.insert(format!("{label} (fixture-like)"));
        surfaces.insert("expanded_mcp_client_variant_fixture_only".to_owned());
    } else {
        surfaces.insert(label.to_owned());
    }
}

fn insert_docker_mcp_launch_surface(surfaces: &mut BTreeSet<String>, normalized_path: &str) {
    if is_expanded_mcp_client_variant_path(normalized_path)
        && normalized_path
            .split('/')
            .any(|segment| FIXTURE_PATH_SEGMENTS.contains(&segment.to_ascii_lowercase().as_str()))
    {
        surfaces.insert("docker_mcp_launch (fixture-like)".to_owned());
        surfaces.insert("docker_mcp_launch_fixture_only".to_owned());
    } else {
        surfaces.insert("docker_mcp_launch".to_owned());
    }
}

fn is_mcp_config_path(normalized_path: &str) -> bool {
    normalized_path == "mcp.json"
        || normalized_path.ends_with(".mcp.json")
        || normalized_path.ends_with(".cursor/mcp.json")
        || normalized_path.ends_with(".vscode/mcp.json")
        || normalized_path.ends_with(".roo/mcp.json")
        || normalized_path.ends_with(".kiro/settings/mcp.json")
        || (normalized_path.contains(".claude/mcp/") && normalized_path.ends_with(".json"))
}

fn is_expanded_mcp_client_variant_path(normalized_path: &str) -> bool {
    normalized_path.ends_with(".cursor/mcp.json")
        || normalized_path.ends_with(".vscode/mcp.json")
        || normalized_path.ends_with(".roo/mcp.json")
        || normalized_path.ends_with(".kiro/settings/mcp.json")
}

fn verify_repo_admission(
    package: ValidationPackage,
    repo: &ShortlistRepo,
    repo_root: &Path,
) -> Result<(), String> {
    let detected = match package {
        ValidationPackage::Canonical => return Ok(()),
        ValidationPackage::ToolJsonExtension => admitted_tool_descriptor_paths(repo_root)?,
        ValidationPackage::ServerJsonExtension => admitted_server_json_paths(repo_root)?,
        ValidationPackage::GithubActionsExtension => admitted_github_workflow_paths(repo_root)?,
        ValidationPackage::AiNativeDiscovery => admitted_ai_native_paths(repo_root)?,
    };

    if repo.admission_paths.is_empty() {
        return Err(format!(
            "{} repo `{}` must declare at least one admission path",
            package_label(package),
            repo.repo
        ));
    }

    let expected = repo
        .admission_paths
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let actual = detected.iter().cloned().collect::<BTreeSet<_>>();

    if expected != actual {
        return Err(format!(
            "{} admission mismatch for `{}`: expected {:?}, got {:?}",
            package_label(package),
            repo.repo,
            expected,
            actual
        ));
    }

    Ok(())
}

fn admitted_tool_descriptor_paths(repo_root: &Path) -> Result<Vec<String>, String> {
    let detector = FileTypeDetector::default();
    let mut admitted = Vec::new();
    let mut builder = WalkBuilder::new(repo_root);
    builder
        .hidden(false)
        .git_ignore(false)
        .git_exclude(false)
        .parents(false);
    for result in builder.build() {
        let entry = result.map_err(|error| format!("tool-json admission walk failed: {error}"))?;
        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(repo_root)
            .map_err(|error| format!("failed to relativize tool-json path: {error}"))?;
        let normalized = normalize_rel_path(relative);
        if is_tool_json_excluded_path(&normalized) {
            continue;
        }
        let Some(detected) = detector.detect(relative, &normalized) else {
            continue;
        };
        if detected.kind != ArtifactKind::ToolDescriptorJson {
            continue;
        }
        let text = fs::read_to_string(entry.path()).map_err(|error| {
            format!(
                "failed to read candidate tool descriptor JSON {}: {error}",
                entry.path().display()
            )
        })?;
        if contains_semantic_tool_descriptor_json(&text) {
            admitted.push(normalized);
        }
    }
    admitted.sort();
    admitted.dedup();
    if admitted.is_empty() {
        return Err(
            "no committed non-fixture ToolDescriptorJson paths passed semantic confirmation"
                .to_owned(),
        );
    }
    Ok(admitted)
}

fn admitted_server_json_paths(repo_root: &Path) -> Result<Vec<String>, String> {
    let detector = FileTypeDetector::default();
    let mut admitted = Vec::new();
    let mut builder = WalkBuilder::new(repo_root);
    builder
        .hidden(false)
        .git_ignore(false)
        .git_exclude(false)
        .parents(false);
    for result in builder.build() {
        let entry =
            result.map_err(|error| format!("server-json admission walk failed: {error}"))?;
        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(repo_root)
            .map_err(|error| format!("failed to relativize server-json path: {error}"))?;
        let normalized = normalize_rel_path(relative);
        if is_generic_validation_excluded_path(&normalized) {
            continue;
        }
        let Some(detected) = detector.detect(relative, &normalized) else {
            continue;
        };
        if detected.kind != ArtifactKind::ServerRegistryConfig {
            continue;
        }
        let text = fs::read_to_string(entry.path()).map_err(|error| {
            format!(
                "failed to read candidate server.json {}: {error}",
                entry.path().display()
            )
        })?;
        if contains_semantic_server_json(&text) {
            admitted.push(normalized);
        }
    }
    admitted.sort();
    admitted.dedup();
    if admitted.is_empty() {
        return Err(
            "no committed non-fixture server.json paths passed semantic confirmation".to_owned(),
        );
    }
    Ok(admitted)
}

fn admitted_github_workflow_paths(repo_root: &Path) -> Result<Vec<String>, String> {
    let detector = FileTypeDetector::default();
    let mut admitted = Vec::new();
    let mut builder = WalkBuilder::new(repo_root);
    builder
        .hidden(false)
        .git_ignore(false)
        .git_exclude(false)
        .parents(false);
    for result in builder.build() {
        let entry =
            result.map_err(|error| format!("github-workflow admission walk failed: {error}"))?;
        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(repo_root)
            .map_err(|error| format!("failed to relativize github-workflow path: {error}"))?;
        let normalized = normalize_rel_path(relative);
        let Some(detected) = detector.detect(relative, &normalized) else {
            continue;
        };
        if detected.kind != ArtifactKind::GitHubWorkflow {
            continue;
        }
        let text = fs::read_to_string(entry.path()).map_err(|error| {
            format!(
                "failed to read candidate github workflow {}: {error}",
                entry.path().display()
            )
        })?;
        if contains_semantic_github_workflow_yaml(&text) {
            admitted.push(normalized);
        }
    }
    admitted.sort();
    admitted.dedup();
    if admitted.is_empty() {
        return Err("no semantically confirmed GitHub workflow paths passed admission".to_owned());
    }
    Ok(admitted)
}

fn admitted_ai_native_paths(repo_root: &Path) -> Result<Vec<String>, String> {
    let mut admitted = Vec::new();
    let mut builder = WalkBuilder::new(repo_root);
    builder
        .hidden(false)
        .git_ignore(false)
        .git_exclude(false)
        .parents(false);
    for result in builder.build() {
        let entry = result.map_err(|error| format!("ai-native admission walk failed: {error}"))?;
        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(repo_root)
            .map_err(|error| format!("failed to relativize ai-native path: {error}"))?;
        let normalized = normalize_rel_path(relative);
        if is_generic_validation_excluded_path(&normalized) {
            continue;
        }
        if is_ai_native_docker_config_path(&normalized) {
            let text = fs::read_to_string(entry.path()).map_err(|error| {
                format!(
                    "failed to read candidate AI-native docker config {}: {error}",
                    entry.path().display()
                )
            })?;
            if contains_semantic_docker_mcp_launch(&text) {
                admitted.push(normalized);
            }
            continue;
        }
        if is_ai_native_claude_settings_path(&normalized) {
            let text = fs::read_to_string(entry.path()).map_err(|error| {
                format!(
                    "failed to read candidate Claude settings {}: {error}",
                    entry.path().display()
                )
            })?;
            if contains_semantic_claude_command_settings(&text) {
                admitted.push(normalized);
            }
            continue;
        }
        if normalized.ends_with(".cursor-plugin/plugin.json") {
            let text = fs::read_to_string(entry.path()).map_err(|error| {
                format!(
                    "failed to read candidate plugin manifest {}: {error}",
                    entry.path().display()
                )
            })?;
            admitted.extend(admitted_plugin_execution_targets(
                repo_root, relative, &text,
            )?);
        }
    }
    admitted.sort();
    admitted.dedup();
    if admitted.is_empty() {
        return Err(
            "no AI-native docker or plugin execution paths passed discovery admission".to_owned(),
        );
    }
    Ok(admitted)
}

fn package_label(package: ValidationPackage) -> &'static str {
    match package {
        ValidationPackage::Canonical => "canonical",
        ValidationPackage::ToolJsonExtension => "tool-json extension",
        ValidationPackage::ServerJsonExtension => "server-json extension",
        ValidationPackage::GithubActionsExtension => "github-actions extension",
        ValidationPackage::AiNativeDiscovery => "ai-native discovery",
    }
}

fn is_generic_validation_excluded_path(normalized_path: &str) -> bool {
    normalized_path
        .split('/')
        .flat_map(segment_tokens)
        .any(|token| {
            FIXTURE_PATH_SEGMENTS
                .iter()
                .any(|reserved| token.eq_ignore_ascii_case(reserved))
                || DOCISH_PATH_SEGMENTS
                    .iter()
                    .any(|reserved| token.eq_ignore_ascii_case(reserved))
        })
}

fn is_tool_json_excluded_path(normalized_path: &str) -> bool {
    is_generic_validation_excluded_path(normalized_path)
}

fn is_ai_native_docker_config_path(normalized_path: &str) -> bool {
    normalized_path.ends_with("gemini-extension.json")
        || normalized_path.ends_with("gemini.settings.json")
        || normalized_path.ends_with("vscode.settings.json")
}

fn is_ai_native_claude_settings_path(normalized_path: &str) -> bool {
    normalized_path == ".claude/settings.json" || normalized_path == "claude/settings.json"
}

fn contains_semantic_tool_descriptor_json(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    json_descendants(&value).any(is_tool_descriptor_shape)
}

fn contains_semantic_docker_mcp_launch(text: &str) -> bool {
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

fn contains_semantic_mcp_command_config(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    json_descendants(&value).any(|candidate| {
        let Some(object) = candidate.as_object() else {
            return false;
        };
        object.get("command").and_then(Value::as_str).is_some()
    })
}

fn contains_semantic_server_json(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    object.get("name").and_then(Value::as_str).is_some()
        && object.get("version").and_then(Value::as_str).is_some()
        && (object.get("remotes").and_then(Value::as_array).is_some()
            || object.get("packages").and_then(Value::as_array).is_some())
}

fn contains_semantic_claude_command_settings(text: &str) -> bool {
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

fn contains_semantic_plugin_hook_commands(text: &str) -> bool {
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

fn admitted_plugin_execution_targets(
    repo_root: &Path,
    manifest_relative: &Path,
    text: &str,
) -> Result<Vec<String>, String> {
    let mut admitted = Vec::new();
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return Ok(admitted);
    };
    let Some(object) = value.as_object() else {
        return Ok(admitted);
    };
    let Some(dot_cursor_plugin_dir) = manifest_relative.parent() else {
        return Ok(admitted);
    };
    let Some(plugin_root_relative) = dot_cursor_plugin_dir.parent() else {
        return Ok(admitted);
    };
    let plugin_root_fs = repo_root.join(plugin_root_relative);

    for key in ["hooks", "agents", "commands", "mcpServers"] {
        let Some(target) = object.get(key).and_then(Value::as_str) else {
            continue;
        };
        let resolved = plugin_root_fs.join(target);
        if !resolved.exists() {
            continue;
        }
        if resolved.is_file() {
            let normalized = normalize_rel_path(
                resolved
                    .strip_prefix(repo_root)
                    .map_err(|error| format!("failed to relativize plugin target: {error}"))?,
            );
            if is_generic_validation_excluded_path(&normalized) {
                continue;
            }
            let file_text = fs::read_to_string(&resolved).map_err(|error| {
                format!(
                    "failed to read plugin execution target {}: {error}",
                    resolved.display()
                )
            })?;
            let semantic = match key {
                "hooks" => contains_semantic_plugin_hook_commands(&file_text),
                "mcpServers" => contains_semantic_mcp_command_config(&file_text),
                _ => false,
            };
            if semantic {
                admitted.push(normalized);
            }
            continue;
        }
        if resolved.is_dir() && matches!(key, "agents" | "commands") {
            let mut builder = WalkBuilder::new(&resolved);
            builder
                .hidden(false)
                .git_ignore(false)
                .git_exclude(false)
                .parents(false);
            for result in builder.build() {
                let entry = result.map_err(|error| {
                    format!(
                        "plugin target walk failed for {}: {error}",
                        resolved.display()
                    )
                })?;
                if !entry
                    .file_type()
                    .is_some_and(|file_type| file_type.is_file())
                {
                    continue;
                }
                if entry.path().extension().and_then(|ext| ext.to_str()) != Some("md") {
                    continue;
                }
                let normalized =
                    normalize_rel_path(entry.path().strip_prefix(repo_root).map_err(|error| {
                        format!("failed to relativize plugin markdown target: {error}")
                    })?);
                if !is_generic_validation_excluded_path(&normalized) {
                    admitted.push(normalized);
                }
            }
        }
    }

    Ok(admitted)
}

fn contains_semantic_github_workflow_yaml(text: &str) -> bool {
    let Ok(value) = serde_yaml_bw::from_str::<Value>(text) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    object.get("jobs").and_then(Value::as_object).is_some()
        && (object.contains_key("on")
            || object.contains_key("permissions")
            || object.values().any(value_contains_workflow_steps))
}

fn value_contains_workflow_steps(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.iter().any(value_contains_workflow_steps),
        Value::Object(object) => {
            object.contains_key("uses")
                || object.contains_key("run")
                || object.values().any(value_contains_workflow_steps)
        }
        _ => false,
    }
}

fn segment_tokens(segment: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let bytes = segment.as_bytes();
    let mut start = 0usize;
    for index in 0..bytes.len() {
        let byte = bytes[index];
        let is_delimiter = matches!(byte, b'_' | b'-' | b'.');
        let is_camel_boundary =
            index > start && bytes[index - 1].is_ascii_lowercase() && byte.is_ascii_uppercase();
        if is_delimiter || is_camel_boundary {
            if start < index {
                tokens.push(&segment[start..index]);
            }
            start = if is_delimiter { index + 1 } else { index };
        }
    }
    if start < segment.len() {
        tokens.push(&segment[start..]);
    }
    tokens
        .into_iter()
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .collect()
}

fn json_descendants<'a>(value: &'a Value) -> Box<dyn Iterator<Item = &'a Value> + 'a> {
    match value {
        Value::Array(items) => {
            Box::new(std::iter::once(value).chain(items.iter().flat_map(json_descendants)))
        }
        Value::Object(map) => {
            Box::new(std::iter::once(value).chain(map.values().flat_map(json_descendants)))
        }
        _ => Box::new(std::iter::once(value)),
    }
}

fn is_tool_descriptor_shape(value: &Value) -> bool {
    let Value::Object(map) = value else {
        return false;
    };
    let has_name = map.get("name").is_some_and(Value::is_string);
    let has_tool_schema = map.contains_key("inputSchema")
        || map.contains_key("input_schema")
        || map.contains_key("parameters");
    let has_function_parameters = map
        .get("function")
        .and_then(Value::as_object)
        .is_some_and(|function| function.get("parameters").is_some());
    has_name && (has_tool_schema || has_function_parameters)
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

fn load_shortlist(
    workspace_root: &Path,
    package: ValidationPackage,
) -> Result<RepoShortlist, String> {
    let text = fs::read_to_string(workspace_root.join(package.shortlist_path()))
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
                admission_paths: Vec::new(),
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
                    surfaces_present: vec![".mcp.json".to_owned()],
                    ..default_entry_from_shortlist(&sample_shortlist().repos[0])
                },
                EvaluationEntry {
                    repo: "zebbern/claude-code-guide".to_owned(),
                    preview_findings: 2,
                    preview_rule_codes: vec!["SEC313".to_owned()],
                    surfaces_present: vec![
                        ".claude/mcp/*.json".to_owned(),
                        "tool_descriptor_json".to_owned(),
                    ],
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
        assert!(markdown.contains("## Hybrid Scope Expansion Results"));
        assert!(markdown.contains("- repos with root `mcp.json`: `0`"));
        assert!(markdown.contains("- repos with `.mcp.json`: `1`"));
        assert!(markdown.contains("- repos with `.cursor/mcp.json`: `0`"));
        assert!(markdown.contains("- repos with `.vscode/mcp.json`: `0`"));
        assert!(markdown.contains("- repos with `.roo/mcp.json`: `0`"));
        assert!(markdown.contains("- repos with `.kiro/settings/mcp.json`: `0`"));
        assert!(markdown.contains("- repos with `.claude/mcp/*.json`: `1`"));
        assert!(markdown.contains("- repos with Docker-based MCP launch configs: `0`"));
        assert!(markdown.contains("- findings from `SEC336`: `0`"));
        assert!(markdown.contains("- findings from `SEC337`-`SEC339`: `0`"));
        assert!(markdown.contains("- repos with `tool_descriptor_json`: `1`"));
        assert!(markdown.contains(
            "- repos where new MCP client-config variants existed only under fixture-like paths: `0`"
        ));
        assert!(markdown.contains(
            "- repos where Docker-based MCP launch existed only under fixture-like client-config variants: `0`"
        ));
        assert!(markdown.contains("## Delta From Previous Wave"));
        assert!(markdown.contains("`datadog-labs/cursor-plugin`: `improved`"));
        assert!(
            markdown.contains("`zebbern/claude-code-guide`: `2` preview finding(s) via `SEC313`")
        );
        assert!(markdown.contains("`cursor/plugins`: `improved`"));
        assert!(markdown.contains("`Emmraan/agent-skills`: `improved`"));
    }

    #[test]
    fn package_flag_defaults_to_canonical() {
        assert_eq!(
            parse_package_flag(&Vec::<String>::new()).unwrap(),
            ValidationPackage::Canonical
        );
    }

    #[test]
    fn package_flag_parses_tool_json_extension() {
        assert_eq!(
            parse_package_flag(&["--package=tool-json-extension".to_owned()]).unwrap(),
            ValidationPackage::ToolJsonExtension
        );
    }

    #[test]
    fn package_flag_parses_server_json_extension() {
        assert_eq!(
            parse_package_flag(&["--package=server-json-extension".to_owned()]).unwrap(),
            ValidationPackage::ServerJsonExtension
        );
    }

    #[test]
    fn package_flag_parses_github_actions_extension() {
        assert_eq!(
            parse_package_flag(&["--package=github-actions-extension".to_owned()]).unwrap(),
            ValidationPackage::GithubActionsExtension
        );
    }

    #[test]
    fn package_flag_parses_ai_native_discovery() {
        assert_eq!(
            parse_package_flag(&["--package=ai-native-discovery".to_owned()]).unwrap(),
            ValidationPackage::AiNativeDiscovery
        );
    }

    #[test]
    fn semantic_docker_mcp_launch_requires_docker_run_shape() {
        assert!(contains_semantic_docker_mcp_launch(
            r#"{"servers":{"demo":{"command":"docker","args":["run","ghcr.io/acme/mcp-server"]}}}"#
        ));
        assert!(!contains_semantic_docker_mcp_launch(
            r#"{"servers":{"demo":{"command":"docker","args":["pull","ghcr.io/acme/mcp-server"]}}}"#
        ));
        assert!(!contains_semantic_docker_mcp_launch(
            r#"{"servers":{"demo":{"command":"node","args":["server.js"]}}}"#
        ));
    }

    #[test]
    fn fixture_like_paths_are_rejected() {
        assert!(is_generic_validation_excluded_path(
            "tests/fixtures/tools.json"
        ));
        assert!(is_generic_validation_excluded_path(
            "pkg/testdata/sample.tools.json"
        ));
        assert!(!is_generic_validation_excluded_path("configs/tools.json"));
    }

    #[test]
    fn docish_tool_json_paths_are_rejected() {
        assert!(is_tool_json_excluded_path("docs/tools.json"));
        assert!(is_tool_json_excluded_path("Resources/schema/tools.json"));
        assert!(is_tool_json_excluded_path(
            "resources/ToolSchemas/tools.json"
        ));
        assert!(is_tool_json_excluded_path(
            "resources/tool-schemas/tools.json"
        ));
        assert!(is_tool_json_excluded_path(
            "resources/schema_store/tools.json"
        ));
        assert!(!is_tool_json_excluded_path("configs/tools.json"));
    }

    #[test]
    fn semantic_tool_descriptor_json_requires_name_and_schema() {
        assert!(contains_semantic_tool_descriptor_json(
            r#"{"tools":[{"name":"search","inputSchema":{"type":"object"}}]}"#
        ));
        assert!(contains_semantic_tool_descriptor_json(
            r#"[{"name":"search","function":{"parameters":{"type":"object"}}}]"#
        ));
        assert!(contains_semantic_tool_descriptor_json(
            r#"{"jsonrpc":"2.0","result":{"tools":[{"name":"search","inputSchema":{"type":"object"}}]}}"#
        ));
        assert!(!contains_semantic_tool_descriptor_json(
            r#"{"$schema":"http://json-schema.org/draft-07/schema#","type":"array"}"#
        ));
        assert!(!contains_semantic_tool_descriptor_json(
            r#"{"tools":[{"description":"missing name","inputSchema":{"type":"object"}}]}"#
        ));
    }

    #[test]
    fn semantic_server_json_requires_name_version_and_remotes_or_packages() {
        assert!(contains_semantic_server_json(
            r#"{"name":"demo","version":"1.0.0","remotes":[{"type":"streamable-http","url":"https://example.com/mcp"}]}"#
        ));
        assert!(contains_semantic_server_json(
            r#"{"name":"demo","version":"1.0.0","packages":[{"registry_name":"npm","name":"demo","version":"1.0.0"}]}"#
        ));
        assert!(!contains_semantic_server_json(
            r#"{"name":"demo","remotes":[{"type":"streamable-http","url":"https://example.com/mcp"}]}"#
        ));
        assert!(!contains_semantic_server_json(
            r#"{"version":"1.0.0","packages":[{"name":"demo"}]}"#
        ));
    }

    #[test]
    fn semantic_claude_settings_require_command_hooks() {
        assert!(contains_semantic_claude_command_settings(
            r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"./hook.sh"}]}]}}"#
        ));
        assert!(!contains_semantic_claude_command_settings(
            r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"notification","message":"hi"}]}]}}"#
        ));
    }

    #[test]
    fn semantic_plugin_hooks_require_command_entries() {
        assert!(contains_semantic_plugin_hook_commands(
            r#"{"hooks":{"stop":[{"command":"./hooks/stop.sh"}]}}"#
        ));
        assert!(!contains_semantic_plugin_hook_commands(
            r#"{"hooks":{"stop":[{"message":"no command"}]}}"#
        ));
    }

    #[test]
    fn semantic_github_workflow_yaml_requires_jobs_and_workflow_keys() {
        assert!(contains_semantic_github_workflow_yaml(
            "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: docker/login-action@v4\n"
        ));
        assert!(!contains_semantic_github_workflow_yaml(
            "name: just a yaml file\nvalues:\n  - demo\n"
        ));
    }

    #[test]
    fn tool_json_extension_report_has_required_sections() {
        let shortlist = RepoShortlist {
            version: 1,
            repos: vec![ShortlistRepo {
                repo: "owner/tool-json".to_owned(),
                url: "https://github.com/owner/tool-json".to_owned(),
                pinned_ref: "abc123".to_owned(),
                category: "tool_json".to_owned(),
                subtype: "stress".to_owned(),
                status: "evaluated".to_owned(),
                surfaces_present: vec!["tool_descriptor_json".to_owned()],
                admission_paths: vec!["tools.json".to_owned()],
                rationale: "Committed tool descriptor JSON.".to_owned(),
            }],
        };
        let baseline = ExternalValidationLedger {
            version: 1,
            wave: 1,
            baseline: None,
            evaluations: vec![EvaluationEntry {
                repo: "owner/old-tool-json".to_owned(),
                ..default_entry_from_shortlist(&sample_shortlist().repos[0])
            }],
        };
        let ledger = ExternalValidationLedger {
            version: 1,
            wave: 2,
            baseline: Some("archive/wave1-ledger.toml".to_owned()),
            evaluations: vec![EvaluationEntry {
                repo: "owner/tool-json".to_owned(),
                url: "https://github.com/owner/tool-json".to_owned(),
                pinned_ref: "abc123".to_owned(),
                category: "tool_json".to_owned(),
                subtype: "stress".to_owned(),
                status: "evaluated".to_owned(),
                surfaces_present: vec!["tool_descriptor_json".to_owned()],
                stable_findings: 1,
                preview_findings: 0,
                stable_rule_codes: vec!["SEC314".to_owned()],
                preview_rule_codes: Vec::new(),
                repo_verdict: "strong_fit".to_owned(),
                stable_precision_notes: String::new(),
                preview_signal_notes: String::new(),
                false_positive_notes: Vec::new(),
                possible_false_negative_notes: Vec::new(),
                follow_up_action: "no_action".to_owned(),
                runtime_errors: vec![RuntimeErrorRecord {
                    path: "other.json".to_owned(),
                    kind: "parse".to_owned(),
                    message: "bad".to_owned(),
                }],
                diagnostics: vec![DiagnosticRecord {
                    path: "tools.json".to_owned(),
                    severity: "warn".to_owned(),
                    code: Some("parse_recovery".to_owned()),
                    message: "recovered".to_owned(),
                }],
            }],
        };

        let markdown = render_tool_json_extension_report(&shortlist, &baseline, &ledger);
        assert!(markdown.contains("## Cohort Composition"));
        assert!(markdown.contains("## Admission Results"));
        assert!(markdown.contains("## Overall Counts"));
        assert!(markdown.contains("## Delta From Previous Wave"));
        assert!(markdown.contains("## Stable Hits"));
        assert!(markdown.contains("## Preview Hits"));
        assert!(markdown.contains("## Runtime / Diagnostic Notes"));
        assert!(markdown.contains("## Fixture Suppression Check"));
        assert!(markdown.contains("## Recommended Next Step"));
        assert!(markdown.contains("`SEC314`"));
        assert!(markdown.contains("admission-path issue"));
        assert!(markdown.contains("non-admission-path issue"));
    }

    #[test]
    fn server_json_extension_report_has_required_sections() {
        let shortlist = RepoShortlist {
            version: 1,
            repos: vec![ShortlistRepo {
                repo: "owner/server-json".to_owned(),
                url: "https://github.com/owner/server-json".to_owned(),
                pinned_ref: "abc123".to_owned(),
                category: "server_json".to_owned(),
                subtype: "stress".to_owned(),
                status: "evaluated".to_owned(),
                surfaces_present: vec!["server.json".to_owned()],
                admission_paths: vec!["server.json".to_owned()],
                rationale: "Committed server registry metadata.".to_owned(),
            }],
        };
        let baseline = ExternalValidationLedger {
            version: 1,
            wave: 1,
            baseline: None,
            evaluations: vec![EvaluationEntry {
                repo: "owner/old-server-json".to_owned(),
                ..default_entry_from_shortlist(&sample_shortlist().repos[0])
            }],
        };
        let ledger = ExternalValidationLedger {
            version: 1,
            wave: 2,
            baseline: Some("archive/wave1-ledger.toml".to_owned()),
            evaluations: vec![EvaluationEntry {
                repo: "owner/server-json".to_owned(),
                url: "https://github.com/owner/server-json".to_owned(),
                pinned_ref: "abc123".to_owned(),
                category: "server_json".to_owned(),
                subtype: "stress".to_owned(),
                status: "evaluated".to_owned(),
                surfaces_present: vec!["server.json".to_owned()],
                stable_findings: 1,
                preview_findings: 0,
                stable_rule_codes: vec!["SEC319".to_owned()],
                preview_rule_codes: Vec::new(),
                repo_verdict: "strong_fit".to_owned(),
                stable_precision_notes: String::new(),
                preview_signal_notes: String::new(),
                false_positive_notes: Vec::new(),
                possible_false_negative_notes: Vec::new(),
                follow_up_action: "no_action".to_owned(),
                runtime_errors: Vec::new(),
                diagnostics: Vec::new(),
            }],
        };

        let markdown = render_server_json_extension_report(&shortlist, &baseline, &ledger);
        assert!(markdown.contains("## Cohort Composition"));
        assert!(markdown.contains("## Admission Results"));
        assert!(markdown.contains("## Overall Counts"));
        assert!(markdown.contains("## Delta From Previous Wave"));
        assert!(markdown.contains("## Stable Hits"));
        assert!(markdown.contains("## Preview Hits"));
        assert!(markdown.contains("## Runtime / Diagnostic Notes"));
        assert!(markdown.contains("## Recommended Next Step"));
        assert!(markdown.contains("`SEC319`"));
    }

    #[test]
    fn github_actions_extension_report_has_required_sections() {
        let shortlist = RepoShortlist {
            version: 1,
            repos: vec![ShortlistRepo {
                repo: "owner/workflows".to_owned(),
                url: "https://github.com/owner/workflows".to_owned(),
                pinned_ref: "abc123".to_owned(),
                category: "github_actions".to_owned(),
                subtype: "stress".to_owned(),
                status: "evaluated".to_owned(),
                surfaces_present: vec![".github/workflows/*.yml".to_owned()],
                admission_paths: vec![".github/workflows/ci.yml".to_owned()],
                rationale: "Workflow repo.".to_owned(),
            }],
        };
        let ledger = ExternalValidationLedger {
            version: 1,
            wave: 1,
            baseline: None,
            evaluations: vec![EvaluationEntry {
                repo: "owner/workflows".to_owned(),
                url: "https://github.com/owner/workflows".to_owned(),
                pinned_ref: "abc123".to_owned(),
                category: "github_actions".to_owned(),
                subtype: "stress".to_owned(),
                status: "evaluated".to_owned(),
                surfaces_present: vec![".github/workflows/*.yml".to_owned()],
                stable_findings: 1,
                preview_findings: 1,
                stable_rule_codes: vec!["SEC324".to_owned(), "SEC327".to_owned()],
                preview_rule_codes: vec!["SEC325".to_owned(), "SEC328".to_owned()],
                repo_verdict: "strong_fit".to_owned(),
                stable_precision_notes: String::new(),
                preview_signal_notes: String::new(),
                false_positive_notes: Vec::new(),
                possible_false_negative_notes: Vec::new(),
                follow_up_action: "no_action".to_owned(),
                runtime_errors: Vec::new(),
                diagnostics: Vec::new(),
            }],
        };

        let markdown = render_github_actions_extension_report(&shortlist, &ledger);
        assert!(markdown.contains("## Cohort Composition"));
        assert!(markdown.contains("## Admission Results"));
        assert!(markdown.contains("## Overall Counts"));
        assert!(markdown.contains("## Stable Hits"));
        assert!(markdown.contains("## Preview Hits"));
        assert!(markdown.contains("## Runtime / Diagnostic Notes"));
        assert!(markdown.contains("## Recommended Next Step"));
        assert!(markdown.contains("`SEC324`"));
        assert!(markdown.contains("`SEC325`"));
        assert!(markdown.contains("`SEC327`"));
        assert!(markdown.contains("`SEC328`"));
    }

    #[test]
    fn ai_native_discovery_report_has_required_sections() {
        let shortlist = RepoShortlist {
            version: 1,
            repos: vec![ShortlistRepo {
                repo: "owner/ai-native".to_owned(),
                url: "https://github.com/owner/ai-native".to_owned(),
                pinned_ref: "abc123".to_owned(),
                category: "ai_native".to_owned(),
                subtype: "claude_settings_command".to_owned(),
                status: "evaluated".to_owned(),
                surfaces_present: vec![".claude/settings.json".to_owned()],
                admission_paths: vec![".claude/settings.json".to_owned()],
                rationale: "Committed Claude settings hooks.".to_owned(),
            }],
        };
        let ledger = ExternalValidationLedger {
            version: 1,
            wave: 1,
            baseline: None,
            evaluations: vec![EvaluationEntry {
                repo: "owner/ai-native".to_owned(),
                url: "https://github.com/owner/ai-native".to_owned(),
                pinned_ref: "abc123".to_owned(),
                category: "ai_native".to_owned(),
                subtype: "claude_settings_command".to_owned(),
                status: "evaluated".to_owned(),
                surfaces_present: vec!["SKILL.md".to_owned()],
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
            }],
        };

        let markdown = render_ai_native_discovery_report(&shortlist, &ledger);
        assert!(markdown.contains("## Cohort Composition"));
        assert!(markdown.contains("## Admission Results"));
        assert!(markdown.contains("## Coverage Status"));
        assert!(markdown.contains("## Overall Counts"));
        assert!(markdown.contains("## Stable Hits"));
        assert!(markdown.contains("## Preview Hits"));
        assert!(markdown.contains("## Runtime / Diagnostic Notes"));
        assert!(markdown.contains("## Recommended Next Step"));
        assert!(markdown.contains("discovery-only"));
    }
}
