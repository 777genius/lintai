use crate::external_validation::*;
use lintai_engine::FileTypeDetector;
use std::collections::BTreeMap;
use std::path::Path;

pub(crate) fn render_ai_native_discovery_report(
    workspace_root: &Path,
    shortlist: &RepoShortlist,
    ledger: &ExternalValidationLedger,
) -> String {
    const AI_NATIVE_RULE_CODES: &[&str] = &[
        "SEC301", "SEC302", "SEC303", "SEC304", "SEC305", "SEC309", "SEC310", "SEC329", "SEC330",
        "SEC331", "SEC335", "SEC336", "SEC337", "SEC338", "SEC339", "SEC340", "SEC341", "SEC342",
        "SEC343", "SEC344", "SEC345", "SEC346",
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
    let sec346_repos = repos_with_rule_hits(ledger, &["SEC346"], true);
    let sec313_hits = rule_count(ledger, &["SEC313"]);
    let sec335_hits = rule_count(ledger, &["SEC335"]);
    let sec347_hits = rule_count(ledger, &["SEC347"]);
    let sec348_hits = rule_count(ledger, &["SEC348"]);
    let sec349_hits = rule_count(ledger, &["SEC349"]);
    let sec350_hits = rule_count(ledger, &["SEC350"]);
    let sec351_hits = rule_count(ledger, &["SEC351"]);
    let sec347_subtypes = sec347_subtype_counts(workspace_root, ledger);
    let sec313_repos = repos_with_rule_hits(ledger, &["SEC313"], false);
    let sec335_repos = repos_with_rule_hits(ledger, &["SEC335"], false);
    let sec347_repos = repos_with_rule_hits(ledger, &["SEC347"], false);
    let sec348_repos = repos_with_rule_hits(ledger, &["SEC348"], false);
    let sec349_repos = repos_with_rule_hits(ledger, &["SEC349"], false);
    let sec350_repos = repos_with_rule_hits(ledger, &["SEC350"], false);
    let sec351_repos = repos_with_rule_hits(ledger, &["SEC351"], false);

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
    output.push_str(&format!(
        "- `{}` plugin-root hook admission paths are now covered\n",
        coverage.plugin_root_hook_paths
    ));
    output.push_str(&format!(
        "- `{}` plugin-root agent markdown admission paths are now covered\n\n",
        coverage.plugin_root_agent_paths
    ));
    output.push_str(&format!(
        "- `{}` plugin-root command markdown admission paths are now covered\n\n",
        coverage.plugin_root_command_paths
    ));
    output.push_str(&format!(
        "- `{}` Gemini-style MCP client admission paths are now covered\n\n",
        coverage.gemini_client_paths
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

    for repo_name in [
        "hashicorp/terraform-mcp-server",
        "SonarSource/sonarqube-mcp-server",
    ] {
        let status = if coverage
            .covered_repos
            .iter()
            .any(|(repo, _)| repo == repo_name)
        {
            "covered"
        } else {
            "discovery-only"
        };
        output.push_str(&format!(
            "- `{repo_name}` is now `{status}` under shipped AI-native detector coverage\n"
        ));
    }
    output.push('\n');

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
        output.push_str("- repo-level AI-native rule hits were observed after the latest detector expansion. Treat these as repo-scope evidence first, then inspect path attribution before claiming they all came from newly covered admission paths.\n\n");
    }
    if sec346_repos.is_empty() {
        output.push_str("- `SEC346` produced no repo-level external hits in this wave\n\n");
    } else {
        for (repo, count, rule_codes) in sec346_repos {
            output.push_str(&format!(
                "- `{repo}`: `{count}` repo-level stable finding(s) via {}\n",
                format_rule_codes(&rule_codes)
            ));
        }
        output.push('\n');
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
    output.push_str(&format!(
        "- AI-native markdown preview hits by rule code: `SEC313`=`{}`, `SEC335`=`{}`, `SEC347`=`{}`, `SEC348`=`{}`, `SEC349`=`{}`, `SEC350`=`{}`, `SEC351`=`{}`\n",
        sec313_hits, sec335_hits, sec347_hits, sec348_hits, sec349_hits, sec350_hits, sec351_hits
    ));
    output.push_str(&format!(
        "- `SEC347` subtype repo hits: CLI-form=`{}`, config-snippet-form=`{}`\n",
        sec347_subtypes.cli_form_repos, sec347_subtypes.config_snippet_repos
    ));
    if coverage.plugin_root_command_paths == 0 {
        output.push_str(
            "- current markdown usefulness is still mainly skills / `CLAUDE.md`; plugin-root command docs remain a non-driving surface with `0` admitted covered paths\n\n",
        );
    } else {
        output.push_str(
            "- plugin-root command docs are now part of the covered markdown surface, but skill / `CLAUDE.md` evidence still dominates current usefulness\n\n",
        );
    }
    if sec347_hits > 0 {
        output.push_str(&format!(
            "- current `SEC347` usefulness is being driven mainly by {}\n\n",
            sec347_primary_driver_label(sec347_subtypes)
        ));
    }

    for (label, repos) in [
        ("SEC313", sec313_repos),
        ("SEC335", sec335_repos),
        ("SEC347", sec347_repos),
        ("SEC348", sec348_repos),
        ("SEC349", sec349_repos),
        ("SEC350", sec350_repos),
        ("SEC351", sec351_repos),
    ] {
        if repos.is_empty() {
            output.push_str(&format!(
                "- `{label}` produced no repo-level external preview hits in this wave\n"
            ));
        } else {
            for (repo, count, rule_codes) in repos {
                output.push_str(&format!(
                    "- `{repo}`: `{count}` repo-level preview finding(s) via {}\n",
                    format_rule_codes(&rule_codes)
                ));
            }
        }
    }
    output.push('\n');

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

    let plugin_repo_entry = ledger
        .evaluations
        .iter()
        .find(|entry| entry.repo == "cursor/plugins");
    if let Some(entry) = plugin_repo_entry {
        output.push_str(&format!(
            "- `cursor/plugins` currently reports `{}` stable and `{}` preview findings at repo scope after plugin-root target coverage expansion\n\n",
            entry.stable_findings, entry.preview_findings
        ));
    }

    output.push_str("## Recommended Next Step\n\n");
    if coverage.discovery_only_admission_paths == 0 {
        output.push_str("Use this package as discovery evidence for the next detector expansion. There are no remaining discovery-only admission paths in the current checked-in AI-native cohort, and markdown usefulness is still being driven mainly by skills / `CLAUDE.md` rather than plugin-root command docs.\n");
    } else {
        output.push_str("Use this package as discovery evidence for the next detector expansion. Plugin-root `hooks.json`, `agents/*.md`, and `commands/*.md` are now partially covered through manifest-backed detection, so the remaining AI-native gaps are deferred plugin surfaces such as `mcpServers`.\n");
    }

    output
}

#[derive(Clone, Debug, Default)]
struct AiNativeCoverageSummary {
    total_admission_paths: usize,
    covered_admission_paths: usize,
    discovery_only_admission_paths: usize,
    plugin_root_hook_paths: usize,
    plugin_root_agent_paths: usize,
    plugin_root_command_paths: usize,
    gemini_client_paths: usize,
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
            if detector.detect(Path::new(path), path).is_some()
                || is_manifest_backed_plugin_target_path(path)
                || is_ai_native_docker_config_path(path)
            {
                summary.covered_admission_paths += 1;
                if is_manifest_backed_plugin_hooks_path(path) {
                    summary.plugin_root_hook_paths += 1;
                }
                if is_manifest_backed_plugin_agent_path(path) {
                    summary.plugin_root_agent_paths += 1;
                }
                if is_manifest_backed_plugin_command_path(path) {
                    summary.plugin_root_command_paths += 1;
                }
                if is_ai_native_docker_config_path(path) {
                    summary.gemini_client_paths += 1;
                }
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

fn is_manifest_backed_plugin_target_path(path: &str) -> bool {
    is_manifest_backed_plugin_hooks_path(path)
        || is_manifest_backed_plugin_agent_path(path)
        || is_manifest_backed_plugin_command_path(path)
}

fn is_manifest_backed_plugin_hooks_path(path: &str) -> bool {
    path.ends_with("/hooks.json") && !path.contains("/.cursor-plugin/")
}

fn is_manifest_backed_plugin_agent_path(path: &str) -> bool {
    path.contains("/agents/") && path.ends_with(".md") && !path.contains("/.cursor-plugin/agents/")
}

fn is_manifest_backed_plugin_command_path(path: &str) -> bool {
    path.contains("/commands/")
        && path.ends_with(".md")
        && !path.contains("/.cursor-plugin/commands/")
        && !path.contains("/.claude/commands/")
}
