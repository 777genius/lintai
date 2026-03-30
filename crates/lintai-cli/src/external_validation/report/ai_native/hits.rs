use std::collections::BTreeMap;
use std::path::Path;

use crate::external_validation::*;

use super::coverage::AiNativeCoverageSummary;

const AI_NATIVE_RULE_CODES: &[&str] = &[
    "SEC301", "SEC302", "SEC303", "SEC304", "SEC305", "SEC309", "SEC310", "SEC329", "SEC330",
    "SEC331", "SEC335", "SEC336", "SEC337", "SEC338", "SEC339", "SEC340", "SEC341", "SEC342",
    "SEC343", "SEC344", "SEC345", "SEC346",
];

pub(super) fn append_cohort_and_counts(
    output: &mut String,
    shortlist: &RepoShortlist,
    ledger: &ExternalValidationLedger,
) {
    let subtype_counts = shortlist
        .repos
        .iter()
        .fold(BTreeMap::new(), |mut counts, repo| {
            *counts.entry(repo.subtype.as_str()).or_insert(0usize) += 1;
            counts
        });
    let counts = aggregate_counts(ledger);

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
}

pub(super) fn append_hit_sections(
    output: &mut String,
    workspace_root: &Path,
    shortlist: &RepoShortlist,
    ledger: &ExternalValidationLedger,
    coverage: &AiNativeCoverageSummary,
) {
    let counts = aggregate_counts(ledger);
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
    let sec352_hits = rule_count(ledger, &["SEC352"]);
    let sec353_hits = rule_count(ledger, &["SEC353"]);
    let sec354_hits = rule_count(ledger, &["SEC354"]);
    let sec355_hits = rule_count(ledger, &["SEC355"]);
    let sec356_hits = rule_count(ledger, &["SEC356"]);
    let sec357_hits = rule_count(ledger, &["SEC357"]);
    let sec358_hits = rule_count(ledger, &["SEC358"]);
    let sec359_hits = rule_count(ledger, &["SEC359"]);
    let sec360_hits = rule_count(ledger, &["SEC360"]);
    let sec361_hits = rule_count(ledger, &["SEC361"]);
    let sec362_hits = rule_count(ledger, &["SEC362"]);
    let sec363_hits = rule_count(ledger, &["SEC363"]);
    let sec364_hits = rule_count(ledger, &["SEC364"]);
    let sec365_hits = rule_count(ledger, &["SEC365"]);
    let sec366_hits = rule_count(ledger, &["SEC366"]);
    let sec367_hits = rule_count(ledger, &["SEC367"]);
    let sec368_hits = rule_count(ledger, &["SEC368"]);
    let sec369_hits = rule_count(ledger, &["SEC369"]);
    let sec370_hits = rule_count(ledger, &["SEC370"]);
    let sec371_hits = rule_count(ledger, &["SEC371"]);
    let sec372_hits = rule_count(ledger, &["SEC372"]);
    let sec373_hits = rule_count(ledger, &["SEC373"]);
    let sec374_hits = rule_count(ledger, &["SEC374"]);
    let sec375_hits = rule_count(ledger, &["SEC375"]);
    let sec376_hits = rule_count(ledger, &["SEC376"]);
    let sec377_hits = rule_count(ledger, &["SEC377"]);
    let sec378_hits = rule_count(ledger, &["SEC378"]);
    let sec379_hits = rule_count(ledger, &["SEC379"]);
    let sec380_hits = rule_count(ledger, &["SEC380"]);
    let sec347_subtypes = sec347_subtype_counts(workspace_root, ledger);
    let sec313_repos = repos_with_rule_hits(ledger, &["SEC313"], false);
    let sec335_repos = repos_with_rule_hits(ledger, &["SEC335"], false);
    let sec347_repos = repos_with_rule_hits(ledger, &["SEC347"], false);
    let sec348_repos = repos_with_rule_hits(ledger, &["SEC348"], false);
    let sec349_repos = repos_with_rule_hits(ledger, &["SEC349"], false);
    let sec350_repos = repos_with_rule_hits(ledger, &["SEC350"], false);
    let sec351_repos = repos_with_rule_hits(ledger, &["SEC351"], false);
    let sec352_repos = repos_with_rule_hits(ledger, &["SEC352"], false);
    let sec353_repos = repos_with_rule_hits(ledger, &["SEC353"], false);
    let sec354_repos = repos_with_rule_hits(ledger, &["SEC354"], false);
    let sec355_repos = repos_with_rule_hits(ledger, &["SEC355"], false);
    let sec356_repos = repos_with_rule_hits(ledger, &["SEC356"], false);
    let sec357_repos = repos_with_rule_hits(ledger, &["SEC357"], false);
    let sec358_repos = repos_with_rule_hits(ledger, &["SEC358"], false);
    let sec359_repos = repos_with_rule_hits(ledger, &["SEC359"], false);
    let sec360_repos = repos_with_rule_hits(ledger, &["SEC360"], false);
    let sec361_repos = repos_with_rule_hits(ledger, &["SEC361"], false);
    let sec362_repos = repos_with_rule_hits(ledger, &["SEC362"], false);
    let sec363_repos = repos_with_rule_hits(ledger, &["SEC363"], false);
    let sec364_repos = repos_with_rule_hits(ledger, &["SEC364"], false);
    let sec365_repos = repos_with_rule_hits(ledger, &["SEC365"], false);
    let sec366_repos = repos_with_rule_hits(ledger, &["SEC366"], false);
    let sec367_repos = repos_with_rule_hits(ledger, &["SEC367"], false);
    let sec368_repos = repos_with_rule_hits(ledger, &["SEC368"], false);
    let sec369_repos = repos_with_rule_hits(ledger, &["SEC369"], false);
    let sec370_repos = repos_with_rule_hits(ledger, &["SEC370"], false);
    let sec371_repos = repos_with_rule_hits(ledger, &["SEC371"], false);
    let sec372_repos = repos_with_rule_hits(ledger, &["SEC372"], false);
    let sec373_repos = repos_with_rule_hits(ledger, &["SEC373"], false);
    let sec374_repos = repos_with_rule_hits(ledger, &["SEC374"], false);
    let sec375_repos = repos_with_rule_hits(ledger, &["SEC375"], false);
    let sec376_repos = repos_with_rule_hits(ledger, &["SEC376"], false);
    let sec377_repos = repos_with_rule_hits(ledger, &["SEC377"], false);
    let sec378_repos = repos_with_rule_hits(ledger, &["SEC378"], false);
    let sec379_repos = repos_with_rule_hits(ledger, &["SEC379"], false);
    let sec380_repos = repos_with_rule_hits(ledger, &["SEC380"], false);

    output.push_str("## Stable Hits\n\n");
    output.push_str(&format!("- current AI-native MCP rule families produced `{}` repo-level rule-code hits in this discovery wave\n", ai_native_rule_hits));
    if ai_native_rule_hits == 0 {
        output.push_str("- no new current-rule hits were observed on the admitted AI-native execution paths in this wave\n\n");
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
        output.push_str(&format!("- `{}` preview hit(s) were observed at repo scope; these should not yet be interpreted as proof on discovery-only admission paths\n\n", counts.preview_findings));
    }
    output.push_str(&format!(
        "- `SEC361` Claude settings files missing `$schema`: `{}`\n",
        sec361_hits
    ));
    output.push_str(&format!(
        "- `SEC362` Claude settings files allowing `Bash(*)`: `{}`\n",
        sec362_hits
    ));
    output.push_str(&format!(
        "- `SEC363` Claude settings files with home-directory hook commands: `{}`\n",
        sec363_hits
    ));
    output.push_str(&format!(
        "- `SEC364` Claude settings files with `permissions.defaultMode = bypassPermissions`: `{}`\n",
        sec364_hits
    ));
    output.push_str(&format!(
        "- `SEC365` Claude settings files with non-HTTPS `allowedHttpHookUrls`: `{}`\n",
        sec365_hits
    ));
    output.push_str(&format!(
        "- `SEC366` Claude settings files with dangerous host literals in `allowedHttpHookUrls`: `{}`\n",
        sec366_hits
    ));
    output.push_str(&format!(
        "- `SEC367` Claude settings files allowing `WebFetch(*)`: `{}`\n",
        sec367_hits
    ));
    output.push_str(&format!(
        "- `SEC368` Claude settings files with repo-external absolute hook paths: `{}`\n",
        sec368_hits
    ));
    output.push_str(&format!(
        "- `SEC369` Claude settings files allowing `Write(*)`: `{}`\n",
        sec369_hits
    ));
    output.push_str(&format!(
        "- `SEC370` path-specific Copilot instructions using the wrong suffix: `{}`\n",
        sec370_hits
    ));
    output.push_str(&format!(
        "- `SEC371` path-specific Copilot instructions with invalid `applyTo`: `{}`\n",
        sec371_hits
    ));
    output.push_str(&format!(
        "- `SEC372` Claude settings files allowing `Read(*)`: `{}`\n",
        sec372_hits
    ));
    output.push_str(&format!(
        "- `SEC373` Claude settings files allowing `Edit(*)`: `{}`\n",
        sec373_hits
    ));
    output.push_str(&format!(
        "- `SEC374` Claude settings files allowing `WebSearch(*)`: `{}`\n",
        sec374_hits
    ));
    output.push_str(&format!(
        "- `SEC375` Claude settings files allowing `Glob(*)`: `{}`\n",
        sec375_hits
    ));
    output.push_str(&format!(
        "- `SEC376` Claude settings files allowing `Grep(*)`: `{}`\n",
        sec376_hits
    ));
    output.push_str(&format!("- AI-native markdown preview hits by rule code: `SEC313`=`{}`, `SEC335`=`{}`, `SEC347`=`{}`, `SEC348`=`{}`, `SEC349`=`{}`, `SEC350`=`{}`, `SEC351`=`{}`, `SEC352`=`{}`, `SEC353`=`{}`, `SEC354`=`{}`, `SEC355`=`{}`, `SEC356`=`{}`, `SEC357`=`{}`, `SEC358`=`{}`, `SEC359`=`{}`, `SEC360`=`{}`, `SEC370`=`{}`, `SEC371`=`{}`, `SEC377`=`{}`, `SEC378`=`{}`, `SEC379`=`{}`, `SEC380`=`{}`\n", sec313_hits, sec335_hits, sec347_hits, sec348_hits, sec349_hits, sec350_hits, sec351_hits, sec352_hits, sec353_hits, sec354_hits, sec355_hits, sec356_hits, sec357_hits, sec358_hits, sec359_hits, sec360_hits, sec370_hits, sec371_hits, sec377_hits, sec378_hits, sec379_hits, sec380_hits));
    output.push_str(&format!(
        "- `SEC347` subtype repo hits: CLI-form=`{}`, config-snippet-form=`{}`\n",
        sec347_subtypes.cli_form_repos, sec347_subtypes.config_snippet_repos
    ));
    if coverage.plugin_root_command_paths == 0 {
        output.push_str("- current markdown usefulness is still mainly skills / `CLAUDE.md`; plugin-root command docs remain a non-driving surface with `0` admitted covered paths\n\n");
    } else {
        output.push_str("- plugin-root command docs are now part of the covered markdown surface, but skill / `CLAUDE.md` evidence still dominates current usefulness\n\n");
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
        ("SEC352", sec352_repos),
        ("SEC353", sec353_repos),
        ("SEC354", sec354_repos),
        ("SEC355", sec355_repos),
        ("SEC356", sec356_repos),
        ("SEC357", sec357_repos),
        ("SEC358", sec358_repos),
        ("SEC359", sec359_repos),
        ("SEC360", sec360_repos),
        ("SEC361", sec361_repos),
        ("SEC362", sec362_repos),
        ("SEC363", sec363_repos),
        ("SEC364", sec364_repos),
        ("SEC365", sec365_repos),
        ("SEC366", sec366_repos),
        ("SEC367", sec367_repos),
        ("SEC368", sec368_repos),
        ("SEC369", sec369_repos),
        ("SEC370", sec370_repos),
        ("SEC371", sec371_repos),
        ("SEC372", sec372_repos),
        ("SEC373", sec373_repos),
        ("SEC374", sec374_repos),
        ("SEC375", sec375_repos),
        ("SEC376", sec376_repos),
        ("SEC377", sec377_repos),
        ("SEC378", sec378_repos),
        ("SEC379", sec379_repos),
        ("SEC380", sec380_repos),
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
        output.push_str(&format!("- `cursor/plugins` currently reports `{}` stable and `{}` preview findings at repo scope after plugin-root target coverage expansion\n\n", entry.stable_findings, entry.preview_findings));
    }

    output.push_str("## Recommended Next Step\n\n");
    if coverage.discovery_only_admission_paths == 0 {
        output.push_str("Use this package as discovery evidence for the next detector expansion. There are no remaining discovery-only admission paths in the current checked-in AI-native cohort, and markdown usefulness is still being driven mainly by skills / `CLAUDE.md` rather than plugin-root command docs.\n");
    } else {
        output.push_str("Use this package as discovery evidence for the next detector expansion. Plugin-root `hooks.json`, `agents/*.md`, and `commands/*.md` are now partially covered through manifest-backed detection, so the remaining AI-native gaps are deferred plugin surfaces such as `mcpServers`.\n");
    }
}
