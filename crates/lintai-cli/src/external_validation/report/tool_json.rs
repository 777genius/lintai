use crate::external_validation::*;

pub(crate) fn render_tool_json_extension_report(
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
