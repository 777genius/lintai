use crate::external_validation::*;

pub(crate) fn render_github_actions_extension_report(
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
                format_rule_codes(rule_codes)
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
