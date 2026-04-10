use crate::external_validation::*;

pub(crate) fn render_server_json_extension_report(
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
        output.push_str(
            "- no external `Stable` hits were observed from the current `server.json` stable rule batch\n\n",
        );
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
        output.push_str("Keep the `server.json` surface and continue discovery; do not weaken the current transport, secret, or compatibility checks just because this wave stays clean but sparse.\n");
    } else {
        output.push_str("Promote the highest-signal server-json repos into future canonical evidence sets and expand the server-json rule batch conservatively.\n");
    }

    output
}
