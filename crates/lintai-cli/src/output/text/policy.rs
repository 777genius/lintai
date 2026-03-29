use crate::output::model::ReportEnvelope;

pub(super) fn append_policy_sections(output: &mut String, report: &ReportEnvelope<'_>) {
    if let Some(policy_stats) = &report.policy_stats {
        output.push_str(&format!(
            "policy matched {} root(s), deny {}, warn {}, inventory roots {}, findings {}\n",
            policy_stats.matched_roots,
            policy_stats.deny_matches,
            policy_stats.warn_matches,
            report.inventory_roots.len(),
            report.findings.len()
        ));
        if let Some(inventory_stats) = &report.inventory_stats {
            output.push_str(&format!(
                "inventory counters: user={} system={} lintable={} discovered_only={} high={} medium={} low={} scanned={} non_target={} excluded={} binary={} unreadable={} unrecognized={}\n",
                inventory_stats.user_roots,
                inventory_stats.system_roots,
                inventory_stats.lintable_roots,
                inventory_stats.discovered_only_roots,
                inventory_stats.high_risk_roots,
                inventory_stats.medium_risk_roots,
                inventory_stats.low_risk_roots,
                inventory_stats.supported_artifacts_scanned,
                inventory_stats.non_target_files_in_lintable_roots,
                inventory_stats.excluded_files,
                inventory_stats.binary_files,
                inventory_stats.unreadable_files,
                inventory_stats.unrecognized_files,
            ));
        }
    }

    for policy_match in &report.policy_matches {
        output.push_str(&format!(
            "policy [{}] {} {} {} {} {}\n",
            policy_match.severity,
            policy_match.policy_id,
            policy_match.client,
            policy_match.surface,
            policy_match.path,
            policy_match.message
        ));
        for rule_code in &policy_match.matched_findings {
            output.push_str(&format!("  matched: {rule_code}\n"));
        }
    }
}
