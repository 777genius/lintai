use crate::output::model::ReportEnvelope;

use super::common::{changed_root_fragment, client_for_inventory_finding};

pub(super) fn append_inventory_summary(output: &mut String, report: &ReportEnvelope<'_>) -> bool {
    if let Some(inventory_diff) = &report.inventory_diff {
        let inventory_stats = report
            .inventory_stats
            .as_ref()
            .expect("inventory_diff requires inventory_stats");
        output.push_str(&format!(
            "inventory diff discovered {} root(s), new {} root(s), removed {} root(s), changed {} root(s), new lintable {} root(s), risk increased {} root(s), new findings {}\n",
            report.inventory_roots.len(),
            inventory_diff.new_roots.len(),
            inventory_diff.removed_roots.len(),
            inventory_diff.changed_roots.len(),
            inventory_diff.new_lintable_roots.len(),
            inventory_diff.risk_increased_roots.len(),
            inventory_diff.new_findings.len()
        ));
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
        return true;
    }

    let Some(inventory_stats) = &report.inventory_stats else {
        return false;
    };
    output.push_str(&format!(
        "inventory discovered {} root(s), user {} root(s), system {} root(s), lintable {} root(s), discovered-only {} root(s), high risk {} root(s), medium risk {} root(s), low risk {} root(s), scanned {} supported artifact(s), non-target {} file(s), found {} finding(s), {} diagnostic(s), {} runtime error(s)\n",
        report.inventory_roots.len(),
        inventory_stats.user_roots,
        inventory_stats.system_roots,
        inventory_stats.lintable_roots,
        inventory_stats.discovered_only_roots,
        inventory_stats.high_risk_roots,
        inventory_stats.medium_risk_roots,
        inventory_stats.low_risk_roots,
        inventory_stats.supported_artifacts_scanned,
        inventory_stats.non_target_total(),
        report.findings.len(),
        report.diagnostics.len(),
        report.runtime_errors.len()
    ));
    output.push_str(&format!(
        "inventory counters: non_target={} excluded={} binary={} unreadable={} unrecognized={}\n",
        inventory_stats.non_target_files_in_lintable_roots,
        inventory_stats.excluded_files,
        inventory_stats.binary_files,
        inventory_stats.unreadable_files,
        inventory_stats.unrecognized_files,
    ));
    true
}

pub(super) fn append_inventory_sections(output: &mut String, report: &ReportEnvelope<'_>) {
    for root in &report.inventory_roots {
        output.push_str(&format!(
            "inventory-root [{} {} {}] {} {} {}\n",
            root.provenance.origin_scope,
            root.risk_level,
            root.mode,
            root.client,
            root.surface,
            root.path
        ));
    }

    if let Some(inventory_diff) = &report.inventory_diff {
        for root in &inventory_diff.new_roots {
            output.push_str(&format!(
                "new-root [{} {}] {} {} {}\n",
                root.risk_level, root.mode, root.client, root.surface, root.path
            ));
        }
        for root in &inventory_diff.removed_roots {
            output.push_str(&format!(
                "removed-root [{} {}] {} {} {}\n",
                root.risk_level, root.mode, root.client, root.surface, root.path
            ));
        }
        for root in &inventory_diff.changed_roots {
            output.push_str(&format!(
                "changed-root [{}] {} {} {}\n",
                changed_root_fragment(root),
                root.client,
                root.surface,
                root.path
            ));
        }
        for root in &inventory_diff.new_lintable_roots {
            output.push_str(&format!(
                "new-lintable-root [{}] {} {} {}\n",
                root.risk_level, root.client, root.surface, root.path
            ));
        }
        for root in &inventory_diff.risk_increased_roots {
            output.push_str(&format!(
                "risk-increased-root [{}->{}] {} {} {}\n",
                root.old_risk_level, root.new_risk_level, root.client, root.surface, root.path
            ));
        }
        for finding in &inventory_diff.new_findings {
            output.push_str(&format!(
                "new-finding {} {} {}\n",
                finding.rule_code,
                client_for_inventory_finding(
                    &report.inventory_roots,
                    finding.location.normalized_path.as_str()
                ),
                finding.location.normalized_path
            ));
        }
    }
}
