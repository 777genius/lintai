use crate::output::model::ReportEnvelope;

pub(super) fn append_discovery_summary(output: &mut String, report: &ReportEnvelope<'_>) -> bool {
    let Some(discovery_stats) = &report.discovery_stats else {
        return false;
    };
    output.push_str(&format!(
        "discovered {} root(s), lintable {} root(s), discovered-only {} root(s), scanned {} supported artifact(s), non-target {} file(s), found {} finding(s), {} diagnostic(s), {} runtime error(s)\n",
        report.discovered_roots.len(),
        discovery_stats.lintable_roots,
        discovery_stats.discovered_only_roots,
        discovery_stats.supported_artifacts_scanned,
        discovery_stats.non_target_total(),
        report.findings.len(),
        report.diagnostics.len(),
        report.runtime_errors.len()
    ));
    output.push_str(&format!(
        "discovery counters: non_target={} excluded={} binary={} unreadable={} unrecognized={}\n",
        discovery_stats.non_target_files_in_lintable_roots,
        discovery_stats.excluded_files,
        discovery_stats.binary_files,
        discovery_stats.unreadable_files,
        discovery_stats.unrecognized_files,
    ));
    true
}

pub(super) fn append_discovered_roots(output: &mut String, report: &ReportEnvelope<'_>) {
    for root in &report.discovered_roots {
        output.push_str(&format!(
            "root [{} {}] {} {} {}\n",
            root.scope, root.mode, root.client, root.surface, root.path
        ));
    }
}
