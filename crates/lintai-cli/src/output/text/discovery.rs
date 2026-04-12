use crate::output::model::ReportEnvelope;

use super::common::{append_section_gap, count_label};
use super::scan::append_lane_summary;
use super::style::ResolvedTextStyle;

pub(super) fn append_discovery_summary(
    output: &mut String,
    report: &ReportEnvelope<'_>,
    style: ResolvedTextStyle,
) -> bool {
    let Some(discovery_stats) = &report.discovery_stats else {
        return false;
    };
    output.push_str(&format!(
        "discovered {}, lintable {}, discovered-only {}, scanned {}, non-target {}, found {}, {}, {}\n",
        count_label(report.discovered_roots.len(), "root", "roots"),
        count_label(discovery_stats.lintable_roots, "root", "roots"),
        count_label(discovery_stats.discovered_only_roots, "root", "roots"),
        count_label(
            discovery_stats.supported_artifacts_scanned,
            "supported artifact",
            "supported artifacts",
        ),
        count_label(discovery_stats.non_target_total(), "file", "files"),
        count_label(report.findings.len(), "finding", "findings"),
        count_label(report.diagnostics.len(), "diagnostic", "diagnostics"),
        count_label(report.runtime_errors.len(), "runtime error", "runtime errors"),
    ));
    output.push_str(&format!(
        "discovery counters: non-target={}, excluded={}, binary={}, unreadable={}, unrecognized={}\n",
        discovery_stats.non_target_files_in_lintable_roots,
        discovery_stats.excluded_files,
        discovery_stats.binary_files,
        discovery_stats.unreadable_files,
        discovery_stats.unrecognized_files,
    ));
    append_lane_summary(output, report.findings, style);
    true
}

pub(super) fn append_discovered_roots(
    output: &mut String,
    report: &ReportEnvelope<'_>,
    style: ResolvedTextStyle,
) {
    if report.discovered_roots.is_empty() {
        return;
    }

    append_section_gap(output);
    output.push_str(&style.section_heading("discovered roots", report.discovered_roots.len()));
    output.push_str("\n\n");

    let mut roots = report.discovered_roots.iter().collect::<Vec<_>>();
    roots.sort_by(|left, right| {
        left.scope
            .cmp(&right.scope)
            .then_with(|| left.client.cmp(&right.client))
            .then_with(|| left.surface.cmp(&right.surface))
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.mode.cmp(&right.mode))
    });

    for (index, root) in roots.iter().enumerate() {
        output.push_str("  ");
        output.push_str(&format!(
            "[{}] [{}] {} {} {}",
            root.scope, root.mode, root.client, root.surface, root.path
        ));
        output.push('\n');

        if index + 1 < roots.len() {
            output.push('\n');
        }
    }
}
