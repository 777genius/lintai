use super::super::*;

pub(crate) fn merge_summary_with_absolute_paths(
    aggregate: &mut ScanSummary,
    mut summary: ScanSummary,
    absolute_base: &Path,
) {
    rewrite_summary_paths(&mut summary, absolute_base);

    aggregate.scanned_files += summary.scanned_files;
    aggregate.skipped_files += summary.skipped_files;
    aggregate.findings.extend(summary.findings);
    aggregate.diagnostics.extend(summary.diagnostics);
    aggregate.runtime_errors.extend(summary.runtime_errors);
    aggregate.provider_metrics.extend(summary.provider_metrics);
}

fn rewrite_summary_paths(summary: &mut ScanSummary, absolute_base: &Path) {
    for finding in &mut summary.findings {
        rewrite_finding_paths(finding, absolute_base);
    }
    for diagnostic in &mut summary.diagnostics {
        diagnostic.normalized_path = absolutize_path(absolute_base, &diagnostic.normalized_path);
    }
    for error in &mut summary.runtime_errors {
        error.normalized_path = absolutize_path(absolute_base, &error.normalized_path);
    }
    for metric in &mut summary.provider_metrics {
        metric.normalized_path = absolutize_path(absolute_base, &metric.normalized_path);
    }
}

fn rewrite_finding_paths(finding: &mut Finding, absolute_base: &Path) {
    let location_path = absolutize_path(absolute_base, &finding.location.normalized_path);
    finding.location.normalized_path = location_path.clone();
    finding.stable_key.normalized_path = location_path;

    for evidence in &mut finding.evidence {
        if let Some(location) = &mut evidence.location {
            location.normalized_path = absolutize_path(absolute_base, &location.normalized_path);
        }
    }

    for related in &mut finding.related {
        related.normalized_path = absolutize_path(absolute_base, &related.normalized_path);
    }
}

fn absolutize_path(absolute_base: &Path, normalized_path: &str) -> String {
    normalize_path_string(&absolute_base.join(normalized_path))
}
