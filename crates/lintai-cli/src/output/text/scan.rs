use crate::output::model::ReportEnvelope;
use crate::shipped_rules::shipped_rule_docs_url;

use super::common::{
    diagnostic_label, error_kind_label, provider_execution_phase_label, severity_label,
};

pub(super) fn append_default_summary(output: &mut String, report: &ReportEnvelope<'_>) {
    output.push_str(&format!(
        "scanned {} file(s), skipped {} file(s), found {} finding(s), {} diagnostic(s), {} runtime error(s)\n",
        report.stats.scanned_files,
        report.stats.skipped_files,
        report.findings.len(),
        report.diagnostics.len(),
        report.runtime_errors.len()
    ));
}

pub(super) fn append_scan_results(output: &mut String, report: &ReportEnvelope<'_>) {
    for finding in report.findings {
        output.push_str(&format!(
            "{} [{}] {}:{}-{} {}\n",
            finding.rule_code,
            severity_label(finding.severity),
            finding.location.normalized_path,
            finding.location.span.start_byte,
            finding.location.span.end_byte,
            finding.message
        ));
        if let Some(url) = shipped_rule_docs_url(&finding.rule_code) {
            output.push_str(&format!("  docs: {url}\n"));
        }
        for suggestion in &finding.suggestions {
            output.push_str(&format!("  suggest: {}\n", suggestion.message));
        }
    }

    for diagnostic in report.diagnostics {
        output.push_str(&format!(
            "diagnostic [{}] {} {}\n",
            diagnostic_label(diagnostic.severity),
            diagnostic.normalized_path,
            diagnostic.message
        ));
    }

    for error in report.runtime_errors {
        let provider_fragment = error
            .provider_id
            .as_deref()
            .map(|provider_id| format!(" provider={provider_id}"))
            .unwrap_or_default();
        let phase_fragment = error
            .phase
            .map(|phase| format!(" phase={}", provider_execution_phase_label(phase)))
            .unwrap_or_default();
        output.push_str(&format!(
            "error [{}] {}{}{} {}\n",
            error_kind_label(error.kind),
            error.normalized_path,
            provider_fragment,
            phase_fragment,
            error.message
        ));
    }
}
