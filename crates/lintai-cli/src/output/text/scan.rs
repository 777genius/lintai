use crate::output::model::ReportEnvelope;
use crate::shipped_rules::{
    PublicLane, shipped_rule_display_label, shipped_rule_docs_url, shipped_rule_public_lane,
};

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

    if !report.findings.is_empty() {
        let mut recommended = 0usize;
        let mut preview = 0usize;
        let mut governance = 0usize;

        for finding in report.findings {
            match shipped_rule_public_lane(&finding.rule_code).unwrap_or(PublicLane::Preview) {
                PublicLane::Recommended => recommended += 1,
                PublicLane::Preview => preview += 1,
                PublicLane::Governance => governance += 1,
            }
        }

        output.push_str(&format!("recommended findings: {recommended}\n"));
        output.push_str(&format!("deeper review findings: {preview}\n"));
        output.push_str(&format!("governance review findings: {governance}\n"));
    }
}

pub(super) fn append_scan_results(output: &mut String, report: &ReportEnvelope<'_>) {
    for finding in report.findings {
        output.push_str(&format!(
            "{} [{}] {}:{}-{} {}\n",
            shipped_rule_display_label(&finding.rule_code),
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
