use lintai_api::{Finding, ProviderError, ProviderErrorKind};

use crate::ResolvedFileConfig;
use crate::artifact_view::ArtifactContextRef;
use crate::normalize::populate_line_columns;
use crate::summary::{
    ProviderExecutionMetric, ProviderExecutionPhase, RuntimeErrorKind, ScanRuntimeError,
    ScanSummary,
};

use super::super::Engine;

impl Engine {
    pub(in crate::engine) fn collect_finding(
        &self,
        context: &ArtifactContextRef<'_>,
        file_config: &ResolvedFileConfig,
        mut finding: Finding,
        summary: &mut ScanSummary,
    ) {
        let _ = context.document;
        let _ = context.semantics;
        populate_line_columns(context.content, &mut finding);
        finding.severity =
            file_config.severity_for(&finding.rule_code, finding.category, finding.severity);
        if matches!(finding.severity, lintai_api::Severity::Allow) {
            return;
        }
        if !self.suppressions.is_suppressed(context, &finding) {
            summary.findings.push(finding);
        }
    }

    pub(in crate::engine) fn record_budget_overrun(
        &self,
        normalized_path: &str,
        provider_id: &str,
        timeout: std::time::Duration,
        elapsed: std::time::Duration,
        summary: &mut ScanSummary,
    ) {
        if elapsed <= timeout {
            return;
        }

        summary.runtime_errors.push(ScanRuntimeError {
            normalized_path: normalized_path.to_owned(),
            kind: RuntimeErrorKind::ProviderTimeout,
            provider_id: Some(provider_id.to_owned()),
            phase: None,
            message: format!(
                "provider `{provider_id}` exceeded its soft time budget: {:?} > {:?}",
                elapsed, timeout
            ),
        });
    }

    pub(in crate::engine) fn record_provider_execution_errors(
        &self,
        normalized_path: &str,
        phase: ProviderExecutionPhase,
        errors: Vec<ProviderError>,
        summary: &mut ScanSummary,
    ) {
        for error in errors {
            summary.runtime_errors.push(ScanRuntimeError {
                normalized_path: normalized_path.to_owned(),
                kind: match error.kind {
                    ProviderErrorKind::Execution => RuntimeErrorKind::ProviderExecution,
                    ProviderErrorKind::Timeout => RuntimeErrorKind::ProviderTimeout,
                },
                provider_id: Some(error.provider_id),
                phase: Some(phase),
                message: error.message,
            });
        }
    }

    pub(in crate::engine) fn record_provider_metric(
        &self,
        normalized_path: &str,
        provider_id: &str,
        phase: ProviderExecutionPhase,
        elapsed: std::time::Duration,
        findings_emitted: usize,
        errors_emitted: usize,
        summary: &mut ScanSummary,
    ) {
        summary.provider_metrics.push(ProviderExecutionMetric {
            normalized_path: normalized_path.to_owned(),
            provider_id: provider_id.to_owned(),
            phase,
            elapsed_us: elapsed.as_micros(),
            findings_emitted,
            errors_emitted,
        });
    }
}
