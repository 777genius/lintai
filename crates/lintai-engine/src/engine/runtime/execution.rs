use std::time::Instant;

use lintai_api::{Finding, ProviderErrorKind, ProviderScanResult};

use crate::provider::ProviderEntry;
use crate::summary::{ProviderExecutionPhase, ScanSummary};

use super::super::Engine;

pub(in crate::engine) struct ProviderExecutionRequest<'provider, 'path> {
    pub(in crate::engine) normalized_path: &'path str,
    pub(in crate::engine) provider: &'provider ProviderEntry<'provider>,
    pub(in crate::engine) phase: ProviderExecutionPhase,
}

impl Engine {
    pub(in crate::engine) fn execute_provider_with_accounting<Run, Reconcile>(
        &self,
        request: ProviderExecutionRequest<'_, '_>,
        summary: &mut ScanSummary,
        run: Run,
        mut reconcile_finding: Reconcile,
    ) where
        Run: FnOnce() -> ProviderScanResult,
        Reconcile: FnMut(Finding, &mut ScanSummary),
    {
        let started = Instant::now();
        let result = run();
        let elapsed = started.elapsed();
        let findings_emitted = result.findings.len();
        let errors_emitted = result.errors.len();

        if !result
            .errors
            .iter()
            .any(|error| matches!(error.kind, ProviderErrorKind::Timeout))
        {
            self.record_budget_overrun(
                request.normalized_path,
                request.provider.id(),
                request.provider.timeout(),
                elapsed,
                summary,
            );
        }

        self.record_provider_metric(
            crate::ProviderExecutionMetric {
                normalized_path: request.normalized_path.to_owned(),
                provider_id: request.provider.id().to_owned(),
                phase: request.phase,
                elapsed_us: elapsed.as_micros(),
                findings_emitted,
                errors_emitted,
            },
            summary,
        );
        self.record_provider_execution_errors(
            request.normalized_path,
            request.phase,
            result.errors,
            summary,
        );

        for finding in result.findings {
            reconcile_finding(finding, summary);
        }
    }
}
