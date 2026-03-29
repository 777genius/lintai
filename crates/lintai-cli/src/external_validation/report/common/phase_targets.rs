use crate::external_validation::ExternalValidationLedger;

pub(crate) enum PhaseTargetKind {
    DatadogSec105,
    InvalidYamlRecovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PhaseTargetStatus {
    Improved,
    Unchanged,
    Regressed,
}

pub(crate) fn target_status_label(status: PhaseTargetStatus) -> &'static str {
    match status {
        PhaseTargetStatus::Improved => "improved",
        PhaseTargetStatus::Unchanged => "stayed unchanged",
        PhaseTargetStatus::Regressed => "regressed",
    }
}

pub(crate) fn phase_target_status(
    baseline: &ExternalValidationLedger,
    current: &ExternalValidationLedger,
    repo: &str,
    kind: PhaseTargetKind,
) -> PhaseTargetStatus {
    let baseline = baseline.evaluations.iter().find(|entry| entry.repo == repo);
    let current = current.evaluations.iter().find(|entry| entry.repo == repo);
    let Some((baseline, current)) = baseline.zip(current) else {
        return PhaseTargetStatus::Unchanged;
    };

    match kind {
        PhaseTargetKind::DatadogSec105 => {
            compare_counts(baseline.preview_findings, current.preview_findings)
        }
        PhaseTargetKind::InvalidYamlRecovery => {
            compare_counts(baseline.runtime_errors.len(), current.runtime_errors.len())
        }
    }
}

pub(crate) fn compare_counts(before: usize, after: usize) -> PhaseTargetStatus {
    match after.cmp(&before) {
        std::cmp::Ordering::Less => PhaseTargetStatus::Improved,
        std::cmp::Ordering::Equal => PhaseTargetStatus::Unchanged,
        std::cmp::Ordering::Greater => PhaseTargetStatus::Regressed,
    }
}
