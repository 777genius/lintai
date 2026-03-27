use lintai_api::Finding;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, Serialize)]
pub struct ScanSummary {
    pub scanned_files: usize,
    pub skipped_files: usize,
    pub findings: Vec<Finding>,
    pub diagnostics: Vec<ScanDiagnostic>,
    pub runtime_errors: Vec<ScanRuntimeError>,
}

impl ScanSummary {
    pub(crate) fn finalize(&mut self) {
        self.dedup_and_sort_findings();
        self.dedup_and_sort_diagnostics();
        self.dedup_and_sort_runtime_errors();
    }

    fn dedup_and_sort_findings(&mut self) {
        let mut findings_by_key = BTreeMap::new();
        for finding in self.findings.drain(..) {
            let key = FindingKey::from(&finding);
            match findings_by_key.get(&key) {
                Some(existing) if !is_better_finding(&finding, existing) => {}
                _ => {
                    findings_by_key.insert(key, finding);
                }
            }
        }
        self.findings = findings_by_key.into_values().collect();
    }

    fn dedup_and_sort_diagnostics(&mut self) {
        let mut seen = BTreeSet::new();
        self.diagnostics.retain(|diagnostic| {
            seen.insert((
                diagnostic.normalized_path.clone(),
                diagnostic.severity,
                diagnostic.code.clone(),
                diagnostic.message.clone(),
            ))
        });
        self.diagnostics.sort_by(|left, right| {
            (
                left.normalized_path.as_str(),
                diagnostic_rank(left.severity),
                left.code.as_deref().unwrap_or(""),
                left.message.as_str(),
            )
                .cmp(&(
                    right.normalized_path.as_str(),
                    diagnostic_rank(right.severity),
                    right.code.as_deref().unwrap_or(""),
                    right.message.as_str(),
                ))
        });
    }

    fn dedup_and_sort_runtime_errors(&mut self) {
        let mut seen = BTreeSet::new();
        self.runtime_errors.retain(|error| {
            seen.insert((
                error.normalized_path.clone(),
                error.kind,
                error.provider_id.clone(),
                error.phase,
                error.message.clone(),
            ))
        });
        self.runtime_errors.sort_by(|left, right| {
            (
                left.normalized_path.as_str(),
                runtime_error_rank(left.kind),
                left.provider_id.as_deref().unwrap_or(""),
                left.phase,
                left.message.as_str(),
            )
                .cmp(&(
                    right.normalized_path.as_str(),
                    runtime_error_rank(right.kind),
                    right.provider_id.as_deref().unwrap_or(""),
                    right.phase,
                    right.message.as_str(),
                ))
        });
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScanDiagnostic {
    pub normalized_path: String,
    pub severity: DiagnosticSeverity,
    pub code: Option<String>,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticSeverity {
    Info,
    Warn,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScanRuntimeError {
    pub normalized_path: String,
    pub kind: RuntimeErrorKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<ProviderExecutionPhase>,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderExecutionPhase {
    File,
    Workspace,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeErrorKind {
    Read,
    InvalidUtf8,
    Parse,
    ProviderExecution,
    ProviderTimeout,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct FindingKey {
    rule_code: String,
    normalized_path: String,
    start_byte: usize,
    end_byte: usize,
    subject_id: Option<String>,
}

impl From<&Finding> for FindingKey {
    fn from(value: &Finding) -> Self {
        Self {
            rule_code: value.stable_key.rule_code.clone(),
            normalized_path: value.stable_key.normalized_path.clone(),
            start_byte: value.stable_key.span.start_byte,
            end_byte: value.stable_key.span.end_byte,
            subject_id: value.stable_key.subject_id.clone(),
        }
    }
}

fn is_better_finding(candidate: &Finding, current: &Finding) -> bool {
    (
        severity_rank(candidate.severity),
        confidence_rank(candidate.confidence),
        candidate.message.as_str(),
    ) > (
        severity_rank(current.severity),
        confidence_rank(current.confidence),
        current.message.as_str(),
    )
}

fn diagnostic_rank(severity: DiagnosticSeverity) -> u8 {
    match severity {
        DiagnosticSeverity::Info => 0,
        DiagnosticSeverity::Warn => 1,
    }
}

fn runtime_error_rank(kind: RuntimeErrorKind) -> u8 {
    match kind {
        RuntimeErrorKind::Read => 0,
        RuntimeErrorKind::InvalidUtf8 => 1,
        RuntimeErrorKind::Parse => 2,
        RuntimeErrorKind::ProviderExecution => 3,
        RuntimeErrorKind::ProviderTimeout => 4,
    }
}

fn severity_rank(severity: lintai_api::Severity) -> u8 {
    match severity {
        lintai_api::Severity::Allow => 0,
        lintai_api::Severity::Warn => 1,
        lintai_api::Severity::Deny => 2,
    }
}

fn confidence_rank(confidence: lintai_api::Confidence) -> u8 {
    match confidence {
        lintai_api::Confidence::Low => 0,
        lintai_api::Confidence::Medium => 1,
        lintai_api::Confidence::High => 2,
    }
}
