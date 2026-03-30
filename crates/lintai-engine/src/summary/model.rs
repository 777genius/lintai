use lintai_api::Finding;
use serde::Serialize;

#[derive(Clone, Debug, Default, Serialize)]
pub struct ScanSummary {
    pub scanned_files: usize,
    pub skipped_files: usize,
    pub findings: Vec<Finding>,
    pub diagnostics: Vec<ScanDiagnostic>,
    pub runtime_errors: Vec<ScanRuntimeError>,
    pub provider_metrics: Vec<ProviderExecutionMetric>,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderExecutionMetric {
    pub normalized_path: String,
    pub provider_id: String,
    pub phase: ProviderExecutionPhase,
    pub elapsed_us: u128,
    pub findings_emitted: usize,
    pub errors_emitted: usize,
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
