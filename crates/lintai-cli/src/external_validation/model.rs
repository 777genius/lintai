use super::*;

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct RepoShortlist {
    #[allow(dead_code)]
    pub version: u32,
    pub repos: Vec<ShortlistRepo>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct ShortlistRepo {
    pub repo: String,
    pub url: String,
    pub pinned_ref: String,
    pub category: String,
    pub subtype: String,
    pub status: String,
    pub surfaces_present: Vec<String>,
    #[serde(default)]
    pub admission_paths: Vec<String>,
    #[allow(dead_code)]
    pub rationale: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct ExternalValidationLedger {
    pub version: u32,
    #[serde(default)]
    pub wave: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<String>,
    #[serde(default)]
    pub evaluations: Vec<EvaluationEntry>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct EvaluationEntry {
    pub repo: String,
    pub url: String,
    pub pinned_ref: String,
    pub category: String,
    pub subtype: String,
    pub status: String,
    pub surfaces_present: Vec<String>,
    pub stable_findings: usize,
    pub preview_findings: usize,
    pub stable_rule_codes: Vec<String>,
    pub preview_rule_codes: Vec<String>,
    pub repo_verdict: String,
    pub stable_precision_notes: String,
    pub preview_signal_notes: String,
    pub false_positive_notes: Vec<FindingNote>,
    pub possible_false_negative_notes: Vec<FindingNote>,
    pub follow_up_action: String,
    #[serde(default)]
    pub runtime_errors: Vec<RuntimeErrorRecord>,
    #[serde(default)]
    pub diagnostics: Vec<DiagnosticRecord>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct FindingNote {
    #[serde(default)]
    pub rule_code: Option<String>,
    #[serde(default)]
    pub verdict: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub problem: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct RuntimeErrorRecord {
    pub path: String,
    pub kind: String,
    pub message: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct DiagnosticRecord {
    pub path: String,
    pub severity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct JsonScanEnvelope {
    pub(crate) findings: Vec<JsonFinding>,
    #[serde(default)]
    pub(crate) diagnostics: Vec<JsonDiagnostic>,
    #[serde(default)]
    pub(crate) runtime_errors: Vec<JsonRuntimeError>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct JsonFinding {
    pub(crate) rule_code: String,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct JsonDiagnostic {
    pub(crate) normalized_path: String,
    pub(crate) severity: String,
    pub(crate) code: Option<String>,
    pub(crate) message: String,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct JsonRuntimeError {
    pub(crate) normalized_path: String,
    pub(crate) kind: String,
    pub(crate) message: String,
}

#[derive(Clone, Debug)]
pub(crate) struct RerunOptions {
    pub workspace_root: PathBuf,
    pub package: ValidationPackage,
    pub lintai_bin: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub(crate) struct RenderReportOptions {
    pub workspace_root: PathBuf,
    pub package: ValidationPackage,
}
