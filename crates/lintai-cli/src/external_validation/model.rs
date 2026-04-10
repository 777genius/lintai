use super::*;
use lintai_api::{Location, StableKey};

fn default_ownership() -> String {
    "community".to_owned()
}

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
    #[serde(default = "default_ownership")]
    pub ownership: String,
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
    #[serde(default = "default_ownership")]
    pub ownership: String,
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
    #[serde(default)]
    pub lane_summaries: Vec<LaneSummary>,
    #[serde(default)]
    pub recommended_stable_hits: Vec<ObservedFindingRecord>,
    #[serde(default)]
    pub recommended_stable_adjudications: Vec<RecommendedStableAdjudication>,
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

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct LaneSummary {
    pub lane_id: String,
    pub stable_findings: usize,
    pub preview_findings: usize,
    pub stable_rule_codes: Vec<String>,
    pub preview_rule_codes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AdjudicationVerdict {
    ConfirmedIssue,
    FalsePositive,
    AcceptedHardeningHit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ObservedFindingRecord {
    pub stable_key: StableKey,
    pub rule_code: String,
    pub normalized_path: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct RecommendedStableAdjudication {
    pub stable_key: StableKey,
    pub rule_code: String,
    pub verdict: AdjudicationVerdict,
    pub summary: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct JsonScanEnvelope {
    pub(crate) findings: Vec<JsonFinding>,
    #[serde(default)]
    pub(crate) diagnostics: Vec<JsonDiagnostic>,
    #[serde(default)]
    pub(crate) runtime_errors: Vec<JsonRuntimeError>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct JsonFinding {
    pub(crate) rule_code: String,
    pub(crate) stable_key: StableKey,
    pub(crate) location: Location,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct JsonDiagnostic {
    pub(crate) normalized_path: String,
    pub(crate) severity: String,
    pub(crate) code: Option<String>,
    pub(crate) message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct JsonRuntimeError {
    pub(crate) normalized_path: String,
    pub(crate) kind: String,
    pub(crate) message: String,
}

#[derive(Clone, Debug)]
pub(crate) struct RerunOptions {
    pub package: ValidationPackage,
    pub lintai_bin: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub(crate) struct RenderReportOptions {
    pub package: ValidationPackage,
}
