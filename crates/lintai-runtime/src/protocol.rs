use lintai_api::{ProviderScanResult, ScanContext, WorkspaceScanContext};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerPhase {
    File,
    Workspace,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct RunnerRequest<S> {
    pub provider: S,
    pub phase: RunnerPhase,
    pub scan: Option<ScanContext>,
    pub workspace: Option<WorkspaceScanContext>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct RunnerResponse {
    pub result: ProviderScanResult,
}
