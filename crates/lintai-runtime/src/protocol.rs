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

#[cfg(test)]
mod tests {
    use super::*;
    use lintai_api::ProviderScanResult;

    #[test]
    fn runner_phase_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&RunnerPhase::File).unwrap(),
            "\"file\""
        );
        assert_eq!(
            serde_json::to_string(&RunnerPhase::Workspace).unwrap(),
            "\"workspace\""
        );
    }

    #[test]
    fn runner_phase_round_trips_from_json() {
        let file: RunnerPhase = serde_json::from_str("\"file\"").unwrap();
        let workspace: RunnerPhase = serde_json::from_str("\"workspace\"").unwrap();
        assert_eq!(file, RunnerPhase::File);
        assert_eq!(workspace, RunnerPhase::Workspace);
    }

    #[test]
    fn runner_request_round_trips_json() {
        let request = RunnerRequest {
            provider: "policy",
            phase: RunnerPhase::Workspace,
            scan: None,
            workspace: None,
        };

        let payload = serde_json::to_string(&request).unwrap();
        let decoded: RunnerRequest<&str> = serde_json::from_str(&payload).unwrap();

        assert_eq!(decoded.provider, "policy");
        assert_eq!(decoded.phase, RunnerPhase::Workspace);
        assert!(decoded.scan.is_none());
        assert!(decoded.workspace.is_none());
    }

    #[test]
    fn runner_response_round_trips_json() {
        let response = RunnerResponse {
            result: ProviderScanResult::new(Vec::new(), Vec::new()),
        };
        let _payload = serde_json::to_string(&response).unwrap();
        let decoded: RunnerResponse = serde_json::to_string(&response)
            .ok()
            .and_then(|encoded| serde_json::from_str(&encoded).ok())
            .unwrap();
        assert_eq!(decoded.result, response.result);
    }

    #[test]
    fn runner_request_handles_provider_payloads() {
        let request = RunnerRequest {
            provider: vec!["a", "b", "c"],
            phase: RunnerPhase::File,
            scan: None,
            workspace: None,
        };
        let payload = serde_json::to_vec(&request).unwrap();
        let decoded: RunnerRequest<Vec<&str>> = serde_json::from_slice(&payload).unwrap();

        assert_eq!(decoded.provider, vec!["a", "b", "c"]);
        assert_eq!(decoded.phase, RunnerPhase::File);
    }
}
