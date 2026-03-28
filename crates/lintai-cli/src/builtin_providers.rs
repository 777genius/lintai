mod backend;
mod kind;
mod product;
mod runner;
#[cfg(debug_assertions)]
mod test_support;

pub(crate) use product::product_provider_set;
pub(crate) use runner::run_provider_runner;

#[cfg(test)]
mod tests {
    use super::{backend::IsolatedBuiltInBackend, kind::BuiltInProviderKind};
    use lintai_api::{Artifact, ArtifactKind, ScanContext, SourceFormat};
    use lintai_runtime::{ProviderBackend, RunnerPhase, RunnerRequest};

    use crate::internal_bin::resolve_lintai_driver_path;

    fn scan_context() -> ScanContext {
        let artifact = Artifact::new("SKILL.md", ArtifactKind::Skill, SourceFormat::Markdown);
        let content = "# demo\n";
        let document = serde_json::from_value(serde_json::json!({
            "regions": [],
            "raw_frontmatter": null
        }))
        .unwrap();
        ScanContext::new(artifact, content, document, None)
    }

    #[test]
    fn resolves_real_lintai_driver_near_test_binary() {
        let path = resolve_lintai_driver_path().unwrap();
        assert!(path.exists());
        assert!(
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .contains("lintai")
        );
    }

    #[test]
    fn isolated_timeout_provider_returns_timeout_error() {
        let provider = IsolatedBuiltInBackend::new(BuiltInProviderKind::TestTimeout);
        let result = provider.check_result(&scan_context());

        assert!(result.findings.is_empty());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].provider_id, "__test-timeout");
        assert_eq!(
            result.errors[0].kind,
            lintai_api::ProviderErrorKind::Timeout
        );
    }

    #[test]
    fn isolated_panic_provider_returns_execution_error() {
        let provider = IsolatedBuiltInBackend::new(BuiltInProviderKind::TestPanic);
        let result = provider.check_result(&scan_context());

        assert!(result.findings.is_empty());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(
            result.errors[0].kind,
            lintai_api::ProviderErrorKind::Execution
        );
    }

    #[test]
    fn isolated_partial_error_provider_preserves_findings_and_errors() {
        let provider = IsolatedBuiltInBackend::new(BuiltInProviderKind::TestPartialError);
        let result = provider.check_result(&scan_context());

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].message, "isolated child finding");
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].provider_id, "__test-partial-error");
    }

    #[test]
    fn runner_request_serializes_schema_and_phase() {
        let request = RunnerRequest {
            provider: BuiltInProviderKind::TestTimeout,
            phase: RunnerPhase::File,
            scan: Some(scan_context()),
            workspace: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"phase\":\"file\""));
    }
}
