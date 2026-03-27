use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, atomic::Ordering};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use lintai_api::{
    Applicability, Finding, Fix, Location, ProviderError, ProviderScanResult, RuleMetadata,
    RuleTier, ScanScope, Span, WorkspaceScanContext,
};

use crate::artifact_view::ArtifactContextRef;
use crate::{Engine, EngineBuilder, InProcessProviderBackend, ProviderBackend, SuppressionMatcher};

fn backend(provider: impl lintai_api::RuleProvider + 'static) -> Arc<dyn ProviderBackend> {
    Arc::new(InProcessProviderBackend::new(Arc::new(provider)))
}

fn backend_with_timeout(
    provider: impl lintai_api::RuleProvider + 'static,
    timeout: Duration,
) -> Arc<dyn ProviderBackend> {
    Arc::new(InProcessProviderBackend::with_timeout(
        Arc::new(provider),
        timeout,
    ))
}

struct EmitFindingProvider;

static EMIT_RULES: [RuleMetadata; 1] = [lintai_api::RuleMetadata::new(
    "SEC001",
    "emits one finding",
    lintai_api::Category::Security,
    lintai_api::Severity::Warn,
    lintai_api::Confidence::High,
    RuleTier::Stable,
)];

impl lintai_api::RuleProvider for EmitFindingProvider {
    fn id(&self) -> &str {
        "emit"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &EMIT_RULES
    }

    fn check_result(&self, ctx: &lintai_api::ScanContext) -> ProviderScanResult {
        ProviderScanResult::new(
            vec![Finding::new(
                &self.rules()[0],
                Location::new(ctx.artifact.normalized_path.clone(), Span::new(0, 1)),
                "test finding",
            )],
            Vec::new(),
        )
    }
}

struct FixingProvider;

static FIXING_RULES: [RuleMetadata; 1] = [lintai_api::RuleMetadata::new(
    "SECFIX",
    "emits one fixable finding",
    lintai_api::Category::Security,
    lintai_api::Severity::Warn,
    lintai_api::Confidence::High,
    RuleTier::Stable,
)];

impl lintai_api::RuleProvider for FixingProvider {
    fn id(&self) -> &str {
        "fixing"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &FIXING_RULES
    }

    fn check_result(&self, ctx: &lintai_api::ScanContext) -> ProviderScanResult {
        ProviderScanResult::new(
            vec![
                Finding::new(
                    &self.rules()[0],
                    Location::new(ctx.artifact.normalized_path.clone(), Span::new(0, 1)),
                    "fixable finding",
                )
                .with_fix(Fix::new(
                    Span::new(0, 1),
                    "X",
                    Applicability::Safe,
                    Some("replace first byte".to_owned()),
                )),
            ],
            Vec::new(),
        )
    }
}

struct UndeclaredFindingProvider;

impl lintai_api::RuleProvider for UndeclaredFindingProvider {
    fn id(&self) -> &str {
        "undeclared"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &[]
    }

    fn check_result(&self, ctx: &lintai_api::ScanContext) -> ProviderScanResult {
        ProviderScanResult::new(
            vec![Finding::new(
                &EMIT_RULES[0],
                Location::new(ctx.artifact.normalized_path.clone(), Span::new(0, 1)),
                "bad finding",
            )],
            Vec::new(),
        )
    }
}

struct WrongStableKeyProvider;

impl lintai_api::RuleProvider for WrongStableKeyProvider {
    fn id(&self) -> &str {
        "wrong-stable-key"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &EMIT_RULES
    }

    fn check_result(&self, ctx: &lintai_api::ScanContext) -> ProviderScanResult {
        let mut finding = Finding::new(
            &EMIT_RULES[0],
            Location::new(ctx.artifact.normalized_path.clone(), Span::new(0, 1)),
            "test finding",
        );
        finding.stable_key.normalized_path = "wrong.md".to_owned();
        ProviderScanResult::new(vec![finding], Vec::new())
    }
}

struct ZeroTimeoutProvider;

impl lintai_api::RuleProvider for ZeroTimeoutProvider {
    fn id(&self) -> &str {
        "zero-timeout"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &[]
    }

    fn check_result(&self, _ctx: &lintai_api::ScanContext) -> ProviderScanResult {
        ProviderScanResult::new(Vec::new(), Vec::new())
    }
}

struct WorkspaceFindingProvider;

impl lintai_api::RuleProvider for WorkspaceFindingProvider {
    fn id(&self) -> &str {
        "workspace-finding"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &EMIT_RULES
    }

    fn check_result(&self, _ctx: &lintai_api::ScanContext) -> ProviderScanResult {
        ProviderScanResult::new(Vec::new(), Vec::new())
    }

    fn scan_scope(&self) -> ScanScope {
        ScanScope::Workspace
    }

    fn check_workspace_result(&self, ctx: &WorkspaceScanContext) -> ProviderScanResult {
        let Some(first) = ctx.artifacts.first() else {
            return ProviderScanResult::new(Vec::new(), Vec::new());
        };
        ProviderScanResult::new(
            vec![Finding::new(
                &EMIT_RULES[0],
                Location::new(first.artifact.normalized_path.clone(), Span::new(0, 1)),
                "workspace finding",
            )],
            Vec::new(),
        )
    }
}

struct DuplicateProviderId;

impl lintai_api::RuleProvider for DuplicateProviderId {
    fn id(&self) -> &str {
        "emit"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &[]
    }

    fn check_result(&self, _ctx: &lintai_api::ScanContext) -> ProviderScanResult {
        ProviderScanResult::new(Vec::new(), Vec::new())
    }
}

struct InvalidSpanProvider;

impl lintai_api::RuleProvider for InvalidSpanProvider {
    fn id(&self) -> &str {
        "invalid-span"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &EMIT_RULES
    }

    fn check_result(&self, ctx: &lintai_api::ScanContext) -> ProviderScanResult {
        ProviderScanResult::new(
            vec![Finding::new(
                &EMIT_RULES[0],
                Location::new(
                    ctx.artifact.normalized_path.clone(),
                    Span::new(ctx.content.len() + 1, ctx.content.len() + 3),
                ),
                "invalid span",
            )],
            Vec::new(),
        )
    }
}

struct InvalidFixProvider;

impl lintai_api::RuleProvider for InvalidFixProvider {
    fn id(&self) -> &str {
        "invalid-fix"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &FIXING_RULES
    }

    fn check_result(&self, ctx: &lintai_api::ScanContext) -> ProviderScanResult {
        ProviderScanResult::new(
            vec![
                Finding::new(
                    &FIXING_RULES[0],
                    Location::new(ctx.artifact.normalized_path.clone(), Span::new(0, 1)),
                    "fixable finding",
                )
                .with_fix(Fix::new(
                    Span::new(0, ctx.content.len() + 5),
                    "X",
                    Applicability::Safe,
                    Some("invalid fix".to_owned()),
                )),
            ],
            Vec::new(),
        )
    }
}

struct DuplicateFindingProvider;

impl lintai_api::RuleProvider for DuplicateFindingProvider {
    fn id(&self) -> &str {
        "duplicate-finding"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &EMIT_RULES
    }

    fn check_result(&self, ctx: &lintai_api::ScanContext) -> ProviderScanResult {
        let mut weaker = Finding::new(
            &EMIT_RULES[0],
            Location::new(ctx.artifact.normalized_path.clone(), Span::new(0, 1)),
            "weaker duplicate",
        );
        weaker.severity = lintai_api::Severity::Allow;
        weaker.confidence = lintai_api::Confidence::Low;

        let mut stronger = Finding::new(
            &EMIT_RULES[0],
            Location::new(ctx.artifact.normalized_path.clone(), Span::new(0, 1)),
            "stronger duplicate",
        );
        stronger.severity = lintai_api::Severity::Deny;
        stronger.confidence = lintai_api::Confidence::High;

        ProviderScanResult::new(vec![weaker, stronger], Vec::new())
    }
}

struct RuleIdSuppressor;

impl SuppressionMatcher for RuleIdSuppressor {
    fn is_suppressed(&self, _ctx: &ArtifactContextRef<'_>, finding: &Finding) -> bool {
        finding.rule_code == "SEC001"
    }
}

struct WorkspaceLineColumnProvider;

impl lintai_api::RuleProvider for WorkspaceLineColumnProvider {
    fn id(&self) -> &str {
        "workspace-line-columns"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &EMIT_RULES
    }

    fn check_result(&self, _ctx: &lintai_api::ScanContext) -> ProviderScanResult {
        ProviderScanResult::new(Vec::new(), Vec::new())
    }

    fn scan_scope(&self) -> ScanScope {
        ScanScope::Workspace
    }

    fn check_workspace_result(&self, ctx: &WorkspaceScanContext) -> ProviderScanResult {
        let Some(first) = ctx.artifacts.first() else {
            return ProviderScanResult::new(Vec::new(), Vec::new());
        };
        let start = first.content.find("title").unwrap();
        let end = start + "title".len();
        ProviderScanResult::new(
            vec![Finding::new(
                &EMIT_RULES[0],
                Location::new(
                    first.artifact.normalized_path.clone(),
                    Span::new(start, end),
                ),
                "workspace finding with offset",
            )],
            Vec::new(),
        )
    }
}

struct ExecutionErrorOnlyProvider;

impl lintai_api::RuleProvider for ExecutionErrorOnlyProvider {
    fn id(&self) -> &str {
        "execution-error-only"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &[]
    }

    fn check_result(&self, _ctx: &lintai_api::ScanContext) -> ProviderScanResult {
        ProviderScanResult::new(
            Vec::new(),
            vec![ProviderError::new(self.id(), "provider execution failed")],
        )
    }
}

struct ReportedTimeoutProvider;

impl lintai_api::RuleProvider for ReportedTimeoutProvider {
    fn id(&self) -> &str {
        "reported-timeout"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &[]
    }

    fn check_result(&self, _ctx: &lintai_api::ScanContext) -> ProviderScanResult {
        ProviderScanResult::new(
            Vec::new(),
            vec![ProviderError::timeout(
                self.id(),
                "isolated child terminated after timeout",
            )],
        )
    }
}

struct FindingAndExecutionErrorProvider;

impl lintai_api::RuleProvider for FindingAndExecutionErrorProvider {
    fn id(&self) -> &str {
        "finding-and-execution-error"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &EMIT_RULES
    }

    fn check_result(&self, ctx: &lintai_api::ScanContext) -> ProviderScanResult {
        ProviderScanResult::new(
            vec![Finding::new(
                &EMIT_RULES[0],
                Location::new(ctx.artifact.normalized_path.clone(), Span::new(0, 1)),
                "finding survives execution error",
            )],
            vec![ProviderError::new(self.id(), "partial provider failure")],
        )
    }
}

struct WorkspaceExecutionErrorProvider;

impl lintai_api::RuleProvider for WorkspaceExecutionErrorProvider {
    fn id(&self) -> &str {
        "workspace-execution-error"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &[]
    }

    fn check_result(&self, _ctx: &lintai_api::ScanContext) -> ProviderScanResult {
        ProviderScanResult::new(Vec::new(), Vec::new())
    }

    fn scan_scope(&self) -> ScanScope {
        ScanScope::Workspace
    }

    fn check_workspace_result(&self, _ctx: &WorkspaceScanContext) -> ProviderScanResult {
        ProviderScanResult::new(
            Vec::new(),
            vec![ProviderError::new(
                self.id(),
                "workspace provider execution failed",
            )],
        )
    }
}

#[test]
fn continues_after_invalid_utf8_file() {
    let temp_dir = unique_temp_dir("lintai-invalid-utf8");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# ok\n").unwrap();
    std::fs::write(temp_dir.join("bad.mdc"), [0xFF, 0xFE]).unwrap();

    let summary = Engine::builder().build().scan_path(&temp_dir).unwrap();

    assert_eq!(summary.scanned_files, 1);
    assert_eq!(summary.runtime_errors.len(), 1);
    assert_eq!(summary.runtime_errors[0].normalized_path, "bad.mdc");
}

#[test]
fn rejects_supported_symlink_that_resolves_outside_project_root() {
    let temp_dir = unique_temp_dir("lintai-symlink-escape");
    let outside_path = unique_temp_dir("lintai-symlink-target").join("outside.md");
    std::fs::create_dir_all(temp_dir.join("docs")).unwrap();
    std::fs::create_dir_all(outside_path.parent().unwrap()).unwrap();
    std::fs::write(&outside_path, b"# outside\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside_path, temp_dir.join("docs/SKILL.md")).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&outside_path, temp_dir.join("docs/SKILL.md")).unwrap();

    let config = crate::EngineConfig {
        project_root: Some(temp_dir.clone()),
        ..crate::EngineConfig::default()
    };

    let summary = EngineBuilder::default()
        .with_config(config)
        .build()
        .scan_path(&temp_dir.join("docs/SKILL.md"))
        .unwrap();

    assert_eq!(summary.scanned_files, 0);
    assert_eq!(summary.runtime_errors.len(), 1);
    assert!(
        summary.runtime_errors[0]
            .message
            .contains("outside project root")
    );
}

#[test]
fn does_not_discover_symlinked_directory_outside_project_root() {
    let temp_dir = unique_temp_dir("lintai-symlink-dir-root");
    let outside_dir = unique_temp_dir("lintai-symlink-dir-target");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();
    std::fs::write(outside_dir.join("SKILL.md"), b"# outside\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside_dir, temp_dir.join("linked")).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(&outside_dir, temp_dir.join("linked")).unwrap();

    let config = crate::EngineConfig {
        project_root: Some(temp_dir.clone()),
        follow_symlinks: true,
        ..crate::EngineConfig::default()
    };

    let summary = EngineBuilder::default()
        .with_config(config)
        .build()
        .scan_path(&temp_dir)
        .unwrap();

    assert_eq!(summary.scanned_files, 0);
    assert_eq!(summary.runtime_errors.len(), 0);
}

#[test]
fn suppression_hook_filters_findings() {
    let temp_dir = unique_temp_dir("lintai-suppression");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# ok\n").unwrap();

    let summary = EngineBuilder::default()
        .with_backend(backend(EmitFindingProvider))
        .with_suppressions(Arc::new(RuleIdSuppressor))
        .build()
        .scan_path(&temp_dir)
        .unwrap();

    assert_eq!(summary.findings.len(), 0);
    assert_eq!(summary.scanned_files, 1);
}

#[test]
fn records_per_file_provider_execution_errors_without_findings() {
    let temp_dir = unique_temp_dir("lintai-provider-execution-error");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# ok\n").unwrap();

    let summary = EngineBuilder::default()
        .with_backend(backend(ExecutionErrorOnlyProvider))
        .build()
        .scan_path(&temp_dir)
        .unwrap();

    assert!(summary.findings.is_empty());
    assert_eq!(summary.runtime_errors.len(), 1);
    let error = &summary.runtime_errors[0];
    assert_eq!(error.kind, crate::RuntimeErrorKind::ProviderExecution);
    assert_eq!(error.provider_id.as_deref(), Some("execution-error-only"));
    assert_eq!(error.phase, Some(crate::ProviderExecutionPhase::File));
    assert_eq!(error.normalized_path, "SKILL.md");
}

#[test]
fn keeps_findings_when_provider_reports_execution_errors() {
    let temp_dir = unique_temp_dir("lintai-provider-findings-and-errors");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# ok\n").unwrap();

    let summary = EngineBuilder::default()
        .with_backend(backend(FindingAndExecutionErrorProvider))
        .build()
        .scan_path(&temp_dir)
        .unwrap();

    assert_eq!(summary.findings.len(), 1);
    assert_eq!(
        summary.findings[0].message,
        "finding survives execution error"
    );
    assert_eq!(summary.runtime_errors.len(), 1);
    assert_eq!(
        summary.runtime_errors[0].kind,
        crate::RuntimeErrorKind::ProviderExecution
    );
    assert_eq!(
        summary.runtime_errors[0].provider_id.as_deref(),
        Some("finding-and-execution-error")
    );
}

#[test]
fn preserves_timeout_runtime_kind_when_provider_reports_timeout() {
    let temp_dir = unique_temp_dir("lintai-provider-reported-timeout");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# ok\n").unwrap();

    let summary = EngineBuilder::default()
        .with_backend(backend(ReportedTimeoutProvider))
        .build()
        .scan_path(&temp_dir)
        .unwrap();

    assert!(summary.findings.is_empty());
    assert_eq!(summary.runtime_errors.len(), 1);
    let error = &summary.runtime_errors[0];
    assert_eq!(error.kind, crate::RuntimeErrorKind::ProviderTimeout);
    assert_eq!(error.provider_id.as_deref(), Some("reported-timeout"));
    assert_eq!(error.phase, Some(crate::ProviderExecutionPhase::File));
}

#[test]
fn derives_line_columns_for_findings() {
    let temp_dir = unique_temp_dir("lintai-line-columns");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# title\n").unwrap();

    let summary = EngineBuilder::default()
        .with_backend(backend(EmitFindingProvider))
        .build()
        .scan_path(&temp_dir)
        .unwrap();

    let finding = &summary.findings[0];
    assert_eq!(finding.location.start.as_ref().map(|pos| pos.line), Some(1));
    assert_eq!(
        finding.location.start.as_ref().map(|pos| pos.column),
        Some(1)
    );
    assert_eq!(finding.location.end.as_ref().map(|pos| pos.line), Some(1));
    assert_eq!(finding.location.end.as_ref().map(|pos| pos.column), Some(2));
}

#[test]
fn keeps_fix_when_finding_carries_safe_fix() {
    let temp_dir = unique_temp_dir("lintai-fix-hook");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# title\n").unwrap();

    let summary = EngineBuilder::default()
        .with_backend(backend(FixingProvider))
        .build()
        .scan_path(&temp_dir)
        .unwrap();

    assert_eq!(summary.findings.len(), 1);
    assert!(summary.findings[0].fix.is_some());
}

#[test]
fn skips_undeclared_provider_rule_and_reports_diagnostic() {
    let temp_dir = unique_temp_dir("lintai-undeclared-rule");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# title\n").unwrap();

    let summary = EngineBuilder::default()
        .with_backend(backend(UndeclaredFindingProvider))
        .build()
        .scan_path(&temp_dir)
        .unwrap();

    assert!(summary.findings.is_empty());
    assert!(summary.diagnostics.iter().any(|diagnostic| {
        diagnostic.code.as_deref() == Some("provider_contract")
            && diagnostic.message.contains("undeclared rule code")
    }));
}

#[test]
fn normalizes_non_canonical_stable_key_and_reports_diagnostic() {
    let temp_dir = unique_temp_dir("lintai-stable-key-normalize");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# title\n").unwrap();

    let summary = EngineBuilder::default()
        .with_backend(backend(WrongStableKeyProvider))
        .build()
        .scan_path(&temp_dir)
        .unwrap();

    assert_eq!(summary.findings.len(), 1);
    assert_eq!(summary.findings[0].stable_key.normalized_path, "SKILL.md");
    assert!(summary.diagnostics.iter().any(|diagnostic| {
        diagnostic.code.as_deref() == Some("provider_contract")
            && diagnostic.message.contains("non-canonical stable_key")
    }));
}

#[test]
fn rejects_duplicate_provider_ids() {
    let temp_dir = unique_temp_dir("lintai-duplicate-provider-id");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# title\n").unwrap();

    let error = EngineBuilder::default()
        .with_backend(backend(EmitFindingProvider))
        .with_backend(backend(DuplicateProviderId))
        .build()
        .scan_path(&temp_dir)
        .unwrap_err();

    assert!(error.to_string().contains("duplicate provider id"));
}

#[test]
fn rejects_zero_timeout_provider_contract() {
    let temp_dir = unique_temp_dir("lintai-zero-timeout");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# title\n").unwrap();

    let error = EngineBuilder::default()
        .with_backend(backend_with_timeout(ZeroTimeoutProvider, Duration::ZERO))
        .build()
        .scan_path(&temp_dir)
        .unwrap_err();

    assert!(error.to_string().contains("zero timeout"));
}

#[test]
fn workspace_provider_emits_findings_after_parse_pass() {
    let temp_dir = unique_temp_dir("lintai-workspace-provider");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# title\n").unwrap();

    let summary = EngineBuilder::default()
        .with_backend(backend(WorkspaceFindingProvider))
        .build()
        .scan_path(&temp_dir)
        .unwrap();

    assert_eq!(summary.findings.len(), 1);
    assert_eq!(summary.findings[0].message, "workspace finding");
}

#[test]
fn workspace_findings_derive_line_columns_without_rebuilding_scan_context() {
    let temp_dir = unique_temp_dir("lintai-workspace-line-columns");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# title\n").unwrap();

    let summary = EngineBuilder::default()
        .with_backend(backend(WorkspaceLineColumnProvider))
        .build()
        .scan_path(&temp_dir)
        .unwrap();

    assert_eq!(summary.findings.len(), 1);
    let finding = &summary.findings[0];
    assert_eq!(finding.location.start.as_ref().map(|pos| pos.line), Some(1));
    assert_eq!(
        finding.location.start.as_ref().map(|pos| pos.column),
        Some(3)
    );
    assert_eq!(finding.location.end.as_ref().map(|pos| pos.line), Some(1));
    assert_eq!(finding.location.end.as_ref().map(|pos| pos.column), Some(8));
}

#[test]
fn suppression_hook_filters_workspace_findings() {
    let temp_dir = unique_temp_dir("lintai-workspace-suppression");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# ok\n").unwrap();

    let summary = EngineBuilder::default()
        .with_backend(backend(WorkspaceFindingProvider))
        .with_suppressions(Arc::new(RuleIdSuppressor))
        .build()
        .scan_path(&temp_dir)
        .unwrap();

    assert_eq!(summary.findings.len(), 0);
    assert_eq!(summary.scanned_files, 1);
}

#[test]
fn records_workspace_provider_execution_errors() {
    let temp_dir = unique_temp_dir("lintai-workspace-provider-execution-error");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# ok\n").unwrap();
    let config = crate::EngineConfig {
        project_root: Some(temp_dir.clone()),
        ..crate::EngineConfig::default()
    };

    let summary = EngineBuilder::default()
        .with_config(config)
        .with_backend(backend(WorkspaceExecutionErrorProvider))
        .build()
        .scan_path(&temp_dir)
        .unwrap();

    assert!(summary.findings.is_empty());
    assert_eq!(summary.runtime_errors.len(), 1);
    let error = &summary.runtime_errors[0];
    assert_eq!(error.kind, crate::RuntimeErrorKind::ProviderExecution);
    assert_eq!(
        error.provider_id.as_deref(),
        Some("workspace-execution-error")
    );
    assert_eq!(error.phase, Some(crate::ProviderExecutionPhase::Workspace));
    assert_eq!(error.normalized_path, temp_dir.display().to_string());
}

#[test]
fn drops_invalid_finding_span_and_reports_diagnostic() {
    let temp_dir = unique_temp_dir("lintai-invalid-span");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# title\n").unwrap();

    let summary = EngineBuilder::default()
        .with_backend(backend(InvalidSpanProvider))
        .build()
        .scan_path(&temp_dir)
        .unwrap();

    assert!(summary.findings.is_empty());
    assert!(summary.diagnostics.iter().any(|diagnostic| {
        diagnostic.code.as_deref() == Some("provider_contract")
            && diagnostic.message.contains("invalid span")
    }));
}

#[test]
fn drops_invalid_fix_and_keeps_finding() {
    let temp_dir = unique_temp_dir("lintai-invalid-fix");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# title\n").unwrap();

    let summary = EngineBuilder::default()
        .with_backend(backend(InvalidFixProvider))
        .build()
        .scan_path(&temp_dir)
        .unwrap();

    assert_eq!(summary.findings.len(), 1);
    assert!(summary.findings[0].fix.is_none());
    assert!(summary.diagnostics.iter().any(|diagnostic| {
        diagnostic.code.as_deref() == Some("provider_contract")
            && diagnostic.message.contains("invalid fix span")
    }));
}

#[test]
fn deduplicates_findings_by_stable_key_keeping_stronger_one() {
    let temp_dir = unique_temp_dir("lintai-dedup-findings");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# title\n").unwrap();

    let summary = EngineBuilder::default()
        .with_backend(backend(DuplicateFindingProvider))
        .build()
        .scan_path(&temp_dir)
        .unwrap();

    assert_eq!(summary.findings.len(), 1);
    assert_eq!(summary.findings[0].severity, lintai_api::Severity::Deny);
    assert_eq!(summary.findings[0].message, "stronger duplicate");
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{nanos}-{sequence}",
        std::process::id()
    ))
}
