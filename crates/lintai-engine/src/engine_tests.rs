use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use lintai_api::{
    Applicability, Finding, Fix, Location, ProviderCapabilities, ProviderError, RuleMetadata,
    ProviderScanResult, RuleTier, ScanScope, Span, WorkspaceScanContext,
};

use crate::artifact_view::ArtifactContextRef;
use crate::{Engine, EngineBuilder, SuppressionMatcher};

struct CountingProvider {
    id: &'static str,
    starts: Arc<AtomicUsize>,
    finishes: Arc<AtomicUsize>,
}

impl lintai_api::RuleProvider for CountingProvider {
    fn id(&self) -> &str {
        self.id
    }

    fn rules(&self) -> &[RuleMetadata] {
        &[]
    }

    fn check(&self, _ctx: &lintai_api::ScanContext) -> Vec<lintai_api::Finding> {
        Vec::new()
    }

    fn on_start(&self) -> Result<(), ProviderError> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn on_finish(&self) -> Result<(), ProviderError> {
        self.finishes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct FailingStartProvider {
    starts: Arc<AtomicUsize>,
    finishes: Arc<AtomicUsize>,
}

impl lintai_api::RuleProvider for FailingStartProvider {
    fn id(&self) -> &str {
        "failing-start"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &[]
    }

    fn check(&self, _ctx: &lintai_api::ScanContext) -> Vec<lintai_api::Finding> {
        Vec::new()
    }

    fn on_start(&self) -> Result<(), ProviderError> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        Err(ProviderError::new(self.id(), "startup failed"))
    }

    fn on_finish(&self) -> Result<(), ProviderError> {
        self.finishes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct FailingFinishProvider {
    finishes: Arc<AtomicUsize>,
}

impl lintai_api::RuleProvider for FailingFinishProvider {
    fn id(&self) -> &str {
        "failing-finish"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &[]
    }

    fn check(&self, _ctx: &lintai_api::ScanContext) -> Vec<lintai_api::Finding> {
        Vec::new()
    }

    fn on_finish(&self) -> Result<(), ProviderError> {
        self.finishes.fetch_add(1, Ordering::SeqCst);
        Err(ProviderError::new(self.id(), "finish failed"))
    }
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

    fn check(&self, ctx: &lintai_api::ScanContext) -> Vec<lintai_api::Finding> {
        vec![Finding::new(
            &self.rules()[0],
            Location::new(ctx.artifact.normalized_path.clone(), Span::new(0, 1)),
            "test finding",
        )]
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

    fn check(&self, ctx: &lintai_api::ScanContext) -> Vec<lintai_api::Finding> {
        vec![Finding::new(
            &self.rules()[0],
            Location::new(ctx.artifact.normalized_path.clone(), Span::new(0, 1)),
            "fixable finding",
        )]
    }

    fn supports_fix(&self) -> bool {
        true
    }

    fn fix(&self, _ctx: &lintai_api::ScanContext, _finding: &Finding) -> Option<Fix> {
        Some(Fix::new(
            Span::new(0, 1),
            "X",
            Applicability::Safe,
            Some("replace first byte".to_owned()),
        ))
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

    fn check(&self, ctx: &lintai_api::ScanContext) -> Vec<lintai_api::Finding> {
        vec![Finding::new(
            &EMIT_RULES[0],
            Location::new(ctx.artifact.normalized_path.clone(), Span::new(0, 1)),
            "bad finding",
        )]
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

    fn check(&self, ctx: &lintai_api::ScanContext) -> Vec<lintai_api::Finding> {
        let mut finding = Finding::new(
            &EMIT_RULES[0],
            Location::new(ctx.artifact.normalized_path.clone(), Span::new(0, 1)),
            "test finding",
        );
        finding.stable_key.normalized_path = "wrong.md".to_owned();
        vec![finding]
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

    fn check(&self, _ctx: &lintai_api::ScanContext) -> Vec<lintai_api::Finding> {
        Vec::new()
    }

    fn timeout(&self) -> Duration {
        Duration::ZERO
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

    fn check(&self, _ctx: &lintai_api::ScanContext) -> Vec<lintai_api::Finding> {
        Vec::new()
    }

    fn scan_scope(&self) -> ScanScope {
        ScanScope::Workspace
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::new(false, false)
    }

    fn check_workspace(&self, ctx: &WorkspaceScanContext) -> Vec<lintai_api::Finding> {
        let Some(first) = ctx.artifacts.first() else {
            return Vec::new();
        };
        vec![Finding::new(
            &EMIT_RULES[0],
            Location::new(first.artifact.normalized_path.clone(), Span::new(0, 1)),
            "workspace finding",
        )]
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

    fn check(&self, _ctx: &lintai_api::ScanContext) -> Vec<lintai_api::Finding> {
        Vec::new()
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

    fn check(&self, ctx: &lintai_api::ScanContext) -> Vec<lintai_api::Finding> {
        vec![Finding::new(
            &EMIT_RULES[0],
            Location::new(
                ctx.artifact.normalized_path.clone(),
                Span::new(ctx.content.len() + 1, ctx.content.len() + 3),
            ),
            "invalid span",
        )]
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

    fn check(&self, ctx: &lintai_api::ScanContext) -> Vec<lintai_api::Finding> {
        vec![Finding::new(
            &FIXING_RULES[0],
            Location::new(ctx.artifact.normalized_path.clone(), Span::new(0, 1)),
            "fixable finding",
        )]
    }

    fn supports_fix(&self) -> bool {
        true
    }

    fn fix(&self, ctx: &lintai_api::ScanContext, _finding: &Finding) -> Option<Fix> {
        Some(Fix::new(
            Span::new(0, ctx.content.len() + 5),
            "X",
            Applicability::Safe,
            Some("invalid fix".to_owned()),
        ))
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

    fn check(&self, ctx: &lintai_api::ScanContext) -> Vec<lintai_api::Finding> {
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

        vec![weaker, stronger]
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

    fn check(&self, _ctx: &lintai_api::ScanContext) -> Vec<lintai_api::Finding> {
        Vec::new()
    }

    fn scan_scope(&self) -> ScanScope {
        ScanScope::Workspace
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::new(false, false)
    }

    fn check_workspace(&self, ctx: &WorkspaceScanContext) -> Vec<lintai_api::Finding> {
        let Some(first) = ctx.artifacts.first() else {
            return Vec::new();
        };
        let start = first.content.find("title").unwrap();
        let end = start + "title".len();
        vec![Finding::new(
            &EMIT_RULES[0],
            Location::new(first.artifact.normalized_path.clone(), Span::new(start, end)),
            "workspace finding with offset",
        )]
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

    fn check(&self, _ctx: &lintai_api::ScanContext) -> Vec<lintai_api::Finding> {
        Vec::new()
    }

    fn check_result(&self, _ctx: &lintai_api::ScanContext) -> ProviderScanResult {
        ProviderScanResult::new(
            Vec::new(),
            vec![ProviderError::new(self.id(), "provider execution failed")],
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

    fn check(&self, ctx: &lintai_api::ScanContext) -> Vec<lintai_api::Finding> {
        vec![Finding::new(
            &EMIT_RULES[0],
            Location::new(ctx.artifact.normalized_path.clone(), Span::new(0, 1)),
            "finding survives execution error",
        )]
    }

    fn check_result(&self, ctx: &lintai_api::ScanContext) -> ProviderScanResult {
        ProviderScanResult::new(
            self.check(ctx),
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

    fn check(&self, _ctx: &lintai_api::ScanContext) -> Vec<lintai_api::Finding> {
        Vec::new()
    }

    fn scan_scope(&self) -> ScanScope {
        ScanScope::Workspace
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::new(false, false)
    }

    fn check_workspace_result(&self, _ctx: &WorkspaceScanContext) -> ProviderScanResult {
        ProviderScanResult::new(
            Vec::new(),
            vec![ProviderError::new(self.id(), "workspace provider execution failed")],
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
fn finish_runs_even_when_scan_setup_fails() {
    let starts = Arc::new(AtomicUsize::new(0));
    let finishes = Arc::new(AtomicUsize::new(0));
    let engine = EngineBuilder::default()
        .with_provider(Arc::new(CountingProvider {
            id: "counting-setup",
            starts: Arc::clone(&starts),
            finishes: Arc::clone(&finishes),
        }))
        .build();

    let result = engine.scan_path(Path::new("/definitely/missing/lintai"));

    assert!(result.is_err());
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(finishes.load(Ordering::SeqCst), 1);
}

#[test]
fn started_providers_are_finished_when_later_start_fails() {
    let first_starts = Arc::new(AtomicUsize::new(0));
    let first_finishes = Arc::new(AtomicUsize::new(0));
    let failing_starts = Arc::new(AtomicUsize::new(0));
    let failing_finishes = Arc::new(AtomicUsize::new(0));

    let engine = EngineBuilder::default()
        .with_provider(Arc::new(CountingProvider {
            id: "counting-first",
            starts: Arc::clone(&first_starts),
            finishes: Arc::clone(&first_finishes),
        }))
        .with_provider(Arc::new(FailingStartProvider {
            starts: Arc::clone(&failing_starts),
            finishes: Arc::clone(&failing_finishes),
        }))
        .build();

    let result = engine.scan_path(Path::new("."));

    assert!(result.is_err());
    assert_eq!(first_starts.load(Ordering::SeqCst), 1);
    assert_eq!(first_finishes.load(Ordering::SeqCst), 1);
    assert_eq!(failing_starts.load(Ordering::SeqCst), 1);
    assert_eq!(failing_finishes.load(Ordering::SeqCst), 0);
}

#[test]
fn finish_continues_after_provider_finish_error() {
    let first_finishes = Arc::new(AtomicUsize::new(0));
    let failing_finishes = Arc::new(AtomicUsize::new(0));
    let last_finishes = Arc::new(AtomicUsize::new(0));
    let temp_dir = unique_temp_dir("lintai-finish-continues");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# ok\n").unwrap();

    let result = EngineBuilder::default()
        .with_provider(Arc::new(CountingProvider {
            id: "counting-before-finish",
            starts: Arc::new(AtomicUsize::new(0)),
            finishes: Arc::clone(&first_finishes),
        }))
        .with_provider(Arc::new(FailingFinishProvider {
            finishes: Arc::clone(&failing_finishes),
        }))
        .with_provider(Arc::new(CountingProvider {
            id: "counting-after-finish",
            starts: Arc::new(AtomicUsize::new(0)),
            finishes: Arc::clone(&last_finishes),
        }))
        .build()
        .scan_path(&temp_dir);

    assert!(result.is_err());
    assert_eq!(first_finishes.load(Ordering::SeqCst), 1);
    assert_eq!(failing_finishes.load(Ordering::SeqCst), 1);
    assert_eq!(last_finishes.load(Ordering::SeqCst), 1);
}

#[test]
fn suppression_hook_filters_findings() {
    let temp_dir = unique_temp_dir("lintai-suppression");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# ok\n").unwrap();

    let summary = EngineBuilder::default()
        .with_provider(Arc::new(EmitFindingProvider))
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
        .with_provider(Arc::new(ExecutionErrorOnlyProvider))
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
        .with_provider(Arc::new(FindingAndExecutionErrorProvider))
        .build()
        .scan_path(&temp_dir)
        .unwrap();

    assert_eq!(summary.findings.len(), 1);
    assert_eq!(summary.findings[0].message, "finding survives execution error");
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
fn derives_line_columns_for_findings() {
    let temp_dir = unique_temp_dir("lintai-line-columns");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# title\n").unwrap();

    let summary = EngineBuilder::default()
        .with_provider(Arc::new(EmitFindingProvider))
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
fn attaches_fix_from_provider_fix_hook() {
    let temp_dir = unique_temp_dir("lintai-fix-hook");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# title\n").unwrap();

    let summary = EngineBuilder::default()
        .with_provider(Arc::new(FixingProvider))
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
        .with_provider(Arc::new(UndeclaredFindingProvider))
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
        .with_provider(Arc::new(WrongStableKeyProvider))
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
        .with_provider(Arc::new(EmitFindingProvider))
        .with_provider(Arc::new(DuplicateProviderId))
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
        .with_provider(Arc::new(ZeroTimeoutProvider))
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
        .with_provider(Arc::new(WorkspaceFindingProvider))
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
        .with_provider(Arc::new(WorkspaceLineColumnProvider))
        .build()
        .scan_path(&temp_dir)
        .unwrap();

    assert_eq!(summary.findings.len(), 1);
    let finding = &summary.findings[0];
    assert_eq!(finding.location.start.as_ref().map(|pos| pos.line), Some(1));
    assert_eq!(finding.location.start.as_ref().map(|pos| pos.column), Some(3));
    assert_eq!(finding.location.end.as_ref().map(|pos| pos.line), Some(1));
    assert_eq!(finding.location.end.as_ref().map(|pos| pos.column), Some(8));
}

#[test]
fn suppression_hook_filters_workspace_findings() {
    let temp_dir = unique_temp_dir("lintai-workspace-suppression");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# ok\n").unwrap();

    let summary = EngineBuilder::default()
        .with_provider(Arc::new(WorkspaceFindingProvider))
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
        .with_provider(Arc::new(WorkspaceExecutionErrorProvider))
        .build()
        .scan_path(&temp_dir)
        .unwrap();

    assert!(summary.findings.is_empty());
    assert_eq!(summary.runtime_errors.len(), 1);
    let error = &summary.runtime_errors[0];
    assert_eq!(error.kind, crate::RuntimeErrorKind::ProviderExecution);
    assert_eq!(error.provider_id.as_deref(), Some("workspace-execution-error"));
    assert_eq!(error.phase, Some(crate::ProviderExecutionPhase::Workspace));
    assert_eq!(error.normalized_path, temp_dir.display().to_string());
}

#[test]
fn drops_invalid_finding_span_and_reports_diagnostic() {
    let temp_dir = unique_temp_dir("lintai-invalid-span");
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join("SKILL.md"), b"# title\n").unwrap();

    let summary = EngineBuilder::default()
        .with_provider(Arc::new(InvalidSpanProvider))
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
        .with_provider(Arc::new(InvalidFixProvider))
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
        .with_provider(Arc::new(DuplicateFindingProvider))
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
