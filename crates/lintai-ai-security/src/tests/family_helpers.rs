use std::path::PathBuf;
use std::sync::Arc;

use lintai_api::{ArtifactKind, Finding, SourceFormat, Span};
use lintai_engine::{EngineBuilder, FileSuppressions, ScanSummary, load_workspace_config};
use lintai_runtime::InProcessFileProviderBackend;
use lintai_testing::ProviderHarness;

use crate::AiSecurityProvider;

pub(super) fn expect_finding<'a>(summary: &'a ScanSummary, rule_code: &str) -> &'a Finding {
    summary
        .findings
        .iter()
        .find(|finding| finding.rule_code == rule_code)
        .unwrap_or_else(|| panic!("expected finding {rule_code}, got {:?}", summary.findings))
}

pub(super) fn assert_has_rule(summary: &ScanSummary, rule_code: &str) {
    let _ = expect_finding(summary, rule_code);
}

pub(super) fn assert_lacks_rule(summary: &ScanSummary, rule_code: &str) {
    assert!(
        !summary
            .findings
            .iter()
            .any(|finding| finding.rule_code == rule_code),
        "did not expect finding {rule_code}, got {:?}",
        summary.findings
    );
}

pub(super) fn assert_marker_span(
    summary: &ScanSummary,
    rule_code: &str,
    content: &str,
    marker: &str,
) {
    let finding = expect_finding(summary, rule_code);
    let start = content.find(marker).unwrap();
    assert_eq!(
        finding.location.span,
        Span::new(start, start + marker.len()),
        "unexpected span for {rule_code} at marker {marker:?}",
    );
}

pub(super) fn scan_provider(
    artifact_kind: ArtifactKind,
    source_format: SourceFormat,
    content: &str,
) -> Vec<Finding> {
    ProviderHarness::run(
        Arc::new(AiSecurityProvider::default()),
        artifact_kind,
        source_format,
        content,
    )
}

pub(super) fn expect_provider_finding<'a>(findings: &'a [Finding], rule_code: &str) -> &'a Finding {
    findings
        .iter()
        .find(|finding| finding.rule_code == rule_code)
        .unwrap_or_else(|| panic!("expected finding {rule_code}, got {findings:?}"))
}

pub(super) fn scan_fixture(
    relative_path: &str,
    content: impl AsRef<[u8]>,
    presets: &[&str],
    temp_prefix: &str,
) -> ScanSummary {
    let temp_dir = unique_temp_dir(temp_prefix);
    let file_path = temp_dir.join(relative_path);
    std::fs::create_dir_all(file_path.parent().unwrap()).unwrap();

    let enabled_presets = presets
        .iter()
        .map(|preset| format!("\"{preset}\""))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        temp_dir.join("lintai.toml"),
        format!("[presets]\nenable = [{enabled_presets}]\n"),
    )
    .unwrap();
    std::fs::write(&file_path, content).unwrap();

    let workspace = load_workspace_config(&temp_dir).unwrap();
    let suppressions = FileSuppressions::load(&workspace.engine_config).unwrap();
    EngineBuilder::default()
        .with_config(workspace.engine_config.clone())
        .with_suppressions(Arc::new(suppressions))
        .with_backend(Arc::new(InProcessFileProviderBackend::new(Arc::new(
            AiSecurityProvider::default(),
        ))))
        .build()
        .scan_path(&temp_dir)
        .unwrap()
}

pub(super) fn unique_temp_dir(prefix: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

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
