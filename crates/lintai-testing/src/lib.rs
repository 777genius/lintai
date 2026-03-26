use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use lintai_api::{ArtifactKind, Finding, RuleProvider, SourceFormat};
use lintai_engine::{
    EngineBuilder, EngineConfig, NoopSuppressionMatcher, ScanSummary, SuppressionMatcher,
};

pub struct ProviderHarness;

impl ProviderHarness {
    pub fn run(
        provider: Arc<dyn RuleProvider>,
        artifact_kind: ArtifactKind,
        format: SourceFormat,
        content: impl Into<String>,
    ) -> Vec<Finding> {
        Self::run_summary(provider, artifact_kind, format, content).findings
    }

    pub fn run_summary(
        provider: Arc<dyn RuleProvider>,
        artifact_kind: ArtifactKind,
        format: SourceFormat,
        content: impl Into<String>,
    ) -> ScanSummary {
        ProviderHarnessBuilder::new(provider).run_summary(artifact_kind, format, content)
    }
}

pub struct ProviderHarnessBuilder {
    provider: Arc<dyn RuleProvider>,
    config: EngineConfig,
    suppressions: Arc<dyn SuppressionMatcher>,
}

impl ProviderHarnessBuilder {
    pub fn new(provider: Arc<dyn RuleProvider>) -> Self {
        Self {
            provider,
            config: EngineConfig::default(),
            suppressions: Arc::new(NoopSuppressionMatcher),
        }
    }

    pub fn with_config(mut self, config: EngineConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_suppressions(mut self, suppressions: Arc<dyn SuppressionMatcher>) -> Self {
        self.suppressions = suppressions;
        self
    }

    pub fn run_summary(
        self,
        artifact_kind: ArtifactKind,
        format: SourceFormat,
        content: impl Into<String>,
    ) -> ScanSummary {
        let temp_dir = unique_temp_dir("lintai-provider-harness");
        let fixture_path = temp_dir.join(fixture_path_for(artifact_kind, format));
        std::fs::create_dir_all(
            fixture_path
                .parent()
                .expect("fixture path should always have a parent"),
        )
        .expect("fixture directory creation should succeed");
        std::fs::write(&fixture_path, content.into()).expect("fixture file write should succeed");

        let mut config = self.config;
        if config.project_root.is_none() {
            config.project_root = Some(temp_dir.clone());
        }

        let engine = EngineBuilder::default()
            .with_config(config)
            .with_suppressions(self.suppressions)
            .with_provider(self.provider)
            .build();
        let summary = engine
            .scan_path(&temp_dir)
            .expect("fixture scan should complete without fatal engine error");

        assert!(
            summary.runtime_errors.is_empty(),
            "fixture scan produced runtime errors: {:?}",
            summary.runtime_errors
        );

        summary
    }
}

pub struct RuleTester {
    provider: Arc<dyn RuleProvider>,
}

impl RuleTester {
    pub fn new(provider: Arc<dyn RuleProvider>) -> Self {
        Self { provider }
    }

    pub fn run_fixture(
        &self,
        artifact_kind: ArtifactKind,
        format: SourceFormat,
        content: impl Into<String>,
    ) -> Vec<Finding> {
        ProviderHarness::run(Arc::clone(&self.provider), artifact_kind, format, content)
    }

    pub fn assert_triggers(
        &self,
        artifact_kind: ArtifactKind,
        format: SourceFormat,
        content: impl Into<String>,
        rule_code: &str,
    ) {
        let findings = self.run_fixture(artifact_kind, format, content);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_code == rule_code),
            "expected rule {rule_code} to trigger, got {findings:?}"
        );
    }

    pub fn assert_not_triggers(
        &self,
        artifact_kind: ArtifactKind,
        format: SourceFormat,
        content: impl Into<String>,
        rule_code: &str,
    ) {
        let findings = self.run_fixture(artifact_kind, format, content);
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule_code != rule_code),
            "expected rule {rule_code} not to trigger, got {findings:?}"
        );
    }
}

fn fixture_path_for(artifact_kind: ArtifactKind, format: SourceFormat) -> &'static Path {
    match (artifact_kind, format) {
        (ArtifactKind::Skill, SourceFormat::Markdown) => Path::new("docs/SKILL.md"),
        (ArtifactKind::Instructions, SourceFormat::Markdown) => Path::new("CLAUDE.md"),
        (ArtifactKind::CursorRules, SourceFormat::Markdown) => Path::new("rules.mdc"),
        (ArtifactKind::McpConfig, SourceFormat::Json) => Path::new("mcp.json"),
        (ArtifactKind::CursorPluginManifest, SourceFormat::Json) => {
            Path::new(".cursor-plugin/plugin.json")
        }
        (ArtifactKind::CursorPluginHooks, SourceFormat::Json) => {
            Path::new(".cursor-plugin/hooks.json")
        }
        (ArtifactKind::CursorHookScript, SourceFormat::Shell) => {
            Path::new(".cursor-plugin/hooks/install.sh")
        }
        (ArtifactKind::CursorPluginCommand, SourceFormat::Markdown) => {
            Path::new(".cursor-plugin/commands/setup.md")
        }
        (ArtifactKind::CursorPluginAgent, SourceFormat::Markdown) => {
            Path::new(".cursor-plugin/agents/reviewer.md")
        }
        _ => panic!("unsupported fixture artifact/format combination"),
    }
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
