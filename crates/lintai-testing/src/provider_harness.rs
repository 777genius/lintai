use std::path::Path;
use std::sync::Arc;

use lintai_api::{
    ArtifactKind, FileRuleProvider, Finding, SourceFormat, builtin_membership_preset_ids,
};
use lintai_engine::{
    EngineBuilder, EngineConfig, NoopSuppressionMatcher, ScanSummary, SuppressionMatcher,
    load_workspace_config,
};
use lintai_runtime::{InProcessFileProviderBackend, ProviderBackend};

pub struct ProviderHarness;

impl ProviderHarness {
    pub fn run(
        provider: Arc<dyn FileRuleProvider>,
        artifact_kind: ArtifactKind,
        format: SourceFormat,
        content: impl Into<String>,
    ) -> Vec<Finding> {
        Self::run_summary(provider, artifact_kind, format, content).findings
    }

    pub fn run_summary(
        provider: Arc<dyn FileRuleProvider>,
        artifact_kind: ArtifactKind,
        format: SourceFormat,
        content: impl Into<String>,
    ) -> ScanSummary {
        ProviderHarnessBuilder::new(Arc::new(InProcessFileProviderBackend::new(provider)))
            .run_summary(artifact_kind, format, content)
    }
}

struct ProviderHarnessBuilder {
    backend: Arc<dyn ProviderBackend>,
    config: EngineConfig,
    suppressions: Arc<dyn SuppressionMatcher>,
}

impl ProviderHarnessBuilder {
    fn new(backend: Arc<dyn ProviderBackend>) -> Self {
        Self {
            backend,
            config: EngineConfig::default(),
            suppressions: Arc::new(NoopSuppressionMatcher),
        }
    }

    fn run_summary(
        self,
        artifact_kind: ArtifactKind,
        format: SourceFormat,
        content: impl Into<String>,
    ) -> ScanSummary {
        let temp_dir = crate::unique_temp_dir("lintai-provider-harness");
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
            std::fs::write(
                temp_dir.join("lintai.toml"),
                provider_harness_presets_config(),
            )
            .expect("provider harness config write should succeed");
            config = load_workspace_config(&temp_dir)
                .expect("provider harness workspace config should load")
                .engine_config;
        }

        let engine = EngineBuilder::default()
            .with_config(config)
            .with_suppressions(self.suppressions)
            .with_backend(self.backend)
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

fn provider_harness_presets_config() -> String {
    let enabled = builtin_membership_preset_ids()
        .into_iter()
        .map(|preset| format!("\"{preset}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[presets]\nenable = [{enabled}]\n")
}

fn fixture_path_for(artifact_kind: ArtifactKind, format: SourceFormat) -> &'static Path {
    match (artifact_kind, format) {
        (ArtifactKind::Skill, SourceFormat::Markdown) => Path::new("docs/SKILL.md"),
        (ArtifactKind::Instructions, SourceFormat::Markdown) => Path::new("CLAUDE.md"),
        (ArtifactKind::CursorRules, SourceFormat::Markdown) => Path::new("rules.mdc"),
        (ArtifactKind::McpConfig, SourceFormat::Json) => Path::new("mcp.json"),
        (ArtifactKind::PackageManifest, SourceFormat::Json) => Path::new("package.json"),
        (ArtifactKind::NpmPackageLock, SourceFormat::Json) => Path::new("package-lock.json"),
        (ArtifactKind::NpmShrinkwrap, SourceFormat::Json) => Path::new("npm-shrinkwrap.json"),
        (ArtifactKind::DevcontainerConfig, SourceFormat::Json) => {
            Path::new(".devcontainer/devcontainer.json")
        }
        (ArtifactKind::ClaudeSettings, SourceFormat::Json) => Path::new(".claude/settings.json"),
        (ArtifactKind::ServerRegistryConfig, SourceFormat::Json) => Path::new("server.json"),
        (ArtifactKind::ToolDescriptorJson, SourceFormat::Json) => {
            Path::new("pkg/mcp/toolsets-full-tools.json")
        }
        (ArtifactKind::GitHubWorkflow, SourceFormat::Yaml) => Path::new(".github/workflows/ci.yml"),
        (ArtifactKind::DockerCompose, SourceFormat::Yaml) => Path::new("docker-compose.yml"),
        (ArtifactKind::PnpmLock, SourceFormat::Yaml) => Path::new("pnpm-lock.yaml"),
        (ArtifactKind::CursorPluginManifest, SourceFormat::Json) => {
            Path::new(".cursor-plugin/plugin.json")
        }
        (ArtifactKind::CursorPluginHooks, SourceFormat::Json) => {
            Path::new(".cursor-plugin/hooks.json")
        }
        (ArtifactKind::Dockerfile, SourceFormat::Shell) => Path::new("Dockerfile"),
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
