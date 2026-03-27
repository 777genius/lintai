mod artifact_view;
mod builder;
mod config;
mod detector;
mod discovery;
mod engine;
mod error;
mod normalize;
mod provider;
mod summary;
mod suppress;
mod workspace_index;

#[cfg(test)]
mod engine_tests;

pub use builder::EngineBuilder;
pub use config::{
    CiPolicy, ConfigError, EngineConfig, OutputFormat, ResolvedFileConfig, SuppressPolicy,
    WorkspaceConfig, config_schema_pretty, explain_file_config, load_workspace_config,
};
pub use detector::{DetectedArtifact, DetectionRule, FileTypeDetector};
pub use engine::Engine;
pub use error::EngineError;
pub use normalize::normalize_path_string;
pub use provider::ProviderBackend;
pub use summary::{
    DiagnosticSeverity, ProviderExecutionPhase, RuntimeErrorKind, ScanDiagnostic, ScanRuntimeError,
    ScanSummary,
};
pub use suppress::{FileSuppressions, NoopSuppressionMatcher, SuppressionMatcher};

#[doc(hidden)]
pub mod internal {
    pub use crate::provider::InProcessProviderBackend;
}
