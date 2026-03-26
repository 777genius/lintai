mod load;
mod model;
mod resolve;
mod schema;

#[cfg(test)]
mod tests;

pub use load::load_workspace_config;
pub use model::{
    CiPolicy, ConfigError, DetectionOverride, EngineConfig, FileOverride, OutputFormat,
    ResolvedFileConfig, SuppressPolicy, WorkspaceConfig,
};
pub use resolve::explain_file_config;
pub use schema::config_schema_pretty;

pub(crate) use model::{DEFAULT_EXCLUDE_PATTERNS, DEFAULT_INCLUDE_PATTERNS};
