mod claude_settings_rules;
mod devcontainer_rules;
mod docker_compose_rules;
mod dockerfile_rules;
mod github_workflow_rules;
mod helpers;
mod hook_rules;
mod json_locator;
mod json_rules;
mod markdown_rules;
mod native_catalog;
mod provider;
mod registry;
mod server_json_rules;
mod signals;
mod tool_json_rules;

#[cfg(test)]
mod corpus_tests;
#[cfg(test)]
mod perf_tests;
#[cfg(test)]
mod tests;

pub use native_catalog::{
    NativeCatalogDetectionClass, NativeCatalogRemediationSupport, NativeCatalogRuleLifecycle,
    NativeCatalogSurface, NativeRuleCatalogEntry, ai_security_rule_catalog_entries,
    native_rule_catalog_entries,
};
pub use provider::AiSecurityProvider;
#[doc(hidden)]
pub use provider::{ProviderPerfProfile, profile_scan_context};
#[doc(hidden)]
pub use signals::SignalWorkBudget;
