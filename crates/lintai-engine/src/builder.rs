use std::sync::Arc;

use lintai_api::RuleProvider;

use crate::{Engine, EngineConfig, FileTypeDetector, NoopSuppressionMatcher, SuppressionMatcher};

#[derive(Default)]
pub struct EngineBuilder {
    config: EngineConfig,
    providers: Vec<Arc<dyn RuleProvider>>,
    suppressions: Option<Arc<dyn SuppressionMatcher>>,
}

impl EngineBuilder {
    pub fn with_config(mut self, config: EngineConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_provider(mut self, provider: Arc<dyn RuleProvider>) -> Self {
        self.providers.push(provider);
        self
    }

    pub fn with_suppressions(mut self, suppressions: Arc<dyn SuppressionMatcher>) -> Self {
        self.suppressions = Some(suppressions);
        self
    }

    pub fn build(self) -> Engine {
        let detector = FileTypeDetector::new(&self.config);
        Engine {
            config: self.config,
            detector,
            providers: self.providers,
            suppressions: self
                .suppressions
                .unwrap_or_else(|| Arc::new(NoopSuppressionMatcher)),
        }
    }
}

impl Engine {
    pub fn builder() -> EngineBuilder {
        EngineBuilder::default()
    }
}
