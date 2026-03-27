use std::sync::Arc;

use crate::{
    Engine, EngineConfig, FileTypeDetector, NoopSuppressionMatcher, ProviderBackend,
    SuppressionMatcher,
};

#[derive(Default)]
pub struct EngineBuilder {
    config: EngineConfig,
    backends: Vec<Arc<dyn ProviderBackend>>,
    suppressions: Option<Arc<dyn SuppressionMatcher>>,
}

impl EngineBuilder {
    pub fn with_config(mut self, config: EngineConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_backend(mut self, backend: Arc<dyn ProviderBackend>) -> Self {
        self.backends.push(backend);
        self
    }

    pub fn with_backends<I>(mut self, backends: I) -> Self
    where
        I: IntoIterator<Item = Arc<dyn ProviderBackend>>,
    {
        self.backends.extend(backends);
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
            backends: self.backends,
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
