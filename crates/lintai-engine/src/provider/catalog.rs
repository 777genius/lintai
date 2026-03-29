use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use lintai_runtime::ProviderBackend;

use crate::EngineError;

use super::{ProviderCatalog, ProviderEntry};

impl<'a> ProviderCatalog<'a> {
    pub(crate) fn new(backends: &'a [Arc<dyn ProviderBackend>]) -> Result<Self, EngineError> {
        let mut provider_ids = BTreeSet::new();
        let mut global_rule_codes = BTreeMap::new();
        let mut entries = Vec::with_capacity(backends.len());

        for backend in backends {
            let backend = backend.as_ref();
            let provider_id = backend.id().to_owned();
            if !provider_ids.insert(provider_id.clone()) {
                return Err(EngineError::ProviderContract(format!(
                    "duplicate provider id `{provider_id}`"
                )));
            }

            let timeout = backend.timeout();
            validate_timeout(provider_id.as_str(), timeout)?;

            let mut rules = BTreeMap::new();
            for rule in backend.rules() {
                if rules.insert(rule.code.to_owned(), *rule).is_some() {
                    return Err(EngineError::ProviderContract(format!(
                        "provider `{provider_id}` declares duplicate rule code `{}`",
                        rule.code
                    )));
                }

                if let Some(other_provider) =
                    global_rule_codes.insert(rule.code.to_owned(), provider_id.clone())
                {
                    return Err(EngineError::ProviderContract(format!(
                        "rule code `{}` is declared by both `{other_provider}` and `{provider_id}`",
                        rule.code
                    )));
                }
            }

            entries.push(ProviderEntry {
                backend,
                id: provider_id,
                rules,
                scope: backend.scan_scope(),
                timeout,
            });
        }

        Ok(Self { entries })
    }

    pub(crate) fn per_file(&self) -> impl Iterator<Item = &ProviderEntry<'a>> {
        self.entries
            .iter()
            .filter(|entry| entry.scope == lintai_api::ScanScope::PerFile)
    }

    pub(crate) fn workspace(&self) -> impl Iterator<Item = &ProviderEntry<'a>> {
        self.entries
            .iter()
            .filter(|entry| entry.scope == lintai_api::ScanScope::Workspace)
    }
}

fn validate_timeout(provider_id: &str, timeout: Duration) -> Result<(), EngineError> {
    if timeout.is_zero() {
        return Err(EngineError::ProviderContract(format!(
            "provider `{provider_id}` declares zero timeout"
        )));
    }

    Ok(())
}
