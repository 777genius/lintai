use std::sync::Arc;

use lintai_runtime::ProviderBackend;

use crate::builtin_providers::backend::IsolatedBuiltInBackend;
use crate::builtin_providers::kind::BuiltInProviderKind;

pub(crate) fn product_provider_set() -> Vec<Arc<dyn ProviderBackend>> {
    BuiltInProviderKind::product_kinds()
        .into_iter()
        .map(|kind| Arc::new(IsolatedBuiltInBackend::new(kind)) as Arc<dyn ProviderBackend>)
        .collect()
}
