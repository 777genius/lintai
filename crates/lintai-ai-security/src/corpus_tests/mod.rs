use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use lintai_api::ScanScope;
use lintai_engine::{InProcessProviderBackend, ProviderBackend};
use lintai_testing::{CaseManifest, WorkspaceHarness};

use crate::{AiSecurityProvider, PolicyMismatchProvider};

mod benign;
mod edge;
mod malicious;

fn provider_set() -> Vec<Arc<dyn ProviderBackend>> {
    vec![
        Arc::new(InProcessProviderBackend::new(Arc::new(
            AiSecurityProvider::default(),
        ))),
        Arc::new(InProcessProviderBackend::with_scope(
            Arc::new(PolicyMismatchProvider),
            ScanScope::Workspace,
        )),
    ]
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root should be discoverable from lintai-ai-security")
}

fn corpus_root(bucket: &str) -> PathBuf {
    repo_root().join("corpus").join(bucket)
}

fn case_dir(bucket: &str, case_name: &str) -> PathBuf {
    corpus_root(bucket).join(case_name)
}

fn load_case(case_dir: &Path) -> CaseManifest {
    CaseManifest::load(case_dir).expect("corpus manifest should load")
}

fn harness() -> WorkspaceHarness {
    WorkspaceHarness::builder()
        .with_backends(provider_set())
        .build()
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
