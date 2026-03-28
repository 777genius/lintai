use std::path::PathBuf;
use std::sync::Arc;

use criterion::{Criterion, criterion_group, criterion_main};
use lintai_ai_security::{AiSecurityProvider, PolicyMismatchProvider};
use lintai_api::ScanScope;
use lintai_runtime::InProcessProviderBackend;
use lintai_testing::{WorkspaceHarness, discover_case_dirs};

fn criterion_benchmark(c: &mut Criterion) {
    let harness = WorkspaceHarness::builder()
        .with_backend(Arc::new(InProcessProviderBackend::new(Arc::new(
            AiSecurityProvider::default(),
        ))))
        .with_backend(Arc::new(InProcessProviderBackend::with_scope(
            Arc::new(PolicyMismatchProvider),
            ScanScope::Workspace,
        )))
        .build();

    for case_dir in discover_case_dirs(&sample_repos_root()).unwrap() {
        let name = case_dir
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap()
            .to_owned();
        c.bench_function(&format!("sample_repo/{name}"), |b| {
            b.iter(|| {
                let summary = harness.scan_case(&case_dir).unwrap();
                criterion::black_box(summary.findings.len());
                criterion::black_box(summary.provider_metrics.len());
            });
        });
    }
}

fn sample_repos_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("sample-repos")
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
