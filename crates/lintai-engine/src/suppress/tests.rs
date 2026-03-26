use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use lintai_api::{
    Artifact, ArtifactKind, Category, Confidence, Finding, Location, ParsedDocument, RegionKind,
    RuleMetadata, RuleTier, ScanContext, Severity, SourceFormat, Span, TextRegion,
};

use crate::{SuppressionMatcher, load_workspace_config};

use super::FileSuppressions;

static TEST_RULE: RuleMetadata = RuleMetadata::new(
    "SEC201",
    "test rule",
    Category::Security,
    Severity::Warn,
    Confidence::High,
    RuleTier::Stable,
);

#[test]
fn reports_unused_suppress_entries() {
    let temp_dir = unique_temp_dir("lintai-suppress-unused");
    std::fs::create_dir_all(temp_dir.join(".lintai")).unwrap();
    std::fs::write(temp_dir.join("lintai.toml"), "[project]\nroot = true\n").unwrap();
    std::fs::write(
        temp_dir.join(".lintai/suppress.toml"),
        r#"
[[suppress]]
files = ["docs/**/*.md"]
rule = "SEC201"
reason = "legacy exception"
"#,
    )
    .unwrap();

    let workspace = load_workspace_config(&temp_dir).unwrap();
    let suppressions = FileSuppressions::load(&workspace.engine_config).unwrap();

    let errors = suppressions.finalize();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].message.contains("unused suppress"));
}

#[test]
fn reports_excessive_suppressions_per_file() {
    let temp_dir = unique_temp_dir("lintai-suppress-max");
    std::fs::create_dir_all(temp_dir.join(".lintai")).unwrap();
    std::fs::write(
        temp_dir.join("lintai.toml"),
        "[project]\nroot = true\n[suppress]\nmax_per_file = 1\n",
    )
    .unwrap();
    std::fs::write(
        temp_dir.join(".lintai/suppress.toml"),
        r#"
[[suppress]]
files = ["docs/**/*.md"]
rule = "SEC201"
reason = "legacy exception"
"#,
    )
    .unwrap();

    let workspace = load_workspace_config(&temp_dir).unwrap();
    let suppressions = FileSuppressions::load(&workspace.engine_config).unwrap();
    let ctx = sample_context("docs/SKILL.md");
    let finding = sample_finding("docs/SKILL.md");

    assert!(suppressions.is_suppressed(&ctx, &finding));
    assert!(suppressions.is_suppressed(&ctx, &finding));

    let errors = suppressions.finalize();
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("max_per_file"))
    );
}

fn sample_context(path: &str) -> ScanContext {
    ScanContext::new(
        Artifact::new(path, ArtifactKind::Skill, SourceFormat::Markdown),
        "# demo\n",
        ParsedDocument::new(
            vec![TextRegion::new(Span::new(0, 7), RegionKind::Normal)],
            None,
        ),
        None,
    )
}

fn sample_finding(path: &str) -> Finding {
    Finding::new(&TEST_RULE, Location::new(path, Span::new(0, 7)), "test")
}

fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
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
