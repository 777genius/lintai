use std::thread;
use std::time::Duration;

use lintai_api::{
    Confidence, FileRuleProvider, Finding, Location, ProviderError, ProviderScanResult,
    RuleMetadata, RuleProvider, RuleTier, ScanContext, Severity, Span,
};

const TEST_RULE: RuleMetadata = RuleMetadata::new(
    "SEC998",
    "isolated test rule",
    lintai_api::Category::Security,
    Severity::Warn,
    Confidence::High,
    RuleTier::Preview,
);

pub(crate) struct TestTimeoutProvider;

impl FileRuleProvider for TestTimeoutProvider {
    fn id(&self) -> &str {
        "__test-timeout"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &[]
    }

    fn check_result(&self, _ctx: &ScanContext) -> ProviderScanResult {
        thread::sleep(Duration::from_millis(100));
        ProviderScanResult::new(Vec::new(), Vec::new())
    }
}

impl RuleProvider for TestTimeoutProvider {
    fn id(&self) -> &str {
        FileRuleProvider::id(self)
    }

    fn rules(&self) -> &[RuleMetadata] {
        FileRuleProvider::rules(self)
    }

    fn check_result(&self, ctx: &ScanContext) -> ProviderScanResult {
        FileRuleProvider::check_result(self, ctx)
    }
}

pub(crate) struct TestPanicProvider;

impl FileRuleProvider for TestPanicProvider {
    fn id(&self) -> &str {
        "__test-panic"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &[]
    }

    fn check_result(&self, _ctx: &ScanContext) -> ProviderScanResult {
        panic!("panic inside isolated provider");
    }
}

impl RuleProvider for TestPanicProvider {
    fn id(&self) -> &str {
        FileRuleProvider::id(self)
    }

    fn rules(&self) -> &[RuleMetadata] {
        FileRuleProvider::rules(self)
    }

    fn check_result(&self, ctx: &ScanContext) -> ProviderScanResult {
        FileRuleProvider::check_result(self, ctx)
    }
}

pub(crate) struct TestPartialErrorProvider;

impl FileRuleProvider for TestPartialErrorProvider {
    fn id(&self) -> &str {
        "__test-partial-error"
    }

    fn rules(&self) -> &[RuleMetadata] {
        &[TEST_RULE]
    }

    fn check_result(&self, ctx: &ScanContext) -> ProviderScanResult {
        ProviderScanResult::new(
            vec![Finding::new(
                &TEST_RULE,
                Location::new(ctx.artifact.normalized_path.clone(), Span::new(0, 1)),
                "isolated child finding",
            )],
            vec![ProviderError::new(
                FileRuleProvider::id(self),
                "isolated child execution error",
            )],
        )
    }
}

impl RuleProvider for TestPartialErrorProvider {
    fn id(&self) -> &str {
        FileRuleProvider::id(self)
    }

    fn rules(&self) -> &[RuleMetadata] {
        FileRuleProvider::rules(self)
    }

    fn check_result(&self, ctx: &ScanContext) -> ProviderScanResult {
        FileRuleProvider::check_result(self, ctx)
    }
}
