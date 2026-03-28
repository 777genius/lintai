use std::time::Duration;

use lintai_ai_security::AiSecurityProvider;
use lintai_api::{RuleProvider, ScanScope};
use lintai_policy::PolicyMismatchProvider;

#[cfg(debug_assertions)]
use crate::builtin_providers::test_support::{
    TestPanicProvider, TestPartialErrorProvider, TestTimeoutProvider,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BuiltInProviderKind {
    AiSecurity,
    PolicyMismatch,
    #[cfg(debug_assertions)]
    TestTimeout,
    #[cfg(debug_assertions)]
    TestPanic,
    #[cfg(debug_assertions)]
    TestPartialError,
}

impl BuiltInProviderKind {
    pub(crate) fn instantiate(self) -> Box<dyn RuleProvider> {
        match self {
            Self::AiSecurity => Box::new(AiSecurityProvider::default()),
            Self::PolicyMismatch => Box::new(PolicyMismatchProvider),
            #[cfg(debug_assertions)]
            Self::TestTimeout => Box::new(TestTimeoutProvider),
            #[cfg(debug_assertions)]
            Self::TestPanic => Box::new(TestPanicProvider),
            #[cfg(debug_assertions)]
            Self::TestPartialError => Box::new(TestPartialErrorProvider),
        }
    }

    pub(crate) fn product_kinds() -> [Self; 2] {
        [Self::AiSecurity, Self::PolicyMismatch]
    }

    pub(crate) fn timeout(self) -> Duration {
        match self {
            Self::AiSecurity | Self::PolicyMismatch => Duration::from_secs(30),
            #[cfg(debug_assertions)]
            Self::TestTimeout => Duration::from_millis(30),
            #[cfg(debug_assertions)]
            Self::TestPanic | Self::TestPartialError => Duration::from_secs(30),
        }
    }

    pub(crate) fn scope(self) -> ScanScope {
        match self {
            Self::AiSecurity => ScanScope::PerFile,
            Self::PolicyMismatch => ScanScope::Workspace,
            #[cfg(debug_assertions)]
            Self::TestTimeout | Self::TestPanic | Self::TestPartialError => ScanScope::PerFile,
        }
    }
}
