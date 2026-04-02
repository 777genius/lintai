use std::time::Duration;

use lintai_ai_security::AiSecurityProvider;
use lintai_api::{FileRuleProvider, RuleMetadata, ScanScope, WorkspaceRuleProvider};
use lintai_dep_vulns::DependencyVulnProvider;
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
    DependencyVulns,
    #[cfg(debug_assertions)]
    TestTimeout,
    #[cfg(debug_assertions)]
    TestPanic,
    #[cfg(debug_assertions)]
    TestPartialError,
}

pub(crate) enum BuiltInProviderInstance {
    File(Box<dyn FileRuleProvider>),
    Workspace(Box<dyn WorkspaceRuleProvider>),
}

impl BuiltInProviderInstance {
    pub(crate) fn id(&self) -> &str {
        match self {
            Self::File(provider) => provider.id(),
            Self::Workspace(provider) => provider.id(),
        }
    }

    pub(crate) fn rules(&self) -> &[RuleMetadata] {
        match self {
            Self::File(provider) => provider.rules(),
            Self::Workspace(provider) => provider.rules(),
        }
    }

    pub(crate) fn scope(&self) -> ScanScope {
        match self {
            Self::File(_) => ScanScope::PerFile,
            Self::Workspace(_) => ScanScope::Workspace,
        }
    }
}

impl BuiltInProviderKind {
    pub(crate) fn instantiate(self) -> BuiltInProviderInstance {
        match self {
            Self::AiSecurity => {
                BuiltInProviderInstance::File(Box::new(AiSecurityProvider::default()))
            }
            Self::PolicyMismatch => {
                BuiltInProviderInstance::Workspace(Box::new(PolicyMismatchProvider))
            }
            Self::DependencyVulns => {
                BuiltInProviderInstance::Workspace(Box::new(DependencyVulnProvider))
            }
            #[cfg(debug_assertions)]
            Self::TestTimeout => BuiltInProviderInstance::File(Box::new(TestTimeoutProvider)),
            #[cfg(debug_assertions)]
            Self::TestPanic => BuiltInProviderInstance::File(Box::new(TestPanicProvider)),
            #[cfg(debug_assertions)]
            Self::TestPartialError => {
                BuiltInProviderInstance::File(Box::new(TestPartialErrorProvider))
            }
        }
    }

    pub(crate) fn product_kinds() -> [Self; 3] {
        [
            Self::AiSecurity,
            Self::PolicyMismatch,
            Self::DependencyVulns,
        ]
    }

    pub(crate) fn timeout(self) -> Duration {
        match self {
            Self::AiSecurity | Self::PolicyMismatch | Self::DependencyVulns => {
                Duration::from_secs(30)
            }
            #[cfg(debug_assertions)]
            Self::TestTimeout => Duration::from_millis(30),
            #[cfg(debug_assertions)]
            Self::TestPanic | Self::TestPartialError => Duration::from_secs(30),
        }
    }
}
