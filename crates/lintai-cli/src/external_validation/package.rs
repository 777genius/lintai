use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ValidationPackage {
    Canonical,
    ToolJsonExtension,
    ServerJsonExtension,
    GithubActionsExtension,
    AiNativeDiscovery,
}

impl ValidationPackage {
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "canonical" => Ok(Self::Canonical),
            "tool-json-extension" => Ok(Self::ToolJsonExtension),
            "server-json-extension" => Ok(Self::ServerJsonExtension),
            "github-actions-extension" => Ok(Self::GithubActionsExtension),
            "ai-native-discovery" => Ok(Self::AiNativeDiscovery),
            _ => Err(format!("unknown external validation package `{value}`")),
        }
    }

    pub(crate) fn shortlist_path(self) -> &'static str {
        match self {
            Self::Canonical => SHORTLIST_PATH,
            Self::ToolJsonExtension => TOOL_JSON_EXTENSION_SHORTLIST_PATH,
            Self::ServerJsonExtension => SERVER_JSON_EXTENSION_SHORTLIST_PATH,
            Self::GithubActionsExtension => GITHUB_ACTIONS_EXTENSION_SHORTLIST_PATH,
            Self::AiNativeDiscovery => AI_NATIVE_DISCOVERY_SHORTLIST_PATH,
        }
    }

    pub(crate) fn ledger_path(self) -> &'static str {
        match self {
            Self::Canonical => LEDGER_PATH,
            Self::ToolJsonExtension => TOOL_JSON_EXTENSION_LEDGER_PATH,
            Self::ServerJsonExtension => SERVER_JSON_EXTENSION_LEDGER_PATH,
            Self::GithubActionsExtension => GITHUB_ACTIONS_EXTENSION_LEDGER_PATH,
            Self::AiNativeDiscovery => AI_NATIVE_DISCOVERY_LEDGER_PATH,
        }
    }

    pub(crate) fn baseline_reference(self) -> Option<&'static str> {
        match self {
            Self::Canonical => Some("archive/wave1-ledger.toml"),
            Self::ToolJsonExtension => Some("archive/wave3-ledger.toml"),
            Self::ServerJsonExtension => Some("archive/wave1-ledger.toml"),
            Self::GithubActionsExtension => None,
            Self::AiNativeDiscovery => None,
        }
    }

    pub(crate) fn candidate_ledger_path(self) -> &'static str {
        match self {
            Self::Canonical => "target/external-validation/wave2/candidate-ledger.toml",
            Self::ToolJsonExtension => {
                "target/external-validation/tool-json-extension/candidate-ledger.toml"
            }
            Self::ServerJsonExtension => {
                "target/external-validation/server-json-extension/candidate-ledger.toml"
            }
            Self::GithubActionsExtension => {
                "target/external-validation/github-actions-extension/candidate-ledger.toml"
            }
            Self::AiNativeDiscovery => {
                "target/external-validation/ai-native-discovery/candidate-ledger.toml"
            }
        }
    }

    pub(crate) fn raw_output_root(self) -> &'static str {
        match self {
            Self::Canonical => "target/external-validation/wave2/raw",
            Self::ToolJsonExtension => "target/external-validation/tool-json-extension/raw",
            Self::ServerJsonExtension => "target/external-validation/server-json-extension/raw",
            Self::GithubActionsExtension => {
                "target/external-validation/github-actions-extension/raw"
            }
            Self::AiNativeDiscovery => "target/external-validation/ai-native-discovery/raw",
        }
    }
    pub(crate) fn default_wave(self) -> u32 {
        match self {
            Self::Canonical => 2,
            Self::ToolJsonExtension => 4,
            Self::ServerJsonExtension => 2,
            Self::GithubActionsExtension => 1,
            Self::AiNativeDiscovery => 1,
        }
    }
}
