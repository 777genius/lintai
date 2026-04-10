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
    pub(crate) const CANONICAL_SCAN_PRESET_MATRIX: &[&str] = &[
        "recommended",
        "base",
        "mcp",
        "claude",
        "skills",
        "preview",
        "threat-review",
        "compat",
        "governance",
        "guidance",
        "supply-chain",
    ];

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
            Self::Canonical => Some("archive/wave2-ledger.toml"),
            Self::ToolJsonExtension => Some("archive/wave3-ledger.toml"),
            Self::ServerJsonExtension => Some("archive/wave1-ledger.toml"),
            Self::GithubActionsExtension => None,
            Self::AiNativeDiscovery => None,
        }
    }

    pub(crate) fn candidate_ledger_path(self) -> &'static str {
        match self {
            Self::Canonical => "target/external-validation/wave3/candidate-ledger.toml",
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
            Self::Canonical => "target/external-validation/wave3/raw",
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
            Self::Canonical => 3,
            Self::ToolJsonExtension => 4,
            Self::ServerJsonExtension => 2,
            Self::GithubActionsExtension => 1,
            Self::AiNativeDiscovery => 1,
        }
    }

    pub(crate) fn scan_preset_matrix(self) -> &'static [&'static str] {
        match self {
            Self::Canonical => Self::CANONICAL_SCAN_PRESET_MATRIX,
            Self::ToolJsonExtension
            | Self::ServerJsonExtension
            | Self::GithubActionsExtension
            | Self::AiNativeDiscovery => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_known_packages() {
        let cases = [
            ("canonical", ValidationPackage::Canonical),
            ("tool-json-extension", ValidationPackage::ToolJsonExtension),
            (
                "server-json-extension",
                ValidationPackage::ServerJsonExtension,
            ),
            (
                "github-actions-extension",
                ValidationPackage::GithubActionsExtension,
            ),
            ("ai-native-discovery", ValidationPackage::AiNativeDiscovery),
        ];

        for (value, expected) in cases {
            assert_eq!(ValidationPackage::parse(value).unwrap(), expected);
        }
    }

    #[test]
    fn parse_rejects_unknown_package() {
        let error = ValidationPackage::parse("does-not-exist").unwrap_err();
        assert_eq!(
            error,
            "unknown external validation package `does-not-exist`"
        );
    }

    #[test]
    fn shortlist_and_ledger_paths_match_spec() {
        let cases = [
            (
                ValidationPackage::Canonical,
                SHORTLIST_PATH,
                LEDGER_PATH,
                Some("archive/wave2-ledger.toml"),
                "target/external-validation/wave3/candidate-ledger.toml",
                "target/external-validation/wave3/raw",
                3,
                ValidationPackage::CANONICAL_SCAN_PRESET_MATRIX,
            ),
            (
                ValidationPackage::ToolJsonExtension,
                TOOL_JSON_EXTENSION_SHORTLIST_PATH,
                TOOL_JSON_EXTENSION_LEDGER_PATH,
                Some("archive/wave3-ledger.toml"),
                "target/external-validation/tool-json-extension/candidate-ledger.toml",
                "target/external-validation/tool-json-extension/raw",
                4,
                &[],
            ),
            (
                ValidationPackage::ServerJsonExtension,
                SERVER_JSON_EXTENSION_SHORTLIST_PATH,
                SERVER_JSON_EXTENSION_LEDGER_PATH,
                Some("archive/wave1-ledger.toml"),
                "target/external-validation/server-json-extension/candidate-ledger.toml",
                "target/external-validation/server-json-extension/raw",
                2,
                &[],
            ),
            (
                ValidationPackage::GithubActionsExtension,
                GITHUB_ACTIONS_EXTENSION_SHORTLIST_PATH,
                GITHUB_ACTIONS_EXTENSION_LEDGER_PATH,
                None,
                "target/external-validation/github-actions-extension/candidate-ledger.toml",
                "target/external-validation/github-actions-extension/raw",
                1,
                &[],
            ),
            (
                ValidationPackage::AiNativeDiscovery,
                AI_NATIVE_DISCOVERY_SHORTLIST_PATH,
                AI_NATIVE_DISCOVERY_LEDGER_PATH,
                None,
                "target/external-validation/ai-native-discovery/candidate-ledger.toml",
                "target/external-validation/ai-native-discovery/raw",
                1,
                &[],
            ),
        ];

        for (package, shortlist, ledger, baseline, candidate, output_root, wave, preset_matrix) in
            cases
        {
            assert_eq!(package.shortlist_path(), shortlist);
            assert_eq!(package.ledger_path(), ledger);
            assert_eq!(package.baseline_reference(), baseline);
            assert_eq!(package.candidate_ledger_path(), candidate);
            assert_eq!(package.raw_output_root(), output_root);
            assert_eq!(package.default_wave(), wave);
            assert_eq!(package.scan_preset_matrix(), preset_matrix);
        }
    }
}
