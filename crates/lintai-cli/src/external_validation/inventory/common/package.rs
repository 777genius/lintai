use super::super::super::*;

pub(crate) fn package_label(package: ValidationPackage) -> &'static str {
    match package {
        ValidationPackage::Canonical => "canonical",
        ValidationPackage::ToolJsonExtension => "tool-json extension",
        ValidationPackage::ServerJsonExtension => "server-json extension",
        ValidationPackage::GithubActionsExtension => "github-actions extension",
        ValidationPackage::AiNativeDiscovery => "ai-native discovery",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_label_canonical_maps_expected_text() {
        assert_eq!(package_label(ValidationPackage::Canonical), "canonical");
    }

    #[test]
    fn package_label_tool_json_extension_maps_expected_text() {
        assert_eq!(
            package_label(ValidationPackage::ToolJsonExtension),
            "tool-json extension"
        );
    }

    #[test]
    fn package_label_server_json_extension_maps_expected_text() {
        assert_eq!(
            package_label(ValidationPackage::ServerJsonExtension),
            "server-json extension"
        );
    }

    #[test]
    fn package_label_github_actions_extension_maps_expected_text() {
        assert_eq!(
            package_label(ValidationPackage::GithubActionsExtension),
            "github-actions extension"
        );
    }

    #[test]
    fn package_label_ai_native_discovery_maps_expected_text() {
        assert_eq!(
            package_label(ValidationPackage::AiNativeDiscovery),
            "ai-native discovery"
        );
    }
}
