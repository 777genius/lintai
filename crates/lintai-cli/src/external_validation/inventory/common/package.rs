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
