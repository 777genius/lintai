pub(crate) const FIXTURE_PATH_SEGMENTS: &[&str] = &[
    "test", "tests", "testdata", "fixture", "fixtures", "example", "examples", "sample", "samples",
];

pub(crate) fn is_fixture_like_tool_json_path(normalized_path: &str) -> bool {
    normalized_path.split('/').any(|segment| {
        matches!(
            segment.to_ascii_lowercase().as_str(),
            "test"
                | "tests"
                | "testdata"
                | "fixture"
                | "fixtures"
                | "example"
                | "examples"
                | "sample"
                | "samples"
        )
    })
}

pub(crate) fn is_expanded_mcp_client_variant_path(normalized_path: &str) -> bool {
    normalized_path.ends_with(".cursor/mcp.json")
        || normalized_path.ends_with(".vscode/mcp.json")
        || normalized_path.ends_with(".roo/mcp.json")
        || normalized_path.ends_with(".kiro/settings/mcp.json")
        || normalized_path.ends_with("gemini-extension.json")
        || normalized_path.ends_with("gemini.settings.json")
        || normalized_path.ends_with(".gemini/settings.json")
        || normalized_path.ends_with("vscode.settings.json")
}

pub(crate) fn is_fixture_like_claude_settings_path(normalized_path: &str) -> bool {
    normalized_path
        .split('/')
        .any(|segment| FIXTURE_PATH_SEGMENTS.contains(&segment.to_ascii_lowercase().as_str()))
}

pub(crate) fn is_fixture_like_markdown_instruction_path(normalized_path: &str) -> bool {
    normalized_path
        .split('/')
        .any(|segment| FIXTURE_PATH_SEGMENTS.contains(&segment.to_ascii_lowercase().as_str()))
}

pub(crate) fn is_fixture_like_expanded_mcp_client_variant_path(normalized_path: &str) -> bool {
    is_expanded_mcp_client_variant_path(normalized_path)
        && normalized_path.split('/').any(|segment| {
            matches!(
                segment.to_ascii_lowercase().as_str(),
                "test"
                    | "tests"
                    | "testdata"
                    | "fixture"
                    | "fixtures"
                    | "example"
                    | "examples"
                    | "sample"
                    | "samples"
            )
        })
}
