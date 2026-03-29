use crate::external_validation::{
    count_any_surface_presence, count_surface_presence, ExternalValidationLedger,
};

pub(crate) struct ExpandedSurfaceCounts {
    pub(crate) top_level_mcp: usize,
    pub(crate) dot_mcp: usize,
    pub(crate) cursor_mcp: usize,
    pub(crate) vscode_mcp: usize,
    pub(crate) roo_mcp: usize,
    pub(crate) kiro_mcp: usize,
    pub(crate) gemini_extension: usize,
    pub(crate) gemini_settings: usize,
    pub(crate) dot_gemini_settings: usize,
    pub(crate) vscode_settings: usize,
    pub(crate) claude_mcp: usize,
    pub(crate) docker_mcp_launch: usize,
    pub(crate) tool_descriptor_json: usize,
    pub(crate) fixture_only_client_variants: usize,
    pub(crate) fixture_only_docker_client_variants: usize,
}

pub(crate) fn expanded_surface_counts(ledger: &ExternalValidationLedger) -> ExpandedSurfaceCounts {
    ExpandedSurfaceCounts {
        top_level_mcp: count_any_surface_presence(ledger, &["mcp.json"]),
        dot_mcp: count_surface_presence(ledger, ".mcp.json"),
        cursor_mcp: count_any_surface_presence(
            ledger,
            &[".cursor/mcp.json", ".cursor/mcp.json (fixture-like)"],
        ),
        vscode_mcp: count_any_surface_presence(
            ledger,
            &[".vscode/mcp.json", ".vscode/mcp.json (fixture-like)"],
        ),
        roo_mcp: count_any_surface_presence(
            ledger,
            &[".roo/mcp.json", ".roo/mcp.json (fixture-like)"],
        ),
        kiro_mcp: count_any_surface_presence(
            ledger,
            &[
                ".kiro/settings/mcp.json",
                ".kiro/settings/mcp.json (fixture-like)",
            ],
        ),
        gemini_extension: count_any_surface_presence(
            ledger,
            &[
                "gemini-extension.json",
                "gemini-extension.json (fixture-like)",
            ],
        ),
        gemini_settings: count_any_surface_presence(
            ledger,
            &[
                "gemini.settings.json",
                "gemini.settings.json (fixture-like)",
            ],
        ),
        dot_gemini_settings: count_any_surface_presence(
            ledger,
            &[
                ".gemini/settings.json",
                ".gemini/settings.json (fixture-like)",
            ],
        ),
        vscode_settings: count_any_surface_presence(
            ledger,
            &[
                "vscode.settings.json",
                "vscode.settings.json (fixture-like)",
            ],
        ),
        claude_mcp: count_surface_presence(ledger, ".claude/mcp/*.json"),
        fixture_only_client_variants: count_surface_presence(
            ledger,
            "expanded_mcp_client_variant_fixture_only",
        ),
        docker_mcp_launch: count_any_surface_presence(
            ledger,
            &["docker_mcp_launch", "docker_mcp_launch (fixture-like)"],
        ),
        fixture_only_docker_client_variants: count_surface_presence(
            ledger,
            "docker_mcp_launch_fixture_only",
        ),
        tool_descriptor_json: count_surface_presence(ledger, "tool_descriptor_json"),
    }
}
