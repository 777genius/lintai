use std::path::Path;

use crate::external_validation::*;

use super::rules::append_rule_repo_hits;

pub(super) fn append_hybrid_scope_expansion(
    output: &mut String,
    workspace_root: &Path,
    current: &ExternalValidationLedger,
) {
    let expanded_surface_counts = expanded_surface_counts(current);
    let tool_rule_hits = rule_count(current, &["SEC314", "SEC315", "SEC316", "SEC317", "SEC318"]);
    let mcp_rule_hits = rule_count(
        current,
        &[
            "SEC301", "SEC302", "SEC303", "SEC304", "SEC305", "SEC306", "SEC307", "SEC308",
            "SEC309", "SEC310", "SEC329", "SEC330", "SEC331", "SEC337", "SEC338", "SEC339",
            "SEC346",
        ],
    );
    let env_file_hits = rule_count(current, &["SEC336"]);
    let docker_rule_hits = rule_count(current, &["SEC337", "SEC338", "SEC339", "SEC346"]);
    let sec313_hits = rule_count(current, &["SEC313"]);
    let sec335_hits = rule_count(current, &["SEC335"]);
    let sec347_hits = rule_count(current, &["SEC347"]);
    let sec348_hits = rule_count(current, &["SEC348"]);
    let sec349_hits = rule_count(current, &["SEC349"]);
    let sec350_hits = rule_count(current, &["SEC350"]);
    let sec351_hits = rule_count(current, &["SEC351"]);
    let sec352_hits = rule_count(current, &["SEC352"]);
    let sec353_hits = rule_count(current, &["SEC353"]);
    let sec354_hits = rule_count(current, &["SEC354"]);
    let sec355_hits = rule_count(current, &["SEC355"]);
    let sec356_hits = rule_count(current, &["SEC356"]);
    let sec357_hits = rule_count(current, &["SEC357"]);
    let sec358_hits = rule_count(current, &["SEC358"]);
    let sec359_hits = rule_count(current, &["SEC359"]);
    let sec360_hits = rule_count(current, &["SEC360"]);
    let sec361_hits = rule_count(current, &["SEC361"]);
    let sec347_subtypes = sec347_subtype_counts(workspace_root, current);
    let sec348_repos = repos_with_rule_hits(current, &["SEC348"], false);
    let sec349_repos = repos_with_rule_hits(current, &["SEC349"], false);
    let sec350_repos = repos_with_rule_hits(current, &["SEC350"], false);
    let sec351_repos = repos_with_rule_hits(current, &["SEC351"], false);
    let sec352_repos = repos_with_rule_hits(current, &["SEC352"], false);
    let sec353_repos = repos_with_rule_hits(current, &["SEC353"], false);
    let sec354_repos = repos_with_rule_hits(current, &["SEC354"], false);
    let sec355_repos = repos_with_rule_hits(current, &["SEC355"], false);
    let sec356_repos = repos_with_rule_hits(current, &["SEC356"], false);
    let sec357_repos = repos_with_rule_hits(current, &["SEC357"], false);
    let sec358_repos = repos_with_rule_hits(current, &["SEC358"], false);
    let sec359_repos = repos_with_rule_hits(current, &["SEC359"], false);
    let sec360_repos = repos_with_rule_hits(current, &["SEC360"], false);
    let sec361_repos = repos_with_rule_hits(current, &["SEC361"], false);

    output.push_str("## Hybrid Scope Expansion Results\n\n");
    output.push_str("Current wave inventory for the newly expanded JSON lanes:\n\n");
    output.push_str(&format!(
        "- repos with root `mcp.json`: `{}`\n",
        expanded_surface_counts.top_level_mcp
    ));
    output.push_str(&format!(
        "- repos with `.mcp.json`: `{}`\n",
        expanded_surface_counts.dot_mcp
    ));
    output.push_str(&format!(
        "- repos with `.cursor/mcp.json`: `{}`\n",
        expanded_surface_counts.cursor_mcp
    ));
    output.push_str(&format!(
        "- repos with `.vscode/mcp.json`: `{}`\n",
        expanded_surface_counts.vscode_mcp
    ));
    output.push_str(&format!(
        "- repos with `.roo/mcp.json`: `{}`\n",
        expanded_surface_counts.roo_mcp
    ));
    output.push_str(&format!(
        "- repos with `.kiro/settings/mcp.json`: `{}`\n",
        expanded_surface_counts.kiro_mcp
    ));
    output.push_str(&format!(
        "- repos with `gemini-extension.json`: `{}`\n",
        expanded_surface_counts.gemini_extension
    ));
    output.push_str(&format!(
        "- repos with `gemini.settings.json`: `{}`\n",
        expanded_surface_counts.gemini_settings
    ));
    output.push_str(&format!(
        "- repos with `.gemini/settings.json`: `{}`\n",
        expanded_surface_counts.dot_gemini_settings
    ));
    output.push_str(&format!(
        "- repos with `vscode.settings.json`: `{}`\n",
        expanded_surface_counts.vscode_settings
    ));
    output.push_str(&format!(
        "- repos with `.claude/mcp/*.json`: `{}`\n",
        expanded_surface_counts.claude_mcp
    ));
    output.push_str(&format!(
        "- repos with Docker-based MCP launch configs: `{}`\n",
        expanded_surface_counts.docker_mcp_launch
    ));
    output.push_str(&format!("- MCP findings from expanded client-config coverage (`SEC301`-`SEC331`, `SEC337`-`SEC339`, `SEC346`): `{}`\n", mcp_rule_hits));
    output.push_str(&format!("- findings from `SEC336`: `{}`\n", env_file_hits));
    output.push_str(&format!(
        "- findings from `SEC337`-`SEC339`, `SEC346`: `{}`\n",
        docker_rule_hits
    ));
    output.push_str("- AI-native markdown preview findings:\n");
    output.push_str(&format!(
        "  - `SEC313` fenced pipe-to-shell examples: `{}`\n",
        sec313_hits
    ));
    output.push_str(&format!(
        "  - `SEC335` metadata-service access examples: `{}`\n",
        sec335_hits
    ));
    output.push_str(&format!(
        "  - `SEC347` mutable MCP setup launcher examples: `{}`\n",
        sec347_hits
    ));
    output.push_str(&format!(
        "    - CLI-form repo hits: `{}`\n",
        sec347_subtypes.cli_form_repos
    ));
    output.push_str(&format!(
        "    - config-snippet-form repo hits: `{}`\n",
        sec347_subtypes.config_snippet_repos
    ));
    output.push_str(&format!(
        "  - `SEC348` mutable Docker registry-image examples: `{}`\n",
        sec348_hits
    ));
    output.push_str(&format!(
        "  - `SEC349` Docker host-escape or privileged runtime examples: `{}`\n",
        sec349_hits
    ));
    output.push_str(&format!(
        "  - `SEC350` untrusted-input instruction-promotion examples: `{}`\n",
        sec350_hits
    ));
    output.push_str(&format!(
        "  - `SEC351` approval-bypass instruction examples: `{}`\n",
        sec351_hits
    ));
    output.push_str(&format!(
        "  - `SEC352` unscoped Bash tool grants in frontmatter: `{}`\n",
        sec352_hits
    ));
    output.push_str(&format!(
        "  - `SEC353` Copilot instruction files above 4000 chars: `{}`\n",
        sec353_hits
    ));
    output.push_str(&format!(
        "  - `SEC354` path-specific Copilot instructions missing `applyTo`: `{}`\n",
        sec354_hits
    ));
    output.push_str(&format!(
        "  - `SEC355` wildcard tool grants in frontmatter: `{}`\n",
        sec355_hits
    ));
    output.push_str(&format!(
        "  - `SEC356` plugin agent frontmatter `permissionMode`: `{}`\n",
        sec356_hits
    ));
    output.push_str(&format!(
        "  - `SEC357` plugin agent frontmatter `hooks`: `{}`\n",
        sec357_hits
    ));
    output.push_str(&format!(
        "  - `SEC358` plugin agent frontmatter `mcpServers`: `{}`\n",
        sec358_hits
    ));
    output.push_str(&format!(
        "  - `SEC359` Cursor rule non-boolean `alwaysApply`: `{}`\n",
        sec359_hits
    ));
    output.push_str(&format!(
        "  - `SEC360` Cursor rule non-sequence `globs`: `{}`\n",
        sec360_hits
    ));
    output.push_str(&format!(
        "  - `SEC361` Claude settings missing `$schema`: `{}`\n",
        sec361_hits
    ));
    if sec347_hits > 0 {
        output.push_str(&format!(
            "  - current `SEC347` usefulness is being driven mainly by {}\n",
            sec347_primary_driver_label(sec347_subtypes)
        ));
    }
    output.push_str(&format!(
        "- repos with `tool_descriptor_json`: `{}`\n",
        expanded_surface_counts.tool_descriptor_json
    ));
    output.push_str(&format!(
        "- findings from `SEC314`-`SEC318`: `{}`\n",
        tool_rule_hits
    ));
    output.push_str(&format!("- repos where new MCP client-config variants existed only under fixture-like paths: `{}`\n", expanded_surface_counts.fixture_only_client_variants));
    output.push_str(&format!("- repos where Docker-based MCP launch existed only under fixture-like client-config variants: `{}`\n", expanded_surface_counts.fixture_only_docker_client_variants));
    if env_file_hits == 0 && mcp_rule_hits == 0 {
        output.push_str("- expanded MCP client-config coverage produced no external MCP hits on the canonical cohort yet\n");
    }
    if docker_rule_hits == 0 {
        output.push_str("- no external hits were produced yet from Docker-based MCP launch hardening on the canonical cohort\n");
    }
    if tool_rule_hits == 0 {
        output.push_str("- no non-fixture external `Stable` hits were produced yet on committed tool-descriptor JSON\n");
    }
    append_rule_repo_hits(output, "SEC348", sec348_repos);
    append_rule_repo_hits(output, "SEC349", sec349_repos);
    append_rule_repo_hits(output, "SEC350", sec350_repos);
    append_rule_repo_hits(output, "SEC351", sec351_repos);
    append_rule_repo_hits(output, "SEC352", sec352_repos);
    append_rule_repo_hits(output, "SEC353", sec353_repos);
    append_rule_repo_hits(output, "SEC354", sec354_repos);
    append_rule_repo_hits(output, "SEC355", sec355_repos);
    append_rule_repo_hits(output, "SEC356", sec356_repos);
    append_rule_repo_hits(output, "SEC357", sec357_repos);
    append_rule_repo_hits(output, "SEC358", sec358_repos);
    append_rule_repo_hits(output, "SEC359", sec359_repos);
    append_rule_repo_hits(output, "SEC360", sec360_repos);
    append_rule_repo_hits(output, "SEC361", sec361_repos);
    output.push_str("- fixture/testdata/example suppression stayed active for the newly added MCP client-config variants and did not create a fake usefulness signal from fixture-like paths\n\n");
}
