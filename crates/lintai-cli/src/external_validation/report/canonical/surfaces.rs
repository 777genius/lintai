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
            "SEC346", "SEC394", "SEC395", "SEC396", "SEC397", "SEC398",
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
    let sec362_hits = rule_count(current, &["SEC362"]);
    let sec363_hits = rule_count(current, &["SEC363"]);
    let sec364_hits = rule_count(current, &["SEC364"]);
    let sec365_hits = rule_count(current, &["SEC365"]);
    let sec366_hits = rule_count(current, &["SEC366"]);
    let sec367_hits = rule_count(current, &["SEC367"]);
    let sec368_hits = rule_count(current, &["SEC368"]);
    let sec369_hits = rule_count(current, &["SEC369"]);
    let sec370_hits = rule_count(current, &["SEC370"]);
    let sec371_hits = rule_count(current, &["SEC371"]);
    let sec372_hits = rule_count(current, &["SEC372"]);
    let sec373_hits = rule_count(current, &["SEC373"]);
    let sec374_hits = rule_count(current, &["SEC374"]);
    let sec375_hits = rule_count(current, &["SEC375"]);
    let sec376_hits = rule_count(current, &["SEC376"]);
    let sec377_hits = rule_count(current, &["SEC377"]);
    let sec378_hits = rule_count(current, &["SEC378"]);
    let sec379_hits = rule_count(current, &["SEC379"]);
    let sec380_hits = rule_count(current, &["SEC380"]);
    let sec381_hits = rule_count(current, &["SEC381"]);
    let sec382_hits = rule_count(current, &["SEC382"]);
    let sec383_hits = rule_count(current, &["SEC383"]);
    let sec384_hits = rule_count(current, &["SEC384"]);
    let sec385_hits = rule_count(current, &["SEC385"]);
    let sec386_hits = rule_count(current, &["SEC386"]);
    let sec387_hits = rule_count(current, &["SEC387"]);
    let sec388_hits = rule_count(current, &["SEC388"]);
    let sec394_hits = rule_count(current, &["SEC394"]);
    let sec395_hits = rule_count(current, &["SEC395"]);
    let sec396_hits = rule_count(current, &["SEC396"]);
    let sec397_hits = rule_count(current, &["SEC397"]);
    let sec398_hits = rule_count(current, &["SEC398"]);
    let sec399_hits = rule_count(current, &["SEC399"]);
    let sec400_hits = rule_count(current, &["SEC400"]);
    let sec405_hits = rule_count(current, &["SEC405"]);
    let sec406_hits = rule_count(current, &["SEC406"]);
    let sec407_hits = rule_count(current, &["SEC407"]);
    let sec408_hits = rule_count(current, &["SEC408"]);
    let sec409_hits = rule_count(current, &["SEC409"]);
    let sec410_hits = rule_count(current, &["SEC410"]);
    let sec411_hits = rule_count(current, &["SEC411"]);
    let sec412_hits = rule_count(current, &["SEC412"]);
    let sec413_hits = rule_count(current, &["SEC413"]);
    let sec414_hits = rule_count(current, &["SEC414"]);
    let sec415_hits = rule_count(current, &["SEC415"]);
    let sec416_hits = rule_count(current, &["SEC416"]);
    let sec417_hits = rule_count(current, &["SEC417"]);
    let sec418_hits = rule_count(current, &["SEC418"]);
    let sec474_hits = rule_count(current, &["SEC474"]);
    let sec475_hits = rule_count(current, &["SEC475"]);
    let sec476_hits = rule_count(current, &["SEC476"]);
    let sec477_hits = rule_count(current, &["SEC477"]);
    let sec478_hits = rule_count(current, &["SEC478"]);
    let sec479_hits = rule_count(current, &["SEC479"]);
    let sec480_hits = rule_count(current, &["SEC480"]);
    let sec481_hits = rule_count(current, &["SEC481"]);
    let sec482_hits = rule_count(current, &["SEC482"]);
    let sec483_hits = rule_count(current, &["SEC483"]);
    let sec484_hits = rule_count(current, &["SEC484"]);
    let sec485_hits = rule_count(current, &["SEC485"]);
    let sec486_hits = rule_count(current, &["SEC486"]);
    let sec487_hits = rule_count(current, &["SEC487"]);
    let sec488_hits = rule_count(current, &["SEC488"]);
    let sec489_hits = rule_count(current, &["SEC489"]);
    let sec490_hits = rule_count(current, &["SEC490"]);
    let sec491_hits = rule_count(current, &["SEC491"]);
    let sec492_hits = rule_count(current, &["SEC492"]);
    let sec493_hits = rule_count(current, &["SEC493"]);
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
    let sec362_repos = repos_with_rule_hits(current, &["SEC362"], false);
    let sec363_repos = repos_with_rule_hits(current, &["SEC363"], false);
    let sec364_repos = repos_with_rule_hits(current, &["SEC364"], false);
    let sec365_repos = repos_with_rule_hits(current, &["SEC365"], false);
    let sec366_repos = repos_with_rule_hits(current, &["SEC366"], false);
    let sec367_repos = repos_with_rule_hits(current, &["SEC367"], false);
    let sec368_repos = repos_with_rule_hits(current, &["SEC368"], false);
    let sec369_repos = repos_with_rule_hits(current, &["SEC369"], false);
    let sec370_repos = repos_with_rule_hits(current, &["SEC370"], false);
    let sec371_repos = repos_with_rule_hits(current, &["SEC371"], false);
    let sec372_repos = repos_with_rule_hits(current, &["SEC372"], false);
    let sec373_repos = repos_with_rule_hits(current, &["SEC373"], false);
    let sec374_repos = repos_with_rule_hits(current, &["SEC374"], false);
    let sec375_repos = repos_with_rule_hits(current, &["SEC375"], false);
    let sec376_repos = repos_with_rule_hits(current, &["SEC376"], false);
    let sec377_repos = repos_with_rule_hits(current, &["SEC377"], false);
    let sec378_repos = repos_with_rule_hits(current, &["SEC378"], false);
    let sec379_repos = repos_with_rule_hits(current, &["SEC379"], false);
    let sec380_repos = repos_with_rule_hits(current, &["SEC380"], false);
    let sec381_repos = repos_with_rule_hits(current, &["SEC381"], false);
    let sec382_repos = repos_with_rule_hits(current, &["SEC382"], false);
    let sec383_repos = repos_with_rule_hits(current, &["SEC383"], false);
    let sec384_repos = repos_with_rule_hits(current, &["SEC384"], false);
    let sec385_repos = repos_with_rule_hits(current, &["SEC385"], false);
    let sec386_repos = repos_with_rule_hits(current, &["SEC386"], false);
    let sec387_repos = repos_with_rule_hits(current, &["SEC387"], false);
    let sec388_repos = repos_with_rule_hits(current, &["SEC388"], false);
    let sec394_repos = repos_with_rule_hits(current, &["SEC394"], false);
    let sec395_repos = repos_with_rule_hits(current, &["SEC395"], false);
    let sec396_repos = repos_with_rule_hits(current, &["SEC396"], false);
    let sec397_repos = repos_with_rule_hits(current, &["SEC397"], false);
    let sec398_repos = repos_with_rule_hits(current, &["SEC398"], false);
    let sec399_repos = repos_with_rule_hits(current, &["SEC399"], false);
    let sec400_repos = repos_with_rule_hits(current, &["SEC400"], false);
    let sec405_repos = repos_with_rule_hits(current, &["SEC405"], false);
    let sec406_repos = repos_with_rule_hits(current, &["SEC406"], false);
    let sec407_repos = repos_with_rule_hits(current, &["SEC407"], false);
    let sec408_repos = repos_with_rule_hits(current, &["SEC408"], false);
    let sec409_repos = repos_with_rule_hits(current, &["SEC409"], false);
    let sec410_repos = repos_with_rule_hits(current, &["SEC410"], false);
    let sec411_repos = repos_with_rule_hits(current, &["SEC411"], false);
    let sec412_repos = repos_with_rule_hits(current, &["SEC412"], false);
    let sec413_repos = repos_with_rule_hits(current, &["SEC413"], false);
    let sec414_repos = repos_with_rule_hits(current, &["SEC414"], false);
    let sec415_repos = repos_with_rule_hits(current, &["SEC415"], false);
    let sec416_repos = repos_with_rule_hits(current, &["SEC416"], false);
    let sec417_repos = repos_with_rule_hits(current, &["SEC417"], false);
    let sec418_repos = repos_with_rule_hits(current, &["SEC418"], false);
    let sec474_repos = repos_with_rule_hits(current, &["SEC474"], false);
    let sec475_repos = repos_with_rule_hits(current, &["SEC475"], false);
    let sec476_repos = repos_with_rule_hits(current, &["SEC476"], false);
    let sec477_repos = repos_with_rule_hits(current, &["SEC477"], false);
    let sec478_repos = repos_with_rule_hits(current, &["SEC478"], false);
    let sec479_repos = repos_with_rule_hits(current, &["SEC479"], false);
    let sec480_repos = repos_with_rule_hits(current, &["SEC480"], false);
    let sec481_repos = repos_with_rule_hits(current, &["SEC481"], false);
    let sec482_repos = repos_with_rule_hits(current, &["SEC482"], false);
    let sec483_repos = repos_with_rule_hits(current, &["SEC483"], false);
    let sec484_repos = repos_with_rule_hits(current, &["SEC484"], false);
    let sec485_repos = repos_with_rule_hits(current, &["SEC485"], false);
    let sec486_repos = repos_with_rule_hits(current, &["SEC486"], false);
    let sec487_repos = repos_with_rule_hits(current, &["SEC487"], false);
    let sec488_repos = repos_with_rule_hits(current, &["SEC488"], false);
    let sec489_repos = repos_with_rule_hits(current, &["SEC489"], false);
    let sec490_repos = repos_with_rule_hits(current, &["SEC490"], false);
    let sec491_repos = repos_with_rule_hits(current, &["SEC491"], false);
    let sec492_repos = repos_with_rule_hits(current, &["SEC492"], false);
    let sec493_repos = repos_with_rule_hits(current, &["SEC493"], false);

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
    output.push_str(&format!(
        "  - `SEC362` Claude settings wildcard `Bash(*)` permissions: `{}`\n",
        sec362_hits
    ));
    output.push_str(&format!(
        "  - `SEC363` Claude settings home-directory hook commands: `{}`\n",
        sec363_hits
    ));
    output.push_str(&format!(
        "  - `SEC364` Claude settings `bypassPermissions` default mode: `{}`\n",
        sec364_hits
    ));
    output.push_str(&format!(
        "  - `SEC365` Claude settings non-HTTPS `allowedHttpHookUrls`: `{}`\n",
        sec365_hits
    ));
    output.push_str(&format!(
        "  - `SEC366` Claude settings dangerous host literals in `allowedHttpHookUrls`: `{}`\n",
        sec366_hits
    ));
    output.push_str(&format!(
        "  - `SEC367` Claude settings wildcard `WebFetch(*)` permissions: `{}`\n",
        sec367_hits
    ));
    output.push_str(&format!(
        "  - `SEC368` Claude settings repo-external absolute hook paths: `{}`\n",
        sec368_hits
    ));
    output.push_str(&format!(
        "  - `SEC369` Claude settings wildcard `Write(*)` permissions: `{}`\n",
        sec369_hits
    ));
    output.push_str(&format!(
        "  - `SEC370` path-specific Copilot instructions using the wrong suffix: `{}`\n",
        sec370_hits
    ));
    output.push_str(&format!(
        "  - `SEC371` path-specific Copilot instructions with invalid `applyTo`: `{}`\n",
        sec371_hits
    ));
    output.push_str(&format!(
        "  - `SEC377` path-specific Copilot instructions with invalid `applyTo` globs: `{}`\n",
        sec377_hits
    ));
    output.push_str(&format!(
        "  - `SEC378` Cursor rules with redundant `globs` alongside `alwaysApply: true`: `{}`\n",
        sec378_hits
    ));
    output.push_str(&format!(
        "  - `SEC379` Cursor rules with unknown frontmatter keys: `{}`\n",
        sec379_hits
    ));
    output.push_str(&format!(
        "  - `SEC380` Cursor rules missing `description`: `{}`\n",
        sec380_hits
    ));
    output.push_str(&format!(
        "  - `SEC381` Claude settings command hooks missing `timeout`: `{}`\n",
        sec381_hits
    ));
    output.push_str(&format!(
        "  - `SEC382` Claude settings `matcher` on unsupported hook events: `{}`\n",
        sec382_hits
    ));
    output.push_str(&format!(
        "  - `SEC383` Claude settings missing `matcher` on matcher-capable hook events: `{}`\n",
        sec383_hits
    ));
    output.push_str(&format!(
        "  - `SEC384` Claude settings bare `WebSearch` permissions: `{}`\n",
        sec384_hits
    ));
    output.push_str(&format!(
        "  - `SEC385` Claude settings shared `git push` permissions: `{}`\n",
        sec385_hits
    ));
    output.push_str(&format!(
        "  - `SEC386` Claude settings shared `git checkout:*` permissions: `{}`\n",
        sec386_hits
    ));
    output.push_str(&format!(
        "  - `SEC387` Claude settings shared `git commit:*` permissions: `{}`\n",
        sec387_hits
    ));
    output.push_str(&format!(
        "  - `SEC388` Claude settings shared `git stash:*` permissions: `{}`\n",
        sec388_hits
    ));
    output.push_str(&format!(
        "  - `SEC394` MCP configs with wildcard `autoApprove`: `{}`\n",
        sec394_hits
    ));
    output.push_str(&format!(
        "  - `SEC395` MCP configs with `autoApproveTools: true`: `{}`\n",
        sec395_hits
    ));
    output.push_str(&format!(
        "  - `SEC396` MCP configs with `trustTools: true`: `{}`\n",
        sec396_hits
    ));
    output.push_str(&format!(
        "  - `SEC397` MCP configs with sandbox disabled: `{}`\n",
        sec397_hits
    ));
    output.push_str(&format!(
        "  - `SEC398` MCP configs with wildcard capabilities: `{}`\n",
        sec398_hits
    ));
    output.push_str(&format!(
        "  - `SEC399` Claude settings shared `Bash(npx ...)` permissions: `{}`\n",
        sec399_hits
    ));
    output.push_str(&format!(
        "  - `SEC400` Claude settings shared `enabledMcpjsonServers`: `{}`\n",
        sec400_hits
    ));
    output.push_str(&format!(
        "  - `SEC405` Claude settings shared package installation permissions: `{}`\n",
        sec405_hits
    ));
    output.push_str(&format!(
        "  - `SEC406` Claude settings shared `git add` permissions: `{}`\n",
        sec406_hits
    ));
    output.push_str(&format!(
        "  - `SEC407` Claude settings shared `git clone` permissions: `{}`\n",
        sec407_hits
    ));
    output.push_str(&format!(
        "  - `SEC408` Claude settings shared `gh pr` permissions: `{}`\n",
        sec408_hits
    ));
    output.push_str(&format!(
        "  - `SEC409` Claude settings shared `git fetch` permissions: `{}`\n",
        sec409_hits
    ));
    output.push_str(&format!(
        "  - `SEC410` Claude settings shared `git ls-remote` permissions: `{}`\n",
        sec410_hits
    ));
    output.push_str(&format!(
        "  - `SEC411` Claude settings shared `curl` permissions: `{}`\n",
        sec411_hits
    ));
    output.push_str(&format!(
        "  - `SEC412` Claude settings shared `wget` permissions: `{}`\n",
        sec412_hits
    ));
    output.push_str(&format!(
        "  - `SEC413` Claude settings shared `git config` permissions: `{}`\n",
        sec413_hits
    ));
    output.push_str(&format!(
        "  - `SEC414` Claude settings shared `git tag` permissions: `{}`\n",
        sec414_hits
    ));
    output.push_str(&format!(
        "  - `SEC415` Claude settings shared `git branch` permissions: `{}`\n",
        sec415_hits
    ));
    output.push_str(&format!(
        "  - `SEC416` AI-native markdown bare `pip install` Claude transcripts: `{}`\n",
        sec416_hits
    ));
    output.push_str(&format!(
        "  - `SEC417` AI-native markdown unpinned `pip install git+https://...` examples: `{}`\n",
        sec417_hits
    ));
    output.push_str(&format!(
        "  - `SEC418` Claude settings raw GitHub content fetch permissions: `{}`\n",
        sec418_hits
    ));
    output.push_str(&format!(
        "  - `SEC474` AI-native markdown shared `gh pr` tool grants: `{}`\n",
        sec474_hits
    ));
    output.push_str(&format!(
        "  - `SEC475` Claude settings unsafe `Read(...)` path permissions: `{}`\n",
        sec475_hits
    ));
    output.push_str(&format!(
        "  - `SEC476` Claude settings unsafe `Write(...)` path permissions: `{}`\n",
        sec476_hits
    ));
    output.push_str(&format!(
        "  - `SEC477` Claude settings unsafe `Edit(...)` path permissions: `{}`\n",
        sec477_hits
    ));
    output.push_str(&format!(
        "  - `SEC478` Claude settings shared `git reset:*` permissions: `{}`\n",
        sec478_hits
    ));
    output.push_str(&format!(
        "  - `SEC479` Claude settings shared `git clean:*` permissions: `{}`\n",
        sec479_hits
    ));
    output.push_str(&format!(
        "  - `SEC480` Claude settings shared `git restore:*` permissions: `{}`\n",
        sec480_hits
    ));
    output.push_str(&format!(
        "  - `SEC481` Claude settings shared `git rebase:*` permissions: `{}`\n",
        sec481_hits
    ));
    output.push_str(&format!(
        "  - `SEC482` Claude settings shared `git merge:*` permissions: `{}`\n",
        sec482_hits
    ));
    output.push_str(&format!(
        "  - `SEC483` Claude settings shared `git cherry-pick:*` permissions: `{}`\n",
        sec483_hits
    ));
    output.push_str(&format!(
        "  - `SEC484` Claude settings shared `git apply:*` permissions: `{}`\n",
        sec484_hits
    ));
    output.push_str(&format!(
        "  - `SEC485` Claude settings shared `git am:*` permissions: `{}`\n",
        sec485_hits
    ));
    output.push_str(&format!(
        "  - `SEC486` Claude settings unsafe `Glob(...)` path permissions: `{}`\n",
        sec486_hits
    ));
    output.push_str(&format!(
        "  - `SEC487` Claude settings unsafe `Grep(...)` path permissions: `{}`\n",
        sec487_hits
    ));
    output.push_str(&format!(
        "  - `SEC488` Claude settings shared `Bash(uvx ...)` permissions: `{}`\n",
        sec488_hits
    ));
    output.push_str(&format!(
        "  - `SEC489` Claude settings shared `Bash(pnpm dlx ...)` permissions: `{}`\n",
        sec489_hits
    ));
    output.push_str(&format!(
        "  - `SEC490` Claude settings shared `Bash(yarn dlx ...)` permissions: `{}`\n",
        sec490_hits
    ));
    output.push_str(&format!(
        "  - `SEC491` Claude settings shared `Bash(pipx run ...)` permissions: `{}`\n",
        sec491_hits
    ));
    output.push_str(&format!(
        "  - `SEC492` Claude settings shared `Bash(npm exec ...)` permissions: `{}`\n",
        sec492_hits
    ));
    output.push_str(&format!(
        "  - `SEC493` Claude settings shared `Bash(bunx ...)` permissions: `{}`\n",
        sec493_hits
    ));
    output.push_str(&format!(
        "  - `SEC372` Claude settings wildcard `Read(*)` permissions: `{}`\n",
        sec372_hits
    ));
    output.push_str(&format!(
        "  - `SEC373` Claude settings wildcard `Edit(*)` permissions: `{}`\n",
        sec373_hits
    ));
    output.push_str(&format!(
        "  - `SEC374` Claude settings wildcard `WebSearch(*)` permissions: `{}`\n",
        sec374_hits
    ));
    output.push_str(&format!(
        "  - `SEC375` Claude settings wildcard `Glob(*)` permissions: `{}`\n",
        sec375_hits
    ));
    output.push_str(&format!(
        "  - `SEC376` Claude settings wildcard `Grep(*)` permissions: `{}`\n",
        sec376_hits
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
    append_rule_repo_hits(output, "SEC362", sec362_repos);
    append_rule_repo_hits(output, "SEC363", sec363_repos);
    append_rule_repo_hits(output, "SEC364", sec364_repos);
    append_rule_repo_hits(output, "SEC365", sec365_repos);
    append_rule_repo_hits(output, "SEC366", sec366_repos);
    append_rule_repo_hits(output, "SEC367", sec367_repos);
    append_rule_repo_hits(output, "SEC368", sec368_repos);
    append_rule_repo_hits(output, "SEC369", sec369_repos);
    append_rule_repo_hits(output, "SEC370", sec370_repos);
    append_rule_repo_hits(output, "SEC371", sec371_repos);
    append_rule_repo_hits(output, "SEC372", sec372_repos);
    append_rule_repo_hits(output, "SEC373", sec373_repos);
    append_rule_repo_hits(output, "SEC374", sec374_repos);
    append_rule_repo_hits(output, "SEC375", sec375_repos);
    append_rule_repo_hits(output, "SEC376", sec376_repos);
    append_rule_repo_hits(output, "SEC377", sec377_repos);
    append_rule_repo_hits(output, "SEC378", sec378_repos);
    append_rule_repo_hits(output, "SEC379", sec379_repos);
    append_rule_repo_hits(output, "SEC380", sec380_repos);
    append_rule_repo_hits(output, "SEC381", sec381_repos);
    append_rule_repo_hits(output, "SEC382", sec382_repos);
    append_rule_repo_hits(output, "SEC383", sec383_repos);
    append_rule_repo_hits(output, "SEC384", sec384_repos);
    append_rule_repo_hits(output, "SEC385", sec385_repos);
    append_rule_repo_hits(output, "SEC386", sec386_repos);
    append_rule_repo_hits(output, "SEC387", sec387_repos);
    append_rule_repo_hits(output, "SEC388", sec388_repos);
    append_rule_repo_hits(output, "SEC399", sec399_repos);
    append_rule_repo_hits(output, "SEC400", sec400_repos);
    append_rule_repo_hits(output, "SEC405", sec405_repos);
    append_rule_repo_hits(output, "SEC406", sec406_repos);
    append_rule_repo_hits(output, "SEC407", sec407_repos);
    append_rule_repo_hits(output, "SEC408", sec408_repos);
    append_rule_repo_hits(output, "SEC409", sec409_repos);
    append_rule_repo_hits(output, "SEC410", sec410_repos);
    append_rule_repo_hits(output, "SEC411", sec411_repos);
    append_rule_repo_hits(output, "SEC412", sec412_repos);
    append_rule_repo_hits(output, "SEC413", sec413_repos);
    append_rule_repo_hits(output, "SEC414", sec414_repos);
    append_rule_repo_hits(output, "SEC415", sec415_repos);
    append_rule_repo_hits(output, "SEC416", sec416_repos);
    append_rule_repo_hits(output, "SEC417", sec417_repos);
    append_rule_repo_hits(output, "SEC418", sec418_repos);
    append_rule_repo_hits(output, "SEC474", sec474_repos);
    append_rule_repo_hits(output, "SEC475", sec475_repos);
    append_rule_repo_hits(output, "SEC476", sec476_repos);
    append_rule_repo_hits(output, "SEC477", sec477_repos);
    append_rule_repo_hits(output, "SEC478", sec478_repos);
    append_rule_repo_hits(output, "SEC479", sec479_repos);
    append_rule_repo_hits(output, "SEC480", sec480_repos);
    append_rule_repo_hits(output, "SEC481", sec481_repos);
    append_rule_repo_hits(output, "SEC482", sec482_repos);
    append_rule_repo_hits(output, "SEC483", sec483_repos);
    append_rule_repo_hits(output, "SEC484", sec484_repos);
    append_rule_repo_hits(output, "SEC485", sec485_repos);
    append_rule_repo_hits(output, "SEC486", sec486_repos);
    append_rule_repo_hits(output, "SEC487", sec487_repos);
    append_rule_repo_hits(output, "SEC488", sec488_repos);
    append_rule_repo_hits(output, "SEC489", sec489_repos);
    append_rule_repo_hits(output, "SEC490", sec490_repos);
    append_rule_repo_hits(output, "SEC491", sec491_repos);
    append_rule_repo_hits(output, "SEC492", sec492_repos);
    append_rule_repo_hits(output, "SEC493", sec493_repos);
    if sec394_repos.is_empty() {
        output.push_str(
            "- `SEC394` produced no repo-level stable hits yet on the canonical cohort\n",
        );
    } else {
        output.push_str("- `SEC394` repo-level stable hits on the canonical cohort:\n");
        for (repo, count, rule_codes) in sec394_repos {
            output.push_str(&format!(
                "  - `{repo}`: `{count}` stable finding(s) via {}\n",
                format_rule_codes(&rule_codes)
            ));
        }
    }
    if sec395_repos.is_empty() {
        output.push_str(
            "- `SEC395` produced no repo-level stable hits yet on the canonical cohort\n",
        );
    } else {
        output.push_str("- `SEC395` repo-level stable hits on the canonical cohort:\n");
        for (repo, count, rule_codes) in sec395_repos {
            output.push_str(&format!(
                "  - `{repo}`: `{count}` stable finding(s) via {}\n",
                format_rule_codes(&rule_codes)
            ));
        }
    }
    if sec396_repos.is_empty() {
        output.push_str(
            "- `SEC396` produced no repo-level stable hits yet on the canonical cohort\n",
        );
    } else {
        output.push_str("- `SEC396` repo-level stable hits on the canonical cohort:\n");
        for (repo, count, rule_codes) in sec396_repos {
            output.push_str(&format!(
                "  - `{repo}`: `{count}` stable finding(s) via {}\n",
                format_rule_codes(&rule_codes)
            ));
        }
    }
    if sec397_repos.is_empty() {
        output.push_str(
            "- `SEC397` produced no repo-level stable hits yet on the canonical cohort\n",
        );
    } else {
        output.push_str("- `SEC397` repo-level stable hits on the canonical cohort:\n");
        for (repo, count, rule_codes) in sec397_repos {
            output.push_str(&format!(
                "  - `{repo}`: `{count}` stable finding(s) via {}\n",
                format_rule_codes(&rule_codes)
            ));
        }
    }
    if sec398_repos.is_empty() {
        output.push_str(
            "- `SEC398` produced no repo-level stable hits yet on the canonical cohort\n",
        );
    } else {
        output.push_str("- `SEC398` repo-level stable hits on the canonical cohort:\n");
        for (repo, count, rule_codes) in sec398_repos {
            output.push_str(&format!(
                "  - `{repo}`: `{count}` stable finding(s) via {}\n",
                format_rule_codes(&rule_codes)
            ));
        }
    }
    output.push_str("- fixture/testdata/example suppression stayed active for the newly added MCP client-config variants and did not create a fake usefulness signal from fixture-like paths\n\n");
}
