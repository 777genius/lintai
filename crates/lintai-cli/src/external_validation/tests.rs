use super::*;

fn sample_shortlist() -> RepoShortlist {
    RepoShortlist {
        version: 1,
        repos: vec![ShortlistRepo {
            repo: "owner/repo".to_owned(),
            url: "https://github.com/owner/repo".to_owned(),
            pinned_ref: "abc123".to_owned(),
            category: "skills".to_owned(),
            subtype: "control".to_owned(),
            status: "evaluated".to_owned(),
            surfaces_present: vec!["SKILL.md".to_owned()],
            admission_paths: Vec::new(),
            rationale: "demo".to_owned(),
        }],
    }
}

#[test]
fn shortlist_parser_shape_is_expected() {
    let shortlist: RepoShortlist = toml::from_str(
        r#"
version = 1

[[repos]]
repo = "owner/repo"
url = "https://github.com/owner/repo"
pinned_ref = "abc123"
category = "skills"
subtype = "control"
status = "evaluated"
surfaces_present = ["SKILL.md"]
rationale = "demo"
"#,
    )
    .unwrap();

    assert_eq!(shortlist.version, 1);
    assert_eq!(shortlist.repos.len(), 1);
    assert_eq!(shortlist.repos[0].repo, "owner/repo");
}

#[test]
fn fill_auto_fields_separates_stable_preview_diagnostics_and_runtime_errors() {
    let repo = &sample_shortlist().repos[0];
    let mut entry = default_entry_from_shortlist(repo);
    let parsed = JsonScanEnvelope {
        findings: vec![
            JsonFinding {
                rule_code: "SEC201".to_owned(),
            },
            JsonFinding {
                rule_code: "SEC105".to_owned(),
            },
        ],
        diagnostics: vec![JsonDiagnostic {
            normalized_path: "SKILL.md".to_owned(),
            severity: "warn".to_owned(),
            code: Some("parse_recovery".to_owned()),
            message: "frontmatter ignored".to_owned(),
        }],
        runtime_errors: vec![JsonRuntimeError {
            normalized_path: "SKILL.md".to_owned(),
            kind: "parse".to_owned(),
            message: "fatal".to_owned(),
        }],
    };

    fill_auto_fields(
        &mut entry,
        repo,
        vec!["SKILL.md".to_owned()],
        &parsed,
        &current_rule_tiers(),
    )
    .unwrap();

    assert_eq!(entry.stable_findings, 1);
    assert_eq!(entry.preview_findings, 1);
    assert_eq!(entry.stable_rule_codes, vec!["SEC201"]);
    assert_eq!(entry.preview_rule_codes, vec!["SEC105"]);
    assert_eq!(entry.diagnostics.len(), 1);
    assert_eq!(entry.runtime_errors.len(), 1);
}

#[test]
fn template_map_preserves_manual_fields() {
    let repo = &sample_shortlist().repos[0];
    let mut prior = default_entry_from_shortlist(repo);
    prior.repo_verdict = "useful_but_noisy".to_owned();
    prior.preview_signal_notes = "carry".to_owned();
    let ledger = ExternalValidationLedger {
        version: 1,
        wave: 1,
        baseline: None,
        evaluations: vec![prior.clone()],
    };

    let mapped = template_map(&ledger);
    assert_eq!(mapped["owner/repo"].repo_verdict, "useful_but_noisy");
    assert_eq!(mapped["owner/repo"].preview_signal_notes, "carry");
}

#[test]
fn report_renderer_emits_delta_and_phase_targets() {
    let mut baseline_entry = default_entry_from_shortlist(&sample_shortlist().repos[0]);
    baseline_entry.repo = "datadog-labs/cursor-plugin".to_owned();
    baseline_entry.preview_findings = 1;
    baseline_entry.preview_rule_codes = vec!["SEC105".to_owned()];
    let baseline = ExternalValidationLedger {
        version: 1,
        wave: 1,
        baseline: None,
        evaluations: vec![
            baseline_entry,
            EvaluationEntry {
                repo: "cursor/plugins".to_owned(),
                runtime_errors: vec![RuntimeErrorRecord {
                    path: "a".to_owned(),
                    kind: "parse".to_owned(),
                    message: "bad".to_owned(),
                }],
                ..default_entry_from_shortlist(&sample_shortlist().repos[0])
            },
            EvaluationEntry {
                repo: "Emmraan/agent-skills".to_owned(),
                runtime_errors: vec![RuntimeErrorRecord {
                    path: "b".to_owned(),
                    kind: "parse".to_owned(),
                    message: "bad".to_owned(),
                }],
                ..default_entry_from_shortlist(&sample_shortlist().repos[0])
            },
        ],
    };
    let current = ExternalValidationLedger {
        version: 1,
        wave: 2,
        baseline: Some("archive/wave1-ledger.toml".to_owned()),
        evaluations: vec![
            EvaluationEntry {
                repo: "datadog-labs/cursor-plugin".to_owned(),
                surfaces_present: vec![".mcp.json".to_owned()],
                ..default_entry_from_shortlist(&sample_shortlist().repos[0])
            },
            EvaluationEntry {
                repo: "zebbern/claude-code-guide".to_owned(),
                preview_findings: 2,
                preview_rule_codes: vec!["SEC313".to_owned()],
                surfaces_present: vec![
                    ".claude/mcp/*.json".to_owned(),
                    "tool_descriptor_json".to_owned(),
                ],
                ..default_entry_from_shortlist(&sample_shortlist().repos[0])
            },
            EvaluationEntry {
                repo: "cursor/plugins".to_owned(),
                diagnostics: vec![DiagnosticRecord {
                    path: "a".to_owned(),
                    severity: "warn".to_owned(),
                    code: Some("parse_recovery".to_owned()),
                    message: "recovered".to_owned(),
                }],
                ..default_entry_from_shortlist(&sample_shortlist().repos[0])
            },
            EvaluationEntry {
                repo: "Emmraan/agent-skills".to_owned(),
                diagnostics: vec![DiagnosticRecord {
                    path: "b".to_owned(),
                    severity: "warn".to_owned(),
                    code: Some("parse_recovery".to_owned()),
                    message: "recovered".to_owned(),
                }],
                ..default_entry_from_shortlist(&sample_shortlist().repos[0])
            },
        ],
    };

    let markdown = render_report_from_ledgers(&workspace_root().unwrap(), &baseline, &current);
    assert!(markdown.contains("## Hybrid Scope Expansion Results"));
    assert!(markdown.contains("- repos with root `mcp.json`: `0`"));
    assert!(markdown.contains("- repos with `.mcp.json`: `1`"));
    assert!(markdown.contains("- repos with `.cursor/mcp.json`: `0`"));
    assert!(markdown.contains("- repos with `.vscode/mcp.json`: `0`"));
    assert!(markdown.contains("- repos with `.roo/mcp.json`: `0`"));
    assert!(markdown.contains("- repos with `.kiro/settings/mcp.json`: `0`"));
    assert!(markdown.contains("- repos with `gemini-extension.json`: `0`"));
    assert!(markdown.contains("- repos with `gemini.settings.json`: `0`"));
    assert!(markdown.contains("- repos with `.gemini/settings.json`: `0`"));
    assert!(markdown.contains("- repos with `vscode.settings.json`: `0`"));
    assert!(markdown.contains("- repos with `.claude/mcp/*.json`: `1`"));
    assert!(markdown.contains("- repos with Docker-based MCP launch configs: `0`"));
    assert!(markdown.contains("- findings from `SEC336`: `0`"));
    assert!(markdown.contains("- findings from `SEC337`-`SEC339`, `SEC346`: `0`"));
    assert!(markdown.contains("- AI-native markdown preview findings:"));
    assert!(markdown.contains("`SEC313` fenced pipe-to-shell examples: `1`"));
    assert!(markdown.contains("`SEC335` metadata-service access examples: `0`"));
    assert!(markdown.contains("`SEC347` mutable MCP setup launcher examples: `0`"));
    assert!(markdown.contains("CLI-form repo hits: `0`"));
    assert!(markdown.contains("config-snippet-form repo hits: `0`"));
    assert!(markdown.contains("`SEC348` mutable Docker registry-image examples: `0`"));
    assert!(markdown.contains("`SEC349` Docker host-escape or privileged runtime examples: `0`"));
    assert!(markdown.contains("`SEC350` untrusted-input instruction-promotion examples: `0`"));
    assert!(markdown.contains("`SEC351` approval-bypass instruction examples: `0`"));
    assert!(markdown.contains("`SEC352` unscoped Bash tool grants in frontmatter: `0`"));
    assert!(markdown.contains("`SEC353` Copilot instruction files above 4000 chars: `0`"));
    assert!(
        markdown.contains("`SEC354` path-specific Copilot instructions missing `applyTo`: `0`")
    );
    assert!(markdown.contains("`SEC355` wildcard tool grants in frontmatter: `0`"));
    assert!(markdown.contains("`SEC356` plugin agent frontmatter `permissionMode`: `0`"));
    assert!(markdown.contains("`SEC357` plugin agent frontmatter `hooks`: `0`"));
    assert!(markdown.contains("`SEC358` plugin agent frontmatter `mcpServers`: `0`"));
    assert!(markdown.contains("`SEC359` Cursor rule non-boolean `alwaysApply`: `0`"));
    assert!(markdown.contains("`SEC360` Cursor rule non-sequence `globs`: `0`"));
    assert!(markdown.contains("`SEC361` Claude settings missing `$schema`: `0`"));
    assert!(markdown.contains("`SEC362` Claude settings wildcard `Bash(*)` permissions: `0`"));
    assert!(markdown.contains("`SEC363` Claude settings home-directory hook commands: `0`"));
    assert!(markdown.contains("`SEC364` Claude settings `bypassPermissions` default mode: `0`"));
    assert!(markdown.contains("`SEC365` Claude settings non-HTTPS `allowedHttpHookUrls`: `0`"));
    assert!(markdown.contains(
        "`SEC366` Claude settings dangerous host literals in `allowedHttpHookUrls`: `0`"
    ));
    assert!(markdown.contains("`SEC367` Claude settings wildcard `WebFetch(*)` permissions: `0`"));
    assert!(markdown.contains("`SEC368` Claude settings repo-external absolute hook paths: `0`"));
    assert!(markdown.contains("`SEC369` Claude settings wildcard `Write(*)` permissions: `0`"));
    assert!(
        markdown
            .contains("`SEC370` path-specific Copilot instructions using the wrong suffix: `0`")
    );
    assert!(
        markdown
            .contains("`SEC371` path-specific Copilot instructions with invalid `applyTo`: `0`")
    );
    assert!(
        markdown.contains(
            "`SEC377` path-specific Copilot instructions with invalid `applyTo` globs: `0`"
        )
    );
    assert!(markdown.contains(
        "`SEC378` Cursor rules with redundant `globs` alongside `alwaysApply: true`: `0`"
    ));
    assert!(markdown.contains("`SEC379` Cursor rules with unknown frontmatter keys: `0`"));
    assert!(markdown.contains("`SEC380` Cursor rules missing `description`: `0`"));
    assert!(markdown.contains("`SEC381` Claude settings command hooks missing `timeout`: `0`"));
    assert!(
        markdown.contains("`SEC382` Claude settings `matcher` on unsupported hook events: `0`")
    );
    assert!(markdown.contains(
        "`SEC383` Claude settings missing `matcher` on matcher-capable hook events: `0`"
    ));
    assert!(markdown.contains("`SEC384` Claude settings bare `WebSearch` permissions: `"));
    assert!(markdown.contains("`SEC385` Claude settings shared `git push` permissions: `"));
    assert!(markdown.contains("`SEC386` Claude settings shared `git checkout:*` permissions: `"));
    assert!(markdown.contains("`SEC387` Claude settings shared `git commit:*` permissions: `"));
    assert!(markdown.contains("`SEC388` Claude settings shared `git stash:*` permissions: `"));
    assert!(markdown.contains("`SEC394` MCP configs with wildcard `autoApprove`: `"));
    assert!(markdown.contains("`SEC395` MCP configs with `autoApproveTools: true`: `"));
    assert!(markdown.contains("`SEC396` MCP configs with `trustTools: true`: `"));
    assert!(markdown.contains("`SEC397` MCP configs with sandbox disabled: `"));
    assert!(markdown.contains("`SEC398` MCP configs with wildcard capabilities: `"));
    assert!(markdown.contains("`SEC399` Claude settings shared `Bash(npx ...)` permissions: `"));
    assert!(markdown.contains("`SEC400` Claude settings shared `enabledMcpjsonServers`: `"));
    assert!(
        markdown.contains("`SEC405` Claude settings shared package installation permissions: `")
    );
    assert!(markdown.contains("`SEC406` Claude settings shared `git add` permissions: `"));
    assert!(markdown.contains("`SEC407` Claude settings shared `git clone` permissions: `"));
    assert!(markdown.contains("`SEC408` Claude settings shared `gh pr` permissions: `"));
    assert!(markdown.contains("`SEC409` Claude settings shared `git fetch` permissions: `"));
    assert!(markdown.contains("`SEC410` Claude settings shared `git ls-remote` permissions: `"));
    assert!(markdown.contains("`SEC411` Claude settings shared `curl` permissions: `"));
    assert!(markdown.contains("`SEC412` Claude settings shared `wget` permissions: `"));
    assert!(markdown.contains("`SEC413` Claude settings shared `git config` permissions: `"));
    assert!(markdown.contains("`SEC414` Claude settings shared `git tag` permissions: `"));
    assert!(markdown.contains("`SEC415` Claude settings shared `git branch` permissions: `"));
    assert!(
        markdown.contains("`SEC416` AI-native markdown bare `pip install` Claude transcripts: `")
    );
    assert!(markdown.contains(
        "`SEC417` AI-native markdown unpinned `pip install git+https://...` examples: `"
    ));
    assert!(markdown.contains("`SEC418` Claude settings raw GitHub content fetch permissions: `"));
    assert!(markdown.contains("`SEC408` Claude settings shared `gh pr` permissions: `"));
    assert!(markdown.contains("`SEC372` Claude settings wildcard `Read(*)` permissions: `0`"));
    assert!(markdown.contains("`SEC373` Claude settings wildcard `Edit(*)` permissions: `0`"));
    assert!(markdown.contains("`SEC374` Claude settings wildcard `WebSearch(*)` permissions: `0`"));
    assert!(markdown.contains("`SEC375` Claude settings wildcard `Glob(*)` permissions: `0`"));
    assert!(markdown.contains("`SEC376` Claude settings wildcard `Grep(*)` permissions: `0`"));
    assert!(markdown.contains("- repos with `tool_descriptor_json`: `1`"));
    assert!(markdown.contains(
        "- repos where new MCP client-config variants existed only under fixture-like paths: `0`"
    ));
    assert!(markdown.contains(
            "- repos where Docker-based MCP launch existed only under fixture-like client-config variants: `0`"
        ));
    assert!(
        markdown
            .contains("- `SEC348` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC349` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC350` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC351` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC352` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC353` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC354` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC355` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC356` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC357` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC358` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC359` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC360` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC361` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC362` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC363` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC364` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC365` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC366` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC370` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC371` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC372` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC373` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC374` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC375` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC376` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC377` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC378` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC379` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC380` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC381` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC382` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(
        markdown
            .contains("- `SEC383` produced no repo-level preview hits yet on the canonical cohort")
    );
    assert!(markdown.contains("- `SEC384`"));
    assert!(markdown.contains("- `SEC385`"));
    assert!(markdown.contains("- `SEC386`"));
    assert!(markdown.contains("- `SEC387`"));
    assert!(markdown.contains("- `SEC388`"));
    assert!(markdown.contains("- `SEC394`"));
    assert!(markdown.contains("- `SEC395`"));
    assert!(markdown.contains("- `SEC396`"));
    assert!(markdown.contains("- `SEC397`"));
    assert!(markdown.contains("- `SEC398`"));
    assert!(markdown.contains("## Delta From Previous Wave"));
    assert!(markdown.contains("`datadog-labs/cursor-plugin`: `improved`"));
    assert!(markdown.contains("`zebbern/claude-code-guide`: `2` preview finding(s) via `SEC313`"));
    assert!(markdown.contains("`cursor/plugins`: `improved`"));
    assert!(markdown.contains("`Emmraan/agent-skills`: `improved`"));
}

#[test]
fn package_flag_defaults_to_canonical() {
    assert_eq!(
        parse_package_flag(&Vec::<String>::new()).unwrap(),
        ValidationPackage::Canonical
    );
}

#[test]
fn package_flag_parses_tool_json_extension() {
    assert_eq!(
        parse_package_flag(&["--package=tool-json-extension".to_owned()]).unwrap(),
        ValidationPackage::ToolJsonExtension
    );
}

#[test]
fn package_flag_parses_server_json_extension() {
    assert_eq!(
        parse_package_flag(&["--package=server-json-extension".to_owned()]).unwrap(),
        ValidationPackage::ServerJsonExtension
    );
}

#[test]
fn package_flag_parses_github_actions_extension() {
    assert_eq!(
        parse_package_flag(&["--package=github-actions-extension".to_owned()]).unwrap(),
        ValidationPackage::GithubActionsExtension
    );
}

#[test]
fn package_flag_parses_ai_native_discovery() {
    assert_eq!(
        parse_package_flag(&["--package=ai-native-discovery".to_owned()]).unwrap(),
        ValidationPackage::AiNativeDiscovery
    );
}

#[test]
fn semantic_docker_mcp_launch_requires_docker_run_shape() {
    assert!(contains_semantic_docker_mcp_launch(
        r#"{"servers":{"demo":{"command":"docker","args":["run","ghcr.io/acme/mcp-server"]}}}"#
    ));
    assert!(!contains_semantic_docker_mcp_launch(
        r#"{"servers":{"demo":{"command":"docker","args":["pull","ghcr.io/acme/mcp-server"]}}}"#
    ));
    assert!(!contains_semantic_docker_mcp_launch(
        r#"{"servers":{"demo":{"command":"node","args":["server.js"]}}}"#
    ));
}

#[test]
fn semantic_gemini_mcp_config_requires_top_level_mcp_servers_with_command() {
    assert!(contains_semantic_gemini_mcp_config(
        r#"{"mcpServers":{"demo":{"command":"docker","args":["run","ghcr.io/acme/mcp-server"]}}}"#
    ));
    assert!(!contains_semantic_gemini_mcp_config(
        r#"{"mcpServers":{"demo":{"args":["run","ghcr.io/acme/mcp-server"]}}}"#
    ));
    assert!(!contains_semantic_gemini_mcp_config(
        r#"{"servers":{"demo":{"command":"docker"}}}"#
    ));
}

#[test]
fn fixture_like_paths_are_rejected() {
    assert!(is_generic_validation_excluded_path(
        "tests/fixtures/tools.json"
    ));
    assert!(is_generic_validation_excluded_path(
        "pkg/testdata/sample.tools.json"
    ));
    assert!(!is_generic_validation_excluded_path("configs/tools.json"));
}

#[test]
fn docish_tool_json_paths_are_rejected() {
    assert!(is_tool_json_excluded_path("docs/tools.json"));
    assert!(is_tool_json_excluded_path("Resources/schema/tools.json"));
    assert!(is_tool_json_excluded_path(
        "resources/ToolSchemas/tools.json"
    ));
    assert!(is_tool_json_excluded_path(
        "resources/tool-schemas/tools.json"
    ));
    assert!(is_tool_json_excluded_path(
        "resources/schema_store/tools.json"
    ));
    assert!(!is_tool_json_excluded_path("configs/tools.json"));
}

#[test]
fn semantic_tool_descriptor_json_requires_name_and_schema() {
    assert!(contains_semantic_tool_descriptor_json(
        r#"{"tools":[{"name":"search","inputSchema":{"type":"object"}}]}"#
    ));
    assert!(contains_semantic_tool_descriptor_json(
        r#"[{"name":"search","function":{"parameters":{"type":"object"}}}]"#
    ));
    assert!(contains_semantic_tool_descriptor_json(
        r#"{"jsonrpc":"2.0","result":{"tools":[{"name":"search","inputSchema":{"type":"object"}}]}}"#
    ));
    assert!(!contains_semantic_tool_descriptor_json(
        r#"{"$schema":"http://json-schema.org/draft-07/schema#","type":"array"}"#
    ));
    assert!(!contains_semantic_tool_descriptor_json(
        r#"{"tools":[{"description":"missing name","inputSchema":{"type":"object"}}]}"#
    ));
}

#[test]
fn semantic_server_json_requires_name_version_and_remotes_or_packages() {
    assert!(contains_semantic_server_json(
        r#"{"name":"demo","version":"1.0.0","remotes":[{"type":"streamable-http","url":"https://example.com/mcp"}]}"#
    ));
    assert!(contains_semantic_server_json(
        r#"{"name":"demo","version":"1.0.0","packages":[{"registry_name":"npm","name":"demo","version":"1.0.0"}]}"#
    ));
    assert!(!contains_semantic_server_json(
        r#"{"name":"demo","remotes":[{"type":"streamable-http","url":"https://example.com/mcp"}]}"#
    ));
    assert!(!contains_semantic_server_json(
        r#"{"version":"1.0.0","packages":[{"name":"demo"}]}"#
    ));
}

#[test]
fn semantic_claude_settings_require_command_hooks() {
    assert!(contains_semantic_claude_command_settings(
        r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"./hook.sh"}]}]}}"#
    ));
    assert!(!contains_semantic_claude_command_settings(
        r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"notification","message":"hi"}]}]}}"#
    ));
}

#[test]
fn semantic_plugin_hooks_require_command_entries() {
    assert!(contains_semantic_plugin_hook_commands(
        r#"{"hooks":{"stop":[{"command":"./hooks/stop.sh"}]}}"#
    ));
    assert!(!contains_semantic_plugin_hook_commands(
        r#"{"hooks":{"stop":[{"message":"no command"}]}}"#
    ));
}

#[test]
fn semantic_github_workflow_yaml_requires_jobs_and_workflow_keys() {
    assert!(contains_semantic_github_workflow_yaml(
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: docker/login-action@v4\n"
    ));
    assert!(!contains_semantic_github_workflow_yaml(
        "name: just a yaml file\nvalues:\n  - demo\n"
    ));
}

#[test]
fn tool_json_extension_report_has_required_sections() {
    let shortlist = RepoShortlist {
        version: 1,
        repos: vec![ShortlistRepo {
            repo: "owner/tool-json".to_owned(),
            url: "https://github.com/owner/tool-json".to_owned(),
            pinned_ref: "abc123".to_owned(),
            category: "tool_json".to_owned(),
            subtype: "stress".to_owned(),
            status: "evaluated".to_owned(),
            surfaces_present: vec!["tool_descriptor_json".to_owned()],
            admission_paths: vec!["tools.json".to_owned()],
            rationale: "Committed tool descriptor JSON.".to_owned(),
        }],
    };
    let baseline = ExternalValidationLedger {
        version: 1,
        wave: 1,
        baseline: None,
        evaluations: vec![EvaluationEntry {
            repo: "owner/old-tool-json".to_owned(),
            ..default_entry_from_shortlist(&sample_shortlist().repos[0])
        }],
    };
    let ledger = ExternalValidationLedger {
        version: 1,
        wave: 2,
        baseline: Some("archive/wave1-ledger.toml".to_owned()),
        evaluations: vec![EvaluationEntry {
            repo: "owner/tool-json".to_owned(),
            url: "https://github.com/owner/tool-json".to_owned(),
            pinned_ref: "abc123".to_owned(),
            category: "tool_json".to_owned(),
            subtype: "stress".to_owned(),
            status: "evaluated".to_owned(),
            surfaces_present: vec!["tool_descriptor_json".to_owned()],
            stable_findings: 1,
            preview_findings: 0,
            stable_rule_codes: vec!["SEC314".to_owned()],
            preview_rule_codes: Vec::new(),
            repo_verdict: "strong_fit".to_owned(),
            stable_precision_notes: String::new(),
            preview_signal_notes: String::new(),
            false_positive_notes: Vec::new(),
            possible_false_negative_notes: Vec::new(),
            follow_up_action: "no_action".to_owned(),
            runtime_errors: vec![RuntimeErrorRecord {
                path: "other.json".to_owned(),
                kind: "parse".to_owned(),
                message: "bad".to_owned(),
            }],
            diagnostics: vec![DiagnosticRecord {
                path: "tools.json".to_owned(),
                severity: "warn".to_owned(),
                code: Some("parse_recovery".to_owned()),
                message: "recovered".to_owned(),
            }],
        }],
    };

    let markdown = render_tool_json_extension_report(&shortlist, &baseline, &ledger);
    assert!(markdown.contains("## Cohort Composition"));
    assert!(markdown.contains("## Admission Results"));
    assert!(markdown.contains("## Overall Counts"));
    assert!(markdown.contains("## Delta From Previous Wave"));
    assert!(markdown.contains("## Stable Hits"));
    assert!(markdown.contains("## Preview Hits"));
    assert!(markdown.contains("## Runtime / Diagnostic Notes"));
    assert!(markdown.contains("## Fixture Suppression Check"));
    assert!(markdown.contains("## Recommended Next Step"));
    assert!(markdown.contains("`SEC314`"));
    assert!(markdown.contains("admission-path issue"));
    assert!(markdown.contains("non-admission-path issue"));
}

#[test]
fn server_json_extension_report_has_required_sections() {
    let shortlist = RepoShortlist {
        version: 1,
        repos: vec![ShortlistRepo {
            repo: "owner/server-json".to_owned(),
            url: "https://github.com/owner/server-json".to_owned(),
            pinned_ref: "abc123".to_owned(),
            category: "server_json".to_owned(),
            subtype: "stress".to_owned(),
            status: "evaluated".to_owned(),
            surfaces_present: vec!["server.json".to_owned()],
            admission_paths: vec!["server.json".to_owned()],
            rationale: "Committed server registry metadata.".to_owned(),
        }],
    };
    let baseline = ExternalValidationLedger {
        version: 1,
        wave: 1,
        baseline: None,
        evaluations: vec![EvaluationEntry {
            repo: "owner/old-server-json".to_owned(),
            ..default_entry_from_shortlist(&sample_shortlist().repos[0])
        }],
    };
    let ledger = ExternalValidationLedger {
        version: 1,
        wave: 2,
        baseline: Some("archive/wave1-ledger.toml".to_owned()),
        evaluations: vec![EvaluationEntry {
            repo: "owner/server-json".to_owned(),
            url: "https://github.com/owner/server-json".to_owned(),
            pinned_ref: "abc123".to_owned(),
            category: "server_json".to_owned(),
            subtype: "stress".to_owned(),
            status: "evaluated".to_owned(),
            surfaces_present: vec!["server.json".to_owned()],
            stable_findings: 1,
            preview_findings: 0,
            stable_rule_codes: vec!["SEC319".to_owned()],
            preview_rule_codes: Vec::new(),
            repo_verdict: "strong_fit".to_owned(),
            stable_precision_notes: String::new(),
            preview_signal_notes: String::new(),
            false_positive_notes: Vec::new(),
            possible_false_negative_notes: Vec::new(),
            follow_up_action: "no_action".to_owned(),
            runtime_errors: Vec::new(),
            diagnostics: Vec::new(),
        }],
    };

    let markdown = render_server_json_extension_report(&shortlist, &baseline, &ledger);
    assert!(markdown.contains("## Cohort Composition"));
    assert!(markdown.contains("## Admission Results"));
    assert!(markdown.contains("## Overall Counts"));
    assert!(markdown.contains("## Delta From Previous Wave"));
    assert!(markdown.contains("## Stable Hits"));
    assert!(markdown.contains("## Preview Hits"));
    assert!(markdown.contains("## Runtime / Diagnostic Notes"));
    assert!(markdown.contains("## Recommended Next Step"));
    assert!(markdown.contains("`SEC319`"));
}

#[test]
fn github_actions_extension_report_has_required_sections() {
    let shortlist = RepoShortlist {
        version: 1,
        repos: vec![ShortlistRepo {
            repo: "owner/workflows".to_owned(),
            url: "https://github.com/owner/workflows".to_owned(),
            pinned_ref: "abc123".to_owned(),
            category: "github_actions".to_owned(),
            subtype: "stress".to_owned(),
            status: "evaluated".to_owned(),
            surfaces_present: vec![".github/workflows/*.yml".to_owned()],
            admission_paths: vec![".github/workflows/ci.yml".to_owned()],
            rationale: "Workflow repo.".to_owned(),
        }],
    };
    let ledger = ExternalValidationLedger {
        version: 1,
        wave: 1,
        baseline: None,
        evaluations: vec![EvaluationEntry {
            repo: "owner/workflows".to_owned(),
            url: "https://github.com/owner/workflows".to_owned(),
            pinned_ref: "abc123".to_owned(),
            category: "github_actions".to_owned(),
            subtype: "stress".to_owned(),
            status: "evaluated".to_owned(),
            surfaces_present: vec![".github/workflows/*.yml".to_owned()],
            stable_findings: 1,
            preview_findings: 1,
            stable_rule_codes: vec!["SEC324".to_owned(), "SEC327".to_owned()],
            preview_rule_codes: vec!["SEC325".to_owned(), "SEC328".to_owned()],
            repo_verdict: "strong_fit".to_owned(),
            stable_precision_notes: String::new(),
            preview_signal_notes: String::new(),
            false_positive_notes: Vec::new(),
            possible_false_negative_notes: Vec::new(),
            follow_up_action: "no_action".to_owned(),
            runtime_errors: Vec::new(),
            diagnostics: Vec::new(),
        }],
    };

    let markdown = render_github_actions_extension_report(&shortlist, &ledger);
    assert!(markdown.contains("## Cohort Composition"));
    assert!(markdown.contains("## Admission Results"));
    assert!(markdown.contains("## Overall Counts"));
    assert!(markdown.contains("## Stable Hits"));
    assert!(markdown.contains("## Preview Hits"));
    assert!(markdown.contains("## Runtime / Diagnostic Notes"));
    assert!(markdown.contains("## Recommended Next Step"));
    assert!(markdown.contains("`SEC324`"));
    assert!(markdown.contains("`SEC325`"));
    assert!(markdown.contains("`SEC327`"));
    assert!(markdown.contains("`SEC328`"));
}

#[test]
fn ai_native_discovery_report_has_required_sections() {
    let shortlist = RepoShortlist {
        version: 1,
        repos: vec![ShortlistRepo {
            repo: "owner/ai-native".to_owned(),
            url: "https://github.com/owner/ai-native".to_owned(),
            pinned_ref: "abc123".to_owned(),
            category: "ai_native".to_owned(),
            subtype: "claude_settings_command".to_owned(),
            status: "evaluated".to_owned(),
            surfaces_present: vec![".claude/settings.json".to_owned()],
            admission_paths: vec![".claude/settings.json".to_owned()],
            rationale: "Committed Claude settings hooks.".to_owned(),
        }],
    };
    let ledger = ExternalValidationLedger {
        version: 1,
        wave: 1,
        baseline: None,
        evaluations: vec![EvaluationEntry {
            repo: "owner/ai-native".to_owned(),
            url: "https://github.com/owner/ai-native".to_owned(),
            pinned_ref: "abc123".to_owned(),
            category: "ai_native".to_owned(),
            subtype: "claude_settings_command".to_owned(),
            status: "evaluated".to_owned(),
            surfaces_present: vec!["SKILL.md".to_owned()],
            stable_findings: 0,
            preview_findings: 0,
            stable_rule_codes: Vec::new(),
            preview_rule_codes: Vec::new(),
            repo_verdict: "strong_fit".to_owned(),
            stable_precision_notes: String::new(),
            preview_signal_notes: String::new(),
            false_positive_notes: Vec::new(),
            possible_false_negative_notes: Vec::new(),
            follow_up_action: "no_action".to_owned(),
            runtime_errors: Vec::new(),
            diagnostics: Vec::new(),
        }],
    };

    let markdown =
        render_ai_native_discovery_report(&workspace_root().unwrap(), &shortlist, &ledger);
    assert!(markdown.contains("## Cohort Composition"));
    assert!(markdown.contains("## Admission Results"));
    assert!(markdown.contains("## Coverage Status"));
    assert!(markdown.contains("## Overall Counts"));
    assert!(markdown.contains("## Stable Hits"));
    assert!(markdown.contains("## Preview Hits"));
    assert!(markdown.contains("## Runtime / Diagnostic Notes"));
    assert!(markdown.contains("## Recommended Next Step"));
    assert!(markdown.contains("plugin-root command markdown admission paths"));
    assert!(markdown.contains("AI-native markdown preview hits by rule code"));
    assert!(markdown.contains("`SEC347` subtype repo hits: CLI-form=`0`, config-snippet-form=`0`"));
    assert!(markdown.contains("`SEC349`=`0`"));
    assert!(markdown.contains("`SEC350`=`0`"));
    assert!(markdown.contains("`SEC351`=`0`"));
    assert!(markdown.contains("`SEC352`=`0`"));
    assert!(markdown.contains("`SEC353`=`0`"));
    assert!(markdown.contains("`SEC354`=`0`"));
    assert!(markdown.contains("`SEC355`=`0`"));
    assert!(markdown.contains("`SEC356`=`0`"));
    assert!(markdown.contains("`SEC357`=`0`"));
    assert!(markdown.contains("`SEC358`=`0`"));
    assert!(markdown.contains("`SEC359`=`0`"));
    assert!(markdown.contains("`SEC360`=`0`"));
    assert!(markdown.contains("`SEC361` Claude settings files missing `$schema`: `0`"));
    assert!(markdown.contains("`SEC362` Claude settings files allowing `Bash(*)`: `0`"));
    assert!(
        markdown.contains("`SEC363` Claude settings files with home-directory hook commands: `0`")
    );
    assert!(markdown.contains(
        "`SEC364` Claude settings files with `permissions.defaultMode = bypassPermissions`: `0`"
    ));
    assert!(
        markdown
            .contains("`SEC365` Claude settings files with non-HTTPS `allowedHttpHookUrls`: `0`")
    );
    assert!(markdown.contains(
        "`SEC366` Claude settings files with dangerous host literals in `allowedHttpHookUrls`: `0`"
    ));
    assert!(markdown.contains("`SEC367` Claude settings files allowing `WebFetch(*)`: `0`"));
    assert!(
        markdown
            .contains("`SEC368` Claude settings files with repo-external absolute hook paths: `0`")
    );
    assert!(markdown.contains("`SEC369` Claude settings files allowing `Write(*)`: `0`"));
    assert!(
        markdown
            .contains("`SEC370` path-specific Copilot instructions using the wrong suffix: `0`")
    );
    assert!(
        markdown
            .contains("`SEC371` path-specific Copilot instructions with invalid `applyTo`: `0`")
    );
    assert!(markdown.contains("`SEC377`=`0`"));
    assert!(markdown.contains("`SEC378`=`0`"));
    assert!(markdown.contains("`SEC379`=`0`"));
    assert!(markdown.contains("`SEC380`=`0`"));
    assert!(markdown.contains("`SEC381` Claude settings command hooks missing `timeout`: `0`"));
    assert!(
        markdown.contains("`SEC382` Claude settings `matcher` on unsupported hook events: `0`")
    );
    assert!(markdown.contains(
        "`SEC383` Claude settings missing `matcher` on matcher-capable hook events: `0`"
    ));
    assert!(markdown.contains("`SEC384` Claude settings bare `WebSearch` permissions: `"));
    assert!(markdown.contains("`SEC385` Claude settings shared `git push` permissions: `"));
    assert!(markdown.contains("`SEC386` Claude settings shared `git checkout:*` permissions: `"));
    assert!(markdown.contains("`SEC387` Claude settings shared `git commit:*` permissions: `"));
    assert!(markdown.contains("`SEC388` Claude settings shared `git stash:*` permissions: `"));
    assert!(markdown.contains("`SEC394` MCP configs with wildcard `autoApprove`: `"));
    assert!(markdown.contains("`SEC395` MCP configs with `autoApproveTools: true`: `"));
    assert!(markdown.contains("`SEC396` MCP configs with `trustTools: true`: `"));
    assert!(markdown.contains("`SEC397` MCP configs with sandbox disabled: `"));
    assert!(markdown.contains("`SEC398` MCP configs with wildcard capabilities: `"));
    assert!(markdown.contains("`SEC399` Claude settings shared `Bash(npx ...)` permissions: `"));
    assert!(markdown.contains("`SEC400` Claude settings shared `enabledMcpjsonServers`: `"));
    assert!(
        markdown.contains("`SEC405` Claude settings shared package installation permissions: `")
    );
    assert!(markdown.contains("`SEC406` Claude settings shared `git add` permissions: `"));
    assert!(markdown.contains("`SEC407` Claude settings shared `git clone` permissions: `"));
    assert!(markdown.contains("`SEC372` Claude settings files allowing `Read(*)`: `0`"));
    assert!(markdown.contains("`SEC373` Claude settings files allowing `Edit(*)`: `0`"));
    assert!(markdown.contains("`SEC374` Claude settings files allowing `WebSearch(*)`: `0`"));
    assert!(markdown.contains("`SEC375` Claude settings files allowing `Glob(*)`: `0`"));
    assert!(markdown.contains("`SEC376` Claude settings files allowing `Grep(*)`: `0`"));
    assert!(markdown.contains("`SEC377`=`0`"));
    assert!(markdown.contains("`SEC378`=`0`"));
    assert!(markdown.contains("`SEC379`=`0`"));
    assert!(markdown.contains("`SEC380`=`0`"));
    assert!(
        markdown.contains("`SEC381` produced no repo-level external preview hits in this wave")
    );
    assert!(
        markdown.contains("`SEC382` produced no repo-level external preview hits in this wave")
    );
    assert!(
        markdown.contains("`SEC383` produced no repo-level external preview hits in this wave")
    );
    assert!(markdown.contains("`SEC384`"));
    assert!(markdown.contains("`SEC385`"));
    assert!(markdown.contains("`SEC386`"));
    assert!(markdown.contains("`SEC387`"));
    assert!(markdown.contains("`SEC388`"));
    assert!(markdown.contains("`SEC394`"));
    assert!(markdown.contains("`SEC395`"));
    assert!(markdown.contains("`SEC396`"));
    assert!(markdown.contains("`SEC397`"));
    assert!(markdown.contains("`SEC398`"));
    assert!(markdown.contains("`SEC399`"));
    assert!(markdown.contains("`SEC400`"));
    assert!(markdown.contains("`SEC405`"));
    assert!(markdown.contains("`SEC406`"));
    assert!(markdown.contains("`SEC407`"));
    assert!(markdown.contains("`SEC408`"));
    assert!(markdown.contains("`SEC409`"));
    assert!(markdown.contains("`SEC410`"));
    assert!(markdown.contains("`SEC411`"));
    assert!(markdown.contains("`SEC412`"));
    assert!(markdown.contains("`SEC413`"));
    assert!(markdown.contains("`SEC414`"));
    assert!(markdown.contains("`SEC415`"));
    assert!(markdown.contains("`SEC416`"));
    assert!(markdown.contains("`SEC417`"));
    assert!(markdown.contains("`SEC418`"));
}
