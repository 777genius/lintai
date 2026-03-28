use std::collections::{BTreeMap, BTreeSet};

fn parse_toml(path: &str) -> toml::Value {
    let text = match path {
        "shortlist" => include_str!("../../../validation/external-repos/repo-shortlist.toml"),
        "ledger" => include_str!("../../../validation/external-repos/ledger.toml"),
        "archive" => include_str!("../../../validation/external-repos/archive/wave1-ledger.toml"),
        "tool_json_shortlist" => {
            include_str!("../../../validation/external-repos-tool-json/repo-shortlist.toml")
        }
        "tool_json_ledger" => {
            include_str!("../../../validation/external-repos-tool-json/ledger.toml")
        }
        "tool_json_archive" => {
            include_str!("../../../validation/external-repos-tool-json/archive/wave3-ledger.toml")
        }
        "server_json_shortlist" => {
            include_str!("../../../validation/external-repos-server-json/repo-shortlist.toml")
        }
        "server_json_ledger" => {
            include_str!("../../../validation/external-repos-server-json/ledger.toml")
        }
        "server_json_archive" => {
            include_str!("../../../validation/external-repos-server-json/archive/wave1-ledger.toml")
        }
        "github_actions_shortlist" => {
            include_str!("../../../validation/external-repos-github-actions/repo-shortlist.toml")
        }
        "github_actions_ledger" => {
            include_str!("../../../validation/external-repos-github-actions/ledger.toml")
        }
        _ => unreachable!(),
    };
    text.parse::<toml::Value>()
        .expect("valid external validation TOML")
}

#[test]
fn external_validation_shortlist_has_expected_category_mix() {
    let value = parse_toml("shortlist");
    let repos = value["repos"].as_array().expect("repos array");
    let mut counts = BTreeMap::new();

    for repo in repos {
        let category = repo["category"].as_str().expect("category");
        *counts.entry(category).or_insert(0usize) += 1;
    }

    assert_eq!(repos.len(), 24, "shortlist should pin 24 repos");
    assert_eq!(counts.get("mcp"), Some(&10));
    assert_eq!(counts.get("cursor_plugin"), Some(&6));
    assert_eq!(counts.get("skills"), Some(&8));
}

#[test]
fn external_validation_repos_reference_valid_categories_and_statuses() {
    let value = parse_toml("shortlist");
    let repos = value["repos"].as_array().expect("repos array");
    let valid_categories = BTreeSet::from(["mcp", "cursor_plugin", "skills"]);
    let valid_subtypes = BTreeSet::from(["stress", "control"]);
    let valid_statuses = BTreeSet::from(["evaluated"]);

    for repo in repos {
        assert!(valid_categories.contains(repo["category"].as_str().unwrap()));
        assert!(valid_subtypes.contains(repo["subtype"].as_str().unwrap()));
        assert!(valid_statuses.contains(repo["status"].as_str().unwrap()));
    }
}

#[test]
fn external_validation_shortlist_entries_include_required_fields() {
    let value = parse_toml("shortlist");
    let repos = value["repos"].as_array().expect("repos array");

    for repo in repos {
        assert!(repo["repo"].as_str().unwrap().contains('/'));
        assert!(
            repo["url"]
                .as_str()
                .unwrap()
                .starts_with("https://github.com/")
        );
        assert!(!repo["pinned_ref"].as_str().unwrap().is_empty());
        assert!(!repo["rationale"].as_str().unwrap().is_empty());
        assert!(
            !repo["surfaces_present"].as_array().unwrap().is_empty(),
            "each shortlisted repo should have at least one target artifact"
        );
    }
}

#[test]
fn external_validation_ledger_entries_use_allowed_verdicts() {
    let value = parse_toml("ledger");
    let entries = value["evaluations"].as_array().expect("evaluations array");
    let valid_repo_verdicts = BTreeSet::from([
        "strong_fit",
        "useful_but_noisy",
        "low_signal",
        "out_of_scope",
    ]);
    let valid_follow_up_actions = BTreeSet::from([
        "tighten_rule",
        "needs_more_samples",
        "promote_preview_later",
        "add_new_structural_rule",
        "no_action",
    ]);

    assert_eq!(
        entries.len(),
        24,
        "ledger should cover the full external cohort"
    );

    for entry in entries {
        assert!(valid_repo_verdicts.contains(entry["repo_verdict"].as_str().unwrap()));
        assert!(valid_follow_up_actions.contains(entry["follow_up_action"].as_str().unwrap()));
        assert!(entry["diagnostics"].is_array());
    }
}

#[test]
fn external_validation_docs_are_linked_from_index() {
    let text = include_str!("../../../docs/INDEX.md");

    assert!(text.contains("[EXTERNAL_VALIDATION_PLAN.md](EXTERNAL_VALIDATION_PLAN.md)"));
    assert!(text.contains("[EXTERNAL_VALIDATION_REPORT.md](EXTERNAL_VALIDATION_REPORT.md)"));
    assert!(text.contains(
        "[EXTERNAL_VALIDATION_TOOL_JSON_REPORT.md](EXTERNAL_VALIDATION_TOOL_JSON_REPORT.md)"
    ));
    assert!(text.contains(
        "[EXTERNAL_VALIDATION_SERVER_JSON_REPORT.md](EXTERNAL_VALIDATION_SERVER_JSON_REPORT.md)"
    ));
    assert!(text.contains(
        "[EXTERNAL_VALIDATION_GITHUB_ACTIONS_REPORT.md](EXTERNAL_VALIDATION_GITHUB_ACTIONS_REPORT.md)"
    ));
}

#[test]
fn external_validation_report_matches_current_ledger_schema() {
    let report = include_str!("../../../docs/EXTERNAL_VALIDATION_REPORT.md");

    assert!(report.contains("## Cohort Composition"));
    assert!(report.contains("## Overall Counts"));
    assert!(report.contains("## Delta From Previous Wave"));
    assert!(report.contains("## Stable Precision Summary"));
    assert!(report.contains("## Preview Usefulness Summary"));
    assert!(report.contains("## Runtime / Diagnostic Notes"));
    assert!(report.contains("## Top FP Clusters"));
    assert!(report.contains("## Top FN Clusters"));
    assert!(report.contains("## Recommended Next Step"));
    assert!(report.contains("stable findings:"));
    assert!(report.contains("preview findings:"));
    assert!(report.contains("runtime parser errors:"));
    assert!(report.contains("diagnostics:"));
    assert!(report.contains("repo verdict changes:"));
}

#[test]
fn external_validation_shortlist_and_ledger_cover_the_same_repo_set() {
    let shortlist = parse_toml("shortlist");
    let ledger = parse_toml("ledger");

    let shortlist_repos: BTreeSet<_> = shortlist["repos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|repo| repo["repo"].as_str().unwrap())
        .collect();
    let ledger_repos: BTreeSet<_> = ledger["evaluations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["repo"].as_str().unwrap())
        .collect();

    assert_eq!(shortlist_repos, ledger_repos);
}

#[test]
fn external_validation_wave_markers_are_present() {
    let ledger = parse_toml("ledger");
    let archive = parse_toml("archive");

    assert_eq!(ledger["wave"].as_integer(), Some(2));
    assert_eq!(
        ledger["baseline"].as_str(),
        Some("archive/wave1-ledger.toml")
    );
    assert_eq!(archive["wave"].as_integer(), Some(1));
}

#[test]
fn tool_json_extension_shortlist_has_expected_shape() {
    let value = parse_toml("tool_json_shortlist");
    let repos = value["repos"].as_array().expect("repos array");
    let cohort = value["cohort"].as_table().expect("cohort table");

    assert_eq!(value["version"].as_integer(), Some(1));
    assert_eq!(cohort["total"].as_integer(), Some(9));
    assert_eq!(repos.len(), 9);

    for repo in repos {
        assert_eq!(repo["category"].as_str(), Some("tool_json"));
        assert!(matches!(
            repo["subtype"].as_str(),
            Some("stress" | "control")
        ));
        assert_eq!(repo["status"].as_str(), Some("evaluated"));
        assert_eq!(
            repo["surfaces_present"].as_array().unwrap(),
            &vec![toml::Value::String("tool_descriptor_json".to_owned())]
        );
        assert!(
            !repo["admission_paths"].as_array().unwrap().is_empty(),
            "tool-json extension repos must record admitted semantic-confirmed paths"
        );
        for path in repo["admission_paths"].as_array().unwrap() {
            let path = path.as_str().unwrap();
            assert!(!path.contains("/tests/"));
            assert!(!path.contains("/fixtures/"));
            assert!(!path.contains("/testdata/"));
            assert!(!path.contains("/examples/"));
            assert!(!path.contains("/samples/"));
            assert!(!path.contains("/docs/"));
            assert!(!path.contains("/schema/"));
            assert!(!path.contains("/schemas/"));
            assert!(!path.contains("/spec/"));
            assert!(!path.contains("/specs/"));
            assert!(!path.contains("/contracts/"));
        }
    }
}

#[test]
fn tool_json_extension_ledger_matches_shortlist_and_wave_marker() {
    let shortlist = parse_toml("tool_json_shortlist");
    let ledger = parse_toml("tool_json_ledger");
    let archive = parse_toml("tool_json_archive");

    assert_eq!(ledger["wave"].as_integer(), Some(4));
    assert_eq!(
        ledger["baseline"].as_str(),
        Some("archive/wave3-ledger.toml")
    );
    assert_eq!(archive["wave"].as_integer(), Some(3));

    let shortlist_repos: BTreeSet<_> = shortlist["repos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|repo| repo["repo"].as_str().unwrap())
        .collect();
    let ledger_repos: BTreeSet<_> = ledger["evaluations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["repo"].as_str().unwrap())
        .collect();

    assert_eq!(shortlist_repos, ledger_repos);
}

#[test]
fn tool_json_extension_report_has_required_sections() {
    let report = include_str!("../../../docs/EXTERNAL_VALIDATION_TOOL_JSON_REPORT.md");

    assert!(report.contains("## Cohort Composition"));
    assert!(report.contains("## Admission Results"));
    assert!(report.contains("## Overall Counts"));
    assert!(report.contains("## Delta From Previous Wave"));
    assert!(report.contains("## Stable Hits"));
    assert!(report.contains("## Preview Hits"));
    assert!(report.contains("## Runtime / Diagnostic Notes"));
    assert!(report.contains("## Fixture Suppression Check"));
    assert!(report.contains("## Recommended Next Step"));
    assert!(report.contains("stable findings:"));
    assert!(report.contains("preview findings:"));
    assert!(report.contains("runtime parser errors:"));
    assert!(report.contains("diagnostics:"));
    assert!(report.contains("admitted repo set changes:"));
    assert!(report.contains("admission-path issue"));
    assert!(report.contains("non-admission-path issue"));
}

#[test]
fn server_json_extension_shortlist_has_expected_shape() {
    let value = parse_toml("server_json_shortlist");
    let repos = value["repos"].as_array().expect("repos array");
    let cohort = value["cohort"].as_table().expect("cohort table");

    assert_eq!(value["version"].as_integer(), Some(1));
    assert_eq!(cohort["total"].as_integer(), Some(18));
    assert_eq!(repos.len(), 18);

    let stress = repos
        .iter()
        .filter(|repo| repo["subtype"].as_str() == Some("stress"))
        .count();
    let control = repos
        .iter()
        .filter(|repo| repo["subtype"].as_str() == Some("control"))
        .count();

    assert_eq!(stress, 12);
    assert_eq!(control, 6);

    for repo in repos {
        assert_eq!(repo["category"].as_str(), Some("server_json"));
        assert_eq!(repo["status"].as_str(), Some("evaluated"));
        assert_eq!(
            repo["surfaces_present"].as_array().unwrap(),
            &vec![toml::Value::String("server.json".to_owned())]
        );
        assert!(
            !repo["admission_paths"].as_array().unwrap().is_empty(),
            "server-json extension repos must record admitted semantic-confirmed paths"
        );
    }
}

#[test]
fn server_json_extension_ledger_matches_shortlist() {
    let shortlist = parse_toml("server_json_shortlist");
    let ledger = parse_toml("server_json_ledger");
    let archive = parse_toml("server_json_archive");

    assert_eq!(ledger["wave"].as_integer(), Some(2));
    assert_eq!(
        ledger["baseline"].as_str(),
        Some("archive/wave1-ledger.toml")
    );
    assert_eq!(archive["wave"].as_integer(), Some(1));

    let shortlist_repos: BTreeSet<_> = shortlist["repos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|repo| repo["repo"].as_str().unwrap())
        .collect();
    let ledger_repos: BTreeSet<_> = ledger["evaluations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["repo"].as_str().unwrap())
        .collect();

    assert_eq!(shortlist_repos, ledger_repos);
}

#[test]
fn server_json_extension_report_has_required_sections() {
    let report = include_str!("../../../docs/EXTERNAL_VALIDATION_SERVER_JSON_REPORT.md");

    assert!(report.contains("## Cohort Composition"));
    assert!(report.contains("## Admission Results"));
    assert!(report.contains("## Overall Counts"));
    assert!(report.contains("## Delta From Previous Wave"));
    assert!(report.contains("## Stable Hits"));
    assert!(report.contains("## Preview Hits"));
    assert!(report.contains("## Runtime / Diagnostic Notes"));
    assert!(report.contains("## Recommended Next Step"));
    assert!(report.contains("stable findings"));
    assert!(report.contains("admitted repo set changes:"));
}

#[test]
fn github_actions_extension_shortlist_has_expected_shape() {
    let value = parse_toml("github_actions_shortlist");
    let repos = value["repos"].as_array().expect("repos array");
    let cohort = value["cohort"].as_table().expect("cohort table");

    assert_eq!(value["version"].as_integer(), Some(1));
    assert_eq!(cohort["total"].as_integer(), Some(18));
    assert_eq!(repos.len(), 18);

    let stress = repos
        .iter()
        .filter(|repo| repo["subtype"].as_str() == Some("stress"))
        .count();
    let control = repos
        .iter()
        .filter(|repo| repo["subtype"].as_str() == Some("control"))
        .count();

    assert_eq!(stress, 12);
    assert_eq!(control, 6);

    for repo in repos {
        assert_eq!(repo["category"].as_str(), Some("github_workflow"));
        assert_eq!(repo["status"].as_str(), Some("evaluated"));
        assert_eq!(
            repo["surfaces_present"].as_array().unwrap(),
            &vec![toml::Value::String(".github/workflows/*.yml".to_owned())]
        );
        assert!(
            !repo["admission_paths"].as_array().unwrap().is_empty(),
            "github-actions extension repos must record admitted workflow paths"
        );
    }
}

#[test]
fn github_actions_extension_ledger_matches_shortlist() {
    let shortlist = parse_toml("github_actions_shortlist");
    let ledger = parse_toml("github_actions_ledger");

    assert_eq!(ledger["wave"].as_integer(), Some(1));
    assert!(ledger.get("baseline").is_none());

    let shortlist_repos: BTreeSet<_> = shortlist["repos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|repo| repo["repo"].as_str().unwrap())
        .collect();
    let ledger_repos: BTreeSet<_> = ledger["evaluations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["repo"].as_str().unwrap())
        .collect();

    assert_eq!(shortlist_repos, ledger_repos);
}

#[test]
fn github_actions_extension_report_has_required_sections() {
    let report = include_str!("../../../docs/EXTERNAL_VALIDATION_GITHUB_ACTIONS_REPORT.md");

    assert!(report.contains("## Cohort Composition"));
    assert!(report.contains("## Admission Results"));
    assert!(report.contains("## Overall Counts"));
    assert!(report.contains("## Stable Hits"));
    assert!(report.contains("## Preview Hits"));
    assert!(report.contains("## Runtime / Diagnostic Notes"));
    assert!(report.contains("## Recommended Next Step"));
    assert!(report.contains("stable findings"));
}
