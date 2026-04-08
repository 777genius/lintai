use std::collections::{BTreeMap, BTreeSet};

use lintai_api::{BuiltinPresetKind, RuleMetadata, builtin_presets};
use serde::Serialize;

use crate::shipped_rules::{
    CatalogRuleLifecycle, SecurityRuleCatalogEntry, canonical_rule_path, provider_slug,
    provider_sort_key, rule_slug, shipped_rule_alias, shipped_security_rule_catalog_entries,
};

#[derive(Debug, Serialize)]
struct SiteCatalog {
    version: u32,
    providers: Vec<SiteProvider>,
    presets: Vec<SitePreset>,
    rules: Vec<SiteRule>,
}

#[derive(Debug, Serialize)]
struct SiteProvider {
    id: String,
    slug: String,
    title: String,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum SitePresetKind {
    Membership,
    Overlay,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SitePreset {
    id: String,
    kind: SitePresetKind,
    title: String,
    description: String,
    extends: Vec<String>,
    rule_ids: Vec<String>,
    canonical_path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SiteRule {
    rule_id: String,
    provider_id: String,
    provider_slug: String,
    display_code: Option<String>,
    alias: Option<String>,
    display_label: String,
    doc_title: String,
    slug: String,
    canonical_path: String,
    summary: String,
    public_lane: String,
    scope: String,
    surface: String,
    tier: String,
    default_severity: String,
    default_confidence: String,
    detection_class: String,
    remediation_support: String,
    default_presets: Vec<String>,
    lifecycle_state: String,
    lifecycle: SiteRuleLifecycle,
    canonical_note: String,
    related_rule_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum SiteRuleLifecycle {
    Preview {
        blocker: String,
        promotion_requirements: String,
    },
    Stable {
        rationale: String,
        malicious_case_ids: Vec<String>,
        benign_case_ids: Vec<String>,
        requires_structured_evidence: bool,
        remediation_reviewed: bool,
        deterministic_signal_basis: String,
    },
}

pub(crate) fn render_site_catalog_json() -> String {
    let catalog = build_site_catalog();
    let mut json =
        serde_json::to_string_pretty(&catalog).expect("site catalog should serialize to JSON");
    json.push('\n');
    json
}

fn build_site_catalog() -> SiteCatalog {
    let entries = shipped_security_rule_catalog_entries();
    let providers = build_providers(&entries);
    let rules = build_rules(&entries);
    let presets = build_presets(&rules);
    let catalog = SiteCatalog {
        version: 1,
        providers,
        presets,
        rules,
    };
    validate_site_catalog(&catalog);
    catalog
}

fn build_providers(entries: &[SecurityRuleCatalogEntry]) -> Vec<SiteProvider> {
    let mut providers = Vec::new();
    for entry in entries {
        if providers
            .iter()
            .any(|provider: &SiteProvider| provider.id == entry.provider_id)
        {
            continue;
        }

        providers.push(SiteProvider {
            id: entry.provider_id.to_owned(),
            slug: provider_slug(entry.provider_id),
            title: entry.provider_id.to_owned(),
        });
    }

    providers.sort_by_key(|provider| provider_sort_key(provider.id.as_str()));
    providers
}

fn build_rules(entries: &[SecurityRuleCatalogEntry]) -> Vec<SiteRule> {
    let provider_slugs = entries
        .iter()
        .map(|entry| {
            (
                entry.provider_id.to_owned(),
                provider_slug(entry.provider_id),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut rules = entries
        .iter()
        .copied()
        .map(|entry| site_rule(entry, &provider_slugs))
        .collect::<Vec<_>>();
    rules.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
    rules
}

fn site_rule(
    entry: SecurityRuleCatalogEntry,
    provider_slugs: &BTreeMap<String, String>,
) -> SiteRule {
    let provider_slug = provider_slugs
        .get(entry.provider_id)
        .expect("provider slug should exist")
        .clone();
    let slug = rule_slug(entry.metadata.code);
    let alias = shipped_rule_alias(entry.metadata.code).map(str::to_owned);
    let display_code = entry.metadata.code.to_owned();
    let display_label = alias
        .as_ref()
        .map(|alias| format!("{display_code} / {alias}"))
        .unwrap_or_else(|| display_code.clone());

    SiteRule {
        rule_id: format!("{}:{}", entry.provider_id, entry.metadata.code),
        provider_id: entry.provider_id.to_owned(),
        provider_slug: provider_slug.clone(),
        display_code: Some(display_code),
        alias,
        display_label,
        doc_title: entry.metadata.doc_title.to_owned(),
        slug: slug.clone(),
        canonical_path: canonical_rule_path(entry.provider_id, entry.metadata.code),
        summary: entry.metadata.summary.to_owned(),
        public_lane: entry.public_lane().slug().to_owned(),
        scope: entry.scope.slug().to_owned(),
        surface: entry.surface.slug().to_owned(),
        tier: entry.metadata.tier.slug().to_owned(),
        default_severity: severity_name(entry.metadata).to_owned(),
        default_confidence: confidence_name(entry.metadata).to_owned(),
        detection_class: entry.detection_class.slug().to_owned(),
        remediation_support: entry.remediation_support.slug().to_owned(),
        default_presets: entry
            .default_presets()
            .into_iter()
            .map(str::to_owned)
            .collect(),
        lifecycle_state: entry.lifecycle_state().to_owned(),
        lifecycle: lifecycle(entry.lifecycle),
        canonical_note: entry.canonical_note().to_owned(),
        related_rule_ids: Vec::new(),
    }
}

fn build_presets(rules: &[SiteRule]) -> Vec<SitePreset> {
    builtin_presets()
        .iter()
        .map(|preset| {
            let mut rule_ids = rules
                .iter()
                .filter(|rule| {
                    rule.default_presets
                        .iter()
                        .any(|candidate| candidate == preset.id)
                })
                .map(|rule| rule.rule_id.clone())
                .collect::<Vec<_>>();
            rule_ids.sort();

            SitePreset {
                id: preset.id.to_owned(),
                kind: site_preset_kind(preset.kind),
                title: preset.id.to_owned(),
                description: preset.description.to_owned(),
                extends: preset
                    .extends
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                rule_ids,
                canonical_path: format!("/presets/{}", preset.id),
            }
        })
        .collect()
}

fn validate_site_catalog(catalog: &SiteCatalog) {
    let known_preset_ids = builtin_presets()
        .iter()
        .map(|preset| preset.id)
        .collect::<BTreeSet<_>>();

    let mut provider_ids = BTreeSet::new();
    let mut provider_slugs = BTreeSet::new();
    for provider in &catalog.providers {
        assert!(
            provider_ids.insert(provider.id.as_str()),
            "duplicate site catalog provider id {}",
            provider.id
        );
        assert!(
            provider_slugs.insert(provider.slug.as_str()),
            "duplicate site catalog provider slug {}",
            provider.slug
        );
    }

    let mut rule_ids = BTreeSet::new();
    let mut rule_paths = BTreeSet::new();
    for rule in &catalog.rules {
        assert!(
            rule_ids.insert(rule.rule_id.as_str()),
            "duplicate site catalog rule id {}",
            rule.rule_id
        );
        assert!(
            rule_paths.insert(rule.canonical_path.as_str()),
            "duplicate site catalog rule path {}",
            rule.canonical_path
        );
        for preset_id in &rule.default_presets {
            assert!(
                known_preset_ids.contains(preset_id.as_str()),
                "rule {} references unknown preset {}",
                rule.rule_id,
                preset_id
            );
        }
    }

    let mut preset_ids = BTreeSet::new();
    let mut preset_paths = BTreeSet::new();
    for preset in &catalog.presets {
        assert!(
            preset_ids.insert(preset.id.as_str()),
            "duplicate site catalog preset id {}",
            preset.id
        );
        assert!(
            preset_paths.insert(preset.canonical_path.as_str()),
            "duplicate site catalog preset path {}",
            preset.canonical_path
        );
        for extended in &preset.extends {
            assert!(
                known_preset_ids.contains(extended.as_str()),
                "preset {} extends unknown preset {}",
                preset.id,
                extended
            );
        }
    }
}

fn site_preset_kind(kind: BuiltinPresetKind) -> SitePresetKind {
    match kind {
        BuiltinPresetKind::Membership => SitePresetKind::Membership,
        BuiltinPresetKind::Overlay => SitePresetKind::Overlay,
    }
}

fn lifecycle(lifecycle: CatalogRuleLifecycle) -> SiteRuleLifecycle {
    match lifecycle {
        CatalogRuleLifecycle::Preview {
            blocker,
            promotion_requirements,
        } => SiteRuleLifecycle::Preview {
            blocker: blocker.to_owned(),
            promotion_requirements: promotion_requirements.to_owned(),
        },
        CatalogRuleLifecycle::Stable {
            rationale,
            malicious_case_ids,
            benign_case_ids,
            requires_structured_evidence,
            remediation_reviewed,
            deterministic_signal_basis,
        } => SiteRuleLifecycle::Stable {
            rationale: rationale.to_owned(),
            malicious_case_ids: malicious_case_ids
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            benign_case_ids: benign_case_ids
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            requires_structured_evidence,
            remediation_reviewed,
            deterministic_signal_basis: deterministic_signal_basis.to_owned(),
        },
    }
}

fn severity_name(metadata: RuleMetadata) -> &'static str {
    metadata.default_severity.slug()
}

fn confidence_name(metadata: RuleMetadata) -> &'static str {
    metadata.default_confidence.slug()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::{SiteRule, SiteRuleLifecycle, build_site_catalog, render_site_catalog_json};

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repo root should resolve from lintai-cli")
    }

    fn docs_root() -> PathBuf {
        repo_root().join("docs")
    }

    fn collect_markdown_pages(root: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        for entry in fs::read_dir(root).expect("docs subdir should exist") {
            let entry = entry.expect("dir entry should be readable");
            let path = entry.path();
            if path.is_dir() {
                files.extend(collect_markdown_pages(&path));
            } else if path.extension().is_some_and(|ext| ext == "md")
                && path.file_name().is_some_and(|name| name != "index.md")
            {
                files.push(path);
            }
        }
        files.sort();
        files
    }

    fn read_frontmatter_fields(path: &Path) -> BTreeMap<String, String> {
        let text = fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let frontmatter = text
            .strip_prefix("---\n")
            .and_then(|rest| rest.split_once("\n---\n"))
            .map(|(frontmatter, _)| frontmatter)
            .unwrap_or_else(|| panic!("missing frontmatter in {}", path.display()));

        let mut fields = BTreeMap::new();
        for line in frontmatter.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let trimmed = value.trim().trim_matches('"').trim_matches('\'');
            fields.insert(key.trim().to_owned(), trimmed.to_owned());
        }
        fields
    }

    fn inline_code(text: &str) -> String {
        format!("`{text}`")
    }

    fn escape_markdown_text(text: &str) -> String {
        text.replace("\r\n", "\n")
            .replace(['\r', '\n'], " ")
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    fn escape_markdown_table_cell(text: &str) -> String {
        escape_markdown_text(text).replace('|', "\\|")
    }

    fn format_presets(presets: &[String]) -> String {
        presets
            .iter()
            .map(|preset| inline_code(preset))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn severity_label(slug: &str) -> &'static str {
        match slug {
            "deny" => "Deny",
            "warn" => "Warn",
            "allow" => "Allow",
            other => panic!("unexpected severity slug {other}"),
        }
    }

    fn confidence_label(slug: &str) -> &'static str {
        match slug {
            "low" => "Low",
            "medium" => "Medium",
            "high" => "High",
            other => panic!("unexpected confidence slug {other}"),
        }
    }

    fn tier_label(slug: &str) -> &'static str {
        match slug {
            "stable" => "Stable",
            "preview" => "Preview",
            other => panic!("unexpected tier slug {other}"),
        }
    }

    fn markdown_detail_section<'a>(markdown: &'a str, rule: &SiteRule) -> &'a str {
        let heading = format!(
            "### {} — {}",
            inline_code(&rule.display_label),
            escape_markdown_text(&rule.summary)
        );
        let start = markdown
            .find(&heading)
            .unwrap_or_else(|| panic!("missing markdown heading for {}", rule.rule_id));
        let tail = &markdown[start..];
        let end = tail
            .find("\n### ")
            .or_else(|| tail.find("\n## Provider: "))
            .unwrap_or(tail.len());
        &tail[..end]
    }

    #[test]
    fn site_catalog_matches_checked_in_snapshot() {
        let expected = fs::read_to_string(docs_root().join(".generated/catalog.json"))
            .expect("checked-in site catalog snapshot should exist");
        assert_eq!(render_site_catalog_json(), expected);
    }

    #[test]
    fn security_rules_markdown_matches_site_catalog_matrix() {
        let catalog = build_site_catalog();
        let markdown = crate::security_rule_catalog::render_security_rules_markdown();

        let provider_summary_lines = markdown
            .lines()
            .skip_while(|line| {
                *line != "Canonical catalog for the shipped security rules currently exposed by:"
            })
            .skip(1)
            .take_while(|line| !line.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let expected_provider_summary_lines = catalog
            .providers
            .iter()
            .map(|provider| format!("- {}", inline_code(&provider.id)))
            .collect::<Vec<_>>();
        assert_eq!(provider_summary_lines, expected_provider_summary_lines);

        let summary_row_count = markdown
            .lines()
            .filter(|line| line.starts_with("| `"))
            .count();
        assert_eq!(summary_row_count, catalog.rules.len());

        for provider in &catalog.providers {
            assert!(
                markdown.contains(&format!("## Provider: {}", inline_code(&provider.id))),
                "markdown is missing provider section for {}",
                provider.id
            );
        }

        for rule in &catalog.rules {
            let summary_line = format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                inline_code(&rule.display_label),
                escape_markdown_table_cell(&rule.summary),
                inline_code(&rule.public_lane),
                tier_label(&rule.tier),
                inline_code(&rule.lifecycle_state),
                severity_label(&rule.default_severity),
                inline_code(&rule.scope),
                inline_code(&rule.surface),
                inline_code(&rule.detection_class),
                inline_code(&rule.remediation_support),
                format_presets(&rule.default_presets),
            );
            assert!(
                markdown.contains(&summary_line),
                "markdown summary row drifted for {}",
                rule.rule_id
            );

            let detail_section = markdown_detail_section(&markdown, rule);
            let expected_detail_lines = [
                format!("- Provider: {}", inline_code(&rule.provider_id)),
                format!(
                    "- Alias: {}",
                    rule.alias
                        .as_deref()
                        .map(inline_code)
                        .unwrap_or_else(|| inline_code("none"))
                ),
                format!("- Scope: {}", inline_code(&rule.scope)),
                format!("- Surface: {}", inline_code(&rule.surface)),
                format!("- Detection: {}", inline_code(&rule.detection_class)),
                format!(
                    "- Default Severity: {}",
                    inline_code(severity_label(&rule.default_severity))
                ),
                format!("- Public Lane: {}", inline_code(&rule.public_lane)),
                format!(
                    "- Default Confidence: {}",
                    inline_code(confidence_label(&rule.default_confidence))
                ),
                format!("- Tier: {}", inline_code(tier_label(&rule.tier))),
                format!(
                    "- Default Presets: {}",
                    format_presets(&rule.default_presets)
                ),
                format!("- Remediation: {}", inline_code(&rule.remediation_support)),
                format!("- Lifecycle: {}", inline_code(&rule.lifecycle_state)),
                format!(
                    "- Canonical Note: {}",
                    escape_markdown_text(&rule.canonical_note)
                ),
            ];
            for expected_line in expected_detail_lines {
                assert!(
                    detail_section.contains(&expected_line),
                    "markdown detail section drifted for {} on line: {}",
                    rule.rule_id,
                    expected_line
                );
            }

            match &rule.lifecycle {
                SiteRuleLifecycle::Preview {
                    blocker,
                    promotion_requirements,
                } => {
                    let expected_lines = [
                        format!("- Promotion Blocker: {}", escape_markdown_text(blocker)),
                        format!(
                            "- Promotion Requirements: {}",
                            escape_markdown_text(promotion_requirements)
                        ),
                    ];
                    for expected_line in expected_lines {
                        assert!(
                            detail_section.contains(&expected_line),
                            "markdown preview lifecycle drifted for {} on line: {}",
                            rule.rule_id,
                            expected_line
                        );
                    }
                }
                SiteRuleLifecycle::Stable {
                    rationale,
                    malicious_case_ids,
                    benign_case_ids,
                    requires_structured_evidence,
                    remediation_reviewed,
                    deterministic_signal_basis,
                } => {
                    let expected_lines = [
                        format!(
                            "- Graduation Rationale: {}",
                            escape_markdown_text(rationale)
                        ),
                        format!(
                            "- Deterministic Signal Basis: {}",
                            escape_markdown_text(deterministic_signal_basis)
                        ),
                        format!(
                            "- Malicious Corpus: {}",
                            malicious_case_ids
                                .iter()
                                .map(|id| inline_code(id))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        format!(
                            "- Benign Corpus: {}",
                            benign_case_ids
                                .iter()
                                .map(|id| inline_code(id))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        format!(
                            "- Structured Evidence Required: `{}`",
                            if *requires_structured_evidence {
                                "true"
                            } else {
                                "false"
                            }
                        ),
                        format!(
                            "- Remediation Reviewed: `{}`",
                            if *remediation_reviewed {
                                "true"
                            } else {
                                "false"
                            }
                        ),
                    ];
                    for expected_line in expected_lines {
                        assert!(
                            detail_section.contains(&expected_line),
                            "markdown stable lifecycle drifted for {} on line: {}",
                            rule.rule_id,
                            expected_line
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn representative_preset_memberships_match_expectations() {
        let catalog = build_site_catalog();

        let sec101 = catalog
            .rules
            .iter()
            .find(|rule| rule.rule_id == "lintai-ai-security:SEC101")
            .expect("SEC101 should exist");
        assert_eq!(sec101.default_presets, vec!["preview", "skills"]);

        let sec340 = catalog
            .rules
            .iter()
            .find(|rule| rule.rule_id == "lintai-ai-security:SEC340")
            .expect("SEC340 should exist");
        assert_eq!(
            sec340.default_presets,
            vec!["recommended", "base", "claude"]
        );
        assert_eq!(sec340.public_lane, "recommended");

        let sec401 = catalog
            .rules
            .iter()
            .find(|rule| rule.rule_id == "lintai-policy-mismatch:SEC401")
            .expect("SEC401 should exist");
        assert_eq!(sec401.default_presets, vec!["compat"]);
        assert_eq!(sec401.public_lane, "compat");

        let sec324 = catalog
            .rules
            .iter()
            .find(|rule| rule.rule_id == "lintai-ai-security:SEC324")
            .expect("SEC324 should exist");
        assert_eq!(sec324.default_presets, vec!["supply-chain"]);
        assert_eq!(sec324.public_lane, "supply-chain");

        let sec352 = catalog
            .rules
            .iter()
            .find(|rule| rule.rule_id == "lintai-ai-security:SEC352")
            .expect("SEC352 should exist");
        assert_eq!(sec352.default_presets, vec!["preview", "skills"]);
        assert_eq!(sec352.public_lane, "preview");

        let sec353 = catalog
            .rules
            .iter()
            .find(|rule| rule.rule_id == "lintai-ai-security:SEC353")
            .expect("SEC353 should exist");
        assert_eq!(sec353.default_presets, vec!["guidance"]);
        assert_eq!(sec353.public_lane, "guidance");

        let sec390 = catalog
            .rules
            .iter()
            .find(|rule| rule.rule_id == "lintai-ai-security:SEC390")
            .expect("SEC390 should exist");
        assert_eq!(sec390.default_presets, vec!["governance"]);
        assert_eq!(sec390.public_lane, "governance");

        let sec756 = catalog
            .rules
            .iter()
            .find(|rule| rule.rule_id == "lintai-dep-vulns:SEC756")
            .expect("SEC756 should exist");
        assert_eq!(sec756.default_presets, vec!["advisory"]);
        assert_eq!(sec756.public_lane, "advisory");

        let strict = catalog
            .presets
            .iter()
            .find(|preset| preset.id == "strict")
            .expect("strict preset should exist");
        let recommended = catalog
            .presets
            .iter()
            .find(|preset| preset.id == "recommended")
            .expect("recommended preset should exist");
        let advisory = catalog
            .presets
            .iter()
            .find(|preset| preset.id == "advisory")
            .expect("advisory preset should exist");
        let governance = catalog
            .presets
            .iter()
            .find(|preset| preset.id == "governance")
            .expect("governance preset should exist");
        assert!(matches!(strict.kind, super::SitePresetKind::Overlay));
        assert!(strict.rule_ids.is_empty());
        assert_eq!(strict.extends, vec!["recommended"]);
        assert!(matches!(
            recommended.kind,
            super::SitePresetKind::Membership
        ));
        assert!(
            !recommended
                .rule_ids
                .contains(&"lintai-ai-security:SEC324".to_owned())
        );
        assert!(
            !recommended
                .rule_ids
                .contains(&"lintai-ai-security:SEC328".to_owned())
        );
        let supply_chain = catalog
            .presets
            .iter()
            .find(|preset| preset.id == "supply-chain")
            .expect("supply-chain preset should exist");
        assert!(matches!(
            supply_chain.kind,
            super::SitePresetKind::Membership
        ));
        assert!(
            supply_chain
                .rule_ids
                .contains(&"lintai-ai-security:SEC324".to_owned())
        );
        assert!(
            supply_chain
                .rule_ids
                .contains(&"lintai-ai-security:SEC328".to_owned())
        );
        assert!(matches!(advisory.kind, super::SitePresetKind::Membership));
        assert!(matches!(governance.kind, super::SitePresetKind::Membership));
        assert!(
            advisory
                .rule_ids
                .iter()
                .any(|rule_id| rule_id == "lintai-dep-vulns:SEC756")
        );
        assert!(
            governance
                .rule_ids
                .iter()
                .any(|rule_id| rule_id == "lintai-ai-security:SEC390")
        );
        assert_eq!(sec101.doc_title, "HTML comment: dangerous instructions");
        assert_eq!(sec340.doc_title, "Claude hook: mutable package launcher");
        assert_eq!(sec401.doc_title, "Policy mismatch: execution");
        assert_eq!(
            sec756.doc_title,
            "Dependency vulnerability: installed npm package version"
        );
        assert_eq!(sec101.alias.as_deref(), Some("MD-HIDDEN-INSTRUCTIONS"));
        assert_eq!(
            sec340.alias.as_deref(),
            Some("CLAUDE-HOOK-MUTABLE-LAUNCHER")
        );
        assert_eq!(sec401.alias.as_deref(), Some("POLICY-EXEC-MISMATCH"));
        assert_eq!(sec756.alias.as_deref(), None);
    }

    #[test]
    fn catalog_paths_have_matching_checked_in_pages() {
        let catalog = build_site_catalog();
        let docs = docs_root();

        for rule in &catalog.rules {
            let path = docs.join(format!(
                "{}.md",
                rule.canonical_path.trim_start_matches('/')
            ));
            let fields = read_frontmatter_fields(&path);
            assert!(
                fields.get("layout").is_some_and(|value| value == "doc"),
                "{} should declare layout: doc",
                path.display()
            );
            assert!(
                fields
                    .get("lintaiPage")
                    .is_some_and(|value| value == "rule"),
                "{} should declare lintaiPage rule",
                path.display()
            );
            assert!(
                fields
                    .get("ruleId")
                    .is_some_and(|value| value == &rule.rule_id),
                "{} should declare ruleId {}",
                path.display(),
                rule.rule_id
            );
            if let Some(title) = fields.get("title") {
                assert_eq!(
                    title,
                    rule.display_code.as_ref().unwrap_or(&rule.slug),
                    "{} should keep title aligned with catalog metadata",
                    path.display()
                );
            }
            if let Some(description) = fields.get("description") {
                assert_eq!(
                    description,
                    &rule.summary,
                    "{} should keep description aligned with catalog metadata",
                    path.display()
                );
            }
        }

        for preset in &catalog.presets {
            let path = docs.join(format!(
                "{}.md",
                preset.canonical_path.trim_start_matches('/')
            ));
            let fields = read_frontmatter_fields(&path);
            assert!(
                fields.get("layout").is_some_and(|value| value == "doc"),
                "{} should declare layout: doc",
                path.display()
            );
            assert!(
                fields
                    .get("lintaiPage")
                    .is_some_and(|value| value == "preset"),
                "{} should declare lintaiPage preset",
                path.display()
            );
            assert!(
                fields
                    .get("presetId")
                    .is_some_and(|value| value == &preset.id),
                "{} should declare presetId {}",
                path.display(),
                preset.id
            );
            if let Some(title) = fields.get("title") {
                assert_eq!(
                    title,
                    &preset.title,
                    "{} should keep title aligned with catalog metadata",
                    path.display()
                );
            }
            if let Some(description) = fields.get("description") {
                assert_eq!(
                    description,
                    &preset.description,
                    "{} should keep description aligned with catalog metadata",
                    path.display()
                );
            }
        }
    }

    #[test]
    fn catalog_identity_fields_are_unique() {
        let catalog = build_site_catalog();
        let mut rule_ids = BTreeSet::new();
        let mut rule_paths = BTreeSet::new();
        let mut preset_ids = BTreeSet::new();
        let mut preset_paths = BTreeSet::new();

        for rule in &catalog.rules {
            assert!(
                rule_ids.insert(rule.rule_id.clone()),
                "duplicate site catalog rule id {}",
                rule.rule_id
            );
            assert!(
                rule_paths.insert(rule.canonical_path.clone()),
                "duplicate site catalog rule path {}",
                rule.canonical_path
            );
        }

        for preset in &catalog.presets {
            assert!(
                preset_ids.insert(preset.id.clone()),
                "duplicate site catalog preset id {}",
                preset.id
            );
            assert!(
                preset_paths.insert(preset.canonical_path.clone()),
                "duplicate site catalog preset path {}",
                preset.canonical_path
            );
        }
    }

    #[test]
    fn checked_in_rule_and_preset_pages_have_no_orphans() {
        let catalog = build_site_catalog();
        let docs = docs_root();

        let expected_rule_pages = catalog
            .rules
            .iter()
            .map(|rule| {
                docs.join(format!(
                    "{}.md",
                    rule.canonical_path.trim_start_matches('/')
                ))
            })
            .collect::<Vec<_>>();
        let actual_rule_pages = collect_markdown_pages(&docs.join("rules"));
        assert_eq!(actual_rule_pages, expected_rule_pages);

        let expected_preset_pages = catalog
            .presets
            .iter()
            .map(|preset| {
                docs.join(format!(
                    "{}.md",
                    preset.canonical_path.trim_start_matches('/')
                ))
            })
            .collect::<Vec<_>>();
        let mut expected_preset_pages = expected_preset_pages;
        expected_preset_pages.sort();
        let actual_preset_pages = collect_markdown_pages(&docs.join("presets"));
        assert_eq!(actual_preset_pages, expected_preset_pages);
    }
}
