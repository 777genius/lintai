use std::collections::BTreeMap;
use std::sync::LazyLock;

use lintai_api::RuleTier;

use super::shipped_security_rule_catalog_entries;

const DOCS_SITE_URL: &str = "https://777genius.github.io/lintai";

static SHIPPED_RULE_DOCS_INDEX: LazyLock<BTreeMap<&'static str, (&'static str, &'static str)>> =
    LazyLock::new(|| {
        let mut index = BTreeMap::new();
        for entry in shipped_security_rule_catalog_entries() {
            index.insert(
                entry.metadata.code,
                (entry.provider_id, entry.metadata.doc_title),
            );
        }
        index
    });

pub(crate) fn shipped_rule_tiers() -> BTreeMap<String, RuleTier> {
    shipped_security_rule_catalog_entries()
        .into_iter()
        .map(|entry| (entry.metadata.code.to_owned(), entry.metadata.tier))
        .collect()
}

pub(crate) fn docs_site_url() -> &'static str {
    DOCS_SITE_URL
}

pub(crate) fn provider_slug(provider_id: &str) -> String {
    slugify(provider_id)
}

pub(crate) fn rule_slug(rule_code: &str) -> String {
    slugify(rule_code)
}

pub(crate) fn canonical_rule_path(provider_id: &str, rule_code: &str) -> String {
    format!(
        "/rules/{}/{}",
        provider_slug(provider_id),
        rule_slug(rule_code)
    )
}

pub(crate) fn shipped_rule_doc_title(rule_code: &str) -> Option<&'static str> {
    SHIPPED_RULE_DOCS_INDEX
        .get(rule_code)
        .map(|(_, doc_title)| *doc_title)
}

pub(crate) fn shipped_rule_docs_url(rule_code: &str) -> Option<String> {
    SHIPPED_RULE_DOCS_INDEX
        .get(rule_code)
        .map(|(provider_id, _)| {
            format!(
                "{}{}",
                docs_site_url(),
                canonical_rule_path(provider_id, rule_code)
            )
        })
}

pub(crate) fn provider_sort_key(provider_id: &str) -> usize {
    match provider_id {
        "lintai-ai-security" => 0,
        "lintai-policy-mismatch" => 1,
        _ => usize::MAX,
    }
}

fn slugify(input: &str) -> String {
    let mut slug = String::new();
    let mut previous_dash = false;

    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            previous_dash = false;
        } else if !previous_dash {
            slug.push('-');
            previous_dash = true;
        }
    }

    slug.trim_matches('-').to_owned()
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_rule_path, docs_site_url, shipped_rule_doc_title, shipped_rule_docs_url,
    };

    #[test]
    fn shipped_rule_docs_urls_follow_public_pages_contract() {
        assert_eq!(
            canonical_rule_path("lintai-ai-security", "SEC101"),
            "/rules/lintai-ai-security/sec101"
        );
        assert_eq!(
            shipped_rule_docs_url("SEC101").as_deref(),
            Some("https://777genius.github.io/lintai/rules/lintai-ai-security/sec101")
        );
        assert_eq!(
            shipped_rule_docs_url("SEC401").as_deref(),
            Some("https://777genius.github.io/lintai/rules/lintai-policy-mismatch/sec401")
        );
        assert_eq!(
            shipped_rule_doc_title("SEC340"),
            Some("Claude hook: mutable package launcher")
        );
        assert_eq!(shipped_rule_docs_url("NOPE"), None);
        assert_eq!(docs_site_url(), "https://777genius.github.io/lintai");
    }
}
