use std::collections::BTreeMap;
use std::sync::LazyLock;

use lintai_api::RuleTier;

use super::shipped_security_rule_catalog_entries;

const DOCS_SITE_URL: &str = "https://777genius.github.io/lintai";

#[derive(Clone, Copy)]
struct ShippedRuleDocIndexEntry {
    provider_id: &'static str,
    doc_title: &'static str,
}

static SHIPPED_RULE_DOCS_INDEX: LazyLock<BTreeMap<&'static str, ShippedRuleDocIndexEntry>> =
    LazyLock::new(|| {
        let mut index = BTreeMap::new();
        for entry in shipped_security_rule_catalog_entries() {
            index.insert(
                entry.metadata.code,
                ShippedRuleDocIndexEntry {
                    provider_id: entry.provider_id,
                    doc_title: entry.metadata.doc_title,
                },
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
        .map(|entry| entry.doc_title)
}

pub(crate) fn shipped_rule_docs_url(rule_code: &str) -> Option<String> {
    SHIPPED_RULE_DOCS_INDEX.get(rule_code).map(|entry| {
        format!(
            "{}{}",
            docs_site_url(),
            canonical_rule_path(entry.provider_id, rule_code)
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
    use crate::shipped_rules::shipped_rule_alias;

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
        assert_eq!(shipped_rule_alias("SEC353"), Some("COPILOT-4K"));
        assert_eq!(shipped_rule_alias("SEC355"), Some("MD-WILDCARD-TOOLS"));
        assert_eq!(
            shipped_rule_alias("SEC356"),
            Some("PLUGIN-AGENT-PERMISSIONMODE")
        );
        assert_eq!(shipped_rule_alias("SEC357"), Some("PLUGIN-AGENT-HOOKS"));
        assert_eq!(
            shipped_rule_alias("SEC358"),
            Some("PLUGIN-AGENT-MCPSERVERS")
        );
        assert_eq!(
            shipped_rule_alias("SEC359"),
            Some("CURSOR-RULE-ALWAYSAPPLY")
        );
        assert_eq!(shipped_rule_alias("SEC360"), Some("CURSOR-RULE-GLOBS"));
        assert_eq!(shipped_rule_alias("SEC361"), Some("CLAUDE-SETTINGS-SCHEMA"));
        assert_eq!(shipped_rule_alias("SEC362"), Some("CLAUDE-BASH-WILDCARD"));
        assert_eq!(shipped_rule_alias("SEC363"), Some("CLAUDE-HOME-HOOK-PATH"));
        assert_eq!(
            shipped_rule_alias("SEC364"),
            Some("CLAUDE-BYPASS-PERMISSIONS")
        );
        assert_eq!(shipped_rule_alias("SEC365"), Some("CLAUDE-HTTP-HOOK-URL"));
        assert_eq!(shipped_rule_alias("SEC366"), Some("CLAUDE-HTTP-HOOK-HOST"));
        assert_eq!(
            shipped_rule_alias("SEC367"),
            Some("CLAUDE-WEBFETCH-WILDCARD")
        );
        assert_eq!(shipped_rule_alias("SEC368"), Some("CLAUDE-ABS-HOOK-PATH"));
        assert_eq!(shipped_rule_alias("SEC369"), Some("CLAUDE-WRITE-WILDCARD"));
        assert_eq!(shipped_rule_alias("SEC370"), Some("COPILOT-PATH-SUFFIX"));
        assert_eq!(shipped_rule_alias("SEC371"), Some("COPILOT-APPLYTO-TYPE"));
        assert_eq!(shipped_rule_alias("SEC372"), Some("CLAUDE-READ-WILDCARD"));
        assert_eq!(shipped_rule_alias("SEC373"), Some("CLAUDE-EDIT-WILDCARD"));
        assert_eq!(
            shipped_rule_alias("SEC374"),
            Some("CLAUDE-WEBSEARCH-WILDCARD")
        );
        assert_eq!(shipped_rule_alias("SEC375"), Some("CLAUDE-GLOB-WILDCARD"));
        assert_eq!(shipped_rule_alias("SEC376"), Some("CLAUDE-GREP-WILDCARD"));
        assert_eq!(shipped_rule_alias("SEC377"), Some("COPILOT-APPLYTO-GLOB"));
        assert_eq!(
            shipped_rule_alias("SEC378"),
            Some("CURSOR-ALWAYSAPPLY-GLOBS")
        );
        assert_eq!(
            shipped_rule_alias("SEC379"),
            Some("CURSOR-UNKNOWN-FRONTMATTER")
        );
        assert_eq!(shipped_rule_alias("SEC380"), Some("CURSOR-DESCRIPTION"));
        assert_eq!(shipped_rule_alias("SEC381"), Some("CLAUDE-HOOK-TIMEOUT"));
        assert_eq!(
            shipped_rule_alias("SEC382"),
            Some("CLAUDE-HOOK-MATCHER-EVENT")
        );
        assert_eq!(
            shipped_rule_alias("SEC383"),
            Some("CLAUDE-HOOK-MISSING-MATCHER")
        );
        assert_eq!(
            shipped_rule_alias("SEC384"),
            Some("CLAUDE-WEBSEARCH-UNSCOPED")
        );
        assert_eq!(
            shipped_rule_alias("SEC385"),
            Some("CLAUDE-GIT-PUSH-PERMISSION")
        );
        assert_eq!(
            shipped_rule_alias("SEC386"),
            Some("CLAUDE-GIT-CHECKOUT-PERMISSION")
        );
        assert_eq!(
            shipped_rule_alias("SEC387"),
            Some("CLAUDE-GIT-COMMIT-PERMISSION")
        );
        assert_eq!(
            shipped_rule_alias("SEC388"),
            Some("CLAUDE-GIT-STASH-PERMISSION")
        );
        assert_eq!(shipped_rule_alias("SEC389"), Some("MD-WEBSEARCH-UNSCOPED"));
        assert_eq!(shipped_rule_alias("SEC390"), Some("MD-GIT-PUSH-PERMISSION"));
        assert_eq!(
            shipped_rule_alias("SEC391"),
            Some("MD-GIT-CHECKOUT-PERMISSION")
        );
        assert_eq!(
            shipped_rule_alias("SEC392"),
            Some("MD-GIT-COMMIT-PERMISSION")
        );
        assert_eq!(
            shipped_rule_alias("SEC393"),
            Some("MD-GIT-STASH-PERMISSION")
        );
        assert_eq!(
            shipped_rule_alias("SEC394"),
            Some("MCP-AUTOAPPROVE-WILDCARD")
        );
        assert_eq!(shipped_rule_alias("SEC395"), Some("MCP-AUTOAPPROVE-TOOLS"));
        assert_eq!(shipped_rule_alias("SEC396"), Some("MCP-TRUST-TOOLS"));
        assert_eq!(shipped_rule_alias("SEC397"), Some("MCP-SANDBOX-DISABLED"));
        assert_eq!(
            shipped_rule_alias("SEC398"),
            Some("MCP-CAPABILITIES-WILDCARD")
        );
        assert_eq!(shipped_rule_alias("SEC399"), Some("CLAUDE-NPX-PERMISSION"));
        assert_eq!(
            shipped_rule_alias("SEC400"),
            Some("CLAUDE-ENABLED-MCPJSON-SERVERS")
        );
        assert_eq!(shipped_rule_alias("SEC404"), Some("MD-WEBFETCH-UNSCOPED"));
        assert_eq!(
            shipped_rule_alias("SEC405"),
            Some("CLAUDE-PACKAGE-INSTALL-PERMISSION")
        );
        assert_eq!(
            shipped_rule_alias("SEC406"),
            Some("CLAUDE-GIT-ADD-PERMISSION")
        );
        assert_eq!(
            shipped_rule_alias("SEC407"),
            Some("CLAUDE-GIT-CLONE-PERMISSION")
        );
        assert_eq!(
            shipped_rule_alias("SEC408"),
            Some("CLAUDE-GH-PR-PERMISSION")
        );
        assert_eq!(
            shipped_rule_alias("SEC409"),
            Some("CLAUDE-GIT-FETCH-PERMISSION")
        );
        assert_eq!(
            shipped_rule_alias("SEC410"),
            Some("CLAUDE-GIT-LS-REMOTE-PERMISSION")
        );
        assert_eq!(shipped_rule_alias("SEC411"), Some("CLAUDE-CURL-PERMISSION"));
        assert_eq!(shipped_rule_alias("SEC412"), Some("CLAUDE-WGET-PERMISSION"));
        assert_eq!(
            shipped_rule_alias("SEC413"),
            Some("CLAUDE-GIT-CONFIG-PERMISSION")
        );
        assert_eq!(
            shipped_rule_alias("SEC414"),
            Some("CLAUDE-GIT-TAG-PERMISSION")
        );
        assert_eq!(
            shipped_rule_alias("SEC415"),
            Some("CLAUDE-GIT-BRANCH-PERMISSION")
        );
        assert_eq!(shipped_rule_alias("SEC416"), Some("MD-CLAUDE-PIP-INSTALL"));
        assert_eq!(shipped_rule_alias("SEC417"), Some("MD-PIP-GIT-UNPINNED"));
        assert_eq!(
            shipped_rule_alias("SEC418"),
            Some("CLAUDE-WEBFETCH-RAW-GITHUB")
        );
        assert_eq!(shipped_rule_alias("SEC419"), Some("MD-CURL-ALLOWED-TOOLS"));
        assert_eq!(shipped_rule_alias("SEC420"), Some("MD-WGET-ALLOWED-TOOLS"));
        assert_eq!(
            shipped_rule_alias("SEC421"),
            Some("MD-GIT-CLONE-ALLOWED-TOOLS")
        );
        assert_eq!(shipped_rule_alias("SEC422"), Some("MCP-COMMAND-SUDO"));
        assert_eq!(shipped_rule_alias("SEC423"), Some("MD-READ-UNSCOPED"));
        assert_eq!(shipped_rule_alias("SEC424"), Some("MD-WRITE-UNSCOPED"));
        assert_eq!(shipped_rule_alias("SEC425"), Some("MD-EDIT-UNSCOPED"));
        assert_eq!(shipped_rule_alias("SEC426"), Some("MD-GLOB-UNSCOPED"));
        assert_eq!(shipped_rule_alias("SEC427"), Some("MD-GREP-UNSCOPED"));
        assert_eq!(shipped_rule_alias("SEC446"), Some("MCP-ARGS-SUDO"));
        assert_eq!(
            shipped_rule_alias("SEC447"),
            Some("MD-PACKAGE-INSTALL-ALLOWED-TOOLS")
        );
        assert_eq!(shipped_rule_alias("SEC448"), Some("MD-PIP-TRUSTED-HOST"));
        assert_eq!(shipped_rule_alias("SEC449"), Some("MD-PIP-HTTP-INDEX"));
        assert_eq!(shipped_rule_alias("SEC450"), Some("MD-NPM-HTTP-REGISTRY"));
        assert_eq!(
            shipped_rule_alias("SEC451"),
            Some("MD-CARGO-HTTP-GIT-INSTALL")
        );
        assert_eq!(shipped_rule_alias("SEC452"), Some("MD-CARGO-HTTP-INDEX"));
        assert_eq!(shipped_rule_alias("SEC453"), Some("MD-PIP-HTTP-SOURCE"));
        assert_eq!(shipped_rule_alias("SEC454"), Some("MD-NPM-HTTP-SOURCE"));
        assert_eq!(
            shipped_rule_alias("SEC455"),
            Some("MD-PIP-HTTP-GIT-INSTALL")
        );
        assert_eq!(shipped_rule_alias("SEC456"), Some("MD-PIP-HTTP-FIND-LINKS"));
        assert_eq!(
            shipped_rule_alias("SEC458"),
            Some("MD-PIP-CONFIG-HTTP-INDEX")
        );
        assert_eq!(
            shipped_rule_alias("SEC457"),
            Some("MD-JS-PACKAGE-STRICT-SSL-FALSE")
        );
        assert_eq!(
            shipped_rule_alias("SEC459"),
            Some("MD-JS-PACKAGE-CONFIG-HTTP-REGISTRY")
        );
        assert_eq!(
            shipped_rule_alias("SEC460"),
            Some("MD-PIP-CONFIG-HTTP-FIND-LINKS")
        );
        assert_eq!(
            shipped_rule_alias("SEC461"),
            Some("MD-PIP-CONFIG-TRUSTED-HOST")
        );
        assert_eq!(shipped_rule_alias("SEC462"), Some("MD-NETWORK-TLS-BYPASS"));
        assert_eq!(shipped_rule_alias("SEC463"), Some("MD-SUDO-ALLOWED-TOOLS"));
        assert_eq!(shipped_rule_alias("SEC464"), Some("MD-GIT-HTTP-CLONE"));
        assert_eq!(shipped_rule_alias("SEC465"), Some("MD-GIT-HTTP-REMOTE"));
        assert_eq!(shipped_rule_alias("SEC466"), Some("MD-RM-ALLOWED-TOOLS"));
        assert_eq!(shipped_rule_alias("SEC467"), Some("MD-CHMOD-ALLOWED-TOOLS"));
        assert_eq!(shipped_rule_alias("SEC468"), Some("MD-CHOWN-ALLOWED-TOOLS"));
        assert_eq!(shipped_rule_alias("SEC401"), Some("POLICY-EXEC-MISMATCH"));
        assert_eq!(shipped_rule_docs_url("NOPE"), None);
        assert_eq!(docs_site_url(), "https://777genius.github.io/lintai");
    }
}
