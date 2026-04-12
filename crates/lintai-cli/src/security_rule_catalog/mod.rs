mod catalog;
pub(crate) mod format;
#[cfg(test)]
mod tests;

use crate::shipped_rules::shipped_security_rule_catalog_entries;
use catalog::{
    provider_ids, render_preset_activation_model, render_provider_sections,
    render_provider_summary, render_summary,
};
use format::render_inline_code;

pub(crate) fn render_security_rules_markdown() -> String {
    let entries = shipped_security_rule_catalog_entries();
    let provider_ids = provider_ids(&entries);
    let mut lines = vec![
        "# Security Rules Catalog".to_owned(),
        String::new(),
        "> Generated file. Do not edit by hand.".to_owned(),
        "> Source: `lintai-cli` shipped rule inventory aggregated from provider catalogs."
            .to_owned(),
        String::new(),
        "Canonical catalog for the shipped security rules currently exposed by:".to_owned(),
    ];
    lines.extend(render_provider_summary(&provider_ids, render_inline_code));
    lines.extend(render_summary(&entries));
    lines.extend(render_preset_activation_model());
    lines.extend(render_provider_sections(&entries, &provider_ids));
    lines.push(String::new());
    lines.join("\n")
}
