use std::collections::{BTreeMap, BTreeSet};

use lintai_ai_security::native_rule_catalog_entries;
use lintai_api::{Category, Severity};
use lintai_policy::policy_rule_catalog_entries;

use super::ConfigError;

pub(crate) const DEFAULT_ENABLED_PRESETS: &[&str] = &["base"];

#[derive(Clone, Debug, Default)]
pub(crate) struct BuiltinPresetSpec {
    pub name: &'static str,
    pub extends: &'static [&'static str],
    pub active_rules: BTreeSet<String>,
    pub category_overrides: BTreeMap<Category, Severity>,
    pub rule_overrides: BTreeMap<String, Severity>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ResolvedPresetPolicy {
    pub enabled_presets: Vec<String>,
    pub known_rules: BTreeSet<String>,
    pub active_rules: BTreeSet<String>,
    pub category_overrides: BTreeMap<Category, Severity>,
    pub rule_overrides: BTreeMap<String, Severity>,
}

pub(crate) fn default_builtin_preset_policy() -> ResolvedPresetPolicy {
    resolve_builtin_presets(None).expect("default builtin preset policy should be valid")
}

pub(crate) fn resolve_builtin_presets(
    configured: Option<Vec<String>>,
) -> Result<ResolvedPresetPolicy, ConfigError> {
    let requested = configured.unwrap_or_else(|| {
        DEFAULT_ENABLED_PRESETS
            .iter()
            .map(|preset| (*preset).to_owned())
            .collect()
    });
    let mut resolved = ResolvedPresetPolicy::default();
    resolved.known_rules = known_builtin_rules();
    let mut expanded = BTreeSet::new();
    let mut ordered = Vec::new();

    for preset in requested {
        expand_preset(&preset, &mut expanded, &mut ordered)?;
    }

    for preset_name in ordered {
        let spec = builtin_preset_spec(preset_name)?;
        resolved.enabled_presets.push(spec.name.to_owned());
        resolved.active_rules.extend(spec.active_rules);
        resolved.category_overrides.extend(spec.category_overrides);
        resolved.rule_overrides.extend(spec.rule_overrides);
    }

    Ok(resolved)
}

fn expand_preset(
    preset_name: &str,
    expanded: &mut BTreeSet<String>,
    ordered: &mut Vec<&'static str>,
) -> Result<(), ConfigError> {
    if expanded.contains(preset_name) {
        return Ok(());
    }

    let spec = builtin_preset_spec(preset_name)?;
    for parent in spec.extends {
        expand_preset(parent, expanded, ordered)?;
    }

    expanded.insert(spec.name.to_owned());
    ordered.push(spec.name);
    Ok(())
}

fn builtin_preset_spec(name: &str) -> Result<BuiltinPresetSpec, ConfigError> {
    match name {
        "base" => Ok(BuiltinPresetSpec {
            name: "base",
            extends: &[],
            active_rules: rules_for_preset("base"),
            ..Default::default()
        }),
        "strict" => Ok(BuiltinPresetSpec {
            name: "strict",
            extends: &["base"],
            category_overrides: BTreeMap::from([(Category::Security, Severity::Deny)]),
            ..Default::default()
        }),
        "compat" => Ok(BuiltinPresetSpec {
            name: "compat",
            extends: &[],
            active_rules: rules_for_preset("compat"),
            ..Default::default()
        }),
        "preview" => Ok(BuiltinPresetSpec {
            name: "preview",
            extends: &[],
            active_rules: rules_for_preset("preview"),
            ..Default::default()
        }),
        "skills" => Ok(BuiltinPresetSpec {
            name: "skills",
            extends: &[],
            active_rules: rules_for_preset("skills"),
            ..Default::default()
        }),
        "mcp" => Ok(BuiltinPresetSpec {
            name: "mcp",
            extends: &[],
            active_rules: rules_for_preset("mcp"),
            ..Default::default()
        }),
        "claude" => Ok(BuiltinPresetSpec {
            name: "claude",
            extends: &[],
            active_rules: rules_for_preset("claude"),
            ..Default::default()
        }),
        other => Err(ConfigError::new(format!(
            "unknown builtin preset `{other}`; expected one of: base, strict, compat, preview, skills, mcp, claude"
        ))),
    }
}

fn rules_for_preset(preset: &str) -> BTreeSet<String> {
    known_catalog_entries()
        .into_iter()
        .filter(|(default_presets, _)| default_presets.contains(&preset))
        .map(|(_, code)| code)
        .collect()
}

fn known_builtin_rules() -> BTreeSet<String> {
    known_catalog_entries()
        .into_iter()
        .map(|(_, code)| code)
        .collect()
}

fn known_catalog_entries() -> Vec<(&'static [&'static str], String)> {
    let mut entries = native_rule_catalog_entries()
        .into_iter()
        .map(|entry| (entry.default_presets, entry.metadata.code.to_owned()))
        .collect::<Vec<_>>();
    entries.extend(
        policy_rule_catalog_entries()
            .iter()
            .map(|entry| (entry.default_presets, entry.metadata.code.to_owned())),
    );
    entries
}
