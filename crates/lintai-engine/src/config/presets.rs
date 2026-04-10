use std::collections::{BTreeMap, BTreeSet};

use lintai_api::{Category, Severity};
use lintai_builtins::{builtin_known_rule_codes, builtin_rule_codes_for_preset};

use super::ConfigError;

pub(crate) const DEFAULT_ENABLED_PRESETS: &[&str] = &["recommended"];

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
    let mut resolved = ResolvedPresetPolicy {
        known_rules: builtin_known_rule_codes(),
        ..ResolvedPresetPolicy::default()
    };
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
        "recommended" => Ok(BuiltinPresetSpec {
            name: "recommended",
            extends: &[],
            active_rules: rules_for_preset("recommended"),
            ..Default::default()
        }),
        "base" => Ok(BuiltinPresetSpec {
            name: "base",
            extends: &[],
            active_rules: rules_for_preset("base"),
            ..Default::default()
        }),
        "strict" => Ok(BuiltinPresetSpec {
            name: "strict",
            extends: &["recommended"],
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
        "threat-review" => Ok(BuiltinPresetSpec {
            name: "threat-review",
            extends: &[],
            active_rules: rules_for_preset("threat-review"),
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
        "guidance" => Ok(BuiltinPresetSpec {
            name: "guidance",
            extends: &[],
            active_rules: rules_for_preset("guidance"),
            ..Default::default()
        }),
        "governance" => Ok(BuiltinPresetSpec {
            name: "governance",
            extends: &[],
            active_rules: rules_for_preset("governance"),
            ..Default::default()
        }),
        "supply-chain" => Ok(BuiltinPresetSpec {
            name: "supply-chain",
            extends: &[],
            active_rules: rules_for_preset("supply-chain"),
            ..Default::default()
        }),
        "advisory" => Ok(BuiltinPresetSpec {
            name: "advisory",
            extends: &[],
            active_rules: rules_for_preset("advisory"),
            ..Default::default()
        }),
        other => Err(ConfigError::new(format!(
            "unknown builtin preset `{other}`; expected one of: recommended, base, strict, compat, preview, threat-review, skills, mcp, claude, guidance, governance, supply-chain, advisory"
        ))),
    }
}

fn rules_for_preset(preset: &str) -> BTreeSet<String> {
    builtin_rule_codes_for_preset(preset)
}
