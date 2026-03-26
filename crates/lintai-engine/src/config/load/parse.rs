use std::collections::BTreeMap;

use lintai_api::Severity;

use crate::ConfigError;

const SUPPORTED_TOP_LEVEL_KEYS: &[&str] = &[
    "project",
    "files",
    "categories",
    "rules",
    "overrides",
    "detection",
    "suppress",
    "output",
    "ci",
    "capabilities",
    "policy",
];
const RESERVED_TOP_LEVEL_KEYS: &[&str] = &["extends", "plugins", "cache", "fix", "disallowed"];

pub(super) fn validate_top_level_keys(value: &toml::Value) -> Result<(), ConfigError> {
    let table = value
        .as_table()
        .ok_or_else(|| ConfigError::new("config root must be a table"))?;
    for key in table.keys() {
        if SUPPORTED_TOP_LEVEL_KEYS.contains(&key.as_str()) {
            continue;
        }
        if RESERVED_TOP_LEVEL_KEYS.contains(&key.as_str()) {
            return Err(ConfigError::new(format!(
                "section `{key}` is reserved but not supported in this release"
            )));
        }
        return Err(ConfigError::new(format!("unknown top-level key `{key}`")));
    }
    Ok(())
}

pub(super) fn parse_rules(
    value: Option<&toml::Value>,
) -> Result<BTreeMap<String, Severity>, ConfigError> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let table = value
        .as_table()
        .ok_or_else(|| ConfigError::new("`[rules]` must be a table"))?;
    let mut parsed = BTreeMap::new();
    for (rule_code, rule_value) in table {
        if let Some(severity) = rule_value.as_str() {
            let parsed_severity = severity
                .parse::<SeverityToml>()
                .map_err(|error| ConfigError::new(format!("rules.{rule_code}: {error}")))?;
            parsed.insert(rule_code.clone(), parsed_severity.into());
            continue;
        }
        return Err(ConfigError::new(format!(
            "rule parameters for `{rule_code}` are reserved but not supported in this release"
        )));
    }
    Ok(parsed)
}

#[derive(Clone, Copy)]
enum SeverityToml {
    Deny,
    Warn,
    Allow,
}

impl std::str::FromStr for SeverityToml {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "deny" => Ok(Self::Deny),
            "warn" => Ok(Self::Warn),
            "allow" => Ok(Self::Allow),
            other => Err(format!("unknown severity `{other}`")),
        }
    }
}

impl From<SeverityToml> for Severity {
    fn from(value: SeverityToml) -> Self {
        match value {
            SeverityToml::Deny => Severity::Deny,
            SeverityToml::Warn => Severity::Warn,
            SeverityToml::Allow => Severity::Allow,
        }
    }
}
