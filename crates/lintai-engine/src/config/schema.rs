use schemars::schema_for;
use serde_json::Value;

use super::load::SchemaRawRootConfig;

pub fn config_schema_pretty() -> String {
    serde_json::to_string_pretty(&config_schema_value())
        .expect("schema serialization should not fail")
}

fn config_schema_value() -> Value {
    let mut value = serde_json::to_value(schema_for!(SchemaRawRootConfig))
        .expect("schema serialization should not fail");
    let Some(root) = value.as_object_mut() else {
        panic!("generated config schema must be a JSON object");
    };
    root.insert(
        "$schema".to_owned(),
        Value::String("https://json-schema.org/draft/2020-12/schema".to_owned()),
    );
    root.insert(
        "title".to_owned(),
        Value::String("lintai config v0 subset".to_owned()),
    );
    value
}
#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::config_schema_pretty;

    #[test]
    fn checked_in_schema_matches_generated_output() {
        let schema_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schema/lintai.schema.json");
        let checked_in = std::fs::read_to_string(schema_path).unwrap();

        let generated = config_schema_pretty();
        assert_eq!(checked_in.trim_end(), generated.trim_end());
    }

    #[test]
    fn schema_mentions_reserved_sections_and_core_sections() {
        let schema = config_schema_pretty();
        for needle in [
            "\"project\"",
            "\"files\"",
            "\"categories\"",
            "\"rules\"",
            "\"overrides\"",
            "\"suppress\"",
            "\"output\"",
            "\"ci\"",
            "\"detection\"",
            "\"capabilities\"",
            "\"policy\"",
            "\"extends\"",
            "\"plugins\"",
            "\"cache\"",
            "\"fix\"",
            "\"disallowed\"",
        ] {
            assert!(schema.contains(needle), "missing {needle} in schema");
        }
    }
}
