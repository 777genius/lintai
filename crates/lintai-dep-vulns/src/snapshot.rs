use std::sync::LazyLock;

use semver::Version;
use serde::{Deserialize, Serialize};

static SNAPSHOT: LazyLock<AdvisorySnapshot> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../data/npm-advisories.v1.json"))
        .expect("bundled npm advisory snapshot should be valid")
});

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdvisorySnapshot {
    pub schema_version: u32,
    pub ecosystem: String,
    pub generated_at: String,
    pub source: String,
    pub snapshot_revision: String,
    pub advisories: Vec<Advisory>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Advisory {
    pub id: String,
    pub package: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub summary: String,
    #[serde(default)]
    pub references: Vec<String>,
    pub ranges: Vec<AffectedRange>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AffectedRange {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
}

pub(crate) fn snapshot() -> &'static AdvisorySnapshot {
    &SNAPSHOT
}

pub fn bundled_snapshot() -> &'static AdvisorySnapshot {
    snapshot()
}

pub fn bundled_snapshot_json_pretty() -> String {
    let mut json = serde_json::to_string_pretty(bundled_snapshot())
        .expect("bundled advisory snapshot serializes");
    json.push('\n');
    json
}

pub fn normalize_snapshot_json(input: &str) -> Result<String, serde_json::Error> {
    let mut snapshot: AdvisorySnapshot = serde_json::from_str(input)?;
    normalize_snapshot(&mut snapshot);
    let mut json =
        serde_json::to_string_pretty(&snapshot).expect("normalized advisory snapshot serializes");
    json.push('\n');
    Ok(json)
}

pub(crate) fn advisory_matches_version(advisory: &Advisory, version: &Version) -> bool {
    advisory
        .ranges
        .iter()
        .any(|range| range_matches(range, version))
}

fn range_matches(range: &AffectedRange, version: &Version) -> bool {
    let Ok(introduced) = parse_bound(range.introduced.as_deref()) else {
        return false;
    };
    let Ok(fixed) = parse_bound(range.fixed.as_deref()) else {
        return false;
    };
    let introduced_ok = introduced.is_none_or(|introduced| version >= &introduced);
    let fixed_ok = fixed.is_none_or(|fixed| version < &fixed);
    introduced_ok && fixed_ok
}

fn parse_bound(value: Option<&str>) -> Result<Option<Version>, ()> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    Version::parse(value).map(Some).map_err(|_| ())
}

fn normalize_snapshot(snapshot: &mut AdvisorySnapshot) {
    snapshot.advisories.sort_by(|left, right| {
        left.package
            .cmp(&right.package)
            .then_with(|| left.id.cmp(&right.id))
    });
    for advisory in &mut snapshot.advisories {
        advisory.aliases.sort();
        advisory.aliases.dedup();
        advisory.references.sort();
        advisory.references.dedup();
        advisory.ranges.sort_by(|left, right| {
            left.introduced
                .cmp(&right.introduced)
                .then_with(|| left.fixed.cmp(&right.fixed))
        });
        advisory.ranges.dedup_by(|left, right| {
            left.introduced == right.introduced && left.fixed == right.fixed
        });
    }
}

#[cfg(test)]
mod tests {
    use semver::Version;

    use super::{AffectedRange, normalize_snapshot_json, range_matches};

    #[test]
    fn invalid_introduced_bound_does_not_match() {
        let range = AffectedRange {
            introduced: Some("not-a-version".to_owned()),
            fixed: Some("2.0.0".to_owned()),
        };

        assert!(!range_matches(&range, &Version::parse("1.5.0").unwrap()));
    }

    #[test]
    fn invalid_fixed_bound_does_not_match() {
        let range = AffectedRange {
            introduced: Some("1.0.0".to_owned()),
            fixed: Some("definitely-not-semver".to_owned()),
        };

        assert!(!range_matches(&range, &Version::parse("1.5.0").unwrap()));
    }

    #[test]
    fn normalization_sorts_and_deduplicates_snapshot_fields() {
        let normalized = normalize_snapshot_json(
            r#"{
              "schema_version": 1,
              "ecosystem": "npm",
              "generated_at": "2026-04-02T00:00:00Z",
              "source": "test",
              "snapshot_revision": "rev-1",
              "advisories": [
                {
                  "id": "B",
                  "package": "z",
                  "aliases": ["b", "a", "a"],
                  "summary": "demo",
                  "references": ["r2", "r1", "r1"],
                  "ranges": [
                    {"introduced": "2.0.0", "fixed": "3.0.0"},
                    {"introduced": "1.0.0", "fixed": "2.0.0"},
                    {"introduced": "1.0.0", "fixed": "2.0.0"}
                  ]
                },
                {
                  "id": "A",
                  "package": "a",
                  "aliases": [],
                  "summary": "demo",
                  "references": [],
                  "ranges": []
                }
              ]
            }"#,
        )
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&normalized).unwrap();
        let advisories = parsed["advisories"].as_array().unwrap();
        assert_eq!(advisories[0]["package"], "a");
        assert_eq!(advisories[1]["aliases"], serde_json::json!(["a", "b"]));
        assert_eq!(advisories[1]["references"], serde_json::json!(["r1", "r2"]));
        assert_eq!(advisories[1]["ranges"].as_array().unwrap().len(), 2);
    }
}
