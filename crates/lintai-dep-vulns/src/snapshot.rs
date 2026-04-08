use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use semver::Version;
use serde::{Deserialize, Serialize};

static SNAPSHOT: LazyLock<Result<AdvisorySnapshot, String>> = LazyLock::new(|| {
    load_snapshot_from_str(
        include_str!("../data/npm-advisories.v1.json"),
        Some(PathBuf::from("bundled:npm-advisories.v1.json")),
    )
});

pub const ADVISORY_SNAPSHOT_ENV: &str = "LINTAI_ADVISORY_SNAPSHOT";

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

pub(crate) enum SnapshotRef<'a> {
    Bundled(&'a AdvisorySnapshot),
    Custom(AdvisorySnapshot),
}

impl SnapshotRef<'_> {
    pub(crate) fn as_snapshot(&self) -> &AdvisorySnapshot {
        match self {
            SnapshotRef::Bundled(snapshot) => snapshot,
            SnapshotRef::Custom(snapshot) => snapshot,
        }
    }
}

pub(crate) fn snapshot() -> Result<SnapshotRef<'static>, String> {
    let Some(path) = std::env::var_os(ADVISORY_SNAPSHOT_ENV) else {
        let snapshot = bundled_snapshot()?;
        return Ok(SnapshotRef::Bundled(snapshot));
    };
    let path = std::path::PathBuf::from(path);
    let snapshot = load_snapshot_file(&path)?;
    Ok(SnapshotRef::Custom(snapshot))
}

pub fn bundled_snapshot() -> Result<&'static AdvisorySnapshot, String> {
    match &*SNAPSHOT {
        Ok(snapshot) => Ok(snapshot),
        Err(error) => Err(error.clone()),
    }
}

pub fn bundled_snapshot_json_pretty() -> Result<String, String> {
    let mut json = serde_json::to_string_pretty(bundled_snapshot()?)
        .expect("bundled advisory snapshot serializes");
    json.push('\n');
    Ok(json)
}

pub fn normalize_snapshot_json(input: &str) -> Result<String, serde_json::Error> {
    let mut snapshot: AdvisorySnapshot = serde_json::from_str(input)?;
    normalize_snapshot(&mut snapshot);
    validate_snapshot(&snapshot, None).map_err(|error| {
        serde_json::Error::io(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    })?;
    let mut json =
        serde_json::to_string_pretty(&snapshot).expect("normalized advisory snapshot serializes");
    json.push('\n');
    Ok(json)
}

pub fn load_snapshot_file(path: &Path) -> Result<AdvisorySnapshot, String> {
    let raw = std::fs::read_to_string(path).map_err(|error| {
        format!(
            "failed to read advisory snapshot {}: {error}",
            path.display()
        )
    })?;
    load_snapshot_from_str(&raw, Some(path.to_path_buf()))
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

fn load_snapshot_from_str(raw: &str, path: Option<PathBuf>) -> Result<AdvisorySnapshot, String> {
    let mut snapshot: AdvisorySnapshot = serde_json::from_str(raw).map_err(|error| {
        format!(
            "invalid advisory snapshot {}: {error}",
            snapshot_path_label(path.as_deref())
        )
    })?;
    normalize_snapshot(&mut snapshot);
    validate_snapshot(&snapshot, path.as_deref())?;
    Ok(snapshot)
}

fn validate_snapshot(snapshot: &AdvisorySnapshot, path: Option<&Path>) -> Result<(), String> {
    if snapshot.schema_version != 1 {
        return Err(format!(
            "{} uses unsupported advisory schema version {}; expected 1",
            snapshot_path_label(path),
            snapshot.schema_version
        ));
    }
    if snapshot.ecosystem != "npm" {
        return Err(format!(
            "{} targets unsupported ecosystem `{}`; expected `npm`",
            snapshot_path_label(path),
            snapshot.ecosystem
        ));
    }
    if snapshot.generated_at.trim().is_empty() {
        return Err(format!(
            "{} must include non-empty `generated_at`",
            snapshot_path_label(path)
        ));
    }
    if !is_valid_rfc3339_timestamp(snapshot.generated_at.trim()) {
        return Err(format!(
            "{} must include RFC3339 `generated_at` timestamp",
            snapshot_path_label(path)
        ));
    }
    if snapshot.source.trim().is_empty() {
        return Err(format!(
            "{} must include non-empty `source`",
            snapshot_path_label(path)
        ));
    }
    if snapshot.snapshot_revision.trim().is_empty() {
        return Err(format!(
            "{} must include non-empty `snapshot_revision`",
            snapshot_path_label(path)
        ));
    }

    let mut seen_ids = std::collections::BTreeSet::new();
    for advisory in &snapshot.advisories {
        let advisory_id = advisory.id.trim();
        if advisory_id.is_empty() {
            return Err(format!(
                "{} contains advisory with empty `id`",
                snapshot_path_label(path)
            ));
        }
        if !seen_ids.insert(advisory_id.to_owned()) {
            return Err(format!(
                "{} contains duplicate advisory id `{advisory_id}`",
                snapshot_path_label(path)
            ));
        }
        if advisory.package.trim().is_empty() {
            return Err(format!(
                "{} advisory `{advisory_id}` must include non-empty `package`",
                snapshot_path_label(path)
            ));
        }
        if advisory.summary.trim().is_empty() {
            return Err(format!(
                "{} advisory `{advisory_id}` must include non-empty `summary`",
                snapshot_path_label(path)
            ));
        }
        if advisory.ranges.is_empty() {
            return Err(format!(
                "{} advisory `{advisory_id}` must include at least one affected range",
                snapshot_path_label(path)
            ));
        }
        for range in &advisory.ranges {
            validate_range(range, advisory_id, path)?;
        }
    }
    Ok(())
}

fn validate_range(
    range: &AffectedRange,
    advisory_id: &str,
    path: Option<&Path>,
) -> Result<(), String> {
    let introduced = parse_bound(range.introduced.as_deref()).map_err(|_| {
        format!(
            "{} advisory `{advisory_id}` has invalid `introduced` semver bound",
            snapshot_path_label(path)
        )
    })?;
    let fixed = parse_bound(range.fixed.as_deref()).map_err(|_| {
        format!(
            "{} advisory `{advisory_id}` has invalid `fixed` semver bound",
            snapshot_path_label(path)
        )
    })?;
    if introduced.is_none() && fixed.is_none() {
        return Err(format!(
            "{} advisory `{advisory_id}` contains empty affected range",
            snapshot_path_label(path)
        ));
    }
    if let (Some(introduced), Some(fixed)) = (&introduced, &fixed)
        && introduced >= fixed
    {
        return Err(format!(
            "{} advisory `{advisory_id}` has non-increasing range `{introduced}` -> `{fixed}`",
            snapshot_path_label(path)
        ));
    }
    Ok(())
}

fn snapshot_path_label(path: Option<&Path>) -> String {
    path.map(|path| path.display().to_string())
        .unwrap_or_else(|| "snapshot".to_owned())
}

fn is_valid_rfc3339_timestamp(value: &str) -> bool {
    let Some((date, time_and_zone)) = value.split_once('T') else {
        return false;
    };
    if !is_valid_date(date) {
        return false;
    }

    if let Some(time) = time_and_zone.strip_suffix('Z') {
        return is_valid_time(time);
    }

    let Some(split) = time_and_zone
        .char_indices()
        .rev()
        .find_map(|(idx, ch)| matches!(ch, '+' | '-').then_some(idx))
    else {
        return false;
    };
    let (time, offset) = time_and_zone.split_at(split);
    is_valid_time(time) && is_valid_offset(offset)
}

fn is_valid_date(value: &str) -> bool {
    let mut parts = value.split('-');
    let (Some(year), Some(month), Some(day), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let Some(year) = parse_digits(year, 4) else {
        return false;
    };
    let Some(month) = parse_digits(month, 2) else {
        return false;
    };
    let Some(day) = parse_digits(day, 2) else {
        return false;
    };
    if !(1..=12).contains(&month) {
        return false;
    }
    let max_day = days_in_month(year, month);
    (1..=max_day).contains(&day)
}

fn is_valid_time(value: &str) -> bool {
    let (clock, fractional) = match value.split_once('.') {
        Some((clock, fractional)) => (clock, Some(fractional)),
        None => (value, None),
    };
    let mut parts = clock.split(':');
    let (Some(hour), Some(minute), Some(second), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let Some(hour) = parse_digits(hour, 2) else {
        return false;
    };
    let Some(minute) = parse_digits(minute, 2) else {
        return false;
    };
    let Some(second) = parse_digits(second, 2) else {
        return false;
    };
    if hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    fractional.is_none_or(|fractional| {
        !fractional.is_empty() && fractional.chars().all(|ch| ch.is_ascii_digit())
    })
}

fn is_valid_offset(value: &str) -> bool {
    let sign = value.as_bytes().first().copied();
    if !matches!(sign, Some(b'+') | Some(b'-')) {
        return false;
    }
    let offset = &value[1..];
    let mut parts = offset.split(':');
    let (Some(hour), Some(minute), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let Some(hour) = parse_digits(hour, 2) else {
        return false;
    };
    let Some(minute) = parse_digits(minute, 2) else {
        return false;
    };
    hour <= 23 && minute <= 59
}

fn parse_digits(value: &str, len: usize) -> Option<u32> {
    if value.len() != len || !value.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use semver::Version;

    use super::{AffectedRange, load_snapshot_file, normalize_snapshot_json, range_matches};

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
                  "ranges": [
                    {"introduced": "0.0.0", "fixed": "1.0.0"}
                  ]
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

    #[test]
    fn normalize_snapshot_json_rejects_wrong_ecosystem() {
        let error = normalize_snapshot_json(
            r#"{
              "schema_version": 1,
              "ecosystem": "pypi",
              "generated_at": "2026-04-02T00:00:00Z",
              "source": "test",
              "snapshot_revision": "rev-1",
              "advisories": []
            }"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("unsupported ecosystem"));
    }

    #[test]
    fn load_snapshot_file_accepts_valid_npm_snapshot() {
        let path = temp_file("lintai-dep-vulns-snapshot-valid.json");
        fs::write(
            &path,
            r#"{
              "schema_version": 1,
              "ecosystem": "npm",
              "generated_at": "2026-04-02T00:00:00Z",
              "source": "custom",
              "snapshot_revision": "custom-1",
              "advisories": []
            }"#,
        )
        .unwrap();

        let snapshot = load_snapshot_file(&path).unwrap();
        assert_eq!(snapshot.schema_version, 1);
        assert_eq!(snapshot.ecosystem, "npm");
    }

    #[test]
    fn load_snapshot_file_rejects_wrong_ecosystem() {
        let path = temp_file("lintai-dep-vulns-snapshot-wrong-ecosystem.json");
        fs::write(
            &path,
            r#"{
              "schema_version": 1,
              "ecosystem": "pypi",
              "generated_at": "2026-04-02T00:00:00Z",
              "source": "custom",
              "snapshot_revision": "custom-1",
              "advisories": []
            }"#,
        )
        .unwrap();

        let error = load_snapshot_file(&path).unwrap_err();
        assert!(error.contains("unsupported ecosystem"));
    }

    #[test]
    fn load_snapshot_file_rejects_wrong_schema_version() {
        let path = temp_file("lintai-dep-vulns-snapshot-wrong-schema.json");
        fs::write(
            &path,
            r#"{
              "schema_version": 2,
              "ecosystem": "npm",
              "generated_at": "2026-04-02T00:00:00Z",
              "source": "custom",
              "snapshot_revision": "custom-1",
              "advisories": []
            }"#,
        )
        .unwrap();

        let error = load_snapshot_file(&path).unwrap_err();
        assert!(error.contains("unsupported advisory schema version"));
    }

    #[test]
    fn normalize_snapshot_json_rejects_invalid_semver_bounds() {
        let error = normalize_snapshot_json(
            r#"{
              "schema_version": 1,
              "ecosystem": "npm",
              "generated_at": "2026-04-02T00:00:00Z",
              "source": "test",
              "snapshot_revision": "rev-1",
              "advisories": [
                {
                  "id": "BAD-1",
                  "package": "demo",
                  "summary": "demo",
                  "references": [],
                  "aliases": [],
                  "ranges": [{"introduced": "not-a-version", "fixed": "1.0.0"}]
                }
              ]
            }"#,
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("invalid `introduced` semver bound")
        );
    }

    #[test]
    fn normalize_snapshot_json_rejects_duplicate_advisory_ids() {
        let error = normalize_snapshot_json(
            r#"{
              "schema_version": 1,
              "ecosystem": "npm",
              "generated_at": "2026-04-02T00:00:00Z",
              "source": "test",
              "snapshot_revision": "rev-1",
              "advisories": [
                {
                  "id": "DUP-1",
                  "package": "demo-a",
                  "summary": "demo",
                  "references": [],
                  "aliases": [],
                  "ranges": [{"introduced": "0.0.0", "fixed": "1.0.0"}]
                },
                {
                  "id": "DUP-1",
                  "package": "demo-b",
                  "summary": "demo",
                  "references": [],
                  "aliases": [],
                  "ranges": [{"introduced": "0.0.0", "fixed": "1.0.0"}]
                }
              ]
            }"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("duplicate advisory id"));
    }

    #[test]
    fn normalize_snapshot_json_rejects_empty_range() {
        let error = normalize_snapshot_json(
            r#"{
              "schema_version": 1,
              "ecosystem": "npm",
              "generated_at": "2026-04-02T00:00:00Z",
              "source": "test",
              "snapshot_revision": "rev-1",
              "advisories": [
                {
                  "id": "EMPTY-RANGE-1",
                  "package": "demo",
                  "summary": "demo",
                  "references": [],
                  "aliases": [],
                  "ranges": [{"introduced": null, "fixed": null}]
                }
              ]
            }"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("contains empty affected range"));
    }

    #[test]
    fn normalize_snapshot_json_rejects_empty_generated_at() {
        let error = normalize_snapshot_json(
            r#"{
              "schema_version": 1,
              "ecosystem": "npm",
              "generated_at": "   ",
              "source": "test",
              "snapshot_revision": "rev-1",
              "advisories": []
            }"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("non-empty `generated_at`"));
    }

    #[test]
    fn normalize_snapshot_json_rejects_invalid_generated_at_timestamp() {
        let error = normalize_snapshot_json(
            r#"{
              "schema_version": 1,
              "ecosystem": "npm",
              "generated_at": "2026-99-99T25:61:61Z",
              "source": "test",
              "snapshot_revision": "rev-1",
              "advisories": []
            }"#,
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("RFC3339 `generated_at` timestamp")
        );
    }

    #[test]
    fn normalize_snapshot_json_rejects_empty_source() {
        let error = normalize_snapshot_json(
            r#"{
              "schema_version": 1,
              "ecosystem": "npm",
              "generated_at": "2026-04-02T00:00:00Z",
              "source": "   ",
              "snapshot_revision": "rev-1",
              "advisories": []
            }"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("non-empty `source`"));
    }

    #[test]
    fn normalize_snapshot_json_rejects_empty_snapshot_revision() {
        let error = normalize_snapshot_json(
            r#"{
              "schema_version": 1,
              "ecosystem": "npm",
              "generated_at": "2026-04-02T00:00:00Z",
              "source": "test",
              "snapshot_revision": "   ",
              "advisories": []
            }"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("non-empty `snapshot_revision`"));
    }

    fn temp_file(name: &str) -> std::path::PathBuf {
        let unique = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::env::temp_dir().join(format!("{name}-{unique}"))
    }
}
