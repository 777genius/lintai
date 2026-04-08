use std::collections::{BTreeMap, BTreeSet};

use lintai_api::{
    Evidence, EvidenceKind, Finding, JsonSemantics, Location, ProviderError, ProviderScanResult,
    WorkspaceArtifact, WorkspaceRuleProvider, WorkspaceScanContext, YamlSemantics,
};
use semver::Version;
use serde_json::{Value, json};

use crate::catalog::InstalledVulnerableDependencyRule;
use crate::snapshot::{advisory_matches_version, snapshot};

pub const PROVIDER_ID: &str = "lintai-dep-vulns";

pub struct DependencyVulnProvider;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct PackageInstance {
    normalized_path: String,
    package: String,
    version: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MatchOccurrence {
    normalized_path: String,
    location: Location,
}

struct AggregatedMatch<'a> {
    package: String,
    version: String,
    advisory: &'a crate::snapshot::Advisory,
    occurrences: Vec<MatchOccurrence>,
}

impl WorkspaceRuleProvider for DependencyVulnProvider {
    fn id(&self) -> &str {
        PROVIDER_ID
    }

    fn rules(&self) -> &[lintai_api::RuleMetadata] {
        &[InstalledVulnerableDependencyRule::METADATA]
    }

    fn check_workspace_result(&self, ctx: &WorkspaceScanContext) -> ProviderScanResult {
        if let Some(active_rule_codes) = ctx.active_rule_codes.as_ref()
            && !active_rule_codes.contains(InstalledVulnerableDependencyRule::METADATA.code)
        {
            return ProviderScanResult::new(Vec::new(), Vec::new());
        }

        let snapshot = match snapshot() {
            Ok(snapshot) => snapshot,
            Err(message) => {
                return ProviderScanResult::new(
                    Vec::new(),
                    vec![ProviderError::new(PROVIDER_ID, message)],
                );
            }
        };
        let snapshot = snapshot.as_snapshot();
        let advisories_by_package = advisory_map(snapshot);
        let mut matched = BTreeMap::new();
        let mut errors = Vec::new();
        let mut seen_errors = BTreeSet::new();

        for artifact in &ctx.artifacts {
            collect_lockfile_validation_errors(
                &mut errors,
                &mut seen_errors,
                artifact,
                &advisories_by_package,
            );
            for instance in extract_package_instances(artifact) {
                let Some(advisories) = advisories_by_package.get(instance.package.as_str()) else {
                    continue;
                };
                let Ok(version) = Version::parse(&instance.version) else {
                    record_invalid_version_error(
                        &mut errors,
                        &mut seen_errors,
                        &instance.normalized_path,
                        &instance.package,
                        &instance.version,
                    );
                    continue;
                };

                for advisory in advisories {
                    if !advisory_matches_version(advisory, &version) {
                        continue;
                    }
                    record_match(&mut matched, artifact, &instance, advisory);
                }
            }
        }

        let findings = matched
            .into_values()
            .map(|matched| {
                vulnerability_finding(
                    &matched,
                    snapshot.schema_version,
                    snapshot.ecosystem.as_str(),
                    snapshot.generated_at.as_str(),
                    snapshot.source.as_str(),
                    snapshot.snapshot_revision.as_str(),
                )
            })
            .collect();

        ProviderScanResult::new(findings, errors)
    }
}

fn collect_lockfile_validation_errors(
    errors: &mut Vec<ProviderError>,
    seen_errors: &mut BTreeSet<(String, String, String)>,
    artifact: &WorkspaceArtifact,
    advisories_by_package: &BTreeMap<&str, Vec<&crate::snapshot::Advisory>>,
) {
    match artifact.artifact.kind {
        lintai_api::ArtifactKind::NpmPackageLock | lintai_api::ArtifactKind::NpmShrinkwrap => {
            collect_npm_lock_validation_errors(errors, seen_errors, artifact, advisories_by_package)
        }
        lintai_api::ArtifactKind::PnpmLock => collect_pnpm_lock_validation_errors(
            errors,
            seen_errors,
            artifact,
            advisories_by_package,
        ),
        _ => {}
    }
}

fn advisory_map(
    snapshot: &crate::snapshot::AdvisorySnapshot,
) -> BTreeMap<&str, Vec<&crate::snapshot::Advisory>> {
    let mut map = BTreeMap::new();
    for advisory in &snapshot.advisories {
        map.entry(advisory.package.as_str())
            .or_insert_with(Vec::new)
            .push(advisory);
    }
    map
}

fn record_match<'a>(
    matched: &mut BTreeMap<String, AggregatedMatch<'a>>,
    artifact: &WorkspaceArtifact,
    instance: &PackageInstance,
    advisory: &'a crate::snapshot::Advisory,
) {
    let subject_id = format!("{}@{}:{}", instance.package, instance.version, advisory.id);
    let location = artifact.location_hint.clone().unwrap_or_else(|| {
        Location::new(
            artifact.artifact.normalized_path.clone(),
            lintai_api::Span::new(0, artifact.content.len()),
        )
    });
    let occurrence = MatchOccurrence {
        normalized_path: instance.normalized_path.clone(),
        location,
    };

    let entry = matched
        .entry(subject_id)
        .or_insert_with(|| AggregatedMatch {
            package: instance.package.clone(),
            version: instance.version.clone(),
            advisory,
            occurrences: Vec::new(),
        });
    if !entry.occurrences.contains(&occurrence) {
        entry.occurrences.push(occurrence);
        entry
            .occurrences
            .sort_by(|left, right| left.normalized_path.cmp(&right.normalized_path));
    }
}

fn record_invalid_version_error(
    errors: &mut Vec<ProviderError>,
    seen_errors: &mut BTreeSet<(String, String, String)>,
    normalized_path: &str,
    package: &str,
    version: &str,
) {
    let key = (
        normalized_path.to_owned(),
        package.to_owned(),
        version.to_owned(),
    );
    if !seen_errors.insert(key) {
        return;
    }
    errors.push(ProviderError::new(
        PROVIDER_ID,
        format!(
            "cannot evaluate advisory coverage for package `{package}` in `{normalized_path}` because installed version `{version}` is not valid semver"
        ),
    ));
}

fn record_missing_version_error(
    errors: &mut Vec<ProviderError>,
    seen_errors: &mut BTreeSet<(String, String, String)>,
    normalized_path: &str,
    package: &str,
) {
    let key = (
        normalized_path.to_owned(),
        package.to_owned(),
        "<missing>".to_owned(),
    );
    if !seen_errors.insert(key) {
        return;
    }
    errors.push(ProviderError::new(
        PROVIDER_ID,
        format!(
            "cannot evaluate advisory coverage for package `{package}` in `{normalized_path}` because the lockfile entry is missing a valid installed version"
        ),
    ));
}

fn collect_npm_lock_validation_errors(
    errors: &mut Vec<ProviderError>,
    seen_errors: &mut BTreeSet<(String, String, String)>,
    artifact: &WorkspaceArtifact,
    advisories_by_package: &BTreeMap<&str, Vec<&crate::snapshot::Advisory>>,
) {
    let Some(semantics) = artifact.semantics.as_ref() else {
        return;
    };
    let Some(JsonSemantics { value, .. }) = semantics.as_json() else {
        return;
    };

    if let Some(entries) = value.get("packages").and_then(Value::as_object) {
        for (path, package_value) in entries {
            let Some(object) = package_value.as_object() else {
                continue;
            };
            let name = object
                .get("name")
                .and_then(Value::as_str)
                .or_else(|| infer_package_name_from_npm_package_path(path));
            let Some(name) = name.map(str::trim).filter(|value| !value.is_empty()) else {
                continue;
            };
            if !advisories_by_package.contains_key(name) {
                continue;
            }
            let version = object
                .get("version")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if version.is_none() {
                record_missing_version_error(
                    errors,
                    seen_errors,
                    &artifact.artifact.normalized_path,
                    name,
                );
            }
        }
    }

    if let Some(entries) = value.get("dependencies").and_then(Value::as_object) {
        collect_legacy_npm_dependency_validation_errors(
            errors,
            seen_errors,
            artifact,
            advisories_by_package,
            entries,
        );
    }
}

fn collect_legacy_npm_dependency_validation_errors(
    errors: &mut Vec<ProviderError>,
    seen_errors: &mut BTreeSet<(String, String, String)>,
    artifact: &WorkspaceArtifact,
    advisories_by_package: &BTreeMap<&str, Vec<&crate::snapshot::Advisory>>,
    deps: &serde_json::Map<String, Value>,
) {
    for (name, value) in deps {
        let Some(object) = value.as_object() else {
            continue;
        };
        if advisories_by_package.contains_key(name.as_str()) {
            let version = object
                .get("version")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if version.is_none() {
                record_missing_version_error(
                    errors,
                    seen_errors,
                    &artifact.artifact.normalized_path,
                    name,
                );
            }
        }
        if let Some(nested) = object.get("dependencies").and_then(Value::as_object) {
            collect_legacy_npm_dependency_validation_errors(
                errors,
                seen_errors,
                artifact,
                advisories_by_package,
                nested,
            );
        }
    }
}

fn collect_pnpm_lock_validation_errors(
    errors: &mut Vec<ProviderError>,
    seen_errors: &mut BTreeSet<(String, String, String)>,
    artifact: &WorkspaceArtifact,
    advisories_by_package: &BTreeMap<&str, Vec<&crate::snapshot::Advisory>>,
) {
    let Some(semantics) = artifact.semantics.as_ref() else {
        return;
    };
    let Some(YamlSemantics { value, .. }) = semantics.as_yaml() else {
        return;
    };
    let Some(entries) = value.get("packages").and_then(Value::as_object) else {
        return;
    };

    for key in entries.keys() {
        if parse_pnpm_package_key(key).is_some() {
            continue;
        }
        let Some(package) = infer_pnpm_package_name(key) else {
            continue;
        };
        if advisories_by_package.contains_key(package.as_str()) {
            record_missing_version_error(
                errors,
                seen_errors,
                &artifact.artifact.normalized_path,
                &package,
            );
        }
    }
}

fn vulnerability_finding(
    matched: &AggregatedMatch<'_>,
    schema_version: u32,
    ecosystem: &str,
    generated_at: &str,
    source: &str,
    snapshot_revision: &str,
) -> Finding {
    let advisory = matched.advisory;
    let fixed_versions = advisory
        .ranges
        .iter()
        .filter_map(|range| range.fixed.as_deref())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let affected_ranges = advisory
        .ranges
        .iter()
        .map(|range| {
            json!({
                "introduced": range.introduced,
                "fixed": range.fixed,
            })
        })
        .collect::<Vec<_>>();
    let affected_paths = matched
        .occurrences
        .iter()
        .map(|occurrence| occurrence.normalized_path.clone())
        .collect::<Vec<_>>();
    let remediation = if fixed_versions.is_empty() {
        "review the advisory and upgrade to a non-affected release".to_owned()
    } else {
        format!(
            "upgrade `{}` to a non-affected release such as `{}`",
            matched.package,
            fixed_versions.join("`, `")
        )
    };
    let location = matched
        .occurrences
        .first()
        .expect("aggregated vulnerability match should have at least one occurrence")
        .location
        .clone();
    let mut finding = Finding::new(
        &InstalledVulnerableDependencyRule::METADATA,
        location.clone(),
        format!(
            "installed `{}` version `{}` matches advisory `{}`",
            matched.package, matched.version, advisory.id
        ),
    )
    .with_tag("dependency-vuln")
    .with_tag("npm")
    .with_suggestion(lintai_api::Suggestion::new(remediation, None))
    .with_metadata(json!({
        "ecosystem": ecosystem,
        "package": matched.package,
        "installed_version": matched.version,
        "advisory_id": advisory.id,
        "aliases": advisory.aliases,
        "references": advisory.references,
        "fixed_versions": fixed_versions.clone(),
        "affected_ranges": affected_ranges.clone(),
        "affected_paths": affected_paths,
        "snapshot_schema_version": schema_version,
        "snapshot_generated_at": generated_at,
        "snapshot_source": source,
        "snapshot_revision": snapshot_revision,
    }));
    let subject_id = format!("{}@{}:{}", matched.package, matched.version, advisory.id);
    finding.stable_key.subject_id = Some(subject_id.clone());
    finding.evidence.clear();
    for (index, occurrence) in matched.occurrences.iter().enumerate() {
        finding.evidence.push(
            Evidence::new(
                EvidenceKind::ObservedBehavior,
                format!(
                    "lockfile records installed package `{}` at version `{}`",
                    matched.package, matched.version
                ),
                if index == 0 {
                    Some(occurrence.location.clone())
                } else {
                    None
                },
            )
            .with_subject_id(subject_id.clone())
            .with_metadata(json!({
                "package": matched.package,
                "version": matched.version,
                "path": occurrence.normalized_path,
            })),
        );
    }
    finding.evidence.push(
        Evidence::new(
            EvidenceKind::Claim,
            format!(
                "advisory `{}` from snapshot `{}` marks this version as affected",
                advisory.id, snapshot_revision
            ),
            None,
        )
        .with_subject_id(subject_id)
        .with_metadata(json!({
            "advisory_id": advisory.id,
            "aliases": advisory.aliases,
            "summary": advisory.summary,
            "references": advisory.references,
            "fixed_versions": fixed_versions,
            "affected_ranges": affected_ranges,
            "snapshot_source": source,
            "snapshot_revision": snapshot_revision,
        })),
    );
    finding
}

fn extract_package_instances(artifact: &WorkspaceArtifact) -> Vec<PackageInstance> {
    match artifact.artifact.kind {
        lintai_api::ArtifactKind::NpmPackageLock | lintai_api::ArtifactKind::NpmShrinkwrap => {
            extract_npm_lock_instances(artifact)
        }
        lintai_api::ArtifactKind::PnpmLock => extract_pnpm_lock_instances(artifact),
        _ => Vec::new(),
    }
}

fn extract_npm_lock_instances(artifact: &WorkspaceArtifact) -> Vec<PackageInstance> {
    let Some(semantics) = artifact.semantics.as_ref() else {
        return Vec::new();
    };
    let Some(JsonSemantics { value, .. }) = semantics.as_json() else {
        return Vec::new();
    };
    let mut seen = BTreeSet::new();
    let mut packages = Vec::new();

    if let Some(entries) = value.get("packages").and_then(Value::as_object) {
        for (path, package_value) in entries {
            let Some(object) = package_value.as_object() else {
                continue;
            };
            let version = object
                .get("version")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let name = object
                .get("name")
                .and_then(Value::as_str)
                .or_else(|| infer_package_name_from_npm_package_path(path));
            let (Some(name), Some(version)) = (name, version) else {
                continue;
            };
            push_package_instance(&mut packages, &mut seen, artifact, name, version);
        }
        if !packages.is_empty() {
            return packages;
        }
    }

    if let Some(entries) = value.get("dependencies").and_then(Value::as_object) {
        walk_legacy_npm_dependencies(entries, artifact, &mut packages, &mut seen);
    }

    packages
}

fn walk_legacy_npm_dependencies(
    deps: &serde_json::Map<String, Value>,
    artifact: &WorkspaceArtifact,
    packages: &mut Vec<PackageInstance>,
    seen: &mut BTreeSet<(String, String, String)>,
) {
    for (name, value) in deps {
        let Some(object) = value.as_object() else {
            continue;
        };
        if let Some(version) = object.get("version").and_then(Value::as_str) {
            push_package_instance(packages, seen, artifact, name, version.trim());
        }
        if let Some(nested) = object.get("dependencies").and_then(Value::as_object) {
            walk_legacy_npm_dependencies(nested, artifact, packages, seen);
        }
    }
}

fn infer_package_name_from_npm_package_path(path: &str) -> Option<&str> {
    let tail = path.rsplit("node_modules/").next()?;
    let trimmed = tail.trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed)
}

fn extract_pnpm_lock_instances(artifact: &WorkspaceArtifact) -> Vec<PackageInstance> {
    let Some(semantics) = artifact.semantics.as_ref() else {
        return Vec::new();
    };
    let Some(YamlSemantics { value, .. }) = semantics.as_yaml() else {
        return Vec::new();
    };
    let mut packages = Vec::new();
    let mut seen = BTreeSet::new();
    let Some(entries) = value.get("packages").and_then(Value::as_object) else {
        return packages;
    };

    for key in entries.keys() {
        let Some((name, version)) = parse_pnpm_package_key(key) else {
            continue;
        };
        push_package_instance(&mut packages, &mut seen, artifact, &name, &version);
    }

    packages
}

fn parse_pnpm_package_key(key: &str) -> Option<(String, String)> {
    let trimmed = key.trim_start_matches('/');
    let trimmed = trimmed.split('(').next()?.trim();
    let split = trimmed.rfind('@')?;
    if split == 0 {
        return None;
    }
    let (name, version) = trimmed.split_at(split);
    let version = version.trim_start_matches('@').trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_owned(), version.to_owned()))
}

fn infer_pnpm_package_name(key: &str) -> Option<String> {
    let trimmed = key.trim_start_matches('/');
    let trimmed = trimmed.split('(').next()?.trim();
    let split = trimmed.rfind('@')?;
    if split == 0 {
        return None;
    }
    let (name, _) = trimmed.split_at(split);
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    Some(name.to_owned())
}

fn push_package_instance(
    packages: &mut Vec<PackageInstance>,
    seen: &mut BTreeSet<(String, String, String)>,
    artifact: &WorkspaceArtifact,
    package: &str,
    version: &str,
) {
    if package.is_empty() || version.is_empty() {
        return;
    }
    let key = (
        artifact.artifact.normalized_path.clone(),
        package.to_owned(),
        version.to_owned(),
    );
    if !seen.insert(key) {
        return;
    }
    packages.push(PackageInstance {
        normalized_path: artifact.artifact.normalized_path.clone(),
        package: package.to_owned(),
        version: version.to_owned(),
    });
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use lintai_api::{
        Artifact, ArtifactKind, CapabilityConflictMode, ParsedDocument, SourceFormat,
        WorkspaceArtifact, WorkspaceRuleProvider, WorkspaceScanContext,
    };

    use super::DependencyVulnProvider;

    #[test]
    fn workspace_check_skips_when_advisory_rule_is_inactive() {
        let result = WorkspaceRuleProvider::check_workspace_result(
            &DependencyVulnProvider,
            &WorkspaceScanContext::new(
                Some("repo".to_owned()),
                vec![WorkspaceArtifact::new(
                    Artifact::new(
                        "package-lock.json",
                        ArtifactKind::NpmPackageLock,
                        SourceFormat::Json,
                    ),
                    "{}",
                    ParsedDocument::new(Vec::new(), None),
                    None,
                )],
                None,
                CapabilityConflictMode::Warn,
            )
            .with_active_rule_codes(BTreeSet::from(["SEC101".to_owned()])),
        );

        assert!(result.errors.is_empty());
        assert!(result.findings.is_empty());
    }
}
