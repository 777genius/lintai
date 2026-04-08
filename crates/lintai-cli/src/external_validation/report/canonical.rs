use std::collections::BTreeMap;
use std::path::Path;

use crate::external_validation::*;

#[path = "canonical/cohort.rs"]
mod cohort;
#[path = "canonical/rules.rs"]
mod rules;
#[path = "canonical/surfaces.rs"]
mod surfaces;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReviewedRecommendedHit {
    pub(crate) repo: String,
    pub(crate) rule_code: String,
    pub(crate) normalized_path: String,
    pub(crate) verdict: AdjudicationVerdict,
    pub(crate) summary: String,
    pub(crate) reason: String,
    pub(crate) problem: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RecommendedPrecisionReview {
    pub(crate) unadjudicated: Vec<(String, ObservedFindingRecord)>,
    pub(crate) reviewed: Vec<ReviewedRecommendedHit>,
    pub(crate) false_positive_hits: Vec<ReviewedRecommendedHit>,
    pub(crate) stale_adjudications: Vec<(String, RecommendedStableAdjudication)>,
    pub(crate) invalid_adjudications: Vec<(String, String)>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct OwnershipCounts {
    pub(crate) official: usize,
    pub(crate) community: usize,
}

struct CanonicalReportContext {
    baseline_counts: AggregateCounts,
    current_counts: AggregateCounts,
    recommended_counts: LaneAggregateCounts,
    supply_chain_counts: LaneAggregateCounts,
    remaining_lane_counts: Vec<(String, LaneAggregateCounts)>,
    ownership_counts: OwnershipCounts,
    recommended_hits_by_ownership: OwnershipCounts,
    zero_hit_coverage_by_ownership: OwnershipCounts,
    precision_review: RecommendedPrecisionReview,
    verdict_changes: Vec<RepoVerdictChange>,
    fp_clusters: Vec<(String, usize)>,
    fn_clusters: Vec<(String, usize)>,
    preview_signal_repos: Vec<(String, usize, Vec<String>)>,
    datadog_status: PhaseTargetStatus,
    cursor_plugins_status: PhaseTargetStatus,
    emmraan_status: PhaseTargetStatus,
}

impl CanonicalReportContext {
    fn from_ledgers(
        baseline: &ExternalValidationLedger,
        current: &ExternalValidationLedger,
    ) -> Self {
        Self {
            baseline_counts: aggregate_counts(baseline),
            current_counts: aggregate_counts(current),
            recommended_counts: aggregate_lane_counts(current, "recommended"),
            supply_chain_counts: aggregate_lane_counts(current, "supply-chain"),
            remaining_lane_counts: aggregate_remaining_lane_counts(
                current,
                &["recommended", "supply-chain"],
            ),
            ownership_counts: aggregate_ownership_counts(current),
            recommended_hits_by_ownership: aggregate_recommended_hits_by_ownership(current),
            zero_hit_coverage_by_ownership: aggregate_zero_hit_coverage_by_ownership(current),
            precision_review: recommended_precision_review(current),
            verdict_changes: repo_verdict_changes(baseline, current),
            fp_clusters: top_clusters(current, ClusterKind::FalsePositive),
            fn_clusters: top_clusters(current, ClusterKind::FalseNegative),
            preview_signal_repos: preview_signal_repos(current),
            datadog_status: phase_target_status(
                baseline,
                current,
                "datadog-labs/cursor-plugin",
                PhaseTargetKind::DatadogSec105,
            ),
            cursor_plugins_status: phase_target_status(
                baseline,
                current,
                "cursor/plugins",
                PhaseTargetKind::InvalidYamlRecovery,
            ),
            emmraan_status: phase_target_status(
                baseline,
                current,
                "Emmraan/agent-skills",
                PhaseTargetKind::InvalidYamlRecovery,
            ),
        }
    }
}

pub(crate) fn render_report_from_ledgers(
    workspace_root: &Path,
    baseline: &ExternalValidationLedger,
    current: &ExternalValidationLedger,
) -> String {
    let context = CanonicalReportContext::from_ledgers(baseline, current);

    let mut output = String::new();
    cohort::append_header_and_cohort(&mut output, current);
    cohort::append_overall_counts(&mut output, current, &context.current_counts);
    cohort::append_lane_counts(
        &mut output,
        context.recommended_counts,
        context.supply_chain_counts,
        &context.remaining_lane_counts,
        context.ownership_counts,
        context.recommended_hits_by_ownership,
        context.zero_hit_coverage_by_ownership,
    );
    surfaces::append_hybrid_scope_expansion(&mut output, workspace_root, current);
    cohort::append_delta_and_precision_summary(
        &mut output,
        &context.baseline_counts,
        &context.current_counts,
        &context.verdict_changes,
        &context.precision_review,
    );
    cohort::append_recommended_hit_review(
        &mut output,
        context.recommended_counts,
        &context.precision_review,
    );
    cohort::append_preview_runtime_and_recommendation(
        &mut output,
        cohort::PreviewRecommendationArgs {
            datadog_status: context.datadog_status,
            cursor_plugins_status: context.cursor_plugins_status,
            emmraan_status: context.emmraan_status,
            preview_signal_repos: context.preview_signal_repos,
            fp_clusters: &context.fp_clusters,
            fn_clusters: &context.fn_clusters,
            precision_review: &context.precision_review,
            preview_findings: context.current_counts.preview_findings,
            cohort_size: current.evaluations.len(),
            ownership_counts: context.ownership_counts,
        },
    );
    output
}

fn aggregate_ownership_counts(current: &ExternalValidationLedger) -> OwnershipCounts {
    let counts = ownership_counts(current);
    OwnershipCounts {
        official: counts.get("official").copied().unwrap_or(0),
        community: counts.get("community").copied().unwrap_or(0),
    }
}

fn aggregate_recommended_hits_by_ownership(current: &ExternalValidationLedger) -> OwnershipCounts {
    let mut counts = OwnershipCounts::default();
    for entry in &current.evaluations {
        match entry.ownership.as_str() {
            "official" => counts.official += entry.recommended_stable_hits.len(),
            _ => counts.community += entry.recommended_stable_hits.len(),
        }
    }
    counts
}

fn aggregate_zero_hit_coverage_by_ownership(current: &ExternalValidationLedger) -> OwnershipCounts {
    let mut counts = OwnershipCounts::default();
    for entry in &current.evaluations {
        if !entry.recommended_stable_hits.is_empty() {
            continue;
        }
        match entry.ownership.as_str() {
            "official" => counts.official += 1,
            _ => counts.community += 1,
        }
    }
    counts
}

pub(crate) fn validate_canonical_precision_contract(
    current: &ExternalValidationLedger,
) -> Result<(), String> {
    let review = recommended_precision_review(current);
    let mut problems = Vec::new();

    for (repo, adjudication) in &review.stale_adjudications {
        problems.push(format!(
            "{repo}: stale recommended adjudication for `{}` at `{}`",
            adjudication.rule_code, adjudication.stable_key.normalized_path
        ));
    }
    for (repo, problem) in &review.invalid_adjudications {
        problems.push(format!("{repo}: {problem}"));
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "canonical external validation precision contract failed:\n- {}",
            problems.join("\n- ")
        ))
    }
}

pub(crate) fn recommended_precision_review(
    current: &ExternalValidationLedger,
) -> RecommendedPrecisionReview {
    let mut review = RecommendedPrecisionReview::default();

    for entry in &current.evaluations {
        let observed = entry
            .recommended_stable_hits
            .iter()
            .map(|hit| (stable_key_fingerprint(&hit.stable_key), hit))
            .collect::<BTreeMap<_, _>>();
        let mut adjudicated = BTreeMap::<String, &RecommendedStableAdjudication>::new();

        for adjudication in &entry.recommended_stable_adjudications {
            let fingerprint = stable_key_fingerprint(&adjudication.stable_key);
            if adjudication.rule_code != adjudication.stable_key.rule_code {
                review.invalid_adjudications.push((
                    entry.repo.clone(),
                    format!(
                        "recommended adjudication rule code `{}` did not match stable key rule code `{}`",
                        adjudication.rule_code, adjudication.stable_key.rule_code
                    ),
                ));
                continue;
            }
            if matches!(
                adjudication.verdict,
                AdjudicationVerdict::AcceptedHardeningHit
            ) {
                review.invalid_adjudications.push((
                    entry.repo.clone(),
                    format!(
                        "recommended stable hit `{}` cannot use `accepted_hardening_hit`",
                        adjudication.rule_code
                    ),
                ));
                continue;
            }
            if adjudicated
                .insert(fingerprint.clone(), adjudication)
                .is_some()
            {
                review.invalid_adjudications.push((
                    entry.repo.clone(),
                    format!(
                        "duplicate recommended adjudication for `{}` at `{}`",
                        adjudication.rule_code, adjudication.stable_key.normalized_path
                    ),
                ));
                continue;
            }
            let Some(observed_hit) = observed.get(&fingerprint) else {
                review
                    .stale_adjudications
                    .push((entry.repo.clone(), adjudication.clone()));
                continue;
            };
            if observed_hit.rule_code != adjudication.rule_code {
                review.invalid_adjudications.push((
                    entry.repo.clone(),
                    format!(
                        "recommended adjudication for `{}` did not match observed rule `{}`",
                        adjudication.rule_code, observed_hit.rule_code
                    ),
                ));
                continue;
            }

            let reviewed_hit = ReviewedRecommendedHit {
                repo: entry.repo.clone(),
                rule_code: adjudication.rule_code.clone(),
                normalized_path: observed_hit.normalized_path.clone(),
                verdict: adjudication.verdict.clone(),
                summary: adjudication.summary.clone(),
                reason: adjudication.reason.clone(),
                problem: adjudication.problem.clone(),
            };
            if matches!(reviewed_hit.verdict, AdjudicationVerdict::FalsePositive) {
                review.false_positive_hits.push(reviewed_hit.clone());
            }
            review.reviewed.push(reviewed_hit);
        }

        for hit in &entry.recommended_stable_hits {
            let fingerprint = stable_key_fingerprint(&hit.stable_key);
            if !adjudicated.contains_key(&fingerprint) {
                review.unadjudicated.push((entry.repo.clone(), hit.clone()));
            }
        }
    }

    review.reviewed.sort_by(|left, right| {
        left.repo
            .cmp(&right.repo)
            .then_with(|| left.rule_code.cmp(&right.rule_code))
            .then_with(|| left.normalized_path.cmp(&right.normalized_path))
    });
    review.false_positive_hits.sort_by(|left, right| {
        left.repo
            .cmp(&right.repo)
            .then_with(|| left.rule_code.cmp(&right.rule_code))
            .then_with(|| left.normalized_path.cmp(&right.normalized_path))
    });
    review.unadjudicated.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.rule_code.cmp(&right.1.rule_code))
            .then_with(|| left.1.normalized_path.cmp(&right.1.normalized_path))
    });
    review.stale_adjudications.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.rule_code.cmp(&right.1.rule_code))
            .then_with(|| {
                left.1
                    .stable_key
                    .normalized_path
                    .cmp(&right.1.stable_key.normalized_path)
            })
    });
    review
        .invalid_adjudications
        .sort_by(|left, right| left.0.cmp(&right.0));
    review
}
