#[path = "text/common.rs"]
mod common;
#[path = "text/discovery.rs"]
mod discovery;
#[path = "text/inventory.rs"]
mod inventory;
#[path = "text/policy.rs"]
mod policy;
#[path = "text/scan.rs"]
mod scan;

use super::model::ReportEnvelope;

pub(crate) fn format_text(report: &ReportEnvelope<'_>) -> String {
    let mut output = String::new();

    if report.policy_stats.is_some() {
        policy::append_policy_sections(&mut output, report);
    } else if report.inventory_diff.is_some() || report.inventory_stats.is_some() {
        inventory::append_inventory_summary(&mut output, report);
    } else if report.discovery_stats.is_some() {
        discovery::append_discovery_summary(&mut output, report);
    } else {
        scan::append_default_summary(&mut output, report);
    }

    discovery::append_discovered_roots(&mut output, report);
    inventory::append_inventory_sections(&mut output, report);
    scan::append_scan_results(&mut output, report);
    output
}
