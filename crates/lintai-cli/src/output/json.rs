use super::model::ReportEnvelope;

pub(crate) fn format_json(report: &ReportEnvelope<'_>) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}
