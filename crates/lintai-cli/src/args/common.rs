use std::iter::Peekable;

use lintai_engine::OutputFormat;

use crate::known_scan::{InventoryOsScope, KnownScope};

pub(super) fn next_flag_value<I>(
    flag: &str,
    arg: &str,
    args: &mut Peekable<I>,
) -> Result<Option<String>, String>
where
    I: Iterator<Item = String>,
{
    if arg == flag {
        return args
            .next()
            .map(Some)
            .ok_or_else(|| format!("missing value for {flag}"));
    }

    let inline_prefix = format!("{flag}=");
    Ok(arg
        .strip_prefix(&inline_prefix)
        .map(std::borrow::ToOwned::to_owned))
}

pub(super) fn parse_output_format(value: &str) -> Result<OutputFormat, String> {
    match value {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        "sarif" => Ok(OutputFormat::Sarif),
        other => Err(format!("unsupported output format: {other}")),
    }
}

pub(super) fn parse_known_scope(value: &str) -> Result<KnownScope, String> {
    match value {
        "project" => Ok(KnownScope::Project),
        "global" => Ok(KnownScope::Global),
        "both" => Ok(KnownScope::Both),
        other => Err(format!("unsupported --scope value: {other}")),
    }
}

pub(super) fn parse_inventory_scope(value: &str) -> Result<InventoryOsScope, String> {
    match value {
        "user" => Ok(InventoryOsScope::User),
        "system" => Ok(InventoryOsScope::System),
        "both" => Ok(InventoryOsScope::Both),
        other => Err(format!("unsupported --scope value: {other}")),
    }
}

pub(super) fn normalize_client_filter(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

pub(super) fn push_preset_id(target: &mut Vec<String>, value: &str) {
    let preset_id = value.trim();
    if preset_id.is_empty() {
        return;
    }
    target.push(preset_id.to_owned());
}

pub(super) fn unknown_flag(value: &str) -> String {
    format!("unknown flag: {value}")
}

pub(super) fn unexpected_extra_argument(value: &str) -> String {
    format!("unexpected extra argument: {value}")
}
