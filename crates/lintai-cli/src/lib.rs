use std::process::ExitCode;

mod app;
mod args;
mod builtin_providers;
mod commands;
#[cfg(test)]
mod compat_tests;
mod execution;
#[path = "external_validation/mod.rs"]
mod external_validation;
mod internal_bin;
#[path = "known_scan/mod.rs"]
mod known_scan;
mod output;
mod path;
mod policy_os;
#[cfg(test)]
mod sample_repo_tests;
mod security_rule_catalog;
mod shipped_rules;
mod site_catalog;

pub fn run_cli() -> Result<ExitCode, String> {
    app::run()
}

pub fn run_external_validation_cli(args: impl Iterator<Item = String>) -> Result<(), String> {
    external_validation::run(args)
}

pub fn render_security_rules_catalog() -> String {
    security_rule_catalog::render_security_rules_markdown()
}

pub fn render_site_catalog_json() -> String {
    site_catalog::render_site_catalog_json()
}
