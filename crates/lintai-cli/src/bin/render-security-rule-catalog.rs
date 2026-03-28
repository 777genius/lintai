#[path = "../security_rule_catalog.rs"]
mod security_rule_catalog;

fn main() {
    print!(
        "{}",
        security_rule_catalog::render_security_rules_markdown()
    );
}
