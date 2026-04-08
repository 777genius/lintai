fn main() {
    print!("{}", lintai_cli::render_security_rules_catalog());
}

#[cfg(test)]
mod tests {
    use super::main;

    #[test]
    fn command_invocation_is_executable() {
        main();
    }

    #[test]
    fn catalog_is_non_empty() {
        let markdown = lintai_cli::render_security_rules_catalog();
        assert!(!markdown.is_empty());
        assert!(markdown.contains("SEC"));
    }
}
