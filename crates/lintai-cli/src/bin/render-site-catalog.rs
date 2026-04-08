fn main() {
    print!("{}", lintai_cli::render_site_catalog_json());
}

#[cfg(test)]
mod tests {
    use super::main;

    #[test]
    fn command_invocation_is_executable() {
        main();
    }

    #[test]
    fn catalog_is_json_like() {
        let json = lintai_cli::render_site_catalog_json();
        assert!(!json.is_empty());
        assert!(json.starts_with("[") || json.starts_with("{"));
    }
}
