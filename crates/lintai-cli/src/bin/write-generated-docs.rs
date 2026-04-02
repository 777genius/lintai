fn main() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root should resolve from lintai-cli");

    if let Err(error) = lintai_cli::write_generated_docs(&repo_root) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
