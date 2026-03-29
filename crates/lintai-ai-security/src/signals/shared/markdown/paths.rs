pub(crate) const MARKDOWN_PATH_ACCESS_VERBS: &[&str] = &[
    "read ", "open ", "cat ", "copy ", "load ", "upload ", "include ", "source ", "inspect ",
];

pub(crate) const MARKDOWN_SAFE_REPO_LOCAL_TARGET_SUFFIXES: &[&str] = &[
    "mcp.json",
    "SKILL.md",
    "CLAUDE.md",
    ".mdc",
    ".cursorrules",
    ".cursor-plugin/plugin.json",
    ".cursor-plugin/hooks.json",
];

pub(crate) fn has_path_traversal_access(
    normalized_path: &str,
    snippet: &str,
    lowered: &str,
) -> bool {
    let has_access_verb = MARKDOWN_PATH_ACCESS_VERBS
        .iter()
        .any(|verb| lowered.contains(verb));
    if !has_access_verb {
        return false;
    }

    let Some(candidate) = extract_path_traversal_candidate(snippet) else {
        return false;
    };

    !is_safe_repo_local_relative_target(normalized_path, candidate)
}

pub(crate) fn extract_path_traversal_candidate(snippet: &str) -> Option<&str> {
    snippet.split_whitespace().find_map(|token| {
        let candidate = trim_path_token(token);
        if candidate.contains("../") || candidate.contains("..\\") {
            Some(candidate)
        } else {
            None
        }
    })
}

pub(crate) fn trim_path_token(token: &str) -> &str {
    token.trim_matches(|ch: char| {
        matches!(
            ch,
            '"' | '\''
                | '`'
                | '('
                | ')'
                | '['
                | ']'
                | '{'
                | '}'
                | '<'
                | '>'
                | ','
                | '.'
                | ';'
                | ':'
                | '!'
                | '?'
        )
    })
}

pub(crate) fn is_safe_repo_local_relative_target(normalized_path: &str, candidate: &str) -> bool {
    let Some(resolved) = lexically_resolve_repo_relative_path(normalized_path, candidate) else {
        return false;
    };

    MARKDOWN_SAFE_REPO_LOCAL_TARGET_SUFFIXES
        .iter()
        .any(|suffix| resolved == *suffix || resolved.ends_with(&format!("/{suffix}")))
}

pub(crate) fn lexically_resolve_repo_relative_path(
    normalized_path: &str,
    candidate: &str,
) -> Option<String> {
    let mut segments = normalized_parent_segments(normalized_path);
    let mut saw_parent = false;

    for part in candidate.replace('\\', "/").split('/') {
        match part {
            "" | "." => {}
            ".." => {
                saw_parent = true;
                segments.pop()?;
            }
            component => segments.push(component.to_owned()),
        }
    }

    saw_parent.then(|| segments.join("/"))
}

pub(crate) fn normalized_parent_segments(normalized_path: &str) -> Vec<String> {
    let mut parts = normalized_path
        .split('/')
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    parts.pop();
    parts
}
