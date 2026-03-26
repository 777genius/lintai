use lintai_api::Fix;

#[derive(Debug, Eq, PartialEq)]
pub enum FixError {
    OutOfBounds,
    InvalidRange,
}

pub fn apply_fix(input: &str, fix: &Fix) -> Result<String, FixError> {
    if fix.span.start_byte > fix.span.end_byte {
        return Err(FixError::InvalidRange);
    }
    if fix.span.end_byte > input.len() {
        return Err(FixError::OutOfBounds);
    }

    let mut output = String::with_capacity(input.len() + fix.replacement.len());
    output.push_str(&input[..fix.span.start_byte]);
    output.push_str(&fix.replacement);
    output.push_str(&input[fix.span.end_byte..]);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use lintai_api::{Applicability, Fix, Span};

    use super::apply_fix;

    #[test]
    fn replaces_requested_range() {
        let output = apply_fix(
            "abc",
            &Fix::new(Span::new(1, 2), "Z", Applicability::Safe, None),
        )
        .unwrap();

        assert_eq!(output, "aZc");
    }
}
