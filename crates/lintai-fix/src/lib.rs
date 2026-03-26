use lintai_api::Fix;

#[derive(Debug, Eq, PartialEq)]
pub enum FixError {
    OutOfBounds,
    InvalidRange,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixBatchPlan {
    pub applicable: Vec<usize>,
    pub conflicts: Vec<usize>,
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

pub fn plan_fixes(fixes: &[Fix]) -> FixBatchPlan {
    let mut ordered = fixes.iter().enumerate().collect::<Vec<_>>();
    ordered.sort_by(|(left_index, left), (right_index, right)| {
        (
            left.span.start_byte,
            left.span.end_byte,
            left.replacement.as_str(),
            *left_index,
        )
            .cmp(&(
                right.span.start_byte,
                right.span.end_byte,
                right.replacement.as_str(),
                *right_index,
            ))
    });

    let mut applicable = Vec::new();
    let mut conflicts = Vec::new();
    let mut last_end = None;

    for (index, fix) in ordered {
        if last_end.is_some_and(|end| fix.span.start_byte < end) {
            conflicts.push(index);
            continue;
        }

        applicable.push(index);
        last_end = Some(fix.span.end_byte);
    }

    FixBatchPlan {
        applicable,
        conflicts,
    }
}

pub fn apply_planned_fixes(
    input: &str,
    fixes: &[Fix],
    plan: &FixBatchPlan,
) -> Result<String, FixError> {
    let mut output = input.to_owned();
    let mut applicable = plan
        .applicable
        .iter()
        .map(|index| (*index, &fixes[*index]))
        .collect::<Vec<_>>();
    applicable.sort_by(|(left_index, left), (right_index, right)| {
        (
            right.span.start_byte,
            right.span.end_byte,
            right.replacement.as_str(),
            right_index,
        )
            .cmp(&(
                left.span.start_byte,
                left.span.end_byte,
                left.replacement.as_str(),
                left_index,
            ))
    });

    for (_, fix) in applicable {
        output = apply_fix(&output, fix)?;
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use lintai_api::{Applicability, Fix, Span};

    use super::{FixBatchPlan, apply_fix, apply_planned_fixes, plan_fixes};

    #[test]
    fn replaces_requested_range() {
        let output = apply_fix(
            "abc",
            &Fix::new(Span::new(1, 2), "Z", Applicability::Safe, None),
        )
        .unwrap();

        assert_eq!(output, "aZc");
    }

    #[test]
    fn plans_non_overlapping_fixes() {
        let fixes = vec![
            Fix::new(Span::new(4, 5), "Y", Applicability::Safe, None),
            Fix::new(Span::new(0, 1), "X", Applicability::Safe, None),
        ];

        let plan = plan_fixes(&fixes);
        assert_eq!(
            plan,
            FixBatchPlan {
                applicable: vec![1, 0],
                conflicts: vec![],
            }
        );
    }

    #[test]
    fn detects_overlapping_fixes_deterministically() {
        let fixes = vec![
            Fix::new(Span::new(0, 4), "", Applicability::Safe, None),
            Fix::new(Span::new(0, 4), "", Applicability::Safe, None),
            Fix::new(Span::new(5, 8), "", Applicability::Safe, None),
        ];

        let plan = plan_fixes(&fixes);
        assert_eq!(plan.applicable, vec![0, 2]);
        assert_eq!(plan.conflicts, vec![1]);
    }

    #[test]
    fn applies_planned_fixes_in_descending_offset_order() {
        let fixes = vec![
            Fix::new(Span::new(0, 1), "X", Applicability::Safe, None),
            Fix::new(Span::new(2, 3), "Z", Applicability::Safe, None),
        ];
        let plan = FixBatchPlan {
            applicable: vec![0, 1],
            conflicts: vec![],
        };

        let output = apply_planned_fixes("abc", &fixes, &plan).unwrap();
        assert_eq!(output, "XbZ");
    }
}
