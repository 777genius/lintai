use super::super::super::*;

pub(crate) fn json_descendants<'a>(value: &'a Value) -> Box<dyn Iterator<Item = &'a Value> + 'a> {
    match value {
        Value::Array(items) => {
            Box::new(std::iter::once(value).chain(items.iter().flat_map(json_descendants)))
        }
        Value::Object(map) => {
            Box::new(std::iter::once(value).chain(map.values().flat_map(json_descendants)))
        }
        _ => Box::new(std::iter::once(value)),
    }
}
