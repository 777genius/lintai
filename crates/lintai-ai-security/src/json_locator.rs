use std::collections::BTreeMap;

use lintai_api::Span;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum JsonPathSegment {
    Key(String),
    Index(usize),
}

#[derive(Clone, Debug, Default)]
pub(crate) struct JsonLocationMap {
    key_spans: BTreeMap<Vec<JsonPathSegment>, Span>,
    value_spans: BTreeMap<Vec<JsonPathSegment>, Span>,
}

impl JsonLocationMap {
    pub(crate) fn parse(input: &str) -> Option<Self> {
        JsonLocatorParser::new(input).parse()
    }

    pub(crate) fn key_span(&self, path: &[JsonPathSegment]) -> Option<&Span> {
        self.key_spans.get(path)
    }

    pub(crate) fn value_span(&self, path: &[JsonPathSegment]) -> Option<&Span> {
        self.value_spans.get(path)
    }
}

struct JsonLocatorParser<'a> {
    input: &'a str,
    offset: usize,
    map: JsonLocationMap,
}

impl<'a> JsonLocatorParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            offset: 0,
            map: JsonLocationMap::default(),
        }
    }

    fn parse(mut self) -> Option<JsonLocationMap> {
        self.skip_whitespace();
        self.parse_value(&mut Vec::new())?;
        self.skip_whitespace();
        (self.offset == self.input.len()).then_some(self.map)
    }

    fn parse_value(&mut self, path: &mut Vec<JsonPathSegment>) -> Option<()> {
        self.skip_whitespace();
        match self.peek_char()? {
            '"' => {
                let (_, span) = self.parse_string_token()?;
                self.map.value_spans.insert(path.clone(), span);
                Some(())
            }
            '{' => self.parse_object(path),
            '[' => self.parse_array(path),
            't' => self.consume_literal("true"),
            'f' => self.consume_literal("false"),
            'n' => self.consume_literal("null"),
            '-' | '0'..='9' => self.parse_number(),
            _ => None,
        }
    }

    fn parse_object(&mut self, path: &mut Vec<JsonPathSegment>) -> Option<()> {
        self.expect_char('{')?;
        self.skip_whitespace();
        if self.consume_char_if('}') {
            return Some(());
        }

        loop {
            self.skip_whitespace();
            let (key, key_span) = self.parse_string_token()?;
            path.push(JsonPathSegment::Key(key));
            self.map.key_spans.insert(path.clone(), key_span);
            self.skip_whitespace();
            self.expect_char(':')?;
            self.parse_value(path)?;
            path.pop();
            self.skip_whitespace();
            if self.consume_char_if('}') {
                break;
            }
            self.expect_char(',')?;
        }

        Some(())
    }

    fn parse_array(&mut self, path: &mut Vec<JsonPathSegment>) -> Option<()> {
        self.expect_char('[')?;
        self.skip_whitespace();
        if self.consume_char_if(']') {
            return Some(());
        }

        let mut index = 0usize;
        loop {
            path.push(JsonPathSegment::Index(index));
            self.parse_value(path)?;
            path.pop();
            index += 1;
            self.skip_whitespace();
            if self.consume_char_if(']') {
                break;
            }
            self.expect_char(',')?;
        }

        Some(())
    }

    fn parse_string_token(&mut self) -> Option<(String, Span)> {
        let start_quote = self.offset;
        self.expect_char('"')?;
        let mut escaped = false;
        while self.offset < self.input.len() {
            let ch = self.peek_char()?;
            self.offset += ch.len_utf8();
            match ch {
                '"' if !escaped => {
                    let token = self.input.get(start_quote..self.offset)?;
                    let decoded = serde_json::from_str::<String>(token).ok()?;
                    return Some((decoded, Span::new(start_quote + 1, self.offset - 1)));
                }
                '\\' if !escaped => escaped = true,
                _ => escaped = false,
            }
        }
        None
    }

    fn parse_number(&mut self) -> Option<()> {
        let start = self.offset;
        while let Some(ch) = self.peek_char() {
            if matches!(ch, '0'..='9' | '-' | '+' | '.' | 'e' | 'E') {
                self.offset += ch.len_utf8();
            } else {
                break;
            }
        }
        (self.offset > start).then_some(())
    }

    fn consume_literal(&mut self, literal: &str) -> Option<()> {
        self.input.get(self.offset..)?.strip_prefix(literal)?;
        self.offset += literal.len();
        Some(())
    }

    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.peek_char() {
            if ch.is_whitespace() {
                self.offset += ch.len_utf8();
            } else {
                break;
            }
        }
    }

    fn peek_char(&self) -> Option<char> {
        self.input.get(self.offset..)?.chars().next()
    }

    fn expect_char(&mut self, expected: char) -> Option<()> {
        (self.peek_char()? == expected).then(|| {
            self.offset += expected.len_utf8();
        })
    }

    fn consume_char_if(&mut self, expected: char) -> bool {
        if self.peek_char() == Some(expected) {
            self.offset += expected.len_utf8();
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{JsonLocationMap, JsonPathSegment};
    use lintai_api::Span;

    #[test]
    fn records_string_value_and_key_spans() {
        let map = JsonLocationMap::parse(
            r#"{"command":"sh","args":["-c","echo hi"],"env":{"OPENAI_API_KEY":"${OPENAI_API_KEY}"}}"#,
        )
        .unwrap();

        assert_eq!(
            map.key_span(&[JsonPathSegment::Key("command".to_owned())]),
            Some(&Span::new(2, 9))
        );
        assert_eq!(
            map.value_span(&[JsonPathSegment::Key("command".to_owned())]),
            Some(&Span::new(12, 14))
        );
        assert_eq!(
            map.value_span(&[
                JsonPathSegment::Key("args".to_owned()),
                JsonPathSegment::Index(0),
            ]),
            Some(&Span::new(25, 27))
        );
        assert_eq!(
            map.key_span(&[
                JsonPathSegment::Key("env".to_owned()),
                JsonPathSegment::Key("OPENAI_API_KEY".to_owned()),
            ]),
            Some(&Span::new(48, 62))
        );
    }
}
