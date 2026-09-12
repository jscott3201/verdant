//! Minimal std-only JSON substrate for the PR02 boundary.
//!
//! Supports the frozen PR02 shapes only: objects, arrays, strings, numbers
//! (kept as raw text, never converted through `f64`), `true`/`false`/`null`.
//! Large integers, decimals and monotonic nanos are encoded as JSON **strings**
//! (explicit exact representation) so no client can silently round them.
//! Numbers appear only where the frozen examples use them (`bool` aside, PR02
//! canonical encodings use strings); the parser still accepts numbers so
//! independent fixtures can probe refusal paths.
//!
//! Malformed input returns [`super::Error`]; it never panics.

use super::Error;
use std::collections::BTreeMap;

/// Parsed JSON value. Numbers keep their raw lexical text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonVal {
    Null,
    Bool(bool),
    /// Raw number text as it appeared (no float conversion).
    Number(String),
    Str(String),
    Array(Vec<JsonVal>),
    Object(BTreeMap<String, JsonVal>),
}

/// Quote a string as a JSON string literal.
pub fn quote(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('"');
    for c in raw.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Parse one top-level JSON string literal (surrounding whitespace allowed).
pub fn parse_string_literal(text: &str) -> Result<String, Error> {
    let mut parser = Parser::new(text);
    parser.skip_ws();
    let value = parser.parse_string().map_err(|m| Error::Json {
        message: m.to_string(),
    })?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(Error::Json {
            message: "trailing characters after JSON string".to_string(),
        });
    }
    Ok(value)
}

/// Parse any top-level JSON value.
pub fn parse(text: &str) -> Result<JsonVal, Error> {
    let mut parser = Parser::new(text);
    parser.skip_ws();
    let value = parser.parse_value(0).map_err(|m| Error::Json {
        message: m.to_string(),
    })?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(Error::Json {
            message: "trailing characters after JSON value".to_string(),
        });
    }
    Ok(value)
}

/// Parse a top-level JSON object into fields.
pub fn parse_object(text: &str) -> Result<BTreeMap<String, JsonVal>, Error> {
    match parse(text)? {
        JsonVal::Object(fields) => Ok(fields),
        _ => Err(Error::Json {
            message: "expected a JSON object".to_string(),
        }),
    }
}

/// Required string field.
pub fn get_string(fields: &BTreeMap<String, JsonVal>, name: &'static str) -> Result<String, Error> {
    match fields.get(name) {
        None => Err(Error::MissingField { field: name }),
        Some(JsonVal::Str(s)) => Ok(s.clone()),
        Some(other) => Err(Error::Json {
            message: format!(
                "field '{name}' must be a JSON string, got {}",
                kind_of(other)
            ),
        }),
    }
}

/// Required boolean field.
pub fn get_bool(fields: &BTreeMap<String, JsonVal>, name: &'static str) -> Result<bool, Error> {
    match fields.get(name) {
        None => Err(Error::MissingField { field: name }),
        Some(JsonVal::Bool(b)) => Ok(*b),
        Some(other) => Err(Error::Json {
            message: format!("field '{name}' must be true/false, got {}", kind_of(other)),
        }),
    }
}

/// Reject unexpected fields against an allow-list.
pub fn reject_unknown(fields: &BTreeMap<String, JsonVal>, allowed: &[&str]) -> Result<(), Error> {
    for key in fields.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(Error::UnexpectedField { field: key.clone() });
        }
    }
    Ok(())
}

/// Canonical JSON serialization for a parsed value.
///
/// Object keys emit in sorted (`BTreeMap`) order; strings use [`quote`].
/// Used to re-serialize nested objects (e.g. a `Value` inside a `Reading`)
/// without a float path.
pub fn stringify(value: &JsonVal) -> String {
    match value {
        JsonVal::Null => "null".to_string(),
        JsonVal::Bool(true) => "true".to_string(),
        JsonVal::Bool(false) => "false".to_string(),
        JsonVal::Number(raw) => raw.clone(),
        JsonVal::Str(s) => quote(s),
        JsonVal::Array(items) => {
            let mut out = String::from("[");
            let mut first = true;
            for item in items {
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&stringify(item));
            }
            out.push(']');
            out
        }
        JsonVal::Object(fields) => {
            let mut out = String::from("{");
            let mut first = true;
            for (key, val) in fields {
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&quote(key));
                out.push(':');
                out.push_str(&stringify(val));
            }
            out.push('}');
            out
        }
    }
}

fn kind_of(value: &JsonVal) -> &'static str {
    match value {
        JsonVal::Null => "null",
        JsonVal::Bool(_) => "boolean",
        JsonVal::Number(_) => "number",
        JsonVal::Str(_) => "string",
        JsonVal::Array(_) => "array",
        JsonVal::Object(_) => "object",
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Parser<'a> {
        Parser {
            bytes: text.as_bytes(),
            pos: 0,
        }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn expect_byte(&mut self, want: u8, what: &str) -> Result<(), String> {
        match self.peek() {
            Some(got) if got == want => {
                self.pos += 1;
                Ok(())
            }
            Some(got) => Err(format!("expected {what}, got '{}'", got as char)),
            None => Err(format!("expected {what}, got end of input")),
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonVal, String> {
        if depth > 16 {
            return Err("JSON nesting exceeds PR02 bound (16)".to_string());
        }
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object_inner(depth).map(JsonVal::Object),
            Some(b'[') => self.parse_array_inner(depth).map(JsonVal::Array),
            Some(b'"') => self.parse_string().map(JsonVal::Str),
            Some(b't') => self.parse_literal("true", JsonVal::Bool(true)),
            Some(b'f') => self.parse_literal("false", JsonVal::Bool(false)),
            Some(b'n') => self.parse_literal("null", JsonVal::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.parse_number().map(JsonVal::Number),
            Some(c) => Err(format!("unexpected character '{}'", c as char)),
            None => Err("unexpected end of input".to_string()),
        }
    }

    fn parse_literal(&mut self, word: &str, value: JsonVal) -> Result<JsonVal, String> {
        let end = self.pos.saturating_add(word.len());
        if end <= self.bytes.len() && &self.bytes[self.pos..end] == word.as_bytes() {
            self.pos = end;
            Ok(value)
        } else {
            Err(format!("expected '{word}'"))
        }
    }

    fn parse_number(&mut self) -> Result<String, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let digits_start = self.pos;
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.pos += 1;
        }
        if self.pos == digits_start {
            return Err("invalid JSON number: expected digits".to_string());
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            let frac_start = self.pos;
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
            if self.pos == frac_start {
                return Err("invalid JSON number: expected digits after '.'".to_string());
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            let exp_start = self.pos;
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
            if self.pos == exp_start {
                return Err("invalid JSON number: expected digits in exponent".to_string());
            }
        }
        String::from_utf8(self.bytes[start..self.pos].to_vec())
            .map_err(|_| "invalid JSON number encoding".to_string())
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect_byte(b'"', "'\"'")?;
        let mut out = String::new();
        loop {
            let byte = self.peek().ok_or("unterminated JSON string".to_string())?;
            match byte {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let esc = self.peek().ok_or("unterminated escape".to_string())?;
                    match esc {
                        b'"' => {
                            out.push('"');
                            self.pos += 1;
                        }
                        b'\\' => {
                            out.push('\\');
                            self.pos += 1;
                        }
                        b'/' => {
                            out.push('/');
                            self.pos += 1;
                        }
                        b'b' => {
                            out.push('\u{0008}');
                            self.pos += 1;
                        }
                        b'f' => {
                            out.push('\u{000C}');
                            self.pos += 1;
                        }
                        b'n' => {
                            out.push('\n');
                            self.pos += 1;
                        }
                        b'r' => {
                            out.push('\r');
                            self.pos += 1;
                        }
                        b't' => {
                            out.push('\t');
                            self.pos += 1;
                        }
                        b'u' => {
                            self.pos += 1;
                            let code = self.parse_hex4()?;
                            // Reject surrogate halves: PR02 fixtures are
                            // Basic-Multilingual-Plane text; surrogates never
                            // appear in canonical encodings here.
                            if (0xD800..0xE000).contains(&code) {
                                return Err("unsupported \\u surrogate half".to_string());
                            }
                            let ch =
                                char::from_u32(code).ok_or("invalid \\u escape".to_string())?;
                            out.push(ch);
                        }
                        other => {
                            return Err(format!("invalid escape '\\{}'", other as char));
                        }
                    }
                }
                0x00..=0x1F => {
                    return Err("unescaped control character in string".to_string());
                }
                _ => {
                    // Consume one UTF-8 scalar.
                    let rest = &self.bytes[self.pos..];
                    let text = std::str::from_utf8(rest)
                        .map_err(|_| "invalid UTF-8 in string".to_string())?;
                    let mut chars = text.chars();
                    match chars.next() {
                        Some(ch) => {
                            out.push(ch);
                            self.pos += ch.len_utf8();
                        }
                        None => return Err("unterminated JSON string".to_string()),
                    }
                }
            }
        }
    }

    fn parse_hex4(&mut self) -> Result<u32, String> {
        if self.pos.saturating_add(4) > self.bytes.len() {
            return Err("truncated \\u escape".to_string());
        }
        let mut value: u32 = 0;
        for i in 0..4 {
            let byte = self.bytes[self.pos + i];
            let digit = match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'a'..=b'f' => u32::from(byte - b'a') + 10,
                b'A'..=b'F' => u32::from(byte - b'A') + 10,
                _ => return Err("invalid hex digit in \\u escape".to_string()),
            };
            value = value.saturating_mul(16).saturating_add(digit);
        }
        self.pos += 4;
        Ok(value)
    }

    fn parse_object_inner(&mut self, depth: usize) -> Result<BTreeMap<String, JsonVal>, String> {
        self.expect_byte(b'{', "'{'")?;
        let mut fields = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(fields);
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err("expected string key in object".to_string());
            }
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect_byte(b':', "':'")?;
            let value = self.parse_value(depth + 1)?;
            if fields.insert(key.clone(), value).is_some() {
                return Err(format!("duplicate key '{key}'"));
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(fields);
                }
                Some(c) => return Err(format!("expected ',' or '}}', got '{}'", c as char)),
                None => return Err("unterminated object".to_string()),
            }
        }
    }

    fn parse_array_inner(&mut self, depth: usize) -> Result<Vec<JsonVal>, String> {
        self.expect_byte(b'[', "'['")?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(items);
        }
        loop {
            let value = self.parse_value(depth + 1)?;
            items.push(value);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(items);
                }
                Some(c) => return Err(format!("expected ',' or ']', got '{}'", c as char)),
                None => return Err("unterminated array".to_string()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_round_trip() {
        for raw in ["", "ahu-1", "a\"b\\c\n\t", "degC", "furlongs"] {
            let quoted = quote(raw);
            let back = parse_string_literal(&quoted).expect("round-trip");
            assert_eq!(back, raw);
        }
    }

    #[test]
    fn malformed_strings_refused() {
        for bad in ["\"unterminated", "\"bad\\escape\\q\"", "\"\n\""] {
            assert!(parse_string_literal(bad).is_err(), "must refuse {bad:?}");
        }
    }

    #[test]
    fn object_parsing_rejects_trailing_and_duplicates() {
        assert!(parse("{\"a\":\"1\"} trailing").is_err());
        assert!(parse("{\"a\":\"1\",\"a\":\"2\"}").is_err());
    }
}
