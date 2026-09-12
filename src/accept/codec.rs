//! Length framing adapter for the frozen seal v1 contract, also used for PR08A
//! records. Read the public canonical bytes; no private seal state is accessed.
use super::{Error, Result};

pub(super) fn encode(fields: &[String]) -> String {
    fields.iter().map(|s| format!("{}:{s}", s.len())).collect()
}
pub(super) fn decode(raw: &str, max_bytes: usize, max_fields: usize) -> Result<Vec<String>> {
    if raw.len() > max_bytes {
        return Err(Error::Limit("record bytes"));
    }
    let mut rest = raw;
    let mut result = Vec::new();
    while !rest.is_empty() {
        if result.len() == max_fields {
            return Err(Error::Limit("record fields"));
        }
        let (len, text) = rest
            .split_once(':')
            .ok_or(Error::Invalid("record framing"))?;
        let count: usize = number(len)?;
        let field = text
            .get(..count)
            .ok_or(Error::Invalid("record length/UTF-8"))?;
        rest = text.get(count..).ok_or(Error::Invalid("record boundary"))?;
        result.push(field.into());
    }
    Ok(result)
}
pub(super) fn number<T: std::str::FromStr + ToString>(raw: &str) -> Result<T> {
    let value: T = raw.parse().map_err(|_| Error::Invalid("record number"))?;
    if value.to_string() != raw {
        return Err(Error::Invalid("noncanonical number"));
    }
    Ok(value)
}
pub(super) fn text_json(raw: &str) -> Result<String> {
    match crate::domain::values::Value::from_json(raw) {
        Ok(crate::domain::values::Value::Text(text)) => Ok(text),
        _ => Err(Error::Invalid("record JSON text")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frozen_framing_is_independent_and_malformed_lengths_refuse() {
        assert_eq!(encode(&["é".into(), "".into(), "x:y".into()]), "2:é0:3:x:y");
        assert_eq!(decode("2:é0:3:x:y", 64, 3).unwrap(), vec!["é", "", "x:y"]);
        for raw in [
            "01:a",
            "1:é",
            "3:é",
            "2:x",
            "-1:x",
            "x:a",
            "1:a0",
            "99999999999999999999999999999:a",
        ] {
            assert!(decode(raw, 64, 3).is_err(), "accepted {raw:?}");
        }
        assert!(matches!(
            decode("0:0:", 64, 1),
            Err(Error::Limit("record fields"))
        ));
        assert!(matches!(
            decode("1:a", 2, 1),
            Err(Error::Limit("record bytes"))
        ));
    }
}
