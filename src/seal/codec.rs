use super::{Result, SealError};

pub(super) fn encode(fields: &[String]) -> String {
    let mut out = String::new();
    for field in fields {
        out.push_str(&format!("{}:{field}", field.len()));
    }
    out
}
pub(super) fn decode(raw: &str, max_bytes: usize, max_fields: usize) -> Result<Vec<String>> {
    if raw.len() > max_bytes {
        return Err(SealError::Limit("encoded bytes"));
    }
    let mut rest = raw;
    let mut fields = Vec::new();
    while !rest.is_empty() {
        if fields.len() == max_fields {
            return Err(SealError::Limit("encoded fields"));
        }
        let (n, body) = rest
            .split_once(':')
            .ok_or(SealError::Invalid("field length"))?;
        let len: usize = number(n)?;
        let value = body
            .get(..len)
            .ok_or(SealError::Invalid("field boundary"))?;
        rest = body
            .get(len..)
            .ok_or(SealError::Invalid("field boundary"))?;
        fields.push(value.into());
    }
    Ok(fields)
}
pub(super) fn number<T: std::str::FromStr + ToString>(raw: &str) -> Result<T> {
    let n: T = raw.parse().map_err(|_| SealError::Invalid("integer"))?;
    if n.to_string() != raw {
        return Err(SealError::Invalid("noncanonical integer"));
    }
    Ok(n)
}
pub(super) fn text(raw: &str) -> Result<String> {
    if raw.is_empty() || raw.len() > 256 || raw.chars().any(char::is_control) {
        return Err(SealError::Invalid("inert reference text"));
    }
    Ok(raw.into())
}
