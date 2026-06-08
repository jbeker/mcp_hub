//! Small shared helpers.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Current unix time in seconds.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A fresh random UUIDv4 string, used for primary keys.
pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Substitute `${VAR}` references in `input` with values from `vars`.
///
/// Only the braced form is recognised. A reference to a variable that isn't in
/// `vars` — or a `${` with no closing `}` — is left exactly as written, so a
/// configuration typo stays visible instead of silently collapsing to an empty
/// string. There is no escape sequence; a literal `${` cannot be expressed,
/// which is fine for the command lines this is used on.
pub fn expand_vars(input: &str, vars: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(pos) = rest.find("${") {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 2..];
        match after.find('}') {
            Some(end) => {
                let name = &after[..end];
                match vars.get(name) {
                    Some(val) => out.push_str(val),
                    // Unknown variable: keep the reference literal.
                    None => {
                        out.push_str("${");
                        out.push_str(name);
                        out.push('}');
                    }
                }
                rest = &after[end + 1..];
            }
            // Unterminated `${`: nothing more can be expanded — copy and stop.
            None => {
                out.push_str("${");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn expands_known_references() {
        let v = vars(&[("TOOL_HOME", "/opt/tool"), ("TOKEN", "abc123")]);
        assert_eq!(expand_vars("${TOOL_HOME}/bin/server", &v), "/opt/tool/bin/server");
        assert_eq!(expand_vars("--token=${TOKEN}", &v), "--token=abc123");
        assert_eq!(expand_vars("${TOOL_HOME}:${TOKEN}", &v), "/opt/tool:abc123");
    }

    #[test]
    fn leaves_unknown_and_malformed_literal() {
        let v = vars(&[("KNOWN", "x")]);
        // Unknown variable is preserved verbatim.
        assert_eq!(expand_vars("${MISSING}/y", &v), "${MISSING}/y");
        // Unterminated reference is preserved.
        assert_eq!(expand_vars("${KNOWN", &v), "${KNOWN");
        assert_eq!(expand_vars("a ${KNOWN} ${OOPS", &v), "a x ${OOPS");
        // A bare `$` without a brace is not a reference.
        assert_eq!(expand_vars("price is $5", &v), "price is $5");
    }

    #[test]
    fn empty_and_no_references() {
        let v = vars(&[("A", "1")]);
        assert_eq!(expand_vars("", &v), "");
        assert_eq!(expand_vars("plain text", &v), "plain text");
    }
}
