//! Zeroization helpers for decrypted vault content that lives in
//! `serde_json::Value` trees and plain `String`s (ADR 0027).
//!
//! `zeroize` covers `String` and `Vec<u8>` directly, but a `Value` owns its
//! strings privately inside nested arrays and maps. These helpers walk the
//! tree and overwrite every string in place before the memory is released.

use serde_json::Value;
use zeroize::Zeroize;

/// Overwrites every string inside `value` (object keys excepted) with zeroes
/// and leaves the tree structurally intact but emptied of text.
///
/// Object keys are field names chosen by this program (`password`, `code`),
/// not secrets, and `serde_json::Map` offers no mutable access to them.
pub fn zeroize_json_value(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(elements) => elements.iter_mut().for_each(zeroize_json_value),
        Value::Object(map) => map.values_mut().for_each(zeroize_json_value),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Zeroizes an optional decrypted `Value` in place.
pub fn zeroize_optional_json_value(value: &mut Option<Value>) {
    if let Some(inner) = value.as_mut() {
        zeroize_json_value(inner);
    }
}

/// Zeroizes an optional decrypted string in place.
pub fn zeroize_optional_string(text: &mut Option<String>) {
    if let Some(inner) = text.as_mut() {
        inner.zeroize();
    }
}

/// Serializes a response and returns the line in memory that is zeroized on
/// drop, so a released secret does not linger in the write buffer.
pub fn serialize_zeroizing(value: &Value) -> zeroize::Zeroizing<String> {
    zeroize::Zeroizing::new(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn contains_non_empty_string(value: &Value) -> bool {
        match value {
            Value::String(text) => !text.is_empty(),
            Value::Array(elements) => elements.iter().any(contains_non_empty_string),
            Value::Object(map) => map.values().any(contains_non_empty_string),
            _ => false,
        }
    }

    #[test]
    fn test_zeroize_json_value_clears_every_nested_string() {
        let mut value = json!({
            "password": "fixture-password",
            "history": [{ "password": "fixture-old", "last_used_date": "2024-01-01" }],
            "nested": { "deeper": ["a", "b", { "c": "d" }] },
            "count": 3,
            "flag": true,
            "missing": null,
        });
        zeroize_json_value(&mut value);
        assert!(!contains_non_empty_string(&value), "got: {value}");
        assert_eq!(value["count"], 3, "non-string values are left alone");
        assert_eq!(value["flag"], true);
        assert!(value["history"].is_array(), "structure is preserved");
    }

    #[test]
    fn test_zeroize_optional_helpers() {
        let mut text = Some("fixture-secret".to_string());
        zeroize_optional_string(&mut text);
        assert_eq!(text.as_deref(), Some(""));

        let mut value = Some(json!({ "code": "123" }));
        zeroize_optional_json_value(&mut value);
        assert_eq!(value.unwrap()["code"], "");

        let mut nothing: Option<Value> = None;
        zeroize_optional_json_value(&mut nothing);
        assert!(nothing.is_none());
    }

    #[test]
    fn test_serialize_zeroizing_round_trips() {
        let line = serialize_zeroizing(&json!({ "ok": true }));
        assert_eq!(line.as_str(), r#"{"ok":true}"#);
    }
}
