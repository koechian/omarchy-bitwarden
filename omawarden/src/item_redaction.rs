//! Redacted item view returned by `list`, `search` and `get_item` (ADR 0027).
//!
//! The view is built from an allowlist: only keys named in a section policy
//! are copied from the decrypted item, so a field added to the decrypted
//! model later stays private until it is deliberately published here. Every
//! secret the policy withholds is replaced by a `has_<field>` presence flag,
//! and its value is only reachable through `reveal_field` / `copy_field`.

use serde_json::{Map, Value};

use crate::vault::VaultItem;

/// Bitwarden custom field types (`CipherFieldType`).
pub const CUSTOM_FIELD_TYPE_TEXT: i64 = 0;
pub const CUSTOM_FIELD_TYPE_HIDDEN: i64 = 1;
pub const CUSTOM_FIELD_TYPE_BOOLEAN: i64 = 2;
pub const CUSTOM_FIELD_TYPE_LINKED: i64 = 3;

/// Payment card numbers are 12 to 19 digits long. A shorter value is not a
/// card number whose last four digits could be shown without revealing it.
pub const CARD_NUMBER_MINIMUM_DIGITS_FOR_SUFFIX: usize = 12;
const CARD_NUMBER_SUFFIX_LENGTH: usize = 4;

/// Which keys of one item section are published, and which secret keys are
/// replaced by presence flags.
struct SectionPolicy {
    public_keys: &'static [&'static str],
    /// (key in the decrypted section, presence flag in the redacted view)
    secret_flags: &'static [(&'static str, &'static str)],
}

const LOGIN_POLICY: SectionPolicy = SectionPolicy {
    public_keys: &["username", "uris", "has_passkey", "passkey_created_at"],
    secret_flags: &[
        ("password", "has_password"),
        ("totp", "has_totp"),
        ("password_history", "has_password_history"),
    ],
};

const CARD_POLICY: SectionPolicy = SectionPolicy {
    public_keys: &["cardholderName", "brand", "expMonth", "expYear"],
    secret_flags: &[("number", "has_number"), ("code", "has_code")],
};

const IDENTITY_POLICY: SectionPolicy = SectionPolicy {
    public_keys: &[
        "title",
        "firstName",
        "middleName",
        "lastName",
        "address1",
        "address2",
        "city",
        "state",
        "postalCode",
        "country",
        "company",
        "email",
        "phone",
        "username",
    ],
    secret_flags: &[
        ("ssn", "has_ssn"),
        ("passportNumber", "has_passport_number"),
        ("licenseNumber", "has_license_number"),
    ],
};

/// A secret counts as present when it is a non-empty string or array.
pub fn secret_is_present(value: Option<&Value>) -> bool {
    match value {
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(elements)) => !elements.is_empty(),
        _ => false,
    }
}

/// The last four digits of a card number, or `None` when the number is too
/// short for the suffix to be anything less than the whole number.
pub fn card_number_last_four(number: &str) -> Option<String> {
    let digits: Vec<char> = number.chars().filter(char::is_ascii_digit).collect();
    if digits.len() < CARD_NUMBER_MINIMUM_DIGITS_FOR_SUFFIX {
        return None;
    }
    Some(
        digits[digits.len() - CARD_NUMBER_SUFFIX_LENGTH..]
            .iter()
            .collect(),
    )
}

/// Whether a custom field's value is published in the redacted view. Only
/// text and boolean fields are; hidden fields and any type this client does
/// not know are treated as secret.
pub fn custom_field_value_is_public(field_type: i64) -> bool {
    matches!(
        field_type,
        CUSTOM_FIELD_TYPE_TEXT | CUSTOM_FIELD_TYPE_BOOLEAN
    )
}

/// The type of a custom field as the server or the decrypted item states
/// it. A missing or non-integer type is reported as hidden, so a malformed
/// field fails closed: its value is neither published nor searchable.
pub fn custom_field_type(field: &Value) -> i64 {
    field
        .get("type")
        .and_then(Value::as_i64)
        .unwrap_or(CUSTOM_FIELD_TYPE_HIDDEN)
}

fn redact_section(section: &Value, policy: &SectionPolicy) -> Map<String, Value> {
    let mut redacted = Map::new();
    for key in policy.public_keys {
        if let Some(value) = section.get(*key) {
            redacted.insert((*key).to_string(), value.clone());
        }
    }
    for (secret_key, flag) in policy.secret_flags {
        let present = secret_is_present(section.get(*secret_key));
        redacted.insert((*flag).to_string(), Value::Bool(present));
    }
    redacted
}

fn redact_login(login: &Value) -> Value {
    let mut redacted = redact_section(login, &LOGIN_POLICY);
    let history_count = login
        .get("password_history")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    redacted.insert("password_history_count".to_string(), history_count.into());
    Value::Object(redacted)
}

fn redact_card(card: &Value) -> Value {
    let mut redacted = redact_section(card, &CARD_POLICY);
    let last_four = card
        .get("number")
        .and_then(Value::as_str)
        .and_then(card_number_last_four);
    redacted.insert("number_last_four".to_string(), Value::from(last_four));
    Value::Object(redacted)
}

fn redact_identity(identity: &Value) -> Value {
    Value::Object(redact_section(identity, &IDENTITY_POLICY))
}

fn redact_custom_field(index: usize, field: &Value) -> Value {
    let field_type = custom_field_type(field);
    let mut redacted = Map::new();
    redacted.insert("index".to_string(), index.into());
    redacted.insert(
        "name".to_string(),
        field.get("name").cloned().unwrap_or(Value::Null),
    );
    redacted.insert("type".to_string(), field_type.into());
    redacted.insert(
        "has_value".to_string(),
        secret_is_present(field.get("value")).into(),
    );
    if custom_field_value_is_public(field_type) {
        redacted.insert(
            "value".to_string(),
            field.get("value").cloned().unwrap_or(Value::Null),
        );
    }
    Value::Object(redacted)
}

fn insert_optional_text(map: &mut Map<String, Value>, key: &str, value: &Option<String>) {
    if let Some(text) = value {
        map.insert(key.to_string(), Value::String(text.clone()));
    }
}

fn insert_item_metadata(map: &mut Map<String, Value>, item: &VaultItem) {
    map.insert("id".to_string(), item.id.clone().into());
    map.insert("name".to_string(), item.name.clone().into());
    map.insert("type".to_string(), item.item_type.into());
    map.insert("type_name".to_string(), item.type_name.clone().into());
    map.insert("sub_title".to_string(), item.sub_title.clone().into());
    map.insert("favorite".to_string(), item.favorite.into());
    insert_optional_text(map, "created_at", &item.created_at);
    insert_optional_text(map, "updated_at", &item.updated_at);
    insert_optional_text(map, "folder_id", &item.folder_id);
    insert_optional_text(map, "folder_name", &item.folder_name);
    insert_optional_text(map, "organization_id", &item.organization_id);
    insert_optional_text(map, "organization_name", &item.organization_name);
    if let Some(collection_ids) = &item.collection_ids {
        map.insert("collection_ids".to_string(), collection_ids.clone().into());
    }
}

fn insert_redacted_section(
    map: &mut Map<String, Value>,
    key: &str,
    section: &Option<Value>,
    redact: fn(&Value) -> Value,
) {
    if let Some(value) = section.as_ref().filter(|v| v.is_object()) {
        map.insert(key.to_string(), redact(value));
    }
}

/// The redacted view of one decrypted item. See docs/agents/contracts.md
/// section 3 for the exact shape.
pub fn redact_item(item: &VaultItem) -> Value {
    let mut map = Map::new();
    insert_item_metadata(&mut map, item);
    let has_notes = item.notes.as_deref().is_some_and(|n| !n.is_empty());
    map.insert("has_notes".to_string(), has_notes.into());
    insert_redacted_section(&mut map, "login", &item.login, redact_login);
    insert_redacted_section(&mut map, "card", &item.card, redact_card);
    insert_redacted_section(&mut map, "identity", &item.identity, redact_identity);
    let fields: Vec<Value> = item
        .fields
        .iter()
        .enumerate()
        .map(|(index, field)| redact_custom_field(index, field))
        .collect();
    map.insert("fields".to_string(), Value::Array(fields));
    Value::Object(map)
}

/// The redacted view of a list of items, in order.
pub fn redact_items(items: &[VaultItem]) -> Value {
    Value::Array(items.iter().map(redact_item).collect())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    /// Secret fixture values. Every one of them is unique so a leak can be
    /// found by searching the serialized view for the exact string.
    pub(crate) const LOGIN_PASSWORD: &str = "fixture-login-password-7c1e";
    pub(crate) const LOGIN_TOTP_SEED: &str = "JBSWY3DPEHPK3PXP";
    pub(crate) const HISTORY_PASSWORD: &str = "fixture-history-password-91af";
    pub(crate) const NOTES: &str = "fixture-secure-notes-44d0";
    pub(crate) const CARD_NUMBER: &str = "4111111111111111";
    pub(crate) const CARD_CODE: &str = "fixture-cvv-913";
    pub(crate) const IDENTITY_SSN: &str = "fixture-ssn-123-45-6789";
    pub(crate) const PASSPORT_NUMBER: &str = "fixture-passport-X12345";
    pub(crate) const LICENSE_NUMBER: &str = "fixture-license-D9876";
    pub(crate) const HIDDEN_FIELD_VALUE: &str = "fixture-hidden-field-5512";
    pub(crate) const UNKNOWN_TYPE_FIELD_VALUE: &str = "fixture-unknown-field-0b7e";

    fn base_item(id: &str, item_type: i64, type_name: &str) -> VaultItem {
        VaultItem {
            id: id.to_string(),
            name: format!("{type_name} fixture"),
            item_type,
            type_name: type_name.to_string(),
            sub_title: String::new(),
            notes: Some(NOTES.to_string()),
            favorite: false,
            created_at: Some("2024-01-01T00:00:00Z".to_string()),
            updated_at: Some("2024-02-01T00:00:00Z".to_string()),
            folder_id: Some("folder-1".to_string()),
            folder_name: Some("Work".to_string()),
            organization_id: None,
            organization_name: None,
            collection_ids: Some(vec!["collection-1".to_string()]),
            login: None,
            card: None,
            identity: None,
            fields: vec![
                json!({ "name": "Account", "value": "public-text-value", "type": 0 }),
                json!({ "name": "PIN", "value": HIDDEN_FIELD_VALUE, "type": 1 }),
                json!({ "name": "Enabled", "value": "true", "type": 2 }),
                json!({ "name": "Linked", "value": "", "type": 3 }),
                json!({ "name": "Future", "value": UNKNOWN_TYPE_FIELD_VALUE, "type": 9 }),
            ],
            search_text: "search text".to_string(),
        }
    }

    pub(crate) fn login_item() -> VaultItem {
        let mut item = base_item("login-1", 1, "login");
        item.login = Some(json!({
            "username": "fixture-user",
            "password": LOGIN_PASSWORD,
            "totp": LOGIN_TOTP_SEED,
            "uris": [{ "uri": "https://example.com" }],
            "password_history": [
                { "password": HISTORY_PASSWORD, "last_used_date": "2023-12-01T00:00:00Z" }
            ],
            "has_passkey": true,
            "passkey_created_at": "2024-01-02T00:00:00Z",
        }));
        item
    }

    pub(crate) fn card_item() -> VaultItem {
        let mut item = base_item("card-1", 3, "card");
        item.card = Some(json!({
            "cardholderName": "Fixture Holder",
            "brand": "Visa",
            "number": CARD_NUMBER,
            "expMonth": "12",
            "expYear": "2030",
            "code": CARD_CODE,
        }));
        item
    }

    pub(crate) fn identity_item() -> VaultItem {
        let mut item = base_item("identity-1", 4, "identity");
        item.identity = Some(json!({
            "title": "Dr",
            "firstName": "Fixture",
            "lastName": "Person",
            "email": "fixture@example.com",
            "phone": "555-0100",
            "address1": "1 Fixture Way",
            "ssn": IDENTITY_SSN,
            "passportNumber": PASSPORT_NUMBER,
            "licenseNumber": LICENSE_NUMBER,
        }));
        item
    }

    pub(crate) fn note_item() -> VaultItem {
        base_item("note-1", 2, "note")
    }

    const ALL_SECRETS: &[&str] = &[
        LOGIN_PASSWORD,
        LOGIN_TOTP_SEED,
        HISTORY_PASSWORD,
        NOTES,
        CARD_NUMBER,
        CARD_CODE,
        IDENTITY_SSN,
        PASSPORT_NUMBER,
        LICENSE_NUMBER,
        HIDDEN_FIELD_VALUE,
        UNKNOWN_TYPE_FIELD_VALUE,
    ];

    #[test]
    fn test_redaction_removes_every_secret_for_each_item_type() {
        let cases: Vec<(&str, VaultItem, &[&str])> = vec![
            (
                "login",
                login_item(),
                &["has_password", "has_totp", "has_password_history"],
            ),
            ("card", card_item(), &["has_number", "has_code"]),
            (
                "identity",
                identity_item(),
                &["has_ssn", "has_passport_number", "has_license_number"],
            ),
            ("note", note_item(), &[]),
        ];
        for (section, item, expected_flags) in cases {
            let view = redact_item(&item);
            let serialized = view.to_string();
            for secret in ALL_SECRETS {
                assert!(
                    !serialized.contains(secret),
                    "{section}: redacted view leaks a secret fixture: {serialized}"
                );
            }
            assert!(
                view.get("search_text").is_none(),
                "{section}: search text is internal"
            );
            assert!(view.get("notes").is_none(), "{section}: notes withheld");
            assert_eq!(view["has_notes"], true, "{section}");
            for flag in expected_flags {
                assert_eq!(view[section][*flag], true, "{section}.{flag}: {view}");
            }
        }
    }

    #[test]
    fn test_redaction_keeps_public_metadata() {
        let login = redact_item(&login_item());
        assert_eq!(login["id"], "login-1");
        assert_eq!(login["type"], 1);
        assert_eq!(login["type_name"], "login");
        assert_eq!(login["folder_name"], "Work");
        assert_eq!(login["collection_ids"], json!(["collection-1"]));
        assert_eq!(login["login"]["username"], "fixture-user");
        assert_eq!(login["login"]["uris"][0]["uri"], "https://example.com");
        assert_eq!(login["login"]["has_passkey"], true);
        assert_eq!(login["login"]["password_history_count"], 1);

        let card = redact_item(&card_item());
        assert_eq!(card["card"]["brand"], "Visa");
        assert_eq!(card["card"]["expYear"], "2030");
        assert_eq!(card["card"]["cardholderName"], "Fixture Holder");
        assert_eq!(card["card"]["number_last_four"], "1111");

        let identity = redact_item(&identity_item());
        assert_eq!(identity["identity"]["email"], "fixture@example.com");
        assert_eq!(identity["identity"]["phone"], "555-0100");
        assert_eq!(identity["identity"]["address1"], "1 Fixture Way");
    }

    #[test]
    fn test_redaction_publishes_only_text_and_boolean_custom_values() {
        let view = redact_item(&login_item());
        let fields = view["fields"].as_array().unwrap();
        let expectations = [
            (0, Some("public-text-value"), true),
            (1, None, true),
            (2, Some("true"), true),
            (3, None, false),
            (4, None, true),
        ];
        for (index, value, has_value) in expectations {
            let field = &fields[index];
            assert_eq!(field["index"], index, "{field}");
            assert_eq!(field.get("value").and_then(Value::as_str), value, "{field}");
            assert_eq!(field["has_value"], has_value, "{field}");
        }
    }

    #[test]
    fn test_custom_field_without_an_integer_type_is_treated_as_hidden() {
        let mut item = login_item();
        item.fields = vec![
            json!({ "name": "No type", "value": UNKNOWN_TYPE_FIELD_VALUE }),
            json!({ "name": "Null type", "value": UNKNOWN_TYPE_FIELD_VALUE, "type": null }),
            json!({ "name": "Text type", "value": UNKNOWN_TYPE_FIELD_VALUE, "type": "0" }),
            json!({ "name": "Fractional", "value": UNKNOWN_TYPE_FIELD_VALUE, "type": 0.5 }),
        ];
        let view = redact_item(&item);
        for field in view["fields"].as_array().unwrap() {
            assert!(field.get("value").is_none(), "{field}");
            assert_eq!(field["type"], CUSTOM_FIELD_TYPE_HIDDEN, "{field}");
            assert_eq!(field["has_value"], true, "{field}");
        }
        assert!(!view.to_string().contains(UNKNOWN_TYPE_FIELD_VALUE));
    }

    #[test]
    fn test_redaction_reports_absent_secrets_as_false() {
        let mut item = login_item();
        item.notes = None;
        item.login = Some(json!({ "username": "u", "password": "", "uris": [] }));
        let view = redact_item(&item);
        assert_eq!(view["has_notes"], false);
        assert_eq!(view["login"]["has_password"], false);
        assert_eq!(view["login"]["has_totp"], false);
        assert_eq!(view["login"]["has_password_history"], false);
        assert_eq!(view["login"]["password_history_count"], 0);
    }

    #[test]
    fn test_card_number_last_four_requires_a_card_length_number() {
        assert_eq!(
            card_number_last_four("4111 1111 1111 1234").as_deref(),
            Some("1234")
        );
        assert_eq!(
            card_number_last_four("4111-1111-1111-9876").as_deref(),
            Some("9876")
        );
        assert_eq!(
            card_number_last_four("1234"),
            None,
            "would reveal the number"
        );
        assert_eq!(card_number_last_four("12345678901"), None);
        assert_eq!(card_number_last_four(""), None);
    }
}
