//! Per-field secret release for the resident daemon (ADR 0027).
//!
//! `list`, `search` and `get_item` return redacted items. A secret leaves the
//! daemon only through `reveal_field` (value in the response) or
//! `copy_field` (value written to the clipboard by the daemon itself), one
//! field of one item per request, and every successful release is counted
//! against a budget of two sliding windows (a minute and an hour). Exceeding
//! either hard-locks the vault. Releases do not reset the idle timer, so a
//! caller cannot keep the vault unlocked by releasing secrets at a steady
//! pace.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use crate::daemon::DaemonState;
use crate::vault::VaultItem;

/// Maximum successful releases (`reveal_field` + `copy_field`) accepted
/// within one `SECRET_RELEASE_WINDOW`. The request that would exceed it is
/// refused and hard-locks the vault.
pub const MAX_SECRET_RELEASES_PER_WINDOW: usize = 30;
/// Length of the short sliding window of the release budget.
pub const SECRET_RELEASE_WINDOW: Duration = Duration::from_secs(60);
/// Maximum successful releases accepted within one
/// `SECRET_RELEASE_HOURLY_WINDOW`. Bounds paced extraction that stays just
/// under the short window's limit.
pub const MAX_SECRET_RELEASES_PER_HOUR: usize = 120;
/// Length of the long sliding window of the release budget.
pub const SECRET_RELEASE_HOURLY_WINDOW: Duration = Duration::from_secs(3600);

/// One sliding-window limit of the release budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseLimit {
    pub max_releases: usize,
    pub window: Duration,
}

/// Every limit a release must fit, checked in this order. The last entry
/// has the longest window.
pub const RELEASE_LIMITS: [ReleaseLimit; 2] = [
    ReleaseLimit {
        max_releases: MAX_SECRET_RELEASES_PER_WINDOW,
        window: SECRET_RELEASE_WINDOW,
    },
    ReleaseLimit {
        max_releases: MAX_SECRET_RELEASES_PER_HOUR,
        window: SECRET_RELEASE_HOURLY_WINDOW,
    },
];

/// Clipboard auto-clear applied by `copy_field` when neither the request nor
/// the configuration supplies a positive value. A released secret is never
/// left on the clipboard indefinitely.
pub const DEFAULT_COPY_CLEAR_SECONDS: u64 = 30;
/// Accepted range for the optional `clear_after_seconds` of `copy_field`.
pub const COPY_CLEAR_SECONDS_RANGE: std::ops::RangeInclusive<u64> = 1..=3600;

/// Machine-readable error codes carried in `error_code` by the secret-access
/// actions, so the overlay can react without parsing prose.
pub mod error_code {
    pub const INVALID_REQUEST: &str = "invalid_request";
    pub const VAULT_LOCKED: &str = "vault_locked";
    pub const ITEM_NOT_FOUND: &str = "item_not_found";
    pub const UNKNOWN_FIELD: &str = "unknown_field";
    pub const FIELD_EMPTY: &str = "field_empty";
    pub const FIELD_NOT_COPYABLE: &str = "field_not_copyable";
    pub const RELEASE_LIMIT_EXCEEDED: &str = "release_limit_exceeded";
    pub const CLIPBOARD_FAILED: &str = "clipboard_failed";
}

/// One releasable secret of an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretField {
    LoginPassword,
    LoginTotp,
    Notes,
    CardNumber,
    CardCode,
    IdentitySsn,
    IdentityPassportNumber,
    IdentityLicenseNumber,
    /// Custom field at this position of the item's `fields` array.
    CustomField(usize),
    PasswordHistory,
}

/// Field identifiers with a fixed name. `custom.<index>` is parsed
/// separately.
const NAMED_SECRET_FIELDS: &[(&str, SecretField)] = &[
    ("login.password", SecretField::LoginPassword),
    ("login.totp", SecretField::LoginTotp),
    ("notes", SecretField::Notes),
    ("card.number", SecretField::CardNumber),
    ("card.code", SecretField::CardCode),
    ("identity.ssn", SecretField::IdentitySsn),
    (
        "identity.passport_number",
        SecretField::IdentityPassportNumber,
    ),
    (
        "identity.license_number",
        SecretField::IdentityLicenseNumber,
    ),
    ("password_history", SecretField::PasswordHistory),
];

const CUSTOM_FIELD_PREFIX: &str = "custom.";

/// Where a text secret lives in the decrypted item.
enum SecretLocation {
    Notes,
    Section(&'static str, &'static str),
    CustomField(usize),
}

impl SecretField {
    /// Parses a field identifier such as `login.password` or `custom.2`.
    pub fn parse(identifier: &str) -> Result<Self, String> {
        if let Some((_, field)) = NAMED_SECRET_FIELDS
            .iter()
            .find(|(name, _)| *name == identifier)
        {
            return Ok(*field);
        }
        identifier
            .strip_prefix(CUSTOM_FIELD_PREFIX)
            .filter(|index| !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|index| index.parse::<usize>().ok())
            .map(SecretField::CustomField)
            .ok_or_else(|| unknown_field_message(identifier))
    }

    /// The identifier this field is addressed by on the wire.
    pub fn identifier(&self) -> String {
        if let SecretField::CustomField(index) = self {
            return format!("{CUSTOM_FIELD_PREFIX}{index}");
        }
        NAMED_SECRET_FIELDS
            .iter()
            .find(|(_, field)| field == self)
            .map(|(name, _)| (*name).to_string())
            .unwrap_or_default()
    }

    fn text_location(&self) -> Option<SecretLocation> {
        let location = match self {
            SecretField::LoginPassword => SecretLocation::Section("login", "password"),
            SecretField::Notes => SecretLocation::Notes,
            SecretField::CardNumber => SecretLocation::Section("card", "number"),
            SecretField::CardCode => SecretLocation::Section("card", "code"),
            SecretField::IdentitySsn => SecretLocation::Section("identity", "ssn"),
            SecretField::IdentityPassportNumber => {
                SecretLocation::Section("identity", "passportNumber")
            }
            SecretField::IdentityLicenseNumber => {
                SecretLocation::Section("identity", "licenseNumber")
            }
            SecretField::CustomField(index) => SecretLocation::CustomField(*index),
            SecretField::LoginTotp | SecretField::PasswordHistory => return None,
        };
        Some(location)
    }
}

fn unknown_field_message(identifier: &str) -> String {
    let mut supported: Vec<&str> = NAMED_SECRET_FIELDS.iter().map(|(name, _)| *name).collect();
    supported.push("custom.<index>");
    format!(
        "Unknown field '{}'. Supported fields: {}.",
        identifier,
        supported.join(", ")
    )
}

/// A failed release: the human-readable message and its `error_code`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseError {
    pub code: &'static str,
    pub message: String,
}

impl ReleaseError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn to_response(&self) -> Value {
        json!({ "ok": false, "error": self.message, "error_code": self.code })
    }
}

/// Sliding-window count of successful secret releases, one entry per
/// charged release.
#[derive(Debug, Default)]
pub struct ReleaseBudget {
    releases: VecDeque<Instant>,
}

impl ReleaseBudget {
    /// Records `cost` releases at `now` if every limit in `RELEASE_LIMITS`
    /// still has room for all of them. Otherwise records nothing and
    /// returns the first limit they would exceed.
    pub fn try_record(&mut self, now: Instant, cost: usize) -> Result<(), ReleaseLimit> {
        self.discard_expired(now);
        if let Some(limit) = RELEASE_LIMITS
            .iter()
            .find(|limit| self.recorded_within(now, limit.window) + cost > limit.max_releases)
        {
            return Err(*limit);
        }
        self.releases.extend(std::iter::repeat_n(now, cost));
        Ok(())
    }

    /// Drops releases older than the longest window; they count nowhere.
    fn discard_expired(&mut self, now: Instant) {
        let longest = RELEASE_LIMITS[RELEASE_LIMITS.len() - 1].window;
        while self
            .releases
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= longest)
        {
            self.releases.pop_front();
        }
    }

    /// Releases recorded less than `window` before `now`.
    pub fn recorded_within(&self, now: Instant, window: Duration) -> usize {
        self.releases
            .iter()
            .rev()
            .take_while(|t| now.saturating_duration_since(**t) < window)
            .count()
    }

    /// Withdraws the most recent `cost` releases, for a release that was
    /// admitted but never delivered (for example a failed clipboard write).
    pub fn refund_latest(&mut self, cost: usize) {
        let remaining = self.releases.len().saturating_sub(cost);
        self.releases.truncate(remaining);
    }

    pub fn reset(&mut self) {
        self.releases.clear();
    }

    /// Releases still counted by at least one window.
    pub fn recorded(&self) -> usize {
        self.releases.len()
    }
}

/// A secret extracted from an item, owned and zeroized on drop.
pub enum ReleasedSecret {
    Text(Zeroizing<String>),
    TotpCode {
        code: Zeroizing<String>,
        seconds_remaining: u64,
        period: u64,
    },
    PasswordHistory(Value),
}

impl ReleasedSecret {
    /// Releases charged to the budget: one per password history entry
    /// (at least one), one for every other secret.
    pub fn release_cost(&self) -> usize {
        match self {
            ReleasedSecret::PasswordHistory(history) => {
                history.as_array().map_or(1, |entries| entries.len().max(1))
            }
            _ => 1,
        }
    }
}

impl Drop for ReleasedSecret {
    fn drop(&mut self) {
        if let ReleasedSecret::PasswordHistory(history) = self {
            crate::secret_memory::zeroize_json_value(history);
        }
    }
}

struct SecretRequest {
    item_id: String,
    field: SecretField,
}

fn parse_secret_request(request: &Value) -> Result<SecretRequest, ReleaseError> {
    let item_id = request
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| ReleaseError::new(error_code::INVALID_REQUEST, "Missing item 'id'."))?;
    let identifier = request
        .get("field")
        .and_then(Value::as_str)
        .ok_or_else(|| ReleaseError::new(error_code::INVALID_REQUEST, "Missing 'field'."))?;
    let field = SecretField::parse(identifier)
        .map_err(|message| ReleaseError::new(error_code::UNKNOWN_FIELD, message))?;
    Ok(SecretRequest {
        item_id: item_id.to_string(),
        field,
    })
}

fn field_empty(field: &SecretField) -> ReleaseError {
    ReleaseError::new(
        error_code::FIELD_EMPTY,
        format!("Field '{}' is empty for this item.", field.identifier()),
    )
}

fn located_text<'a>(item: &'a VaultItem, location: &SecretLocation) -> Option<&'a str> {
    match location {
        SecretLocation::Notes => item.notes.as_deref(),
        SecretLocation::Section(section, key) => section_value(item, section)
            .and_then(|s| s.get(*key))
            .and_then(Value::as_str),
        SecretLocation::CustomField(index) => item
            .fields
            .get(*index)
            .and_then(|f| f.get("value"))
            .and_then(Value::as_str),
    }
}

fn section_value<'a>(item: &'a VaultItem, section: &str) -> Option<&'a Value> {
    match section {
        "login" => item.login.as_ref(),
        "card" => item.card.as_ref(),
        "identity" => item.identity.as_ref(),
        _ => None,
    }
}

fn extract_text(item: &VaultItem, field: &SecretField) -> Result<ReleasedSecret, ReleaseError> {
    let location = field.text_location().ok_or_else(|| field_empty(field))?;
    located_text(item, &location)
        .filter(|text| !text.is_empty())
        .map(|text| ReleasedSecret::Text(Zeroizing::new(text.to_string())))
        .ok_or_else(|| field_empty(field))
}

fn extract_totp_code(item: &VaultItem) -> Result<ReleasedSecret, ReleaseError> {
    let seed = item
        .login
        .as_ref()
        .and_then(|login| login.get("totp"))
        .and_then(Value::as_str)
        .filter(|seed| !seed.is_empty())
        .ok_or_else(|| field_empty(&SecretField::LoginTotp))?;
    let generated = crate::totp::generate_totp(seed, None, 6, 30).ok_or_else(|| {
        ReleaseError::new(
            error_code::FIELD_EMPTY,
            "Field 'login.totp' does not hold a valid TOTP configuration.",
        )
    })?;
    Ok(ReleasedSecret::TotpCode {
        code: Zeroizing::new(generated.code),
        seconds_remaining: generated.ttl,
        period: generated.period,
    })
}

fn extract_password_history(item: &VaultItem) -> Result<ReleasedSecret, ReleaseError> {
    item.login
        .as_ref()
        .and_then(|login| login.get("password_history"))
        .filter(|history| crate::item_redaction::secret_is_present(Some(history)))
        .map(|history| ReleasedSecret::PasswordHistory(history.clone()))
        .ok_or_else(|| field_empty(&SecretField::PasswordHistory))
}

/// Copies one secret out of an item.
pub fn extract_secret(
    item: &VaultItem,
    field: &SecretField,
) -> Result<ReleasedSecret, ReleaseError> {
    match field {
        SecretField::LoginTotp => extract_totp_code(item),
        SecretField::PasswordHistory => extract_password_history(item),
        _ => extract_text(item, field),
    }
}

fn locate_and_extract(
    state: &DaemonState,
    request: &SecretRequest,
) -> Result<ReleasedSecret, ReleaseError> {
    if !state.vault_mgr.is_unlocked() {
        return Err(ReleaseError::new(
            error_code::VAULT_LOCKED,
            "Vault is locked. Please unlock the vault first.",
        ));
    }
    let items =
        state.vault_mgr.decrypted_items.read().map_err(|_| {
            ReleaseError::new(error_code::VAULT_LOCKED, "Vault items are unavailable.")
        })?;
    let item = items
        .iter()
        .find(|item| item.id == request.item_id)
        .ok_or_else(|| {
            ReleaseError::new(
                error_code::ITEM_NOT_FOUND,
                format!("Item '{}' not found in vault.", request.item_id),
            )
        })?;
    extract_secret(item, &request.field)
}

/// Charges `cost` releases to the budget, hard-locking the vault when they
/// do not fit. A poisoned budget fails closed against the short window.
pub fn charge_release(state: &DaemonState, cost: usize) -> Result<(), ReleaseError> {
    let outcome = state
        .release_budget
        .lock()
        .map_err(|_| RELEASE_LIMITS[0])
        .and_then(|mut budget| budget.try_record(Instant::now(), cost));
    let Err(limit) = outcome else {
        return Ok(());
    };
    crate::log_warn!(
        "omawarden:daemon",
        "More than {} secret releases within {}s; hard-locking the vault",
        limit.max_releases,
        limit.window.as_secs()
    );
    state.lock();
    Err(ReleaseError::new(
        error_code::RELEASE_LIMIT_EXCEEDED,
        format!(
            "Too many secrets were requested (more than {} within {} seconds). The vault has been locked.",
            limit.max_releases,
            limit.window.as_secs()
        ),
    ))
}

/// Withdraws a charge whose secret was never delivered, so failed requests
/// do not count toward the budget (contracts §3).
fn refund_release(state: &DaemonState, cost: usize) {
    if let Ok(mut budget) = state.release_budget.lock() {
        budget.refund_latest(cost);
    }
}

fn release_response(request: &SecretRequest, secret: &ReleasedSecret) -> Value {
    let mut response = Map::new();
    response.insert("ok".to_string(), true.into());
    response.insert("id".to_string(), request.item_id.clone().into());
    response.insert("field".to_string(), request.field.identifier().into());
    match secret {
        ReleasedSecret::Text(text) => {
            response.insert("value".to_string(), text.as_str().into());
        }
        ReleasedSecret::TotpCode {
            code,
            seconds_remaining,
            period,
        } => {
            response.insert("value".to_string(), code.as_str().into());
            response.insert("seconds_remaining".to_string(), (*seconds_remaining).into());
            response.insert("period".to_string(), (*period).into());
        }
        ReleasedSecret::PasswordHistory(history) => {
            response.insert("value".to_string(), history.clone());
        }
    }
    Value::Object(response)
}

fn reveal(state: &DaemonState, request: &Value) -> Result<Value, ReleaseError> {
    let request = parse_secret_request(request)?;
    let secret = locate_and_extract(state, &request)?;
    charge_release(state, secret.release_cost())?;
    Ok(release_response(&request, &secret))
}

/// `reveal_field {id, field}`: returns exactly one secret value.
pub fn handle_reveal_field(state: &DaemonState, request: &Value) -> Value {
    reveal(state, request).unwrap_or_else(|error| error.to_response())
}

fn copyable_text(secret: &ReleasedSecret) -> Result<&str, ReleaseError> {
    match secret {
        ReleasedSecret::Text(text) => Ok(text.as_str()),
        ReleasedSecret::TotpCode { code, .. } => Ok(code.as_str()),
        ReleasedSecret::PasswordHistory(_) => Err(ReleaseError::new(
            error_code::FIELD_NOT_COPYABLE,
            "Field 'password_history' cannot be copied; use reveal_field.",
        )),
    }
}

fn requested_clear_seconds(state: &DaemonState, request: &Value) -> Result<u64, ReleaseError> {
    let Some(raw) = request.get("clear_after_seconds") else {
        return Ok(state.copy_clear_seconds());
    };
    raw.as_u64()
        .filter(|seconds| COPY_CLEAR_SECONDS_RANGE.contains(seconds))
        .ok_or_else(|| {
            ReleaseError::new(
                error_code::INVALID_REQUEST,
                format!(
                    "clear_after_seconds must be an integer between {} and {}.",
                    COPY_CLEAR_SECONDS_RANGE.start(),
                    COPY_CLEAR_SECONDS_RANGE.end()
                ),
            )
        })
}

fn copy(state: &DaemonState, request: &Value) -> Result<Value, ReleaseError> {
    let clear_after = requested_clear_seconds(state, request)?;
    let request = parse_secret_request(request)?;
    let secret = locate_and_extract(state, &request)?;
    let text = copyable_text(&secret)?;
    let cost = secret.release_cost();
    charge_release(state, cost)?;
    let clipboard = state.clipboard();
    if !clipboard.copy_with_duration(text, true, Duration::from_secs(clear_after)) {
        refund_release(state, cost);
        return Err(ReleaseError::new(
            error_code::CLIPBOARD_FAILED,
            "Failed to copy to clipboard.",
        ));
    }
    Ok(json!({
        "ok": true,
        "id": request.item_id,
        "field": request.field.identifier(),
        "copied": true,
        "clear_after_seconds": clear_after,
    }))
}

/// `copy_field {id, field}`: the daemon copies one secret to the clipboard
/// (wl-copy over stdin, sensitive hint, auto-clear) and never returns it.
pub fn handle_copy_field(state: &DaemonState, request: &Value) -> Value {
    copy(state, request).unwrap_or_else(|error| error.to_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item_redaction::tests as fixtures;
    use crate::storage::StorageManager;
    use std::sync::Arc;

    fn unlocked_state(items: Vec<VaultItem>) -> (tempfile::TempDir, Arc<DaemonState>) {
        let dir = tempfile::tempdir().unwrap();
        let state = DaemonState::new(StorageManager::new(dir.path().join("data.json")), 15);
        *state.vault_mgr.decrypted_items.write().unwrap() = items;
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        (dir, Arc::new(state))
    }

    fn all_fixture_items() -> Vec<VaultItem> {
        vec![
            fixtures::login_item(),
            fixtures::card_item(),
            fixtures::identity_item(),
            fixtures::note_item(),
        ]
    }

    #[test]
    fn test_parse_field_identifiers() {
        for (name, field) in NAMED_SECRET_FIELDS {
            assert_eq!(SecretField::parse(name), Ok(*field));
            assert_eq!(field.identifier(), *name);
        }
        assert_eq!(
            SecretField::parse("custom.3"),
            Ok(SecretField::CustomField(3))
        );
        assert_eq!(SecretField::CustomField(3).identifier(), "custom.3");
        for invalid in [
            "",
            "custom.",
            "custom.-1",
            "custom.+1",
            "custom.x",
            "login",
            "password",
        ] {
            let error = SecretField::parse(invalid).unwrap_err();
            assert!(error.contains("Unknown field"), "{invalid}: {error}");
        }
    }

    #[test]
    fn test_reveal_field_returns_each_text_secret() {
        let (_dir, state) = unlocked_state(all_fixture_items());
        let cases = [
            ("login-1", "login.password", fixtures::LOGIN_PASSWORD),
            ("login-1", "notes", fixtures::NOTES),
            ("login-1", "custom.1", fixtures::HIDDEN_FIELD_VALUE),
            ("card-1", "card.number", fixtures::CARD_NUMBER),
            ("card-1", "card.code", fixtures::CARD_CODE),
            ("identity-1", "identity.ssn", fixtures::IDENTITY_SSN),
            (
                "identity-1",
                "identity.passport_number",
                fixtures::PASSPORT_NUMBER,
            ),
            (
                "identity-1",
                "identity.license_number",
                fixtures::LICENSE_NUMBER,
            ),
        ];
        for (id, field, expected) in cases {
            let response = handle_reveal_field(&state, &json!({ "id": id, "field": field }));
            assert_eq!(response["ok"], true, "{id} {field}: {response}");
            assert_eq!(response["id"], id);
            assert_eq!(response["field"], field);
            assert_eq!(response["value"], expected, "{id} {field}");
        }
    }

    #[test]
    fn test_reveal_totp_returns_code_and_never_the_seed() {
        let (_dir, state) = unlocked_state(all_fixture_items());
        let response =
            handle_reveal_field(&state, &json!({ "id": "login-1", "field": "login.totp" }));
        assert_eq!(response["ok"], true, "{response}");
        let code = response["value"].as_str().unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert!(response["seconds_remaining"].as_u64().unwrap() <= 30);
        assert_eq!(response["period"], 30);
        assert!(!response.to_string().contains(fixtures::LOGIN_TOTP_SEED));
    }

    #[test]
    fn test_reveal_password_history_returns_entries() {
        let (_dir, state) = unlocked_state(all_fixture_items());
        let response = handle_reveal_field(
            &state,
            &json!({ "id": "login-1", "field": "password_history" }),
        );
        assert_eq!(response["ok"], true, "{response}");
        assert_eq!(response["value"][0]["password"], fixtures::HISTORY_PASSWORD);
        assert!(response["value"][0]["last_used_date"].is_string());
    }

    #[test]
    fn test_reveal_rejects_unknown_item_field_and_empty_values() {
        let (_dir, state) = unlocked_state(all_fixture_items());
        let cases = [
            (
                json!({ "id": "missing", "field": "notes" }),
                error_code::ITEM_NOT_FOUND,
            ),
            (
                json!({ "id": "login-1", "field": "login.secret" }),
                error_code::UNKNOWN_FIELD,
            ),
            (
                json!({ "id": "login-1", "field": "custom.99" }),
                error_code::FIELD_EMPTY,
            ),
            (
                json!({ "id": "card-1", "field": "login.password" }),
                error_code::FIELD_EMPTY,
            ),
            (
                json!({ "id": "login-1", "field": "custom.3" }),
                error_code::FIELD_EMPTY,
            ),
            (json!({ "field": "notes" }), error_code::INVALID_REQUEST),
            (json!({ "id": "login-1" }), error_code::INVALID_REQUEST),
        ];
        for (request, expected_code) in cases {
            let response = handle_reveal_field(&state, &request);
            assert_eq!(response["ok"], false, "{request}: {response}");
            assert_eq!(
                response["error_code"], expected_code,
                "{request}: {response}"
            );
            assert!(response["error"].as_str().is_some_and(|e| !e.is_empty()));
        }
        assert_eq!(
            state.release_budget.lock().unwrap().recorded(),
            0,
            "failed requests are not charged to the budget"
        );
    }

    #[test]
    fn test_reveal_requires_an_unlocked_vault() {
        let (_dir, state) = unlocked_state(all_fixture_items());
        *state.vault_mgr.is_unlocked.write().unwrap() = false;
        let response = handle_reveal_field(&state, &json!({ "id": "login-1", "field": "notes" }));
        assert_eq!(response["error_code"], error_code::VAULT_LOCKED);
    }

    fn mock_clipboard(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let clip_file = dir.join("clipboard.txt");
        let args_file = dir.join("args.txt");
        let program = dir.join("mock-wl-copy");
        crate::write_test_executable(
            &program,
            format!(
                "#!/bin/sh\necho \"$@\" >> '{}'\ncase \"$1\" in --clear) exit 0;; esac\ncat > '{}'\n",
                args_file.display(),
                clip_file.display()
            ),
        );
        (program, clip_file)
    }

    #[test]
    fn test_copy_field_copies_each_secret_without_returning_it() {
        let (dir, state) = unlocked_state(all_fixture_items());
        let (program, clip_file) = mock_clipboard(dir.path());
        let mut state = Arc::try_unwrap(state).ok().unwrap();
        state.clipboard_program = program.to_string_lossy().to_string();
        let state = Arc::new(state);
        let cases = [
            ("login-1", "login.password", Some(fixtures::LOGIN_PASSWORD)),
            ("card-1", "card.number", Some(fixtures::CARD_NUMBER)),
            ("card-1", "card.code", Some(fixtures::CARD_CODE)),
            ("identity-1", "identity.ssn", Some(fixtures::IDENTITY_SSN)),
            ("login-1", "custom.1", Some(fixtures::HIDDEN_FIELD_VALUE)),
            ("note-1", "notes", Some(fixtures::NOTES)),
            ("login-1", "login.totp", None),
        ];
        for (id, field, expected) in cases {
            let response = handle_copy_field(&state, &json!({ "id": id, "field": field }));
            assert_eq!(response["ok"], true, "{id} {field}: {response}");
            assert_eq!(response["copied"], true);
            assert!(
                response.get("value").is_none(),
                "copy never returns the value"
            );
            let copied = std::fs::read_to_string(&clip_file).unwrap();
            match expected {
                Some(secret) => assert_eq!(copied, secret),
                None => assert_eq!(copied.len(), 6, "TOTP copies the current code"),
            }
            for secret in [fixtures::LOGIN_PASSWORD, fixtures::CARD_NUMBER] {
                assert!(!response.to_string().contains(secret));
            }
        }
        let args = std::fs::read_to_string(dir.path().join("args.txt")).unwrap();
        assert!(
            args.lines()
                .all(|line| line.split_whitespace().any(|arg| arg == "--sensitive")),
            "every copy uses the sensitive hint: {args}"
        );
    }

    #[test]
    fn test_copy_field_refuses_password_history_and_bad_clear_after() {
        let (_dir, state) = unlocked_state(all_fixture_items());
        let response = handle_copy_field(
            &state,
            &json!({ "id": "login-1", "field": "password_history" }),
        );
        assert_eq!(response["error_code"], error_code::FIELD_NOT_COPYABLE);
        for bad in [json!(0), json!(3601), json!("30"), json!(-5)] {
            let response = handle_copy_field(
                &state,
                &json!({ "id": "login-1", "field": "notes", "clear_after_seconds": bad }),
            );
            assert_eq!(response["error_code"], error_code::INVALID_REQUEST, "{bad}");
        }
        assert_eq!(state.release_budget.lock().unwrap().recorded(), 0);
    }

    #[test]
    fn test_failed_clipboard_write_is_not_charged_to_the_budget() {
        let (dir, state) = unlocked_state(all_fixture_items());
        let mut state = Arc::try_unwrap(state).ok().unwrap();
        state.clipboard_program = dir
            .path()
            .join("missing-clipboard-program")
            .to_string_lossy()
            .to_string();
        let state = Arc::new(state);
        let response = handle_copy_field(
            &state,
            &json!({ "id": "login-1", "field": "login.password" }),
        );
        assert_eq!(response["error_code"], error_code::CLIPBOARD_FAILED);
        assert_eq!(state.release_budget.lock().unwrap().recorded(), 0);
    }

    #[test]
    fn test_release_budget_window_arithmetic() {
        let mut budget = ReleaseBudget::default();
        let start = Instant::now();
        for _ in 0..MAX_SECRET_RELEASES_PER_WINDOW {
            assert_eq!(budget.try_record(start, 1), Ok(()));
        }
        assert_eq!(
            budget.try_record(start + Duration::from_secs(59), 1),
            Err(RELEASE_LIMITS[0])
        );
        assert_eq!(budget.recorded(), MAX_SECRET_RELEASES_PER_WINDOW);
        let later = start + SECRET_RELEASE_WINDOW;
        assert_eq!(
            budget.try_record(later, 1),
            Ok(()),
            "releases older than the short window no longer count there"
        );
        assert_eq!(budget.recorded_within(later, SECRET_RELEASE_WINDOW), 1);
        assert_eq!(
            budget.recorded_within(later, SECRET_RELEASE_HOURLY_WINDOW),
            MAX_SECRET_RELEASES_PER_WINDOW + 1
        );
    }

    #[test]
    fn test_release_budget_hourly_window_stops_paced_extraction() {
        let mut budget = ReleaseBudget::default();
        let start = Instant::now();
        let batches = MAX_SECRET_RELEASES_PER_HOUR / MAX_SECRET_RELEASES_PER_WINDOW;
        for batch in 0..batches {
            let at = start + SECRET_RELEASE_WINDOW * batch as u32;
            for _ in 0..MAX_SECRET_RELEASES_PER_WINDOW {
                assert_eq!(budget.try_record(at, 1), Ok(()), "batch {batch}");
            }
        }
        let paced = start + SECRET_RELEASE_WINDOW * batches as u32;
        assert_eq!(
            budget.try_record(paced, 1),
            Err(RELEASE_LIMITS[1]),
            "30 releases a minute must not run past the hourly limit"
        );
        assert_eq!(
            budget.try_record(start + SECRET_RELEASE_HOURLY_WINDOW, 1),
            Ok(()),
            "the first batch leaves the hourly window after an hour"
        );
    }

    #[test]
    fn test_release_budget_charges_and_refunds_a_multiple_cost() {
        let mut budget = ReleaseBudget::default();
        let now = Instant::now();
        assert_eq!(
            budget.try_record(now, MAX_SECRET_RELEASES_PER_WINDOW - 2),
            Ok(())
        );
        assert_eq!(budget.try_record(now, 3), Err(RELEASE_LIMITS[0]));
        assert_eq!(budget.recorded(), MAX_SECRET_RELEASES_PER_WINDOW - 2);
        assert_eq!(budget.try_record(now, 2), Ok(()));
        budget.refund_latest(2);
        assert_eq!(budget.recorded(), MAX_SECRET_RELEASES_PER_WINDOW - 2);
    }

    #[test]
    fn test_password_history_is_charged_one_release_per_entry() {
        let mut item = fixtures::login_item();
        let entry = json!({ "password": fixtures::HISTORY_PASSWORD, "last_used_date": null });
        item.login.as_mut().unwrap()["password_history"] =
            Value::Array(vec![entry.clone(), entry.clone(), entry]);
        let (_dir, state) = unlocked_state(vec![item]);
        let response = handle_reveal_field(
            &state,
            &json!({ "id": "login-1", "field": "password_history" }),
        );
        assert_eq!(response["ok"], true, "{response}");
        assert_eq!(state.release_budget.lock().unwrap().recorded(), 3);

        let single = ReleasedSecret::PasswordHistory(json!([]));
        assert_eq!(single.release_cost(), 1, "an empty history still costs one");
    }

    #[test]
    fn test_password_history_larger_than_the_window_is_refused_and_locks() {
        let mut item = fixtures::login_item();
        let entry = json!({ "password": fixtures::HISTORY_PASSWORD, "last_used_date": null });
        item.login.as_mut().unwrap()["password_history"] =
            Value::Array(vec![entry; MAX_SECRET_RELEASES_PER_WINDOW + 1]);
        let (_dir, state) = unlocked_state(vec![item]);
        let response = handle_reveal_field(
            &state,
            &json!({ "id": "login-1", "field": "password_history" }),
        );
        assert_eq!(response["error_code"], error_code::RELEASE_LIMIT_EXCEEDED);
        assert!(response.get("value").is_none());
        assert!(!state.vault_mgr.is_unlocked());
    }

    #[test]
    fn test_release_budget_exhaustion_hard_locks_and_purges() {
        let (_dir, state) = unlocked_state(all_fixture_items());
        let request = json!({ "id": "login-1", "field": "login.password" });
        for attempt in 0..MAX_SECRET_RELEASES_PER_WINDOW {
            let response = handle_reveal_field(&state, &request);
            assert_eq!(response["ok"], true, "attempt {attempt}: {response}");
        }
        let response = handle_reveal_field(&state, &request);
        assert_eq!(response["ok"], false);
        assert_eq!(response["error_code"], error_code::RELEASE_LIMIT_EXCEEDED);
        assert!(response.get("value").is_none());
        assert!(
            !state.vault_mgr.is_unlocked(),
            "budget exhaustion hard-locks"
        );
        assert!(state.vault_mgr.decrypted_items.read().unwrap().is_empty());
        assert!(state.vault_mgr.user_key.read().unwrap().is_none());
        assert!(!state.vault_mgr.quick_unlock_available());
        assert_eq!(
            state.release_budget.lock().unwrap().recorded(),
            0,
            "a hard lock resets the budget for the next session"
        );
    }

    #[test]
    fn test_copy_and_reveal_share_one_budget() {
        let (dir, state) = unlocked_state(all_fixture_items());
        let (program, _clip) = mock_clipboard(dir.path());
        let mut state = Arc::try_unwrap(state).ok().unwrap();
        state.clipboard_program = program.to_string_lossy().to_string();
        let state = Arc::new(state);
        let request = json!({ "id": "card-1", "field": "card.code" });
        for attempt in 0..MAX_SECRET_RELEASES_PER_WINDOW {
            let response = if attempt % 2 == 0 {
                handle_reveal_field(&state, &request)
            } else {
                handle_copy_field(&state, &request)
            };
            assert_eq!(response["ok"], true, "attempt {attempt}: {response}");
        }
        let response = handle_copy_field(&state, &request);
        assert_eq!(response["error_code"], error_code::RELEASE_LIMIT_EXCEEDED);
        assert!(!state.vault_mgr.is_unlocked());
    }
}
