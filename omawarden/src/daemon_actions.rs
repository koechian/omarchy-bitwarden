//! Request dispatch for the resident daemon: one table entry per action with
//! its access requirement, its effect on the idle timer, and a small handler.
//! See docs/agents/contracts.md section 3 for the wire contract.

use std::time::Duration;

use serde_json::{json, Value};

use crate::daemon::DaemonState;

/// What the connection handler does after an action ran.
#[derive(Debug)]
pub enum ActionOutcome {
    Respond(Value),
    /// Write the response, then terminate the daemon (`stop`).
    RespondThenExit(Value),
}

type ActionHandler = fn(&DaemonState, &Value) -> ActionOutcome;

/// One daemon action.
pub struct ActionSpec {
    pub name: &'static str,
    /// Refused with a locked error while the vault is locked.
    pub requires_unlocked: bool,
    /// Resets the idle auto-lock timer. Only browsing the unlocked vault
    /// (`search`, `get_item`) and a successful unlock count as activity.
    /// Polling (`ping`, `status`), loading (`list`), background work
    /// (`sync`), secret releases (`reveal_field`, `copy_field`,
    /// `copy_sequence`) and actions
    /// that also work while locked (`copy`, `generate_password`, `totp`)
    /// never do: otherwise a caller could keep the vault unlocked by
    /// releasing secrets at a steady pace, or by periodic calls that need no
    /// key at all (ADR 0010, ADR 0027).
    pub records_activity: bool,
    handler: ActionHandler,
}

const fn action(
    name: &'static str,
    requires_unlocked: bool,
    records_activity: bool,
    handler: ActionHandler,
) -> ActionSpec {
    ActionSpec {
        name,
        requires_unlocked,
        records_activity,
        handler,
    }
}

/// `unlock` and `quick_unlock` reset the idle timer inside the unlock itself,
/// so they are not marked here.
pub const ACTIONS: &[ActionSpec] = &[
    action("ping", false, false, handle_ping),
    action("status", false, false, handle_status),
    action("stop", false, false, handle_stop),
    action("unlock", false, false, handle_unlock),
    action("quick_unlock", false, false, handle_quick_unlock),
    action("wipe_quick_unlock", false, false, handle_wipe_quick_unlock),
    action("set_quick_unlock", false, false, handle_set_quick_unlock),
    action("lock", false, false, handle_lock),
    action("sync", true, false, handle_sync),
    action("list", true, false, handle_list),
    action("search", true, true, handle_search),
    action("get_item", true, true, handle_get_item),
    action("reveal_field", true, false, handle_reveal_field),
    action("copy_field", true, false, handle_copy_field),
    action("copy_sequence", true, false, handle_copy_sequence),
    action("totp", false, false, handle_totp_from_secret),
    action("copy", false, false, handle_copy_text),
    action("generate_password", false, false, handle_generate_password),
    action("set_auto_lock", false, false, handle_set_auto_lock),
    action("clear_item_usage", false, false, handle_clear_item_usage),
];

/// Shortest accepted idle auto-lock interval.
pub const MIN_AUTO_LOCK: Duration = Duration::from_secs(60);
/// Longest accepted idle auto-lock interval: the 12-hour session ceiling.
pub const MAX_AUTO_LOCK: Duration = Duration::from_secs(12 * 3600);

pub fn find_action(name: &str) -> Option<&'static ActionSpec> {
    ACTIONS.iter().find(|spec| spec.name == name)
}

/// Whether an action resets the idle timer. Client-supplied overrides (the
/// former `"touch"` field) are not consulted.
pub fn action_records_activity(name: &str) -> bool {
    find_action(name).is_some_and(|spec| spec.records_activity)
}

fn locked_response() -> Value {
    json!({
        "ok": false,
        "error": "Vault is locked. Please unlock the vault first.",
        "error_code": crate::secret_access::error_code::VAULT_LOCKED,
    })
}

/// Runs the action named in `request`.
pub fn dispatch(state: &DaemonState, request: &Value) -> ActionOutcome {
    let name = request.get("action").and_then(Value::as_str).unwrap_or("");
    let Some(spec) = find_action(name) else {
        return ActionOutcome::Respond(
            json!({ "ok": false, "error": format!("Unknown action: {}", name) }),
        );
    };
    if spec.requires_unlocked && !state.vault_mgr.is_unlocked() {
        return ActionOutcome::Respond(locked_response());
    }
    if spec.records_activity {
        state.touch_activity();
    }
    (spec.handler)(state, request)
}

fn respond(value: Value) -> ActionOutcome {
    ActionOutcome::Respond(value)
}

fn text_argument<'a>(request: &'a Value, key: &str) -> Option<&'a str> {
    request.get(key).and_then(Value::as_str)
}

fn handle_ping(state: &DaemonState, _request: &Value) -> ActionOutcome {
    respond(json!({
        "ok": true,
        "pong": true,
        "version": env!("CARGO_PKG_VERSION"),
        "commit": env!("GIT_HASH"),
        "unlocked": state.vault_mgr.is_unlocked(),
        "quick_unlock": state.quick_unlock_ready(),
        // The daemon's cached setting, so `auth quick-unlock-check` reports
        // enabled/available from one source.
        "quick_unlock_enabled": state.quick_unlock_enabled(),
        // False means mlock failed at least once (degraded protection).
        "memory_locked": !crate::locked::mlock_fallback_active(),
    }))
}

fn handle_status(state: &DaemonState, _request: &Value) -> ActionOutcome {
    respond(state.vault_mgr.get_status())
}

fn handle_stop(state: &DaemonState, _request: &Value) -> ActionOutcome {
    state.lock();
    ActionOutcome::RespondThenExit(json!({ "ok": true }))
}

fn unlocked_response(count: usize) -> Value {
    json!({ "ok": true, "status": "unlocked", "items_count": count })
}

fn handle_unlock(state: &DaemonState, request: &Value) -> ActionOutcome {
    let password = text_argument(request, "password").unwrap_or("");
    match state.unlock(password) {
        Ok(count) => respond(unlocked_response(count)),
        Err(e) => respond(json!({ "ok": false, "status": "locked", "error": e })),
    }
}

/// ADR 0025: system-authentication re-unlock from the retained key.
fn handle_quick_unlock(state: &DaemonState, _request: &Value) -> ActionOutcome {
    match state.perform_quick_unlock() {
        Ok(count) => {
            state.synchronize_sleep_inhibitor();
            respond(unlocked_response(count))
        }
        Err(reason) => respond(json!({ "ok": false, "status": "locked", "error": reason })),
    }
}

/// Configuration side effect: drop the retained key without locking.
fn handle_wipe_quick_unlock(state: &DaemonState, _request: &Value) -> ActionOutcome {
    state.vault_mgr.wipe_quick_unlock();
    state.synchronize_sleep_inhibitor();
    respond(json!({ "ok": true }))
}

/// Refreshes the cached `quick_unlock` setting (sent by
/// `config set --quick-unlock`). Disabling it also wipes the retained key.
fn handle_set_quick_unlock(state: &DaemonState, request: &Value) -> ActionOutcome {
    let enabled = request
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    state.set_quick_unlock_enabled(enabled);
    if !enabled {
        state.vault_mgr.wipe_quick_unlock();
        state.synchronize_sleep_inhibitor();
    }
    respond(json!({ "ok": true, "quick_unlock_enabled": enabled }))
}

fn handle_lock(state: &DaemonState, _request: &Value) -> ActionOutcome {
    state.lock();
    respond(json!({ "ok": true, "status": "locked" }))
}

fn handle_sync(state: &DaemonState, request: &Value) -> ActionOutcome {
    let client_context: Option<crate::api::ClientContext> = request
        .get("client")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .filter(|c: &crate::api::ClientContext| c.is_valid());
    match state.sync_with_client(client_context.as_ref()) {
        Ok(count) => respond(json!({ "ok": true, "ciphers_count": count })),
        Err(e) => respond(json!({ "ok": false, "error": e })),
    }
}

/// Every item, redacted, favorites first; `category` optionally filters by
/// type name (`login`, `card`, `identity`, `note`).
fn handle_list(state: &DaemonState, request: &Value) -> ActionOutcome {
    let category = text_argument(request, "category");
    let items = state.vault_mgr.search_items("", category);
    respond(redacted_listing(state, &items))
}

fn handle_search(state: &DaemonState, request: &Value) -> ActionOutcome {
    let query = text_argument(request, "query").unwrap_or("");
    let category = text_argument(request, "category");
    let items = state.vault_mgr.search_items(query, category);
    respond(redacted_listing(state, &items))
}

/// The redacted items, each with its `usage_score` and `last_used_at`.
fn redacted_listing(state: &DaemonState, items: &[crate::vault::VaultItem]) -> Value {
    let mut listing = crate::item_redaction::redact_items(items);
    state.annotate_item_usage(&mut listing);
    listing
}

fn redacted_item(state: &DaemonState, item: &crate::vault::VaultItem) -> Value {
    let mut view = crate::item_redaction::redact_item(item);
    state.annotate_single_item_usage(&mut view);
    view
}

/// Logout (ADR 0029): forgets every recorded item use and deletes the
/// usage file. Works while locked; locking alone keeps the record.
fn handle_clear_item_usage(state: &DaemonState, _request: &Value) -> ActionOutcome {
    state.clear_item_usage();
    respond(json!({ "ok": true }))
}

fn handle_get_item(state: &DaemonState, request: &Value) -> ActionOutcome {
    let query = text_argument(request, "query").unwrap_or("");
    let category = text_argument(request, "category");
    match state.vault_mgr.find_item(query, category) {
        Some(item) => respond(json!({
            "ok": true,
            "item": redacted_item(state, &item),
        })),
        None => respond(json!({
            "ok": false,
            "error": format!("Item '{}' not found in vault", query),
            "error_code": crate::secret_access::error_code::ITEM_NOT_FOUND,
        })),
    }
}

fn handle_reveal_field(state: &DaemonState, request: &Value) -> ActionOutcome {
    respond(crate::secret_access::handle_reveal_field(state, request))
}

fn handle_copy_field(state: &DaemonState, request: &Value) -> ActionOutcome {
    respond(crate::secret_access::handle_copy_field(state, request))
}

fn handle_copy_sequence(state: &DaemonState, request: &Value) -> ActionOutcome {
    respond(crate::sequence_release::handle_copy_sequence(
        state, request,
    ))
}

/// Generates a code from a seed the caller supplies. Codes for vault items
/// are released through `reveal_field` with `login.totp`, which is counted
/// against the release budget.
fn handle_totp_from_secret(_state: &DaemonState, request: &Value) -> ActionOutcome {
    if request.get("query").is_some() || request.get("id").is_some() {
        return respond(json!({
            "ok": false,
            "error": "Item TOTP codes are released through reveal_field with field 'login.totp'.",
            "error_code": crate::secret_access::error_code::INVALID_REQUEST,
        }));
    }
    let Some(secret) = text_argument(request, "secret") else {
        return respond(json!({ "ok": false, "error": "Missing TOTP secret" }));
    };
    match crate::totp::generate_totp(secret, None, 6, 30) {
        Some(res) => respond(json!({
            "ok": true, "code": res.code, "ttl": res.ttl, "period": res.period
        })),
        None => respond(json!({ "ok": false, "error": "Invalid TOTP secret" })),
    }
}

/// Copies caller-supplied text that is not a vault secret (username, URI, a
/// generated password). `sensitive` adds the clipboard-manager hint and the
/// auto-clear; generated passwords must be sent with `sensitive: true`.
fn handle_copy_text(state: &DaemonState, request: &Value) -> ActionOutcome {
    let text = text_argument(request, "text").unwrap_or("");
    let sensitive = request
        .get("sensitive")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let timeout = request.get("timeout").and_then(Value::as_i64).unwrap_or(30);
    let clipboard = state.clipboard();
    if clipboard.copy(text, sensitive, timeout) {
        respond(json!({ "ok": true }))
    } else {
        respond(json!({ "ok": false, "error": "Failed to copy to clipboard" }))
    }
}

fn unsigned_argument(request: &Value, key: &str, default: usize) -> usize {
    request
        .get(key)
        .and_then(Value::as_u64)
        .map_or(default, |n| n as usize)
}

fn boolean_argument(request: &Value, key: &str, default: bool) -> bool {
    request.get(key).and_then(Value::as_bool).unwrap_or(default)
}

fn passphrase_options(request: &Value) -> crate::generator::PassphraseOptions {
    crate::generator::PassphraseOptions {
        words: unsigned_argument(request, "words", crate::generator::DEFAULT_PASSPHRASE_WORDS),
        separator: text_argument(request, "separator")
            .unwrap_or("-")
            .to_string(),
        capitalize: boolean_argument(request, "capitalize", false),
    }
}

fn password_options(request: &Value) -> crate::generator::PasswordOptions {
    crate::generator::PasswordOptions {
        length: unsigned_argument(request, "length", crate::generator::DEFAULT_PASSWORD_LENGTH),
        uppercase: boolean_argument(request, "uppercase", true),
        lowercase: boolean_argument(request, "lowercase", true),
        numbers: boolean_argument(request, "numbers", true),
        special: boolean_argument(request, "special", true),
        avoid_ambiguous: boolean_argument(request, "avoid_ambiguous", false),
        min_numbers: unsigned_argument(request, "min_numbers", 1),
        min_special: unsigned_argument(request, "min_special", 1),
    }
}

fn handle_generate_password(_state: &DaemonState, request: &Value) -> ActionOutcome {
    let generated = if boolean_argument(request, "passphrase", false) {
        crate::generator::generate_passphrase(&passphrase_options(request))
    } else {
        crate::generator::generate_password(&password_options(request))
    };
    match generated {
        Ok(secret) => respond(json!({
            "ok": true,
            "password": secret.value,
            "entropy": secret.entropy,
            "type": secret.secret_type,
        })),
        Err(e) => respond(json!({ "ok": false, "error": e })),
    }
}

/// Validates an idle auto-lock interval: `MIN_AUTO_LOCK..=MAX_AUTO_LOCK`.
/// Zero (never lock) is refused.
pub fn validate_auto_lock(seconds: u64) -> Result<Duration, String> {
    let duration = Duration::from_secs(seconds);
    if (MIN_AUTO_LOCK..=MAX_AUTO_LOCK).contains(&duration) {
        return Ok(duration);
    }
    Err(format!(
        "Auto-lock must be between {} and {} seconds ({} minute to {} hours); disabling it is not supported.",
        MIN_AUTO_LOCK.as_secs(),
        MAX_AUTO_LOCK.as_secs(),
        MIN_AUTO_LOCK.as_secs() / 60,
        MAX_AUTO_LOCK.as_secs() / 3600
    ))
}

fn requested_auto_lock_seconds(request: &Value) -> Option<u64> {
    let seconds = request.get("auto_lock_seconds").and_then(Value::as_u64);
    let minutes = request
        .get("auto_lock")
        .or_else(|| request.get("auto_lock_minutes"))
        .and_then(Value::as_u64)
        .map(|minutes| minutes.saturating_mul(60));
    seconds.or(minutes)
}

fn handle_set_auto_lock(state: &DaemonState, request: &Value) -> ActionOutcome {
    let Some(seconds) = requested_auto_lock_seconds(request) else {
        return respond(json!({
            "ok": false,
            "error": "Missing auto_lock_seconds or auto_lock_minutes (non-negative integer).",
        }));
    };
    match validate_auto_lock(seconds) {
        Ok(duration) => {
            state.set_auto_lock_duration(duration);
            respond(json!({ "ok": true, "auto_lock_seconds": seconds }))
        }
        Err(error) => respond(json!({ "ok": false, "error": error })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_every_action_name_is_unique() {
        for (index, spec) in ACTIONS.iter().enumerate() {
            assert!(
                ACTIONS[index + 1..]
                    .iter()
                    .all(|other| other.name != spec.name),
                "duplicate action {}",
                spec.name
            );
        }
    }

    #[test]
    fn test_activity_is_recorded_only_by_user_actions() {
        for name in ["search", "get_item"] {
            assert!(action_records_activity(name), "{name}");
        }
        for name in [
            "reveal_field",
            "copy_field",
            "copy_sequence",
            "copy",
            "generate_password",
            "ping",
            "status",
            "stop",
            "lock",
            "list",
            "sync",
            "totp",
            "set_auto_lock",
            "clear_item_usage",
            "unknown",
            "",
        ] {
            assert!(!action_records_activity(name), "{name}");
        }
    }

    #[test]
    fn test_secret_reading_actions_require_an_unlocked_vault() {
        for name in [
            "list",
            "search",
            "get_item",
            "reveal_field",
            "copy_field",
            "copy_sequence",
            "sync",
        ] {
            assert!(find_action(name).unwrap().requires_unlocked, "{name}");
        }
    }

    #[test]
    fn test_clear_item_usage_works_while_locked() {
        let spec = find_action("clear_item_usage").unwrap();
        assert!(!spec.requires_unlocked, "logout may happen while locked");
    }

    #[test]
    fn test_validate_auto_lock_range() {
        assert!(
            validate_auto_lock(0).is_err(),
            "zero must not disable auto-lock"
        );
        assert!(validate_auto_lock(59).is_err());
        assert_eq!(validate_auto_lock(60), Ok(MIN_AUTO_LOCK));
        assert_eq!(validate_auto_lock(900), Ok(Duration::from_secs(900)));
        assert_eq!(validate_auto_lock(43_200), Ok(MAX_AUTO_LOCK));
        let error = validate_auto_lock(43_201).unwrap_err();
        assert!(error.contains("between 60 and 43200 seconds"), "{error}");
    }

    #[test]
    fn test_requested_auto_lock_seconds_prefers_seconds() {
        assert_eq!(
            requested_auto_lock_seconds(
                &json!({ "auto_lock_seconds": 90, "auto_lock_minutes": 5 })
            ),
            Some(90)
        );
        assert_eq!(
            requested_auto_lock_seconds(&json!({ "auto_lock_minutes": 5 })),
            Some(300)
        );
        assert_eq!(
            requested_auto_lock_seconds(&json!({ "auto_lock": 2 })),
            Some(120)
        );
        assert_eq!(requested_auto_lock_seconds(&json!({})), None);
    }
}
