//! `copy_sequence {id, fields, clear_after_seconds?}` (ADR 0028): stages
//! several secrets of one item on the clipboard in order, so the first paste
//! yields the first field, the second paste the second field, and so on.
//!
//! Every field is validated before anything is charged: it must be a known
//! identifier, present on the item and copyable (the `copy_field` rules;
//! `password_history` is refused). The sequence then costs one release per
//! stage, charged when it is accepted and refunded in full when it cannot
//! start. The values stay in the daemon; the response names the fields only.

use std::time::Duration;

use serde_json::{json, Value};

use crate::daemon::DaemonState;
use crate::paste_sequence::{StageValue, MAX_SEQUENCE_STAGES};
use crate::secret_access::{
    charge_release, error_code, parse_field, password_history_not_copyable, refund_release,
    requested_clear_seconds, requested_item_id, text_secret, totp_seed, with_unlocked_item,
    ReleaseError, SecretField,
};
use crate::vault::VaultItem;

/// A validated `copy_sequence` request.
struct SequenceRequest {
    item_id: String,
    fields: Vec<SecretField>,
}

fn invalid_fields() -> ReleaseError {
    ReleaseError::new(
        error_code::INVALID_REQUEST,
        format!("'fields' must be an array of 1 to {MAX_SEQUENCE_STAGES} field identifiers."),
    )
}

/// The identifiers of `fields`: an array of 1 to `MAX_SEQUENCE_STAGES`
/// strings.
fn requested_identifiers(request: &Value) -> Result<Vec<&str>, ReleaseError> {
    let entries = request
        .get("fields")
        .and_then(Value::as_array)
        .filter(|entries| (1..=MAX_SEQUENCE_STAGES).contains(&entries.len()))
        .ok_or_else(invalid_fields)?;
    entries
        .iter()
        .map(|entry| entry.as_str().ok_or_else(invalid_fields))
        .collect()
}

/// Parses one stage's field; `password_history` cannot be staged.
fn parse_stage_field(identifier: &str) -> Result<SecretField, ReleaseError> {
    match parse_field(identifier)? {
        SecretField::PasswordHistory => Err(password_history_not_copyable()),
        field => Ok(field),
    }
}

fn parse_sequence_request(request: &Value) -> Result<SequenceRequest, ReleaseError> {
    let item_id = requested_item_id(request)?;
    let fields = requested_identifiers(request)?
        .into_iter()
        .map(parse_stage_field)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SequenceRequest { item_id, fields })
}

/// The value one stage serves: the text of a text field, or the TOTP seed,
/// from which a fresh code is computed at each serve.
fn stage_value(item: &VaultItem, field: &SecretField) -> Result<StageValue, ReleaseError> {
    match field {
        SecretField::LoginTotp => totp_seed(item).map(StageValue::TotpSeed),
        _ => text_secret(item, field).map(StageValue::Text),
    }
}

fn stage_values(item: &VaultItem, fields: &[SecretField]) -> Result<Vec<StageValue>, ReleaseError> {
    fields
        .iter()
        .map(|field| stage_value(item, field))
        .collect()
}

fn copy_sequence(state: &DaemonState, request: &Value) -> Result<Value, ReleaseError> {
    let clear_after = requested_clear_seconds(state, request)?;
    let request = parse_sequence_request(request)?;
    let stages = with_unlocked_item(state, &request.item_id, |item| {
        stage_values(item, &request.fields)
    })?;
    let cost = stages.len();
    charge_release(state, cost)?;
    if let Err(message) = state.start_paste_sequence(stages, Duration::from_secs(clear_after)) {
        refund_release(state, cost);
        crate::log_warn!(
            "omawarden:clipboard",
            "Paste sequence could not start: {}",
            message
        );
        return Err(ReleaseError::new(
            error_code::CLIPBOARD_FAILED,
            format!("Failed to stage the paste sequence: {message}"),
        ));
    }
    state.record_item_use(&request.item_id);
    let identifiers: Vec<String> = request.fields.iter().map(SecretField::identifier).collect();
    Ok(json!({
        "ok": true,
        "id": request.item_id,
        "fields": identifiers,
        "clear_after_seconds": clear_after,
    }))
}

/// `copy_sequence {id, fields, clear_after_seconds?}`: the daemon stages the
/// fields on the clipboard, one per paste, and never returns their values.
/// Responds once the first stage is the selection.
pub fn handle_copy_sequence(state: &DaemonState, request: &Value) -> Value {
    copy_sequence(state, request).unwrap_or_else(|error| error.to_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item_redaction::tests as fixtures;
    use crate::secret_access::MAX_SECRET_RELEASES_PER_WINDOW;
    use crate::selection_source::SequenceControl;
    use crate::storage::StorageManager;
    use std::sync::{Arc, Mutex};

    /// What the injected launcher received: each stage rendered at a fixed
    /// time, and the lifetime.
    type LaunchRecord = Arc<Mutex<Vec<(Vec<Vec<u8>>, Duration)>>>;

    const RENDER_TIMESTAMP: u64 = 1_234_567_890;

    fn state_with_launcher(
        launcher: Arc<crate::selection_source::PasteSequenceLauncher>,
    ) -> (tempfile::TempDir, Arc<DaemonState>) {
        let dir = tempfile::tempdir().unwrap();
        let mut state = DaemonState::new(StorageManager::new(dir.path().join("data.json")), 15);
        *state.vault_mgr.decrypted_items.write().unwrap() = vec![
            fixtures::login_item(),
            fixtures::card_item(),
            fixtures::note_item(),
        ];
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        state.paste_sequence_launcher = launcher;
        (dir, Arc::new(state))
    }

    fn recording_state() -> (tempfile::TempDir, Arc<DaemonState>, LaunchRecord) {
        let record: LaunchRecord = Arc::default();
        let sink = Arc::clone(&record);
        let launcher: Arc<crate::selection_source::PasteSequenceLauncher> =
            Arc::new(move |stages: Vec<StageValue>, lifetime| {
                let rendered = stages
                    .iter()
                    .map(|stage| stage.render(Some(RENDER_TIMESTAMP)).unwrap().to_vec())
                    .collect();
                sink.lock().unwrap().push((rendered, lifetime));
                Ok(SequenceControl::unattended())
            });
        let (dir, state) = state_with_launcher(launcher);
        (dir, state, record)
    }

    fn recorded_releases(state: &DaemonState) -> usize {
        state.release_budget.lock().unwrap().recorded()
    }

    #[test]
    fn test_copy_sequence_stages_password_then_totp() {
        let (_dir, state, record) = recording_state();
        let response = handle_copy_sequence(
            &state,
            &json!({
                "id": "login-1",
                "fields": ["login.password", "login.totp"],
                "clear_after_seconds": 45,
            }),
        );
        assert_eq!(response["ok"], true, "{response}");
        assert_eq!(response["id"], "login-1");
        assert_eq!(response["fields"], json!(["login.password", "login.totp"]));
        assert_eq!(response["clear_after_seconds"], 45);
        let text = response.to_string();
        assert!(!text.contains(fixtures::LOGIN_PASSWORD));
        assert!(!text.contains(fixtures::LOGIN_TOTP_SEED));

        let launches = record.lock().unwrap();
        assert_eq!(launches.len(), 1);
        let (stages, lifetime) = &launches[0];
        assert_eq!(*lifetime, Duration::from_secs(45));
        assert_eq!(stages[0], fixtures::LOGIN_PASSWORD.as_bytes());
        let expected_code =
            crate::totp::generate_totp(fixtures::LOGIN_TOTP_SEED, Some(RENDER_TIMESTAMP), 6, 30)
                .unwrap()
                .code;
        assert_eq!(stages[1], expected_code.as_bytes());
        assert_eq!(recorded_releases(&state), 2, "one release per stage");
        assert!(state.clipboard_offers.paste_sequence_active());
    }

    fn recorded_uses(state: &DaemonState, item_id: &str) -> usize {
        state.item_usage.lock().unwrap().table().uses(item_id).len()
    }

    #[test]
    fn test_copy_sequence_records_exactly_one_use() {
        let (_dir, state, _record) = recording_state();
        let response = handle_copy_sequence(
            &state,
            &json!({ "id": "login-1", "fields": ["login.password", "login.totp", "notes"] }),
        );
        assert_eq!(response["ok"], true, "{response}");
        assert_eq!(recorded_releases(&state), 3, "one release per stage");
        assert_eq!(recorded_uses(&state, "login-1"), 1, "one use per sequence");
    }

    #[test]
    fn test_a_sequence_that_cannot_start_records_no_use() {
        let (_dir, state) = state_with_launcher(Arc::new(|_, _| {
            Err("The compositor offers no clipboard data-control protocol.".to_string())
        }));
        let response = handle_copy_sequence(
            &state,
            &json!({ "id": "login-1", "fields": ["login.password", "login.totp"] }),
        );
        assert_eq!(response["error_code"], error_code::CLIPBOARD_FAILED);
        assert_eq!(recorded_uses(&state, "login-1"), 0);
    }

    #[test]
    fn test_copy_sequence_uses_the_configured_clear_after_by_default() {
        let (_dir, state, record) = recording_state();
        let response = handle_copy_sequence(
            &state,
            &json!({ "id": "card-1", "fields": ["card.number", "card.code"] }),
        );
        assert_eq!(response["ok"], true, "{response}");
        let expected = state.copy_clear_seconds();
        assert_eq!(response["clear_after_seconds"], expected);
        assert_eq!(record.lock().unwrap()[0].1, Duration::from_secs(expected));
    }

    #[test]
    fn test_copy_sequence_validates_every_field_before_charging() {
        let (_dir, state, record) = recording_state();
        let too_many: Vec<&str> = vec!["login.password"; MAX_SEQUENCE_STAGES + 1];
        let cases = [
            (
                json!({ "fields": ["login.password"] }),
                error_code::INVALID_REQUEST,
            ),
            (json!({ "id": "login-1" }), error_code::INVALID_REQUEST),
            (
                json!({ "id": "login-1", "fields": [] }),
                error_code::INVALID_REQUEST,
            ),
            (
                json!({ "id": "login-1", "fields": "login.password" }),
                error_code::INVALID_REQUEST,
            ),
            (
                json!({ "id": "login-1", "fields": ["login.password", 7] }),
                error_code::INVALID_REQUEST,
            ),
            (
                json!({ "id": "login-1", "fields": too_many }),
                error_code::INVALID_REQUEST,
            ),
            (
                json!({ "id": "login-1", "fields": ["login.password"], "clear_after_seconds": 0 }),
                error_code::INVALID_REQUEST,
            ),
            (
                json!({ "id": "login-1", "fields": ["login.password"], "clear_after_seconds": 3601 }),
                error_code::INVALID_REQUEST,
            ),
            (
                json!({ "id": "login-1", "fields": ["login.password", "login.secret"] }),
                error_code::UNKNOWN_FIELD,
            ),
            (
                json!({ "id": "login-1", "fields": ["login.password", "password_history"] }),
                error_code::FIELD_NOT_COPYABLE,
            ),
            (
                json!({ "id": "missing", "fields": ["login.password"] }),
                error_code::ITEM_NOT_FOUND,
            ),
            (
                json!({ "id": "card-1", "fields": ["card.number", "login.totp"] }),
                error_code::FIELD_EMPTY,
            ),
            (
                json!({ "id": "login-1", "fields": ["login.password", "custom.99"] }),
                error_code::FIELD_EMPTY,
            ),
        ];
        for (request, expected_code) in cases {
            let response = handle_copy_sequence(&state, &request);
            assert_eq!(response["ok"], false, "{request}: {response}");
            assert_eq!(
                response["error_code"], expected_code,
                "{request}: {response}"
            );
        }
        assert_eq!(recorded_releases(&state), 0, "nothing is charged");
        assert!(record.lock().unwrap().is_empty(), "nothing is staged");
    }

    #[test]
    fn test_copy_sequence_refunds_every_stage_when_it_cannot_start() {
        let (_dir, state) = state_with_launcher(Arc::new(|_, _| {
            Err("The compositor offers no clipboard data-control protocol.".to_string())
        }));
        let response = handle_copy_sequence(
            &state,
            &json!({ "id": "login-1", "fields": ["login.password", "login.totp", "notes"] }),
        );
        assert_eq!(response["error_code"], error_code::CLIPBOARD_FAILED);
        assert!(response["error"].as_str().unwrap().contains("data-control"));
        assert_eq!(recorded_releases(&state), 0);
        assert!(!state.clipboard_offers.paste_sequence_active());
    }

    #[test]
    fn test_copy_sequence_requires_an_unlocked_vault() {
        let (_dir, state, _record) = recording_state();
        *state.vault_mgr.is_unlocked.write().unwrap() = false;
        let response = handle_copy_sequence(
            &state,
            &json!({ "id": "login-1", "fields": ["login.password"] }),
        );
        assert_eq!(response["error_code"], error_code::VAULT_LOCKED);
    }

    #[test]
    fn test_copy_sequence_cost_beyond_the_budget_is_refused_and_locks() {
        let (_dir, state, record) = recording_state();
        state
            .release_budget
            .lock()
            .unwrap()
            .try_record(
                std::time::Instant::now(),
                MAX_SECRET_RELEASES_PER_WINDOW - 1,
            )
            .unwrap();
        let response = handle_copy_sequence(
            &state,
            &json!({ "id": "login-1", "fields": ["login.password", "login.totp"] }),
        );
        assert_eq!(response["error_code"], error_code::RELEASE_LIMIT_EXCEEDED);
        assert!(
            !state.vault_mgr.is_unlocked(),
            "budget exhaustion hard-locks"
        );
        assert!(record.lock().unwrap().is_empty());
    }

    #[test]
    fn test_lock_withdraws_an_active_sequence() {
        let (_dir, state, _record) = recording_state();
        let response = handle_copy_sequence(
            &state,
            &json!({ "id": "login-1", "fields": ["login.password", "login.totp"] }),
        );
        assert_eq!(response["ok"], true, "{response}");
        assert!(state.clipboard_offers.paste_sequence_active());
        state.lock();
        assert!(!state.clipboard_offers.paste_sequence_active());
    }

    #[test]
    fn test_a_new_sequence_replaces_the_previous_one() {
        let controls: Arc<Mutex<Vec<Arc<SequenceControl>>>> = Arc::default();
        let issued = Arc::clone(&controls);
        let (_dir, state) = state_with_launcher(Arc::new(move |_, _| {
            let control = SequenceControl::unattended();
            issued.lock().unwrap().push(Arc::clone(&control));
            Ok(control)
        }));
        let request = json!({ "id": "login-1", "fields": ["login.password"] });
        assert_eq!(handle_copy_sequence(&state, &request)["ok"], true);
        assert_eq!(handle_copy_sequence(&state, &request)["ok"], true);
        let controls = controls.lock().unwrap();
        assert!(
            controls[0].is_finished(),
            "the first sequence was withdrawn"
        );
        assert!(!controls[1].is_finished());
    }

    #[test]
    fn test_copy_sequence_action_is_dispatched_and_requires_unlock() {
        let spec = crate::daemon_actions::find_action("copy_sequence").unwrap();
        assert!(spec.requires_unlocked);
        assert!(!spec.records_activity);
    }
}
