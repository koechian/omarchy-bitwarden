use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::RwLock;

use crate::api::{decrypt_sync_ciphers_with_context, ApiError, BitwardenApiClient, ClientContext};
use crate::crypto::SymmetricCryptoKey;
use crate::keyring::KeyringManager;
use crate::storage::{StorageManager, VaultStorage};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultItem {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub item_type: i64,
    pub type_name: String,
    pub sub_title: String,
    pub notes: Option<String>,
    pub favorite: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Value>,
    #[serde(default)]
    pub fields: Vec<Value>,
    pub search_text: String,
}

impl VaultItem {
    /// Overwrites every decrypted string of the item with zeroes (ADR 0027).
    pub fn zeroize_contents(&mut self) {
        use crate::secret_memory::{
            zeroize_json_value, zeroize_optional_json_value, zeroize_optional_string,
        };
        use zeroize::Zeroize;
        for text in [
            &mut self.id,
            &mut self.name,
            &mut self.type_name,
            &mut self.sub_title,
            &mut self.search_text,
        ] {
            text.zeroize();
        }
        for text in [
            &mut self.notes,
            &mut self.created_at,
            &mut self.updated_at,
            &mut self.folder_id,
            &mut self.folder_name,
            &mut self.organization_id,
            &mut self.organization_name,
        ] {
            zeroize_optional_string(text);
        }
        if let Some(ids) = self.collection_ids.as_mut() {
            ids.iter_mut().for_each(Zeroize::zeroize);
        }
        for section in [&mut self.login, &mut self.card, &mut self.identity] {
            zeroize_optional_json_value(section);
        }
        self.fields.iter_mut().for_each(zeroize_json_value);
    }
}

/// Every copy of a decrypted item (the cache, clones handed to handlers,
/// search results) is zeroized when it is dropped: on lock, purge and
/// replacement after a sync.
impl Drop for VaultItem {
    fn drop(&mut self) {
        self.zeroize_contents();
    }
}

/// Bitwarden cipher type for SSH key items. This client does not list them.
pub const SSH_KEY_CIPHER_TYPE: i64 = 5;

/// Reports whether vault items of the given Bitwarden cipher type are listed.
pub fn is_listed_cipher_type(item_type: i64) -> bool {
    item_type != SSH_KEY_CIPHER_TYPE
}

pub fn is_fuzzy_match(pattern: &str, text: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }
    let p_lower = pattern.to_lowercase();
    let t_lower = text.to_lowercase();
    if t_lower.contains(&p_lower) {
        return true;
    }

    let p_chars: Vec<char> = p_lower.chars().collect();
    let mut p_idx = 0;
    for c in t_lower.chars() {
        if c == p_chars[p_idx] {
            p_idx += 1;
            if p_idx == p_chars.len() {
                return true;
            }
        }
    }
    false
}

pub struct VaultManager {
    pub server_url: String,
    pub identity_url: Option<String>,
    pub storage_mgr: StorageManager,
    pub keyring_mgr: KeyringManager,
    pub storage: RwLock<VaultStorage>,
    pub decrypted_items: RwLock<Vec<VaultItem>>,
    pub user_key: RwLock<Option<SymmetricCryptoKey>>,
    pub is_unlocked: RwLock<bool>,
    /// ADR-0025: user key retained across soft locks so a polkit check can
    /// re-unlock without the master password. Never leaves mlocked memory.
    pub quick_unlock_key: RwLock<Option<SymmetricCryptoKey>>,
    /// Bumped on every quick-unlock wipe. quick_unlock_restore samples it
    /// before decrypting and aborts if a wipe landed mid-restore, so a hard
    /// lock racing a restore can never be overridden.
    pub quick_unlock_epoch: std::sync::atomic::AtomicU64,
    /// Bumped each time an unlocked vault locks (hard or soft), so a caller
    /// can tell lock cycles apart without having watched the transitions.
    lock_generation: std::sync::atomic::AtomicU64,
    /// `enc_user_key` as it was when the key was retained. That wrapping is
    /// unique per account *and* per master password, so comparing it on
    /// restore proves the retained key still belongs to this vault even when
    /// there is nothing to decrypt-test (an empty vault with no wrapped
    /// private key). Ciphertext, not a secret; cleared with the slot.
    pub quick_unlock_user_key_wrap: RwLock<Option<String>>,
    /// The epoch check alone leaves a window: a wipe could land between the
    /// final re-check and the four unlocked-state writes, and the restore
    /// would overwrite it (vault left unlocked, ceiling disarmed). Held by
    /// `wipe_quick_unlock` for its whole body and by the restore's final
    /// commit section (which re-checks the epoch under the guard), making
    /// wipe-vs-restore mutually exclusive at the commit point.
    pub restore_guard: std::sync::Mutex<()>,
}

/// A user key copied out for re-decrypting items after a sync, with the
/// lock generation sampled before the copy.
struct ItemRefresh {
    lock_generation: u64,
    user_key: SymmetricCryptoKey,
}

/// Error returned when the retained quick-unlock key no longer opens the
/// stored vault.
const STALE_RETAINED_KEY_ERROR: &str =
    "The retained key no longer matches this vault; unlock with the master password.";

/// What the wrapped private key says about a retained key.
enum PrivateKeyEvidence {
    /// Wrapped under the user key (types 0..=2) and decrypts.
    Confirms,
    /// Wrapped under the user key and does not decrypt.
    Refutes,
    /// Absent, unparseable or asymmetric: proves nothing.
    Inconclusive,
}

fn private_key_evidence(
    enc_private_key: Option<&str>,
    key: &SymmetricCryptoKey,
) -> PrivateKeyEvidence {
    let Some(parsed) = enc_private_key.and_then(|k| crate::crypto::EncString::parse(k).ok()) else {
        return PrivateKeyEvidence::Inconclusive;
    };
    if parsed.enc_type > 2 {
        return PrivateKeyEvidence::Inconclusive;
    }
    // The decrypted DER is the RSA private key: zeroize it immediately.
    match parsed.decrypt(key).map(zeroize::Zeroizing::new) {
        Ok(_) => PrivateKeyEvidence::Confirms,
        Err(_) => PrivateKeyEvidence::Refutes,
    }
}

fn is_personal_live_cipher(cipher: &Value) -> bool {
    let deleted = cipher
        .get("deletedDate")
        .or_else(|| cipher.get("DeletedDate"))
        .is_some_and(|v| !v.is_null());
    let organization = cipher.get("organizationId").is_some_and(|v| !v.is_null());
    !deleted && !organization
}

/// Whether any EncString the cipher exposes under the user key decrypts:
/// its own item key first, then its name. `None` when it exposes neither.
/// A real item key decrypts to a raw key blob, so the probe uses decrypt()
/// (raw bytes, zeroized at once) rather than decrypt_string().
fn cipher_decrypts_under(cipher: &Value, key: &SymmetricCryptoKey) -> Option<bool> {
    let key_field = cipher.get("key").and_then(|v| v.as_str());
    let name_field = cipher.get("name").and_then(|v| v.as_str());
    if key_field.is_none() && name_field.is_none() {
        return None;
    }
    let decrypts = [key_field, name_field].into_iter().flatten().any(|field| {
        crate::crypto::EncString::parse(field)
            .ok()
            .is_some_and(|parsed| parsed.decrypt(key).map(zeroize::Zeroizing::new).is_ok())
    });
    Some(decrypts)
}

/// Personal-cipher evidence: `Some(true)` when one decrypts, `Some(false)`
/// when candidates exist and none decrypts, `None` without candidates.
fn personal_cipher_evidence(ciphers: &[Value], key: &SymmetricCryptoKey) -> Option<bool> {
    let mut candidates = false;
    for cipher in ciphers.iter().filter(|c| is_personal_live_cipher(c)) {
        match cipher_decrypts_under(cipher, key) {
            Some(true) => return Some(true),
            Some(false) => candidates = true,
            None => {}
        }
    }
    candidates.then_some(false)
}

impl VaultManager {
    /// Proves that a retained key still belongs to the stored vault,
    /// strongest evidence first: the wrapped private key, then any personal
    /// cipher, then (for an empty vault) the account wrapping recorded at
    /// retention time. An identical wrapping means the same account, the
    /// same master password and therefore the same user key.
    fn verify_retained_key(
        &self,
        key: &SymmetricCryptoKey,
        storage: &VaultStorage,
    ) -> Result<(), &'static str> {
        match private_key_evidence(storage.enc_private_key.as_deref(), key) {
            PrivateKeyEvidence::Confirms => return Ok(()),
            PrivateKeyEvidence::Refutes => {
                return Err("Retained key fails to decrypt the private key")
            }
            PrivateKeyEvidence::Inconclusive => {}
        }
        match personal_cipher_evidence(&storage.ciphers, key) {
            Some(true) => return Ok(()),
            Some(false) => return Err("Retained key fails to decrypt any personal cipher"),
            None => {}
        }
        let recorded = self
            .quick_unlock_user_key_wrap
            .read()
            .ok()
            .and_then(|wrap| wrap.clone());
        match (recorded.as_deref(), storage.enc_user_key.as_deref()) {
            (Some(recorded), Some(current)) if recorded == current => Ok(()),
            _ => Err("Retained key cannot be verified against this vault"),
        }
    }
}

impl VaultManager {
    pub fn new(
        server_url: &str,
        storage_mgr: Option<StorageManager>,
        keyring_mgr: Option<KeyringManager>,
    ) -> Self {
        Self::with_identity_url(server_url, None, storage_mgr, keyring_mgr)
    }

    pub fn with_identity_url(
        server_url: &str,
        identity_url: Option<&str>,
        storage_mgr: Option<StorageManager>,
        keyring_mgr: Option<KeyringManager>,
    ) -> Self {
        let sm = storage_mgr.unwrap_or_default();
        let storage = sm.load();
        let effective_url = if server_url.is_empty() {
            storage.server_url.clone()
        } else {
            server_url.to_string()
        };
        let effective_identity_url = if let Some(id) = identity_url {
            let id_trim = id.trim();
            if !id_trim.is_empty() {
                Some(id_trim.to_string())
            } else {
                None
            }
        } else if server_url.is_empty() || server_url == storage.server_url {
            storage.identity_url.clone()
        } else {
            None
        };

        Self {
            server_url: effective_url,
            identity_url: effective_identity_url,
            storage_mgr: sm,
            keyring_mgr: keyring_mgr.unwrap_or_default(),
            storage: RwLock::new(storage),
            decrypted_items: RwLock::new(Vec::new()),
            user_key: RwLock::new(None),
            is_unlocked: RwLock::new(false),
            quick_unlock_key: RwLock::new(None),
            quick_unlock_epoch: std::sync::atomic::AtomicU64::new(0),
            lock_generation: std::sync::atomic::AtomicU64::new(0),
            quick_unlock_user_key_wrap: RwLock::new(None),
            restore_guard: std::sync::Mutex::new(()),
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.is_unlocked.read().map(|g| *g).unwrap_or(false)
    }

    /// Which lock cycle the vault is in. Changes only when an unlocked vault
    /// locks; locking an already locked vault leaves it alone.
    pub fn lock_generation(&self) -> u64 {
        self.lock_generation
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn purge_decrypted_state(&self) {
        // The generation is bumped and the flag cleared while the items
        // write lock is held, so `store_refreshed_items` (which checks both
        // under the same lock) either stores before this purge, which then
        // clears what it stored, or sees the lock and discards its result.
        // Lock order: decrypted_items, then is_unlocked.
        if let Ok(mut items) = self.decrypted_items.write() {
            if let Ok(mut unl) = self.is_unlocked.write() {
                if *unl {
                    self.lock_generation
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                *unl = false;
            }
            items.clear();
        }
        if let Ok(mut key) = self.user_key.write() {
            *key = None;
        }
    }

    /// Full lock: purges decrypted state AND the quick-unlock slot. This is
    /// the fail-safe default — retention happens only through soft_lock().
    pub fn lock(&self) {
        // Order matters. wipe_quick_unlock takes restore_guard and bumps the
        // epoch, which is what makes an in-flight quick_unlock_restore abort
        // instead of committing. Purging first would leave a window where a
        // restore commit lands between the purge and the wipe: the vault
        // would end up unlocked with the decrypted items and user key back,
        // and the wipe (which only clears the slot) would not undo it. The
        // hard lock must therefore invalidate restores before it purges.
        self.wipe_quick_unlock();
        self.purge_decrypted_state();
    }

    /// Soft lock (ADR-0025): purge everything a hard lock purges, except the
    /// user key, which moves to the quick-unlock slot so a later polkit check
    /// can restore the session. Reports whether a key was retained.
    pub fn soft_lock(&self) -> bool {
        // restore_guard makes retention mutually exclusive with the quick
        // unlock restore commit in both directions: without it, the key move
        // and purge below could interleave with the restore's writes and
        // leave the vault flagged unlocked with no items and no user key
        // (recoverable only by locking again). Same lock as
        // wipe_quick_unlock; see quick_unlock_restore for the commit side.
        let _restore = match self.restore_guard.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Read the binding before taking the key lock, so the lock order is
        // always user_key -> slot -> wrap (see wipe_quick_unlock).
        let account_wrap = self
            .storage
            .read()
            .ok()
            .and_then(|s| s.enc_user_key.clone());
        let retained = match self.user_key.write() {
            Ok(mut src) => {
                let taken = src.take();
                let had = taken.is_some();
                if let Ok(mut slot) = self.quick_unlock_key.write() {
                    // Keep a previously retained key if this call had nothing
                    // to move (called on an already-locked vault): dropping
                    // retention would be a surprising side effect.
                    if had || slot.is_none() {
                        *slot = taken;
                        let has_key = slot.is_some();
                        if let Ok(mut wrap) = self.quick_unlock_user_key_wrap.write() {
                            *wrap = if has_key { account_wrap } else { None };
                        }
                    }
                }
                had
            }
            Err(_) => false,
        };
        self.purge_decrypted_state();
        if retained {
            crate::log_info!(
                "omawarden:vault",
                "Soft-locked vault; user key retained for quick unlock."
            );
        }
        retained
    }

    /// Hard lock: everything lock() does (explicit alias for readability at
    /// ADR-0025 call sites: suspend, max session lifetime, explicit lock,
    /// three failed polkit checks, server/account change).
    pub fn hard_lock(&self) {
        self.lock();
    }

    pub fn quick_unlock_available(&self) -> bool {
        self.quick_unlock_key
            .read()
            .map(|slot| slot.is_some())
            .unwrap_or(false)
    }

    pub fn wipe_quick_unlock(&self) {
        // restore_guard makes this wipe mutually exclusive with the
        // restore's final commit section (see quick_unlock_restore).
        let _restore = match self.restore_guard.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.quick_unlock_epoch
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Ok(mut slot) = self.quick_unlock_key.write() {
            // Dropping the LockedMemory-backed key zeroizes its page.
            *slot = None;
            if let Ok(mut wrap) = self.quick_unlock_user_key_wrap.write() {
                *wrap = None;
            }
        }
    }

    /// Re-unlock from the retained key (ADR-0025): same decryption path as
    /// unlock(), minus the master-password KDF. The slot keeps its key
    /// untouched; a wipe landing mid-restore aborts via the epoch guard and
    /// the restore_guard mutex (the final commit re-checks the epoch under
    /// the same guard wipe_quick_unlock holds) instead of being silently
    /// overridden.
    pub fn quick_unlock_restore(&self) -> Result<usize, String> {
        let epoch_before = self
            .quick_unlock_epoch
            .load(std::sync::atomic::Ordering::SeqCst);
        let key = {
            let slot = self
                .quick_unlock_key
                .read()
                .map_err(|_| "Quick unlock slot unavailable".to_string())?;
            slot.clone()
        }
        .ok_or_else(|| "No key retained for quick unlock".to_string())?;

        let fresh_storage = self.storage_mgr.load();
        if fresh_storage.enc_user_key.is_none() {
            return Err("Account not logged in or missing encryption keys.".to_string());
        }

        let items = decrypt_sync_ciphers_with_context(
            &fresh_storage.ciphers,
            &fresh_storage.folders,
            &fresh_storage.organizations,
            &key,
            fresh_storage.enc_private_key.as_deref(),
        );
        let count = items.len();

        // Fail closed on a stale key (server-side rotation, password change
        // elsewhere, account switch while soft-locked): decryption failures
        // fall back to "Untitled" names, so the vault would otherwise look
        // unlocked with garbage content.
        if let Err(reason) = self.verify_retained_key(&key, &fresh_storage) {
            crate::log_warn!("omawarden:vault", "{}; wiping quick unlock", reason);
            self.wipe_quick_unlock();
            return Err(STALE_RETAINED_KEY_ERROR.to_string());
        }

        // A hard lock (suspend drift, 12h ceiling, explicit lock/logout)
        // landing during the decryption above must win: abort instead of
        // writing unlocked state over a fresh wipe. The cheap epoch check
        // first, then the commit runs under restore_guard with the epoch
        // re-checked inside — wipe_quick_unlock holds the same guard, so a
        // wipe can no longer interleave between this check and the writes.
        self.ensure_no_wipe_since(epoch_before)?;
        self.commit_restored_session(epoch_before, items, key, fresh_storage)?;

        crate::log_info!(
            "omawarden:vault",
            "Quick-unlocked vault; {} items restored.",
            count
        );
        Ok(count)
    }

    /// Fails when a quick-unlock wipe happened after `epoch_before` was
    /// sampled.
    fn ensure_no_wipe_since(&self, epoch_before: u64) -> Result<(), String> {
        let current = self
            .quick_unlock_epoch
            .load(std::sync::atomic::Ordering::SeqCst);
        if current == epoch_before {
            return Ok(());
        }
        crate::log_warn!(
            "omawarden:vault",
            "Vault was locked during quick unlock; aborting restore"
        );
        Err("The vault was locked during unlock. Try again.".to_string())
    }

    /// Writes the restored session under `restore_guard`, re-checking the
    /// epoch inside the guard so a concurrent wipe either lands before (and
    /// aborts this commit) or after (and locks the restored session).
    fn commit_restored_session(
        &self,
        epoch_before: u64,
        items: Vec<VaultItem>,
        key: SymmetricCryptoKey,
        storage: VaultStorage,
    ) -> Result<(), String> {
        let _restore = match self.restore_guard.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.ensure_no_wipe_since(epoch_before)?;
        if let Ok(mut dec_items) = self.decrypted_items.write() {
            *dec_items = items;
        }
        if let Ok(mut key_slot) = self.user_key.write() {
            *key_slot = Some(key);
        }
        if let Ok(mut unl) = self.is_unlocked.write() {
            *unl = true;
        }
        if let Ok(mut st) = self.storage.write() {
            *st = storage;
        }
        // The retained slot is intentionally left untouched: it still holds
        // the same key, and rewriting it would resurrect a key a concurrent
        // wipe just destroyed.
        Ok(())
    }

    pub fn unlock(&self, password: &str) -> Result<usize, String> {
        let fresh_storage = self.storage_mgr.load();
        if fresh_storage.enc_user_key.is_none() {
            crate::log_error!(
                "omawarden:vault",
                "Account not logged in or missing encryption keys."
            );
            return Err("Account not logged in or missing encryption keys.".to_string());
        }

        let user_key = self
            .storage_mgr
            .unlock_user_key(password, &fresh_storage)
            .map_err(|e| {
                crate::log_warn!("omawarden:vault", "Unlock user key failed: {:?}", e);
                format!("Unlock failed: {:?}", e)
            })?;

        let items = decrypt_sync_ciphers_with_context(
            &fresh_storage.ciphers,
            &fresh_storage.folders,
            &fresh_storage.organizations,
            &user_key,
            fresh_storage.enc_private_key.as_deref(),
        );
        let count = items.len();

        if let Ok(mut dec_items) = self.decrypted_items.write() {
            *dec_items = items;
        }
        if let Ok(mut key) = self.user_key.write() {
            *key = Some(user_key.clone());
        }
        // If a soft lock retained a key earlier, keep that copy current with
        // the key now in use (e.g. after a server-side key rotation) and
        // rebind it to the wrapping that came with this unlock.
        let account_wrap = fresh_storage.enc_user_key.clone();
        if let Ok(mut slot) = self.quick_unlock_key.write() {
            if slot.is_some() {
                *slot = Some(user_key);
                if let Ok(mut wrap) = self.quick_unlock_user_key_wrap.write() {
                    *wrap = account_wrap;
                }
            }
        }
        if let Ok(mut unl) = self.is_unlocked.write() {
            *unl = true;
        }
        if let Ok(mut st) = self.storage.write() {
            *st = fresh_storage;
        }

        crate::log_info!(
            "omawarden:vault",
            "Decrypted and cached {} items in memory.",
            count
        );
        Ok(count)
    }

    pub fn sync(&self) -> Result<usize, String> {
        self.sync_with_client(None)
    }

    pub fn sync_with_client(
        &self,
        client_context: Option<&ClientContext>,
    ) -> Result<usize, String> {
        crate::log_info!(
            "omawarden:vault",
            "Starting vault synchronization with server..."
        );
        let storage = self.storage_mgr.load();
        let s_url = if !storage.server_url.is_empty() {
            &storage.server_url
        } else {
            &self.server_url
        };
        let id_url = self
            .identity_url
            .as_deref()
            .or(storage.identity_url.as_deref());
        let client = BitwardenApiClient::with_options(s_url, id_url, client_context);

        let initial_token = self
            .keyring_mgr
            .get_token(s_url, crate::keyring::KIND_ACCESS_TOKEN)
            .or_else(|| self.keyring_mgr.get_session(s_url))
            .or_else(|| storage.access_token.clone());

        let active_token = match initial_token {
            Some(tok) if !crate::auth::is_jwt_expired(&tok) => tok,
            Some(_) => {
                crate::log_info!(
                    "omawarden:vault",
                    "Access token is expired, attempting renewal..."
                );
                self.renew_session_with_client(client_context)?
            }
            None => {
                let has_refresh = self
                    .keyring_mgr
                    .get_token(s_url, crate::keyring::KIND_REFRESH_TOKEN)
                    .is_some()
                    || storage.refresh_token.is_some();
                let has_api_secret = storage
                    .client_id
                    .as_ref()
                    .and_then(|cid| self.keyring_mgr.get_api_secret(s_url, cid))
                    .is_some();
                if has_refresh || has_api_secret {
                    self.renew_session_with_client(client_context)?
                } else {
                    crate::log_error!("omawarden:vault", "Session token missing. Please log in.");
                    return Err("Session token missing. Please log in.".to_string());
                }
            }
        };

        let sync_resp_res = client.sync_vault(&active_token);

        let sync_resp = match sync_resp_res {
            Ok(resp) => resp,
            Err(ApiError::HttpStatus(code, _))
                if code == reqwest::StatusCode::UNAUTHORIZED
                    || code == reqwest::StatusCode::FORBIDDEN =>
            {
                crate::log_warn!(
                    "omawarden:vault",
                    "HTTP {} on sync. Attempting session renewal...",
                    code
                );
                let renewed_token = self.renew_session_with_client(client_context)?;
                client.sync_vault(&renewed_token).map_err(|e| {
                    crate::log_error!(
                        "omawarden:vault",
                        "Sync failed after token renewal: {:?}",
                        e
                    );
                    format!("Sync failed: {:?}", e)
                })?
            }
            Err(ApiError::Http(ref msg)) if msg.contains("401") || msg.contains("403") => {
                crate::log_warn!(
                    "omawarden:vault",
                    "HTTP 401/403 on sync. Attempting session renewal..."
                );
                let renewed_token = self.renew_session_with_client(client_context)?;
                client.sync_vault(&renewed_token).map_err(|e| {
                    crate::log_error!(
                        "omawarden:vault",
                        "Sync failed after token renewal: {:?}",
                        e
                    );
                    format!("Sync failed: {:?}", e)
                })?
            }
            Err(e) => {
                crate::log_error!("omawarden:vault", "Sync failed: {:?}", e);
                return Err(format!("Sync failed: {:?}", e));
            }
        };

        let count = sync_resp.ciphers.len();
        let mut updated = self.storage_mgr.load();
        updated.ciphers = sync_resp.ciphers;
        updated.folders = sync_resp.folders;
        updated.collections = sync_resp.collections;
        if let Some(ref prof) = sync_resp.profile {
            if let Some(orgs) = prof.get("organizations").and_then(|v| v.as_array()) {
                updated.organizations = orgs.clone();
            }
        }
        updated.last_sync = Some(chrono::Utc::now().to_rfc3339());

        self.storage_mgr
            .save(&updated)
            .map_err(|e| format!("Failed to save storage: {:?}", e))?;

        self.refresh_decrypted_items(&updated);

        if let Ok(mut st) = self.storage.write() {
            *st = updated;
        }

        crate::log_info!(
            "omawarden:vault",
            "Vault sync complete. {} ciphers, {} folders saved.",
            count,
            self.storage.read().map(|s| s.folders.len()).unwrap_or(0)
        );

        Ok(count)
    }

    /// Re-decrypts the cached items from freshly synced storage. The key is
    /// copied out instead of held, so a concurrent lock never waits for the
    /// decryption, and the result is stored only if no lock happened since
    /// the lock generation was sampled (see `store_refreshed_items`).
    fn refresh_decrypted_items(&self, storage: &VaultStorage) {
        let Some(refresh) = self.begin_item_refresh() else {
            return;
        };
        let items = decrypt_sync_ciphers_with_context(
            &storage.ciphers,
            &storage.folders,
            &storage.organizations,
            &refresh.user_key,
            storage.enc_private_key.as_deref(),
        );
        self.store_refreshed_items(refresh.lock_generation, items);
    }

    /// Samples the lock generation, then copies the user key. Sampling
    /// first means a lock landing between the two is always detected.
    fn begin_item_refresh(&self) -> Option<ItemRefresh> {
        let lock_generation = self.lock_generation();
        let user_key = self.user_key.read().ok()?.clone()?;
        Some(ItemRefresh {
            lock_generation,
            user_key,
        })
    }

    /// Stores re-decrypted items unless the vault locked after
    /// `lock_generation` was sampled or is no longer unlocked. A discarded
    /// result is zeroized on drop. Returns whether the items were stored.
    fn store_refreshed_items(&self, lock_generation: u64, items: Vec<VaultItem>) -> bool {
        let Ok(mut cached) = self.decrypted_items.write() else {
            return false;
        };
        let locked_since = self.lock_generation() != lock_generation || !self.is_unlocked();
        if locked_since {
            crate::log_info!(
                "omawarden:vault",
                "Vault locked during synchronization; discarding the decrypted result"
            );
            return false;
        }
        *cached = items;
        true
    }

    pub fn renew_session(&self) -> Result<String, String> {
        self.renew_session_with_client(None)
    }

    pub fn renew_session_with_client(
        &self,
        client_context: Option<&ClientContext>,
    ) -> Result<String, String> {
        let storage = self.storage_mgr.load();
        let s_url = if !storage.server_url.is_empty() {
            &storage.server_url
        } else {
            &self.server_url
        };
        let id_url = self
            .identity_url
            .as_deref()
            .or(storage.identity_url.as_deref());
        let client = BitwardenApiClient::with_options(s_url, id_url, client_context);

        let mut had_credentials = false;
        let mut auth_failed = false;
        let mut last_error = None;

        // 1. Try refresh_token grant
        let refresh_token = self
            .keyring_mgr
            .get_token(s_url, crate::keyring::KIND_REFRESH_TOKEN)
            .or_else(|| storage.refresh_token.clone());

        if let Some(ref ref_tok) = refresh_token {
            had_credentials = true;
            crate::log_info!(
                "omawarden:vault",
                "Attempting session renewal via refresh token..."
            );
            match client.refresh_token_grant(ref_tok) {
                Ok(tok_resp) => {
                    crate::log_info!("omawarden:vault", "Token refresh grant successful.");
                    self.persist_renewed_tokens(&tok_resp);
                    return Ok(tok_resp.access_token);
                }
                Err(ApiError::AuthFailed(msg)) => {
                    crate::log_warn!(
                        "omawarden:vault",
                        "Refresh token grant rejected (auth failed: {}). Falling back to API credentials...",
                        msg
                    );
                    auth_failed = true;
                    last_error = Some(format!("Authentication failed: {}", msg));
                }
                Err(ApiError::Network(msg))
                | Err(ApiError::Http(msg))
                | Err(ApiError::HttpStatus(_, msg)) => {
                    crate::log_warn!(
                        "omawarden:vault",
                        "Refresh token grant encountered network or server error: {}. Falling back...",
                        msg
                    );
                    last_error = Some(format!("Network error during token refresh: {}", msg));
                }
                Err(e) => {
                    crate::log_warn!(
                        "omawarden:vault",
                        "Refresh token grant failed: {:?}. Falling back...",
                        e
                    );
                    last_error = Some(format!("Token refresh failed: {:?}", e));
                }
            }
        }

        // 2. Try client_credentials grant via client_id + client_secret in Keyring
        if let Some(ref cid) = storage.client_id {
            if let Some(sec) = self.keyring_mgr.get_api_secret(s_url, cid) {
                had_credentials = true;
                crate::log_info!(
                    "omawarden:vault",
                    "Attempting silent re-authentication via API key secret..."
                );
                match client.login_apikey(cid, &sec) {
                    Ok(tok_resp) => {
                        crate::log_info!(
                            "omawarden:vault",
                            "Silent re-authentication via API key successful."
                        );
                        self.persist_renewed_tokens(&tok_resp);
                        return Ok(tok_resp.access_token);
                    }
                    Err(ApiError::AuthFailed(msg)) => {
                        crate::log_error!(
                            "omawarden:vault",
                            "API key silent re-auth rejected (auth failed: {})",
                            msg
                        );
                        auth_failed = true;
                        last_error = Some(format!("Authentication failed: {}", msg));
                    }
                    Err(ApiError::Network(msg))
                    | Err(ApiError::Http(msg))
                    | Err(ApiError::HttpStatus(_, msg)) => {
                        crate::log_error!(
                            "omawarden:vault",
                            "API key silent re-auth encountered network or server error: {}",
                            msg
                        );
                        last_error = Some(format!(
                            "Network error during API key authentication: {}",
                            msg
                        ));
                    }
                    Err(e) => {
                        crate::log_error!(
                            "omawarden:vault",
                            "API key silent re-auth failed: {:?}",
                            e
                        );
                        last_error = Some(format!("API key login failed: {:?}", e));
                    }
                }
            }
        }

        if !had_credentials {
            self.purge_credentials_and_lock();
            return Err("Session token missing. Please log in.".to_string());
        }

        if auth_failed {
            self.purge_credentials_and_lock();
            return Err(
                "Session expired or credentials rejected. Please log in again.".to_string(),
            );
        }

        Err(last_error.unwrap_or_else(|| {
            "Session renewal failed due to network error. Please check your connection.".to_string()
        }))
    }

    fn persist_renewed_tokens(&self, tok_resp: &crate::api::TokenResponse) {
        let mut updated_storage = self.storage_mgr.load();
        let s_url = if !updated_storage.server_url.is_empty() {
            &updated_storage.server_url
        } else {
            &self.server_url
        };
        if self.keyring_mgr.is_available() {
            let s1 = self.keyring_mgr.store_token(
                s_url,
                crate::keyring::KIND_ACCESS_TOKEN,
                &tok_resp.access_token,
            );
            let s2 = if let Some(ref new_ref) = tok_resp.refresh_token {
                self.keyring_mgr
                    .store_token(s_url, crate::keyring::KIND_REFRESH_TOKEN, new_ref)
            } else {
                self.keyring_mgr
                    .clear_token(s_url, crate::keyring::KIND_REFRESH_TOKEN);
                true
            };
            if s1 && s2 {
                updated_storage.access_token = None;
                updated_storage.refresh_token = None;
                let _ = self.storage_mgr.save(&updated_storage);
                return;
            }
        }

        crate::log_error!(
            "omawarden:vault",
            "Keyring not available or failed to store renewed tokens. Locking session."
        );
        self.purge_credentials_and_lock();
    }

    fn purge_credentials_and_lock(&self) {
        let mut updated = self.storage_mgr.load();
        let s_url = if !updated.server_url.is_empty() {
            &updated.server_url
        } else {
            &self.server_url
        };
        self.keyring_mgr
            .clear_token(s_url, crate::keyring::KIND_ACCESS_TOKEN);
        self.keyring_mgr
            .clear_token(s_url, crate::keyring::KIND_REFRESH_TOKEN);
        self.keyring_mgr.clear_session(s_url);
        updated.access_token = None;
        updated.refresh_token = None;
        let _ = self.storage_mgr.save(&updated);
        self.lock();
    }

    /// The decrypted items held by this manager; empty while locked. The
    /// daemon is the only holder of decrypted items, and it exposes them to
    /// clients only in redacted form (ADR 0027), so there is no fallback to
    /// asking the daemon here.
    pub fn get_items(&self) -> Vec<VaultItem> {
        if !self.is_unlocked() {
            return Vec::new();
        }
        self.decrypted_items
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    pub fn search_items(&self, query: &str, category: Option<&str>) -> Vec<VaultItem> {
        let items = self.get_items();
        self.search(&items, query, category)
    }

    pub fn get_user_key(&self) -> Option<SymmetricCryptoKey> {
        self.user_key.read().ok().and_then(|k| k.clone())
    }

    pub fn find_item(&self, query: &str, category: Option<&str>) -> Option<VaultItem> {
        let items = self.get_items();
        let target = query.trim();
        if target.is_empty() {
            return None;
        }

        let cat_filter = category.map(|c| c.to_lowercase());

        // 1. Exact ID match
        if let Some(item) = items.iter().find(|i| {
            if let Some(ref c) = cat_filter {
                if &i.type_name != c {
                    return false;
                }
            }
            i.id == target
        }) {
            return Some(item.clone());
        }

        // 2. Exact Name match (case-insensitive)
        if let Some(item) = items.iter().find(|i| {
            if let Some(ref c) = cat_filter {
                if &i.type_name != c {
                    return false;
                }
            }
            i.name.eq_ignore_ascii_case(target)
        }) {
            return Some(item.clone());
        }

        // 3. Name contains query (case-insensitive)
        let lower = target.to_lowercase();
        if let Some(item) = items.iter().find(|i| {
            if let Some(ref c) = cat_filter {
                if &i.type_name != c {
                    return false;
                }
            }
            i.name.to_lowercase().contains(&lower)
        }) {
            return Some(item.clone());
        }

        None
    }

    pub fn get_status(&self) -> Value {
        let is_unlocked = self.is_unlocked();
        let fresh_storage = self.storage_mgr.load();
        let s_url = if !fresh_storage.server_url.is_empty() {
            &fresh_storage.server_url
        } else {
            &self.server_url
        };
        let active_token = self
            .keyring_mgr
            .get_token(s_url, crate::keyring::KIND_ACCESS_TOKEN)
            .or_else(|| self.keyring_mgr.get_session(s_url))
            .or_else(|| fresh_storage.access_token.clone());

        let has_refresh = self
            .keyring_mgr
            .get_token(s_url, crate::keyring::KIND_REFRESH_TOKEN)
            .is_some()
            || fresh_storage.refresh_token.is_some();
        let has_api_secret = fresh_storage
            .client_id
            .as_ref()
            .and_then(|cid| self.keyring_mgr.get_api_secret(s_url, cid))
            .is_some();

        let has_valid_token = if let Some(ref tok) = active_token {
            !crate::auth::is_jwt_expired(tok) || has_refresh || has_api_secret
        } else {
            has_refresh || has_api_secret
        };

        let status = if !has_valid_token {
            "unauthenticated"
        } else if is_unlocked {
            "unlocked"
        } else if fresh_storage.enc_user_key.is_some() {
            "locked"
        } else {
            "unauthenticated"
        };

        json!({
            "ok": true,
            "status": status,
            "server_url": fresh_storage.server_url,
            "user_email": fresh_storage.user_email,
            "user_id": fresh_storage.user_id,
            "last_sync": fresh_storage.last_sync,
            "is_unlocked": is_unlocked && has_valid_token,
            "has_session": has_valid_token,
            "items_count": if has_valid_token { self.decrypted_items.read().map(|i| i.len()).unwrap_or(0) } else { 0 },
        })
    }

    pub fn parse_raw_items(&self, raw_items: &[Value]) -> Vec<VaultItem> {
        let mut parsed: Vec<VaultItem> = Vec::new();

        for raw in raw_items {
            let item_type = raw.get("type").and_then(|v| v.as_i64()).unwrap_or(1);
            if !is_listed_cipher_type(item_type) {
                continue;
            }
            let name = raw
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Untitled")
                .to_string();
            let notes = raw
                .get("notes")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let favorite = raw
                .get("favorite")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let fields = raw
                .get("fields")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let id = raw
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let folder_id = raw
                .get("folderId")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let organization_id = raw
                .get("organizationId")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let collection_ids = raw
                .get("collectionIds")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect::<Vec<_>>()
                });
            let created_at = raw
                .get("created_at")
                .or_else(|| raw.get("creationDate"))
                .or_else(|| raw.get("creation_date"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let updated_at = raw
                .get("updated_at")
                .or_else(|| raw.get("revisionDate"))
                .or_else(|| raw.get("revision_date"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let type_name = match item_type {
                1 => "login",
                2 => "note",
                3 => "card",
                4 => "identity",
                _ => "login",
            }
            .to_string();

            let (sub_title, search_tokens) = self.extract_metadata(
                item_type,
                raw,
                &name,
                notes.as_deref().unwrap_or(""),
                &fields,
            );

            let search_text = search_tokens
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ");

            parsed.push(VaultItem {
                id,
                name,
                item_type,
                type_name,
                sub_title,
                notes,
                favorite,
                created_at,
                updated_at,
                folder_id,
                folder_name: None,
                organization_id,
                organization_name: None,
                collection_ids,
                login: if item_type == 1 {
                    raw.get("login").cloned()
                } else {
                    None
                },
                card: if item_type == 3 {
                    raw.get("card").cloned()
                } else {
                    None
                },
                identity: if item_type == 4 {
                    raw.get("identity").cloned()
                } else {
                    None
                },
                fields,
                search_text,
            });
        }

        parsed
    }

    fn extract_metadata(
        &self,
        item_type: i64,
        raw: &Value,
        name: &str,
        notes: &str,
        fields: &[Value],
    ) -> (String, Vec<String>) {
        let mut search_tokens = vec![name.to_lowercase(), notes.to_lowercase()];
        let mut sub_title = String::new();

        match item_type {
            1 => {
                if let Some(login_data) = raw.get("login") {
                    let username = login_data
                        .get("username")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    sub_title = username.to_string();
                    search_tokens.push(username.to_lowercase());
                    if let Some(uris) = login_data.get("uris").and_then(|v| v.as_array()) {
                        for u in uris {
                            if let Some(uri_val) = u.get("uri").and_then(|v| v.as_str()) {
                                search_tokens.push(uri_val.to_lowercase());
                            }
                        }
                    }
                }
            }
            3 => {
                if let Some(card_data) = raw.get("card") {
                    let num = card_data
                        .get("number")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let brand = card_data
                        .get("brand")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Card");
                    let last4 = if num.len() >= 4 {
                        &num[num.len() - 4..]
                    } else {
                        num
                    };
                    sub_title = if !last4.is_empty() {
                        format!("{} •••• {}", brand, last4)
                    } else {
                        brand.to_string()
                    };
                    search_tokens.push(brand.to_lowercase());
                    search_tokens.push(num.to_string());
                }
            }
            4 => {
                if let Some(id_data) = raw.get("identity") {
                    let email = id_data.get("email").and_then(|v| v.as_str()).unwrap_or("");
                    let fname = id_data
                        .get("firstName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let lname = id_data
                        .get("lastName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let full_name = format!("{} {}", fname, lname).trim().to_string();
                    sub_title = if !email.is_empty() {
                        email.to_string()
                    } else if !full_name.is_empty() {
                        full_name.clone()
                    } else {
                        "Identity".to_string()
                    };
                    search_tokens.push(email.to_lowercase());
                    search_tokens.push(fname.to_lowercase());
                    search_tokens.push(lname.to_lowercase());
                    search_tokens.push(full_name.to_lowercase());
                }
            }
            2 => {
                sub_title = "Secure Note".to_string();
            }
            _ => {}
        }

        for f in fields {
            let fname = f.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let fval = f
                .get("value")
                .map(|v| match v {
                    Value::String(s) => s.as_str(),
                    _ => "",
                })
                .unwrap_or("");
            search_tokens.push(fname.to_lowercase());
            search_tokens.push(fval.to_lowercase());
        }

        (sub_title, search_tokens)
    }

    /// Items matching every query word, best match first (favorites get a
    /// bonus). Names, subtitles and the non-secret search text are matched;
    /// notes and other secret fields are not, so search cannot be used to
    /// probe secret content (ADR 0027).
    pub fn search(
        &self,
        items: &[VaultItem],
        query: &str,
        category: Option<&str>,
    ) -> Vec<VaultItem> {
        let query_lower = query.trim().to_lowercase();
        let words: Vec<&str> = query_lower.split_whitespace().collect();
        let category_filter = normalized_category_filter(category);

        let mut scored_items: Vec<(&VaultItem, i64)> = items
            .iter()
            .filter(|item| {
                category_filter
                    .as_deref()
                    .is_none_or(|category| item.type_name == category)
            })
            .filter_map(|item| score_item(item, &words).map(|score| (item, score)))
            .collect();

        scored_items.sort_by_key(|a| std::cmp::Reverse(a.1));
        scored_items
            .into_iter()
            .map(|(item, _)| item.clone())
            .collect()
    }
}

/// The category to filter by, or `None` for every category ("" or "all").
fn normalized_category_filter(category: Option<&str>) -> Option<String> {
    let category = category.unwrap_or("").trim().to_lowercase();
    (!category.is_empty() && category != "all").then_some(category)
}

/// Relevance of `item` for the query words, or `None` when any word fails
/// to match. An empty query matches every item.
fn score_item(item: &VaultItem, words: &[&str]) -> Option<i64> {
    let favorite_bonus = if item.favorite { 100 } else { 0 };
    let haystack = SearchHaystack::new(item);
    words.iter().try_fold(favorite_bonus, |total, word| {
        haystack.score_word(word).map(|score| total + score)
    })
}

/// Lower-cased, non-secret text of one item that query words match against.
struct SearchHaystack {
    name: String,
    sub_title: String,
    search_text: String,
}

impl SearchHaystack {
    fn new(item: &VaultItem) -> Self {
        Self {
            name: item.name.to_lowercase(),
            sub_title: item.sub_title.to_lowercase(),
            search_text: item.search_text.to_lowercase(),
        }
    }

    /// Score of one word, strongest match first.
    fn score_word(&self, word: &str) -> Option<i64> {
        if self.name == word {
            return Some(2000);
        }
        if self.name.starts_with(word) {
            return Some(1000);
        }
        if self.name.contains(word) {
            return Some(500);
        }
        if self.sub_title.starts_with(word) {
            return Some(400);
        }
        if self.sub_title.contains(word) {
            return Some(300);
        }
        if self.search_text.contains(word) {
            return Some(100);
        }
        is_fuzzy_match(word, &self.name).then_some(80)
    }
}

#[cfg(test)]
// pub(crate): daemon tests reuse the seeded vault fixture for the IPC
// quick-unlock flow.
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    /// Builds a VaultManager whose data.json carries a real login: a type-2
    /// EncString wrapping the raw 64-byte user key under the master key, so
    /// unlock(password) exercises the production key-unwrapping path.
    pub(crate) fn seeded_vault(dir: &std::path::Path, password: &str) -> VaultManager {
        use crate::crypto::{derive_master_key, KdfType, SymmetricCryptoKey, BASE64};
        use base64::Engine as _;
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        use hmac::Mac;
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
        type HmacSha256 = hmac::Hmac<sha2::Sha256>;

        let email = "quick@unlock.test";
        let master_key =
            derive_master_key(email, password, KdfType::Pbkdf2Sha256, 600_000, None, None)
                .expect("master key");
        let master_sym = SymmetricCryptoKey::stretch_master_key(master_key.as_slice()).unwrap();
        let raw = [42u8; 64];

        let iv = [9u8; 16];
        let enc = Aes256CbcEnc::new_from_slices(&master_sym.enc_key, &iv).expect("cipher");
        let mut buf = vec![0u8; raw.len() + 16];
        let ct = enc
            .encrypt_padded_b2b_mut::<cbc::cipher::block_padding::Pkcs7>(&raw, &mut buf)
            .expect("encrypt");
        let mut mac = HmacSha256::new_from_slice(master_sym.mac_key.as_ref().expect("mac key"))
            .expect("hmac");
        mac.update(&iv);
        mac.update(ct);
        let mac = mac.finalize().into_bytes();
        let enc_user_key = format!(
            "2.{}|{}|{}",
            BASE64.encode(iv),
            BASE64.encode(ct),
            BASE64.encode(mac)
        );

        let storage = VaultStorage {
            server_url: "https://vault.example.com".to_string(),
            user_email: email.to_string(),
            kdf: Some(0),
            kdf_iterations: Some(600_000),
            enc_user_key: Some(enc_user_key),
            ..Default::default()
        };
        let storage_mgr = StorageManager::new(dir.join("data.json"));
        storage_mgr.save(&storage).expect("save storage");
        VaultManager::new("", Some(storage_mgr), None)
    }

    #[test]
    fn test_vault_item_zeroize_contents_clears_every_string() {
        let mut item = crate::item_redaction::tests::login_item();
        item.zeroize_contents();
        let serialized = serde_json::to_value(&item).unwrap();
        fn has_text(value: &Value) -> bool {
            match value {
                Value::String(text) => !text.is_empty(),
                Value::Array(values) => values.iter().any(has_text),
                Value::Object(map) => map.values().any(has_text),
                _ => false,
            }
        }
        assert!(
            !has_text(&serialized),
            "every string is zeroized: {serialized}"
        );
    }

    #[test]
    fn test_soft_lock_retains_key_and_quick_unlock_restores() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        assert!(!vault.quick_unlock_available());

        assert_eq!(vault.unlock("master-pw").unwrap(), 0);
        assert!(vault.is_unlocked());

        assert!(vault.soft_lock(), "an unlocked vault must retain its key");
        assert!(!vault.is_unlocked());
        assert!(vault.decrypted_items.read().unwrap().is_empty());
        assert!(vault.user_key.read().unwrap().is_none());
        assert!(vault.quick_unlock_available());

        assert_eq!(vault.quick_unlock_restore().unwrap(), 0);
        assert!(vault.is_unlocked());
        assert!(vault.user_key.read().unwrap().is_some());
        assert!(vault.quick_unlock_available(), "slot stays primed");

        // A second soft lock keeps retention working.
        assert!(vault.soft_lock());
        assert!(vault.quick_unlock_restore().is_ok());

        // Hard lock wipes the slot; restore now fails.
        vault.hard_lock();
        assert!(!vault.quick_unlock_available());
        assert!(vault.quick_unlock_restore().is_err());
    }

    #[test]
    fn test_plain_lock_wipes_quick_unlock_slot() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        assert!(vault.soft_lock());
        assert!(vault.quick_unlock_available());

        // lock() is the fail-safe path: any caller that has not opted into
        // retention must not leave the slot behind.
        vault.unlock("master-pw").unwrap();
        vault.lock();
        assert!(!vault.quick_unlock_available());
    }

    #[test]
    fn test_soft_lock_without_unlock_retains_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        assert!(!vault.soft_lock());
        assert!(!vault.quick_unlock_available());
        assert!(vault.quick_unlock_restore().is_err());
    }

    #[test]
    fn test_unlock_refreshes_stale_retained_key() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        assert!(vault.soft_lock());

        // A fresh password unlock replaces the retained copy with the key now
        // in use, so a later restore cannot resurrect an old key.
        vault.unlock("master-pw").unwrap();
        vault.lock();
        assert!(!vault.quick_unlock_available());
    }

    #[test]
    fn test_quick_unlock_restore_fails_closed_on_stale_key() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        assert!(vault.soft_lock());
        assert!(vault.quick_unlock_available());

        // Simulate a vault whose ciphers were re-encrypted under a different
        // key (rotation / account switch): the retained key decrypts none of
        // them, which previously surfaced as an "unlocked" empty vault.
        let mut stale = vault.storage_mgr.load();
        stale.ciphers = vec![serde_json::json!({
            "id": "cipher-1",
            "type": 1,
            "name": "2.not-a-valid-encstring",
            "login": null,
        })];
        vault.storage_mgr.save(&stale).unwrap();

        let err = vault.quick_unlock_restore().unwrap_err();
        assert!(err.contains("no longer matches"), "got: {err}");
        assert!(
            !vault.is_unlocked(),
            "restore must not leave the vault unlocked"
        );
        assert!(
            !vault.quick_unlock_available(),
            "a stale retained key must be wiped, not re-primed"
        );
    }

    #[test]
    fn test_hard_lock_takes_the_restore_guard_before_purging() {
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();

        // Regression for the purge-before-wipe ordering: the restore commit
        // section holds restore_guard, so a hard lock that purged first could
        // be overwritten by a commit landing in the gap and leave the vault
        // unlocked after a suspend, the 12h ceiling or an explicit lock. Hold
        // the guard (as the commit section does) and prove the hard lock has
        // not purged anything, nor bumped the epoch, before it gets the guard.
        let epoch_before = vault.quick_unlock_epoch.load(Ordering::SeqCst);
        let guard = vault.restore_guard.lock().unwrap();
        std::thread::scope(|s| {
            let locker = s.spawn(|| vault.lock());
            std::thread::sleep(Duration::from_millis(100));
            assert!(
                vault.is_unlocked(),
                "a hard lock must wait for the restore commit guard before purging"
            );
            assert!(
                vault.user_key.read().unwrap().is_some(),
                "the user key must survive until the wipe has the guard"
            );
            assert_eq!(
                vault.quick_unlock_epoch.load(Ordering::SeqCst),
                epoch_before,
                "the epoch bump that aborts an in-flight restore must come before the purge"
            );
            drop(guard);
            locker.join().unwrap();
        });
        assert!(
            !vault.is_unlocked(),
            "the hard lock must land once the guard is free"
        );
        assert!(!vault.quick_unlock_available());
        assert_ne!(
            vault.quick_unlock_epoch.load(Ordering::SeqCst),
            epoch_before
        );
    }

    #[test]
    fn test_wipe_is_serialized_with_restore_commit() {
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        assert!(vault.soft_lock());
        assert!(vault.quick_unlock_available());

        // Regression for the restore TOCTOU: the wipe must share the mutex
        // the restore's commit section holds, so a hard lock landing while a
        // restore is committing cannot be overwritten. Hold the guard (as the
        // commit section does) and prove wipe_quick_unlock waits on it.
        let epoch_before = vault.quick_unlock_epoch.load(Ordering::SeqCst);
        let guard = vault.restore_guard.lock().unwrap();
        std::thread::scope(|s| {
            let wiper = s.spawn(|| vault.wipe_quick_unlock());
            std::thread::sleep(Duration::from_millis(100));
            assert_eq!(
                vault.quick_unlock_epoch.load(Ordering::SeqCst),
                epoch_before,
                "a wipe must not bypass the restore commit guard"
            );
            assert!(
                vault.quick_unlock_available(),
                "the slot must survive while the commit section holds the guard"
            );
            drop(guard);
            wiper.join().unwrap();
        });
        assert_ne!(
            vault.quick_unlock_epoch.load(Ordering::SeqCst),
            epoch_before
        );
        assert!(!vault.quick_unlock_available());
    }

    #[test]
    fn test_sync_result_is_discarded_when_a_lock_lands_during_decryption() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();

        // The interleaving of the race, step by step: the sync samples the
        // generation and copies the key, a lock lands while it decrypts,
        // and the sync then tries to store its plaintext.
        let refresh = vault.begin_item_refresh().expect("unlocked vault");
        vault.lock();
        assert!(
            vault.user_key.read().unwrap().is_none(),
            "the lock does not wait for the decryption"
        );
        let decrypted = vec![crate::item_redaction::tests::login_item()];
        assert!(!vault.store_refreshed_items(refresh.lock_generation, decrypted));
        assert!(!vault.is_unlocked());
        assert!(
            vault.decrypted_items.read().unwrap().is_empty(),
            "no plaintext may be stored after a lock"
        );

        // A lock and a fresh unlock in between are detected as well.
        let refresh = vault.begin_item_refresh();
        assert!(
            refresh.is_none(),
            "a locked vault has no key to refresh with"
        );
        vault.unlock("master-pw").unwrap();
        let refresh = vault.begin_item_refresh().unwrap();
        vault.lock();
        vault.unlock("master-pw").unwrap();
        let stale = vec![crate::item_redaction::tests::login_item()];
        assert!(!vault.store_refreshed_items(refresh.lock_generation, stale));
        assert!(vault.decrypted_items.read().unwrap().is_empty());
    }

    #[test]
    fn test_sync_result_is_stored_when_no_lock_intervenes() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        let refresh = vault.begin_item_refresh().unwrap();
        let decrypted = vec![crate::item_redaction::tests::login_item()];
        assert!(vault.store_refreshed_items(refresh.lock_generation, decrypted));
        assert_eq!(vault.decrypted_items.read().unwrap().len(), 1);
    }

    #[test]
    fn test_lock_generation_changes_only_when_an_unlocked_vault_locks() {
        let vault_mgr = VaultManager::new("https://vault.example.com", None, None);
        let start = vault_mgr.lock_generation();

        // Locking an already locked vault is not a new lock cycle.
        vault_mgr.hard_lock();
        vault_mgr.soft_lock();
        assert_eq!(vault_mgr.lock_generation(), start);

        *vault_mgr.is_unlocked.write().unwrap() = true;
        assert_eq!(vault_mgr.lock_generation(), start, "unlocking keeps it");
        vault_mgr.soft_lock();
        assert_eq!(vault_mgr.lock_generation(), start + 1);

        *vault_mgr.is_unlocked.write().unwrap() = true;
        vault_mgr.hard_lock();
        assert_eq!(vault_mgr.lock_generation(), start + 2);
    }

    #[test]
    fn test_soft_lock_on_locked_vault_keeps_existing_slot() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        assert!(vault.soft_lock());
        // Calling soft_lock again (nothing to move) must not drop retention.
        assert!(!vault.soft_lock());
        assert!(vault.quick_unlock_available());
    }

    #[test]
    fn test_soft_lock_is_serialized_with_restore_commit() {
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();

        // Soft lock must share the restore commit guard: while the commit
        // section holds it, the key move and purge cannot run, so the vault
        // stays fully unlocked instead of ending up flagged locked with the
        // key half-moved.
        let guard = vault.restore_guard.lock().unwrap();
        std::thread::scope(|s| {
            let locker = s.spawn(|| vault.soft_lock());
            std::thread::sleep(Duration::from_millis(100));
            assert!(
                vault.is_unlocked(),
                "soft lock must not bypass the restore commit guard"
            );
            assert!(
                vault.user_key.read().unwrap().is_some(),
                "the user key must stay in the session while the guard is held"
            );
            drop(guard);
            assert!(locker.join().unwrap());
        });
        assert!(!vault.is_unlocked());
        assert!(vault.quick_unlock_available());
    }

    #[test]
    fn test_quick_unlock_restore_fails_closed_on_empty_vault_with_changed_wrap() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        assert!(vault.soft_lock());
        assert!(vault.quick_unlock_available());

        // An empty vault (no ciphers, no wrapped private key) has nothing to
        // decrypt-test, so the only honest check is the account binding
        // recorded at retention. Here the user key is now wrapped under a
        // different master password: the retained key is stale and would
        // otherwise "unlock" an empty vault, letting the user create items
        // under a key the next real unlock cannot read.
        let mut rotated = vault.storage_mgr.load();
        rotated.ciphers = Vec::new();
        rotated.enc_private_key = None;
        rotated.enc_user_key = Some("2.rotated-by-a-password-change".to_string());
        vault.storage_mgr.save(&rotated).unwrap();

        let err = vault.quick_unlock_restore().unwrap_err();
        assert!(err.contains("no longer matches"), "got: {err}");
        assert!(!vault.is_unlocked());
        assert!(
            !vault.quick_unlock_available(),
            "an unverifiable retained key must be wiped, not left in the slot"
        );
        assert!(
            vault.quick_unlock_user_key_wrap.read().unwrap().is_none(),
            "the account binding must be wiped with the key"
        );
    }

    #[test]
    fn test_quick_unlock_restore_allows_an_unchanged_empty_vault() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        assert!(vault.soft_lock());

        // Same account, same wrapping: the binding still matches, so an empty
        // vault must not be forced back to the master password.
        let mut same_account = vault.storage_mgr.load();
        same_account.ciphers = Vec::new();
        same_account.enc_private_key = None;
        vault.storage_mgr.save(&same_account).unwrap();

        assert_eq!(vault.quick_unlock_restore().unwrap(), 0);
        assert!(vault.is_unlocked());
    }

    #[test]
    fn test_unlock_rebinds_the_retained_key_so_an_empty_vault_stays_restorable() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        assert!(vault.soft_lock());

        // A real unlock while a key is retained replaces the slot copy (and
        // its binding) with the key now in use. If the binding were dropped,
        // the empty-vault fallback below would fail closed for no reason.
        vault.unlock("master-pw").unwrap();
        let storage_wrap = vault
            .storage_mgr
            .load()
            .enc_user_key
            .expect("storage keeps the user key wrapping");
        assert_eq!(
            vault.quick_unlock_user_key_wrap.read().unwrap().as_deref(),
            Some(storage_wrap.as_str())
        );

        assert!(vault.soft_lock());
        assert_eq!(vault.quick_unlock_restore().unwrap(), 0);
        assert!(vault.is_unlocked());
    }

    #[test]
    fn test_quick_unlock_restore_wipes_on_stale_keyed_ciphers() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        assert!(vault.soft_lock());
        assert!(vault.quick_unlock_available());

        // Every personal cipher carries its own item key that does not
        // decrypt under the retained key. This vault shape used to leave
        // candidates == 0 (keyed ciphers were skipped) and fail open with
        // "Untitled" items; the key itself must now feed the probe.
        let mut stale = vault.storage_mgr.load();
        stale.ciphers = vec![serde_json::json!({
            "id": "cipher-keyed",
            "type": 1,
            "key": "2.not-a-valid-encstring",
            "name": "2.another-invalid-encstring",
            "login": null,
        })];
        vault.storage_mgr.save(&stale).unwrap();

        let err = vault.quick_unlock_restore().unwrap_err();
        assert!(err.contains("no longer matches"), "got: {err}");
        assert!(!vault.is_unlocked());
        assert!(!vault.quick_unlock_available());
    }

    #[test]
    fn test_quick_unlock_restore_accepts_keyed_ciphers_with_valid_keys() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        // Capture the key before soft_lock moves it to the retained slot.
        let user_key = vault.user_key.read().unwrap().clone().unwrap();
        // A REAL item key: a 64-byte symmetric key blob, not UTF-8 text. The
        // probe must accept it via raw decrypt(); a decrypt_string() probe
        // would reject the valid blob and wipe a perfectly good key.
        let item_key_blob = [42u8; 64];
        let item_key_enc = user_key.encrypt(&item_key_blob).unwrap();
        assert!(vault.soft_lock());

        // A keyed cipher whose item key decrypts under the retained key
        // validates the restore: carrying an item key must not count as a
        // failure (the probe prefers the key over the name).
        let mut fresh = vault.storage_mgr.load();
        fresh.ciphers = vec![serde_json::json!({
            "id": "cipher-keyed-ok",
            "type": 1,
            "key": item_key_enc,
            "name": "2.undecryptable-name-is-irrelevant",
            "login": null,
        })];
        vault.storage_mgr.save(&fresh).unwrap();

        vault.quick_unlock_restore().unwrap();
        assert!(vault.is_unlocked());
    }

    #[test]
    fn test_quick_unlock_restore_falls_back_to_name_when_key_is_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        let user_key = vault.user_key.read().unwrap().clone().unwrap();
        let valid_name_enc = user_key.encrypt_string("GitHub").unwrap();
        assert!(vault.soft_lock());

        // An unparseable item key (corrupt sync, server quirk) must not veto
        // the cipher's valid encrypted name: the probe tries both fields.
        let mut fresh = vault.storage_mgr.load();
        fresh.ciphers = vec![serde_json::json!({
            "id": "cipher-corrupt-key",
            "type": 1,
            "key": "2.corrupt-item-key",
            "name": valid_name_enc,
            "login": null,
        })];
        vault.storage_mgr.save(&fresh).unwrap();

        vault.quick_unlock_restore().unwrap();
        assert!(vault.is_unlocked());
        assert!(vault.quick_unlock_available(), "no spurious wipe");
    }

    #[test]
    fn test_fuzzy_match() {
        assert!(is_fuzzy_match("", "anything"));
        assert!(is_fuzzy_match("git", "github"));
        assert!(is_fuzzy_match("gh", "github"));
        assert!(is_fuzzy_match("gthb", "github"));
        assert!(!is_fuzzy_match("xyz", "github"));
    }

    #[test]
    fn test_parse_and_search_categories() {
        let raw_items = vec![
            json!({
                "id": "1",
                "name": "GitHub",
                "type": 1,
                "login": {
                    "username": "octocat",
                    "uris": [{ "uri": "https://github.com" }]
                },
                "favorite": true
            }),
            json!({
                "id": "2",
                "name": "Bank Card",
                "type": 3,
                "card": {
                    "brand": "Visa",
                    "number": "4111222233334444"
                }
            }),
            json!({
                "id": "3",
                "name": "Server Access",
                "type": 5,
                "sshKey": {
                    "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... user@host",
                    "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----",
                    "keyFingerprint": "SHA256:abcd1234efgh"
                }
            }),
            json!({
                "id": "4",
                "name": "Server Backup Notes",
                "type": 2,
                "notes": "Here is a note with ssh-rsa AAAAB3... that should stay as a note"
            }),
        ];

        let vault_mgr = VaultManager::new("https://vault.example.com", None, None);
        let items = vault_mgr.parse_raw_items(&raw_items);
        // The SSH key item (type 5) is not listed.
        assert_eq!(items.len(), 3);
        assert!(items.iter().all(|i| i.id != "3"));

        assert_eq!(items[0].type_name, "login");
        assert_eq!(items[0].sub_title, "octocat");

        assert_eq!(items[1].type_name, "card");
        assert_eq!(items[1].sub_title, "Visa •••• 4444");

        assert_eq!(items[2].type_name, "note");
        assert_eq!(items[2].sub_title, "Secure Note");

        let search_gh = vault_mgr.search(&items, "github", None);
        assert_eq!(search_gh.len(), 1);
        assert_eq!(search_gh[0].id, "1");

        let search_card = vault_mgr.search(&items, "", Some("card"));
        assert_eq!(search_card.len(), 1);
        assert_eq!(search_card[0].id, "2");

        let search_note = vault_mgr.search(&items, "", Some("note"));
        assert_eq!(search_note.len(), 1);
        assert_eq!(search_note[0].id, "4");
    }

    #[test]
    fn test_vault_manager_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault_test.json");
        let storage_mgr = StorageManager::new(path);

        let dummy_keyring = KeyringManager::new("/nonexistent-keyring");
        let vault_mgr = VaultManager::new(
            "https://vault.example.com",
            Some(storage_mgr),
            Some(dummy_keyring),
        );
        assert!(!vault_mgr.is_unlocked());
        assert_eq!(vault_mgr.decrypted_items.read().unwrap().len(), 0);

        let st = vault_mgr.get_status();
        assert_eq!(
            st.get("status").unwrap().as_str().unwrap(),
            "unauthenticated"
        );

        vault_mgr.lock();
        assert!(!vault_mgr.is_unlocked());
        let sync_err = vault_mgr.sync();
        assert!(sync_err.is_err());
        assert_eq!(
            sync_err.unwrap_err(),
            "Session token missing. Please log in."
        );
    }

    #[test]
    fn test_sync_allowed_when_locked_with_session() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault_sync_locked.json");
        let storage_mgr = StorageManager::new(path.clone());
        let legacy_json = serde_json::json!({
            "access_token": "fake_test_token"
        });
        std::fs::write(&path, legacy_json.to_string()).unwrap();

        let dummy_keyring = KeyringManager::new("/nonexistent-keyring");
        let vault_mgr =
            VaultManager::new("http://127.0.0.1:9", Some(storage_mgr), Some(dummy_keyring));
        assert!(!vault_mgr.is_unlocked());

        let sync_res = vault_mgr.sync();
        assert!(sync_res.is_err());
        let err_msg = sync_res.unwrap_err();
        assert!(!err_msg.contains("Vault is locked"));
        assert!(!err_msg.contains("Session token missing"));
        assert!(err_msg.contains("Sync failed"));
    }

    #[test]
    fn test_vault_sync_silent_reauth_with_api_secret_on_expired_token() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use std::fs;
        use std::io::{Read, Write};
        use std::net::TcpListener;

        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_url = format!("http://127.0.0.1:{}", port);

        // Spawn mock server responding to /identity/connect/token and /api/sync
        let server_handle = thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);

                if req.contains("/identity/connect/token") {
                    let body = serde_json::json!({
                        "access_token": "renewed_access_token_abc123",
                        "expires_in": 7200,
                        "token_type": "Bearer"
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                } else if req.contains("/api/sync") {
                    assert!(req.contains("Bearer renewed_access_token_abc123"));
                    let body = serde_json::json!({
                        "ciphers": [],
                        "folders": [],
                        "collections": [],
                        "profile": {
                            "id": "uuid-sync-user",
                            "email": "sync@example.com"
                        }
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    break;
                }
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let storage_path = dir.path().join("vault_reauth.json");
        let storage_mgr = StorageManager::new(storage_path);

        let store_dir = dir.path().join("store");
        fs::create_dir_all(&store_dir).unwrap();
        let script_path = dir.path().join("mock-secret-tool");

        let script = format!(
            r#"#!/bin/sh
STORE_DIR="{}"
cmd="$1"
shift
case "$1" in
    --label=*)
        shift
        ;;
esac

key=""
while [ $# -gt 0 ]; do
    k="$1"
    v="$2"
    safe_v=$(printf '%s' "$v" | tr '/:' '_')
    key="${{key}}__${{k}}=${{safe_v}}"
    shift 2 2>/dev/null || shift 1
done

case "$cmd" in
    store)
        cat > "${{STORE_DIR}}/${{key}}"
        exit 0
        ;;
    lookup)
        if [ -f "${{STORE_DIR}}/${{key}}" ]; then
            cat "${{STORE_DIR}}/${{key}}"
            exit 0
        else
            exit 1
        fi
        ;;
    clear)
        if [ -z "$key" ] || [ "$key" = "__service=omarchy-bitwarden" ]; then
            rm -f "${{STORE_DIR}}"/*
        else
            rm -f "${{STORE_DIR}}/${{key}}"*
        fi
        exit 0
        ;;
    *)
        exit 1
        ;;
esac
"#,
            store_dir.display()
        );

        crate::write_test_executable(&script_path, script);

        let mock_keyring = KeyringManager::new(script_path.to_str().unwrap());

        let client_id = "user.reauth-test-id";
        let client_secret = "reauth-secret-val";

        // Store API secret in Keyring
        assert!(mock_keyring.store_api_secret(&server_url, client_id, client_secret));

        // Store an EXPIRED access token in Keyring
        let now = chrono::Utc::now().timestamp();
        let past_payload = serde_json::json!({ "exp": now - 300 });
        let past_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&past_payload).unwrap());
        let expired_token = format!("eyJhbGciOiJSUzI1NiJ9.{}.sig", past_b64);
        assert!(mock_keyring.store_token(
            &server_url,
            crate::keyring::KIND_ACCESS_TOKEN,
            &expired_token
        ));

        let storage = VaultStorage {
            server_url: server_url.clone(),
            user_email: "reauth@example.com".to_string(),
            client_id: Some(client_id.to_string()),
            ..Default::default()
        };
        storage_mgr.save(&storage).unwrap();

        let vault_mgr = VaultManager::new(
            &server_url,
            Some(storage_mgr.clone()),
            Some(mock_keyring.clone()),
        );

        // sync() should detect expired token, silently re-auth via API secret, and successfully sync
        let sync_res = vault_mgr.sync();
        assert!(
            sync_res.is_ok(),
            "Sync should succeed after silent re-auth: {:?}",
            sync_res
        );

        let _ = server_handle.join();

        // Verify the new token is stored in Keyring
        assert_eq!(
            mock_keyring.get_token(&server_url, crate::keyring::KIND_ACCESS_TOKEN),
            Some("renewed_access_token_abc123".to_string())
        );
        // Verify disk storage remains zero-plaintext
        let fresh_storage = storage_mgr.load();
        assert!(fresh_storage.access_token.is_none());
    }

    #[test]
    fn test_vault_sync_reauth_failure_purges_tokens_and_locks() {
        use std::fs;
        use std::io::{Read, Write};
        use std::net::TcpListener;

        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_url = format!("http://{}", listener.local_addr().unwrap());

        let server_handle = thread::spawn(move || {
            for stream in listener.incoming().take(1) {
                let mut stream = stream.unwrap();
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                if req.contains("/connect/token") {
                    let body = serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": "Refresh token revoked"
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                }
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let storage_path = dir.path().join("vault_reauth_fail.json");
        let storage_mgr = StorageManager::new(storage_path);

        let store_dir = dir.path().join("store");
        fs::create_dir_all(&store_dir).unwrap();
        let script_path = dir.path().join("mock-secret-tool");

        let script = format!(
            r#"#!/bin/sh
STORE_DIR="{}"
cmd="$1"
shift
case "$1" in
    --label=*)
        shift
        ;;
esac

key=""
while [ $# -gt 0 ]; do
    k="$1"
    v="$2"
    safe_v=$(printf '%s' "$v" | tr '/:' '_')
    key="${{key}}__${{k}}=${{safe_v}}"
    shift 2 2>/dev/null || shift 1
done

case "$cmd" in
    store)
        cat > "${{STORE_DIR}}/${{key}}"
        exit 0
        ;;
    lookup)
        if [ -f "${{STORE_DIR}}/${{key}}" ]; then
            cat "${{STORE_DIR}}/${{key}}"
            exit 0
        else
            exit 1
        fi
        ;;
    clear)
        if [ -z "$key" ] || [ "$key" = "__service=omarchy-bitwarden" ]; then
            rm -f "${{STORE_DIR}}"/*
        else
            rm -f "${{STORE_DIR}}/${{key}}"*
        fi
        exit 0
        ;;
    *)
        exit 1
        ;;
esac
"#,
            store_dir.display()
        );

        crate::write_test_executable(&script_path, script);

        let mock_keyring = KeyringManager::new(script_path.to_str().unwrap());

        let client_id = "user.fail-test";
        let client_secret = "secret-val-to-retain";

        // Store API secret in Keyring
        assert!(mock_keyring.store_api_secret(&server_url, client_id, client_secret));

        // Set refresh token in Keyring and storage
        assert!(mock_keyring.store_token(
            &server_url,
            crate::keyring::KIND_REFRESH_TOKEN,
            "revoked_ref_token"
        ));

        let storage = VaultStorage {
            server_url: server_url.clone(),
            user_email: "fail@example.com".to_string(),
            refresh_token: Some("revoked_ref_token".to_string()),
            ..Default::default()
        };
        storage_mgr.save(&storage).unwrap();

        let vault_mgr = VaultManager::new(
            &server_url,
            Some(storage_mgr.clone()),
            Some(mock_keyring.clone()),
        );

        // renew_session should fail with auth rejection, purge tokens, and lock vault
        let res = vault_mgr.renew_session();
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            "Session expired or credentials rejected. Please log in again."
        );

        let _ = server_handle.join();

        // Keyring tokens purged
        assert_eq!(
            mock_keyring.get_token(&server_url, crate::keyring::KIND_ACCESS_TOKEN),
            None
        );
        assert_eq!(
            mock_keyring.get_token(&server_url, crate::keyring::KIND_REFRESH_TOKEN),
            None
        );

        // API secret is preserved
        assert_eq!(
            mock_keyring.get_api_secret(&server_url, client_id),
            Some(client_secret.to_string())
        );

        // Storage tokens purged
        let fresh_storage = storage_mgr.load();
        assert!(fresh_storage.access_token.is_none());
        assert!(fresh_storage.refresh_token.is_none());
    }

    #[test]
    fn test_vault_sync_network_error_preserves_tokens() {
        use std::fs;

        let dir = tempfile::tempdir().unwrap();
        let storage_path = dir.path().join("vault_reauth_net_fail.json");
        let storage_mgr = StorageManager::new(storage_path.clone());

        let store_dir = dir.path().join("store");
        fs::create_dir_all(&store_dir).unwrap();
        let script_path = dir.path().join("mock-secret-tool");

        let script = format!(
            r#"#!/bin/sh
STORE_DIR="{}"
cmd="$1"
shift
case "$1" in
    --label=*)
        shift
        ;;
esac

key=""
while [ $# -gt 0 ]; do
    k="$1"
    v="$2"
    safe_v=$(printf '%s' "$v" | tr '/:' '_')
    key="${{key}}__${{k}}=${{safe_v}}"
    shift 2 2>/dev/null || shift 1
done

case "$cmd" in
    store)
        cat > "${{STORE_DIR}}/${{key}}"
        exit 0
        ;;
    lookup)
        if [ -f "${{STORE_DIR}}/${{key}}" ]; then
            cat "${{STORE_DIR}}/${{key}}"
            exit 0
        else
            exit 1
        fi
        ;;
    clear)
        if [ -z "$key" ] || [ "$key" = "__service=omarchy-bitwarden" ]; then
            rm -f "${{STORE_DIR}}"/*
        else
            rm -f "${{STORE_DIR}}/${{key}}"*
        fi
        exit 0
        ;;
    *)
        exit 1
        ;;
esac
"#,
            store_dir.display()
        );

        crate::write_test_executable(&script_path, script);

        let mock_keyring = KeyringManager::new(script_path.to_str().unwrap());

        // Set refresh token
        assert!(mock_keyring.store_token(
            "http://127.0.0.1:9",
            crate::keyring::KIND_REFRESH_TOKEN,
            "valid_ref_token"
        ));

        let legacy_json = serde_json::json!({
            "server_url": "http://127.0.0.1:9",
            "user_email": "offline@example.com",
            "refresh_token": "valid_ref_token"
        });
        fs::write(&storage_path, legacy_json.to_string()).unwrap();

        let vault_mgr = VaultManager::new(
            "http://127.0.0.1:9",
            Some(storage_mgr.clone()),
            Some(mock_keyring.clone()),
        );

        // renew_session should fail due to network error without wiping tokens
        let res = vault_mgr.renew_session();
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Network error"));

        // Keyring refresh token NOT purged
        assert_eq!(
            mock_keyring.get_token("http://127.0.0.1:9", crate::keyring::KIND_REFRESH_TOKEN),
            Some("valid_ref_token".to_string())
        );

        // Storage tokens NOT purged
        let fresh_storage = storage_mgr.load();
        assert_eq!(
            fresh_storage.refresh_token,
            Some("valid_ref_token".to_string())
        );
    }

    #[test]
    fn test_vault_sync_server_502_error_preserves_tokens() {
        use std::fs;
        use std::io::{Read, Write};
        use std::net::TcpListener;

        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_url = format!("http://127.0.0.1:{}", port);

        let handle = thread::spawn(move || {
            let mut count = 0;
            for mut stream in listener.incoming().flatten() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let resp =
                    "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(resp.as_bytes());
                count += 1;
                if count >= 2 {
                    break;
                }
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let storage_path = dir.path().join("vault_502_preserves.json");
        let storage_mgr = StorageManager::new(storage_path.clone());

        let store_dir = dir.path().join("store");
        fs::create_dir_all(&store_dir).unwrap();
        let script_path = dir.path().join("mock-secret-tool");

        let script = format!(
            r#"#!/bin/sh
STORE_DIR="{}"
cmd="$1"
shift
case "$1" in
    --label=*)
        shift
        ;;
esac

key=""
while [ $# -gt 0 ]; do
    k="$1"
    v="$2"
    safe_v=$(printf '%s' "$v" | tr '/:' '_')
    key="${{key}}__${{k}}=${{safe_v}}"
    shift 2 2>/dev/null || shift 1
done

case "$cmd" in
    store)
        cat > "${{STORE_DIR}}/${{key}}"
        exit 0
        ;;
    lookup)
        if [ -f "${{STORE_DIR}}/${{key}}" ]; then
            cat "${{STORE_DIR}}/${{key}}"
            exit 0
        else
            exit 1
        fi
        ;;
    clear)
        if [ -z "$key" ] || [ "$key" = "__service=omarchy-bitwarden" ]; then
            rm -f "${{STORE_DIR}}"/*
        else
            rm -f "${{STORE_DIR}}/${{key}}"*
        fi
        exit 0
        ;;
    *)
        exit 1
        ;;
esac
"#,
            store_dir.display()
        );

        crate::write_test_executable(&script_path, script);

        let mock_keyring = KeyringManager::new(script_path.to_str().unwrap());

        // Set refresh token and api secret
        assert!(mock_keyring.store_token(
            &server_url,
            crate::keyring::KIND_REFRESH_TOKEN,
            "valid_ref_token"
        ));
        assert!(mock_keyring.store_api_secret(&server_url, "test_client_id", "test_secret"));

        let legacy_json = serde_json::json!({
            "server_url": server_url.clone(),
            "user_email": "gateway502@example.com",
            "client_id": "test_client_id",
            "refresh_token": "valid_ref_token"
        });
        fs::write(&storage_path, legacy_json.to_string()).unwrap();

        let vault_mgr = VaultManager::new(
            &server_url,
            Some(storage_mgr.clone()),
            Some(mock_keyring.clone()),
        );

        // renew_session should fail due to 502 without wiping tokens
        let res = vault_mgr.renew_session();
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Network error"));

        // Keyring refresh token and api secret NOT purged
        assert_eq!(
            mock_keyring.get_token(&server_url, crate::keyring::KIND_REFRESH_TOKEN),
            Some("valid_ref_token".to_string())
        );
        assert_eq!(
            mock_keyring.get_api_secret(&server_url, "test_client_id"),
            Some("test_secret".to_string())
        );

        // Storage tokens NOT purged
        let fresh_storage = storage_mgr.load();
        assert_eq!(
            fresh_storage.refresh_token,
            Some("valid_ref_token".to_string())
        );

        let _ = handle.join();
    }
}
