//! Recent use of vault items (ADR 0029).
//!
//! The daemon records one use per successful `copy_field` and one per
//! successful `copy_sequence`, and the redacted item views (`list`,
//! `search`, `get_item`) carry the resulting `usage_score` and
//! `last_used_at`. The record holds item ids and Unix timestamps only, in
//! `usage.json` next to the vault cache (`data.json`), mode 0600.
//!
//! The score of an item is the sum, over its kept uses, of
//! `0.5 ^ (age / USAGE_HALF_LIFE)`: a use counts 1 when it happens and half
//! as much a half-life later, so items used often and lately rank first.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::storage::VaultStorage;

/// Name of the usage record, in the directory of the vault cache.
pub const USAGE_FILENAME: &str = "usage.json";
/// Age at which a use counts half as much toward the score.
pub const USAGE_HALF_LIFE: Duration = Duration::from_secs(7 * 24 * 3600);
/// Uses older than this are discarded.
pub const USAGE_RETENTION: Duration = Duration::from_secs(90 * 24 * 3600);
/// Most recent uses kept per item; older ones are discarded.
pub const USAGE_TIMESTAMPS_PER_ITEM: usize = 20;
/// Format version written to the usage record.
pub const USAGE_FILE_VERSION: u32 = 1;
/// Decimal places of `usage_score` in item views.
pub const USAGE_SCORE_DECIMALS: i32 = 3;

const USAGE_FILE_MODE: u32 = 0o600;
const USAGE_DIRECTORY_MODE: u32 = 0o700;
const LOG_TARGET: &str = "omawarden:usage";

/// The current time in Unix seconds.
pub fn current_unix_seconds() -> i64 {
    chrono::Utc::now().timestamp()
}

/// The usage record that belongs to the vault cache at `storage_path`.
pub fn usage_file_path(storage_path: &Path) -> PathBuf {
    storage_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(USAGE_FILENAME)
}

/// The ids of every cipher in the vault cache.
pub fn vault_item_ids(storage: &VaultStorage) -> HashSet<String> {
    storage
        .ciphers
        .iter()
        .filter_map(|cipher| cipher.get("id").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

fn duration_seconds(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

/// Weight of one use made at `used_at`, seen at `now`. A use stamped in
/// the future (clock moved back) counts as a use made now.
fn use_weight(used_at: i64, now: i64) -> f64 {
    let age = now.saturating_sub(used_at).max(0) as f64;
    0.5_f64.powf(age / duration_seconds(USAGE_HALF_LIFE) as f64)
}

fn rounded_score(score: f64) -> f64 {
    let scale = 10_f64.powi(USAGE_SCORE_DECIMALS);
    (score * scale).round() / scale
}

fn rfc3339_utc(timestamp: i64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp, 0)
        .map(|moment| moment.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// The use timestamps of every item, ascending per item. Pure: every
/// operation takes the current time as an argument.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UsageTable {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    items: BTreeMap<String, Vec<i64>>,
}

impl UsageTable {
    /// Records one use of `item_id` at `now`, then applies the retention
    /// and the per-item cap.
    pub fn record(&mut self, item_id: &str, now: i64) {
        self.items.entry(item_id.to_string()).or_default().push(now);
        self.prune(now);
    }

    /// Drops uses older than `USAGE_RETENTION`, uses beyond the per-item
    /// cap (oldest first) and items left without uses. Returns whether any
    /// use was dropped.
    pub fn prune(&mut self, now: i64) -> bool {
        let oldest_kept = now.saturating_sub(duration_seconds(USAGE_RETENTION));
        let before = self.use_count();
        for uses in self.items.values_mut() {
            uses.retain(|used_at| *used_at > oldest_kept);
            uses.sort_unstable();
            let excess = uses.len().saturating_sub(USAGE_TIMESTAMPS_PER_ITEM);
            uses.drain(..excess);
        }
        self.items.retain(|_, uses| !uses.is_empty());
        self.use_count() != before
    }

    fn use_count(&self) -> usize {
        self.items.values().map(Vec::len).sum()
    }

    /// Keeps only the items whose id is in `present`. Returns whether any
    /// item was removed.
    pub fn retain_items(&mut self, present: &HashSet<String>) -> bool {
        let before = self.items.len();
        self.items.retain(|item_id, _| present.contains(item_id));
        self.items.len() != before
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The kept use timestamps of `item_id`, ascending.
    pub fn uses(&self, item_id: &str) -> &[i64] {
        self.items.get(item_id).map_or(&[], Vec::as_slice)
    }

    /// The unrounded score of `item_id` at `now`; 0 when never used.
    pub fn score(&self, item_id: &str, now: i64) -> f64 {
        self.uses(item_id)
            .iter()
            .map(|used_at| use_weight(*used_at, now))
            .sum()
    }

    /// The timestamp of the latest use of `item_id`.
    pub fn last_used(&self, item_id: &str) -> Option<i64> {
        self.uses(item_id).last().copied()
    }

    /// Adds `usage_score` and `last_used_at` to one redacted item view.
    /// A view without a string `id` is left unchanged.
    pub fn annotate_item(&self, view: &mut Value, now: i64) {
        let Some(item_id) = view.get("id").and_then(Value::as_str).map(str::to_string) else {
            return;
        };
        let Some(map) = view.as_object_mut() else {
            return;
        };
        let score = rounded_score(self.score(&item_id, now));
        let last_used_at = self.last_used(&item_id).and_then(rfc3339_utc);
        map.insert("usage_score".to_string(), score.into());
        map.insert("last_used_at".to_string(), last_used_at.into());
    }

    /// Adds the usage fields to every item of a redacted listing.
    pub fn annotate_items(&self, listing: &mut Value, now: i64) {
        if let Some(views) = listing.as_array_mut() {
            for view in views {
                self.annotate_item(view, now);
            }
        }
    }

    fn serialized(&self) -> Result<String, serde_json::Error> {
        let mut table = self.clone();
        table.version = USAGE_FILE_VERSION;
        serde_json::to_string(&table)
    }
}

/// The usage table and the file it is kept in. Saving failures are logged
/// and never reported to the caller: a use that cannot be saved must not
/// fail the copy that caused it.
#[derive(Debug)]
pub struct ItemUsage {
    file_path: PathBuf,
    table: UsageTable,
}

impl ItemUsage {
    /// Reads the record at `file_path`, pruned as of `now`. A missing file
    /// is an empty record; an unreadable or malformed one is logged and
    /// treated as empty.
    pub fn load(file_path: PathBuf, now: i64) -> Self {
        let mut table = read_table(&file_path);
        table.prune(now);
        Self { file_path, table }
    }

    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    pub fn table(&self) -> &UsageTable {
        &self.table
    }

    /// Records one use of `item_id` and saves the record.
    pub fn record_use(&mut self, item_id: &str, now: i64) {
        self.table.record(item_id, now);
        self.save();
    }

    /// Removes items no longer in the vault (`present`), prunes as of
    /// `now`, and saves the record when it changed.
    pub fn retain_items(&mut self, present: &HashSet<String>, now: i64) {
        let removed = self.table.retain_items(present);
        let pruned = self.table.prune(now);
        if removed || pruned {
            self.save();
        }
    }

    /// Forgets every use and deletes the file.
    pub fn clear(&mut self) {
        self.table = UsageTable::default();
        remove_usage_file(&self.file_path);
    }

    fn save(&self) {
        if let Err(error) = write_table(&self.file_path, &self.table) {
            crate::log_warn!(
                LOG_TARGET,
                "Could not save the item usage record: {}",
                error
            );
        }
    }
}

fn read_table(file_path: &Path) -> UsageTable {
    let content = match std::fs::read_to_string(file_path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return UsageTable::default();
        }
        Err(error) => {
            crate::log_warn!(
                LOG_TARGET,
                "Could not read the item usage record: {}",
                error
            );
            return UsageTable::default();
        }
    };
    serde_json::from_str(&content).unwrap_or_else(|error| {
        crate::log_warn!(
            LOG_TARGET,
            "Ignoring a malformed item usage record: {}",
            error
        );
        UsageTable::default()
    })
}

fn write_table(file_path: &Path, table: &UsageTable) -> std::io::Result<()> {
    if let Some(parent) = file_path.parent() {
        crate::fs_util::create_secure_dir_all(parent, USAGE_DIRECTORY_MODE)?;
    }
    let content = table
        .serialized()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    crate::fs_util::atomic_write_str(file_path, &content, USAGE_FILE_MODE)
}

/// Deletes the usage record at `file_path`; a missing file is not an error.
pub fn remove_usage_file(file_path: &Path) {
    match std::fs::remove_file(file_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => crate::log_warn!(
            LOG_TARGET,
            "Could not delete the item usage record: {}",
            error
        ),
    }
}

/// Prunes the usage record of the vault cache at `storage_path` to the
/// items of `storage`. Used after a sync made without the daemon.
pub fn retain_vault_items_on_disk(storage_path: &Path, storage: &VaultStorage) {
    let file_path = usage_file_path(storage_path);
    if !file_path.exists() {
        return;
    }
    let now = current_unix_seconds();
    ItemUsage::load(file_path, now).retain_items(&vault_item_ids(storage), now);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 24 * 3600;

    fn half_life() -> i64 {
        duration_seconds(USAGE_HALF_LIFE)
    }

    #[test]
    fn test_constants_match_the_specification() {
        assert_eq!(USAGE_HALF_LIFE, Duration::from_secs(7 * 24 * 3600));
        assert_eq!(USAGE_RETENTION, Duration::from_secs(90 * 24 * 3600));
        assert_eq!(USAGE_TIMESTAMPS_PER_ITEM, 20);
    }

    #[test]
    fn test_a_single_use_halves_after_one_half_life() {
        let mut table = UsageTable::default();
        table.record("item", NOW);
        assert_eq!(table.score("item", NOW), 1.0);
        assert!((table.score("item", NOW + half_life()) - 0.5).abs() < 1e-12);
        assert!((table.score("item", NOW + 2 * half_life()) - 0.25).abs() < 1e-12);
        assert_eq!(table.score("never-used", NOW), 0.0);
    }

    #[test]
    fn test_score_sums_every_kept_use() {
        let mut table = UsageTable::default();
        table.record("item", NOW - half_life());
        table.record("item", NOW);
        assert!((table.score("item", NOW) - 1.5).abs() < 1e-12);
    }

    #[test]
    fn test_a_future_timestamp_counts_as_a_use_made_now() {
        let mut table = UsageTable::default();
        table.record("item", NOW + DAY);
        assert_eq!(table.score("item", NOW), 1.0);
    }

    #[test]
    fn test_retention_prunes_uses_at_ninety_days() {
        let retention = duration_seconds(USAGE_RETENTION);
        let mut table = UsageTable::default();
        table.record("old", NOW - retention);
        table.record("kept", NOW - retention + 1);
        table.record("kept", NOW);
        assert!(table.uses("old").is_empty(), "a use 90 days old is dropped");
        assert_eq!(table.uses("kept"), &[NOW - retention + 1, NOW]);

        assert!(table.prune(NOW + 1));
        assert_eq!(table.uses("kept"), &[NOW]);
        assert!(!table.prune(NOW + 1), "a second prune changes nothing");
        assert!(!table.items.contains_key("old"));
    }

    #[test]
    fn test_each_item_keeps_its_twenty_most_recent_uses() {
        let mut table = UsageTable::default();
        for offset in 0..(USAGE_TIMESTAMPS_PER_ITEM as i64 + 5) {
            table.record("item", NOW + offset);
        }
        let uses = table.uses("item");
        assert_eq!(uses.len(), USAGE_TIMESTAMPS_PER_ITEM);
        assert_eq!(uses[0], NOW + 5, "the oldest uses are dropped");
        assert_eq!(table.last_used("item"), Some(NOW + 24));
    }

    #[test]
    fn test_retain_items_removes_ids_missing_from_the_vault() {
        let mut table = UsageTable::default();
        table.record("kept", NOW);
        table.record("deleted", NOW);
        let present: HashSet<String> = ["kept".to_string()].into();
        assert!(table.retain_items(&present));
        assert_eq!(table.uses("kept"), &[NOW]);
        assert!(table.uses("deleted").is_empty());
        assert!(!table.retain_items(&present));
    }

    #[test]
    fn test_annotation_adds_rounded_score_and_last_use() {
        let mut table = UsageTable::default();
        table.record("used", NOW - DAY);
        let mut listing = json!([{ "id": "used" }, { "id": "unused" }, { "name": "no id" }]);
        table.annotate_items(&mut listing, NOW);

        let expected = rounded_score(0.5_f64.powf(1.0 / 7.0));
        assert_eq!(listing[0]["usage_score"], json!(expected));
        assert_eq!(listing[0]["usage_score"], json!(0.906));
        let expected_time = rfc3339_utc(NOW - DAY).unwrap();
        assert_eq!(listing[0]["last_used_at"], json!(expected_time));
        assert!(expected_time.ends_with('Z'), "{expected_time}");
        assert_eq!(listing[1]["usage_score"], json!(0.0));
        assert_eq!(listing[1]["last_used_at"], Value::Null);
        assert!(listing[2].get("usage_score").is_none());
    }

    #[test]
    fn test_rfc3339_output_is_utc_with_whole_seconds() {
        assert_eq!(rfc3339_utc(0).as_deref(), Some("1970-01-01T00:00:00Z"));
        assert_eq!(
            rfc3339_utc(1_762_473_600).as_deref(),
            Some("2025-11-07T00:00:00Z")
        );
    }

    #[test]
    fn test_record_saves_ids_and_timestamps_only_with_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join(USAGE_FILENAME);
        let mut usage = ItemUsage::load(path.clone(), NOW);
        usage.record_use("item-1", NOW);

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let directory_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(directory_mode, 0o700);

        let saved: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            saved,
            json!({ "version": USAGE_FILE_VERSION, "items": { "item-1": [NOW] } })
        );
    }

    #[test]
    fn test_load_prunes_expired_uses_and_tolerates_bad_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(USAGE_FILENAME);
        let expired = NOW - duration_seconds(USAGE_RETENTION) - 1;
        std::fs::write(
            &path,
            json!({ "version": 1, "items": { "a": [expired, NOW], "b": [expired] } }).to_string(),
        )
        .unwrap();
        let usage = ItemUsage::load(path.clone(), NOW);
        assert_eq!(usage.table().uses("a"), &[NOW]);
        assert!(usage.table().uses("b").is_empty());

        std::fs::write(&path, "not json").unwrap();
        assert!(ItemUsage::load(path.clone(), NOW).table().is_empty());
        let missing = dir.path().join("missing.json");
        assert!(ItemUsage::load(missing, NOW).table().is_empty());
    }

    #[test]
    fn test_clear_forgets_uses_and_deletes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(USAGE_FILENAME);
        let mut usage = ItemUsage::load(path.clone(), NOW);
        usage.record_use("item-1", NOW);
        assert!(path.exists());
        usage.clear();
        assert!(!path.exists());
        assert!(usage.table().is_empty());
        usage.clear();
    }

    #[test]
    fn test_a_failed_save_keeps_the_use_in_memory() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("file");
        std::fs::write(&blocker, "").unwrap();
        let mut usage = ItemUsage::load(blocker.join(USAGE_FILENAME), NOW);
        usage.record_use("item-1", NOW);
        assert_eq!(usage.table().uses("item-1"), &[NOW]);
    }

    #[test]
    fn test_usage_file_sits_next_to_the_vault_cache() {
        assert_eq!(
            usage_file_path(Path::new("/data/omawarden/data.json")),
            PathBuf::from("/data/omawarden/usage.json")
        );
    }

    #[test]
    fn test_retain_vault_items_on_disk_prunes_the_saved_record() {
        let dir = tempfile::tempdir().unwrap();
        let storage_path = dir.path().join("data.json");
        let usage_path = usage_file_path(&storage_path);
        let now = current_unix_seconds();
        let mut usage = ItemUsage::load(usage_path.clone(), now);
        usage.record_use("kept", now);
        usage.record_use("deleted", now);
        let storage = VaultStorage {
            ciphers: vec![json!({ "id": "kept" }), json!({ "name": "no id" })],
            ..Default::default()
        };
        retain_vault_items_on_disk(&storage_path, &storage);
        let reloaded = ItemUsage::load(usage_path, now);
        assert_eq!(reloaded.table().uses("kept"), &[now]);
        assert!(reloaded.table().uses("deleted").is_empty());
    }
}
