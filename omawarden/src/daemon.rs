use serde_json::{json, Value};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::daemon_actions::ActionOutcome;
use crate::daemon_requests::{ConnectionLimiter, RESPONSE_WRITE_TIMEOUT};
use crate::secret_access::ReleaseBudget;
use crate::secret_memory::{serialize_zeroizing, zeroize_json_value};
use crate::session_supervision::{SessionBinding, SleepInhibitor, SupervisionPrograms};
use crate::storage::StorageManager;
use crate::vault::VaultManager;

use std::os::unix::process::CommandExt;

/// Idle auto-lock applied when the configured value is outside the accepted
/// range (`daemon_actions::MIN_AUTO_LOCK..=MAX_AUTO_LOCK`).
pub const DEFAULT_AUTO_LOCK_MINUTES: u64 = 15;
/// Name of the daemon socket inside the runtime directory.
pub const SOCKET_FILENAME: &str = "omawarden.sock";
/// Attempts, 100 ms apart, to see a previous daemon release the socket
/// before a new daemon refuses to start.
const SOCKET_RELEASE_ATTEMPTS: u32 = 10;

fn runtime_dir_error(message: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message)
}

/// Requires `dir` to be an absolute, real directory owned by the current
/// user with mode 0700 (the contract of `XDG_RUNTIME_DIR`).
pub fn validate_runtime_dir(dir: &Path) -> std::io::Result<()> {
    if !dir.is_absolute() {
        return Err(runtime_dir_error(format!(
            "XDG_RUNTIME_DIR '{}' is not an absolute path",
            dir.display()
        )));
    }
    let meta = fs::symlink_metadata(dir).map_err(|e| {
        runtime_dir_error(format!(
            "XDG_RUNTIME_DIR '{}' is not accessible: {}",
            dir.display(),
            e
        ))
    })?;
    if !meta.file_type().is_dir() {
        return Err(runtime_dir_error(format!(
            "XDG_RUNTIME_DIR '{}' is not a directory (symlinks are refused)",
            dir.display()
        )));
    }
    let current_uid = unsafe { libc::getuid() };
    if meta.uid() != current_uid {
        return Err(runtime_dir_error(format!(
            "XDG_RUNTIME_DIR '{}' is owned by UID {} instead of the current UID {}",
            dir.display(),
            meta.uid(),
            current_uid
        )));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o700 {
        return Err(runtime_dir_error(format!(
            "XDG_RUNTIME_DIR '{}' has mode {:o}; it must be 0700",
            dir.display(),
            mode
        )));
    }
    Ok(())
}

/// Tests never resolve to the login session's `/run/user/{uid}`: some send
/// `stop` or start a daemon, which would lock the user's real vault. They
/// use a private directory instead, created 0700 and validated like any
/// other runtime directory.
#[cfg(test)]
fn test_runtime_dir_for(dir: PathBuf) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let current_uid = unsafe { libc::getuid() };
    if dir != Path::new(&format!("/run/user/{}", current_uid)) {
        return Ok(dir);
    }
    let isolated = env::temp_dir().join(format!("omawarden-test-runtime-{}", current_uid));
    match fs::DirBuilder::new().mode(0o700).create(&isolated) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    Ok(isolated)
}

#[cfg(not(test))]
fn test_runtime_dir_for(dir: PathBuf) -> std::io::Result<PathBuf> {
    Ok(dir)
}

/// Resolves the runtime directory for the daemon socket and IPC files from
/// `XDG_RUNTIME_DIR`. There is no fallback: an unset variable or a directory
/// that is not owned by the user with mode 0700 is an error, because a
/// shared location such as /tmp cannot be made race-free for the socket.
pub fn get_runtime_dir() -> std::io::Result<PathBuf> {
    let raw = env::var_os("XDG_RUNTIME_DIR")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            runtime_dir_error(
                "XDG_RUNTIME_DIR is not set; omawarden needs the per-user runtime directory of a login session".to_string(),
            )
        })?;
    let dir = test_runtime_dir_for(PathBuf::from(raw))?;
    validate_runtime_dir(&dir)?;
    Ok(dir)
}

pub fn get_socket_path() -> std::io::Result<PathBuf> {
    Ok(get_runtime_dir()?.join(SOCKET_FILENAME))
}

fn foreign_owner_error(what: &str, path: &Path, uid: u32) -> std::io::Error {
    let current_uid = unsafe { libc::getuid() };
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "{} '{}' is owned by foreign UID {} (expected current UID {})",
            what,
            path.display(),
            uid,
            current_uid
        ),
    )
}

fn symlink_error(what: &str, path: &Path) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "{} '{}' is a symlink (potential hijacking attempt)",
            what,
            path.display()
        ),
    )
}

fn validate_owned_non_symlink(what: &str, path: &Path) -> std::io::Result<()> {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if meta.file_type().is_symlink() {
        return Err(symlink_error(what, path));
    }
    if meta.uid() != unsafe { libc::getuid() } {
        return Err(foreign_owner_error(what, path, meta.uid()));
    }
    Ok(())
}

/// Validates that a socket file (and its parent directory) is owned by the current UID
/// and is not a symlink to prevent cross-user socket hijacking or TOCTOU attacks.
pub fn validate_socket_path(path: &Path) -> std::io::Result<()> {
    validate_owned_non_symlink("Socket path", path)?;
    match path.parent() {
        Some(parent) => validate_owned_non_symlink("Socket parent directory", parent),
        None => Ok(()),
    }
}

/// What to do about a running daemon built from a different commit.
#[derive(Debug, PartialEq)]
enum DaemonCheck {
    UpToDate,
    /// Mismatched but unlocked: replacing it would lock the vault mid-use,
    /// so leave it until it locks.
    Defer,
    Replace,
}

fn check_running_daemon(ping: &Value, our_commit: &str) -> DaemonCheck {
    let running_commit = ping.get("commit").and_then(|v| v.as_str()).unwrap_or("");
    if running_commit == our_commit {
        DaemonCheck::UpToDate
    } else if ping.get("unlocked").and_then(|v| v.as_bool()) == Some(true) {
        DaemonCheck::Defer
    } else {
        DaemonCheck::Replace
    }
}

/// Stops an outdated, locked daemon. Returns false when the running daemon
/// must be kept (current build, or another build that is unlocked).
fn replace_outdated_daemon(ping: &Value) -> bool {
    let check = check_running_daemon(ping, env!("GIT_HASH"));
    if check == DaemonCheck::Defer {
        crate::log_info!(
            "omawarden:daemon",
            "Running daemon is from another build but the vault is unlocked; keeping it until it locks"
        );
    }
    if check != DaemonCheck::Replace {
        return false;
    }
    let _ = send_daemon_request(&json!({ "action": "stop" }));
    std::thread::sleep(Duration::from_millis(50));
    true
}

fn configured_auto_lock_minutes() -> u64 {
    let cfg = crate::config::ConfigManager::default().load();
    u64::try_from(cfg.auto_lock_minutes).unwrap_or(DEFAULT_AUTO_LOCK_MINUTES)
}

fn spawn_daemon_process(exe_path: PathBuf) {
    let mut cmd = Command::new(exe_path);
    cmd.arg("daemon")
        .arg("--auto-lock")
        .arg(configured_auto_lock_minutes().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }

    let _ = cmd.spawn();
}

pub fn ensure_daemon_running() {
    if let Err(e) = get_runtime_dir() {
        crate::log_error!("omawarden:daemon", "Cannot start the daemon: {}", e);
        eprintln!("Error: cannot start the omawarden daemon: {}", e);
        return;
    }
    if let Some(resp) = send_daemon_request(&json!({ "action": "ping" })) {
        if !replace_outdated_daemon(&resp) {
            return;
        }
    }

    let Ok(exe_path) = env::current_exe() else {
        return;
    };
    spawn_daemon_process(exe_path);
    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(20));
        if send_daemon_request(&json!({ "action": "ping" })).is_some() {
            break;
        }
    }
}

/// Connects to the daemon socket after validating it, and verifies that the
/// listening process is the same user and the same omawarden executable
/// before anything (a master password in particular) is sent to it.
fn connect_verified_daemon() -> Option<UnixStream> {
    let socket_path = match get_socket_path() {
        Ok(path) => path,
        Err(e) => {
            crate::log_error!("omawarden:daemon", "No usable runtime directory: {}", e);
            return None;
        }
    };
    if !socket_path.exists() {
        return None;
    }
    if let Err(e) = validate_socket_path(&socket_path) {
        crate::log_error!(
            "omawarden:daemon",
            "Refusing to connect to socket {}: {}",
            socket_path.display(),
            e
        );
        return None;
    }
    let stream = UnixStream::connect(&socket_path).ok()?;
    if let Err(e) = verify_daemon_peer(&stream) {
        crate::log_error!(
            "omawarden:daemon",
            "Refusing to send request: the daemon failed caller verification: {}",
            e
        );
        return None;
    }
    Some(stream)
}

fn verify_daemon_peer(stream: &UnixStream) -> std::io::Result<()> {
    let own = crate::peer_identity::own_executable()?;
    crate::peer_identity::verify_peer(stream, &own)
}

fn request_with_client_context(req: &Value) -> Value {
    let mut payload = req.clone();
    if let Value::Object(ref mut map) = payload {
        if !map.contains_key("client") {
            if let Some(ctx) = crate::api::resolve_effective_client_context(None) {
                map.insert("client".to_string(), json!(ctx));
            }
        }
    }
    payload
}

/// Sends one request and reads one response line. The copy of the request
/// and its serialized form are zeroized after sending; callers that put a
/// secret into `req` zeroize their own value (see `send_unlock_request`).
pub fn send_daemon_request(req: &Value) -> Option<Value> {
    let mut stream = connect_verified_daemon()?;
    let mut payload = request_with_client_context(req);
    let line = Zeroizing::new(format!("{}\n", payload));
    zeroize_json_value(&mut payload);
    stream.write_all(line.as_bytes()).ok()?;
    stream.flush().ok()?;

    let mut reader = BufReader::new(stream);
    let mut response_line = Zeroizing::new(String::new());
    reader.read_line(&mut response_line).ok()?;
    serde_json::from_str(&response_line).ok()
}

/// Sends `unlock` with the master password and zeroizes the request value
/// that carried it.
pub fn send_unlock_request(password: &str) -> Option<Value> {
    let mut request = json!({ "action": "unlock", "password": password });
    let response = send_daemon_request(&request);
    zeroize_json_value(&mut request);
    response
}

pub struct DaemonState {
    pub vault_mgr: Arc<VaultManager>,
    pub last_activity: Mutex<Instant>,
    pub auto_lock_duration: Mutex<Duration>,
    pub unlocked_at: Mutex<Option<Instant>>,
    pub max_session_lifetime: Mutex<Duration>,
    /// Failed polkit checks since the last successful quick unlock. Three in
    /// a row wipe the retained key (ADR-0025).
    pub quick_unlock_failures: Mutex<u32>,
    /// Held for the duration of an interactive polkit prompt so concurrent
    /// requests don't stack dialogs.
    pub quick_unlock_busy: Mutex<()>,
    /// Injectable for tests; defaults to `pkcheck` resolved from PATH.
    pub polkit_binary: PathBuf,
    /// Cached `quick_unlock` setting, read once at startup and refreshed via
    /// the `set_quick_unlock` IPC that `config set --quick-unlock` sends.
    /// Reading the file per call put a disk read + parse on the ping path
    /// (the overlay polls every 3s), on every watchdog tick and inside
    /// check_auto_lock, and a transient read failure silently meant
    /// "disabled", turning a soft lock into a hard lock mid-session.
    pub quick_unlock_setting: Mutex<bool>,
    /// Whether the packaged policy file for POLKIT_ACTION_ID exists in the
    /// polkit action directories, resolved once at startup. Without the
    /// policy, pkcheck exits 127 and quick unlock can only ever fail, so
    /// readiness must not advertise it.
    pub polkit_policy_registered: bool,
    /// Rule 9 / ADR-0025: when the current session's last master-password
    /// unlock happened. Survives soft locks so the 12h ceiling bounds the
    /// retained key too; cleared by every hard lock.
    pub session_anchor: Mutex<Option<Instant>>,
    /// CLOCK_BOOTTIME minus CLOCK_MONOTONIC, in whole seconds, as of the last
    /// watchdog tick. Suspend time accumulates in BOOTTIME only, so a growing
    /// delta is a deterministic resume-edge detector (no D-Bus needed).
    pub last_boot_delta_secs: Mutex<Option<u64>>,
    /// ADR 0027: successful `reveal_field` / `copy_field` releases in the
    /// current window. Reset by every hard lock.
    pub release_budget: Mutex<ReleaseBudget>,
    /// Clipboard program used by `copy` and `copy_field`, resolved from
    /// trusted root-owned locations (empty when none); injectable for tests.
    pub clipboard_program: String,
    /// Clipboard offers served by `copy` and `copy_field`, and the active
    /// paste sequence of `copy_sequence`; withdrawn by every lock.
    pub clipboard_offers: Arc<crate::clipboard::OfferRegistry>,
    /// Starts a paste sequence (`copy_sequence`): the native Wayland
    /// data-control source. Test builds refuse, so unit tests never touch
    /// the real clipboard unless they inject a launcher.
    pub paste_sequence_launcher: Arc<crate::selection_source::PasteSequenceLauncher>,
    /// `clipboard_clear_seconds` from the configuration at startup.
    pub clipboard_clear_seconds: i64,
    /// Normalized path of this executable, compared against every client.
    pub own_executable: PathBuf,
    /// External programs for the sleep inhibitor, sleep monitor and session
    /// probe; empty in test builds unless a test injects fixtures.
    pub supervision_programs: SupervisionPrograms,
    /// The logind delay inhibitor held while key material is resident.
    pub sleep_inhibitor: Mutex<Option<SleepInhibitor>>,
    /// Whether the PrepareForSleep monitor is running.
    pub sleep_monitor_active: AtomicBool,
    /// Bumped by every lock taken because of a suspend. An unlock samples it
    /// before its key derivation and ends locked when it changed.
    pub sleep_generation: AtomicU64,
    /// Between PrepareForSleep(true) and PrepareForSleep(false) (or a
    /// detected resume): no unlock may complete.
    pub sleep_pending: AtomicBool,
    /// The login session this daemon ends with.
    pub session_binding: SessionBinding,
    /// (device, inode) of the socket this daemon bound, so it only ever
    /// removes its own socket file on exit.
    pub bound_socket: Mutex<Option<(PathBuf, u64, u64)>>,
}

/// What locked the session. Sleep is treated harder than a screen lock
/// everywhere: a soft lock never survives a suspend (ADR-0025).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockSignal {
    None,
    Screen,
    Sleep,
}

/// Hard limit of consecutive denied quick-unlock prompts before the retained
/// key is wiped and the master password is required again.
pub const MAX_QUICK_UNLOCK_FAILURES: u32 = 3;

/// Resolve pkcheck from trusted system locations only, requiring a
/// root-owned regular file that group/other cannot write. A plain PATH
/// lookup would let any same-UID process plant a fake `pkcheck` in
/// ~/.local/bin that authorizes every quick unlock without a dialog
/// (full-review security finding).
fn resolve_pkcheck() -> Option<PathBuf> {
    crate::session_supervision::resolve_trusted_system_program(&[
        "/usr/bin/pkcheck",
        "/usr/sbin/pkcheck",
    ])
}

/// The trusted `wl-copy` for `copy` and `copy_field`. Test builds resolve
/// none, so unit tests never touch the real clipboard unless they inject a
/// fixture program.
fn resolve_clipboard_program() -> String {
    if cfg!(test) {
        return String::new();
    }
    crate::clipboard::resolve_trusted_wl_copy()
        .map(|path| path.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// The launcher of paste sequences: the compositor of `WAYLAND_DISPLAY`,
/// except in test builds, which have none.
fn default_paste_sequence_launcher() -> Arc<crate::selection_source::PasteSequenceLauncher> {
    if cfg!(test) {
        return Arc::new(|_, _| Err("No Wayland data-control source in test builds.".to_string()));
    }
    Arc::new(crate::selection_source::start_paste_sequence)
}

/// The idle auto-lock for a daemon started with `minutes`. A value outside
/// the accepted range (including the legacy 0 = never) falls back to the
/// default with a warning instead of disabling the idle lock.
pub fn initial_auto_lock_duration(minutes: u64) -> Duration {
    let seconds = minutes.saturating_mul(60);
    crate::daemon_actions::validate_auto_lock(seconds).unwrap_or_else(|reason| {
        crate::log_warn!(
            "omawarden:daemon",
            "Configured auto-lock of {} minutes is not accepted ({}); using {} minutes",
            minutes,
            reason,
            DEFAULT_AUTO_LOCK_MINUTES
        );
        Duration::from_secs(DEFAULT_AUTO_LOCK_MINUTES * 60)
    })
}

impl DaemonState {
    pub fn new(storage_mgr: StorageManager, auto_lock_minutes: u64) -> Self {
        let vault_mgr = Arc::new(VaultManager::new("", Some(storage_mgr), None));
        let polkit_binary = resolve_pkcheck().unwrap_or_default();
        let config = crate::config::ConfigManager::default().load();
        let polkit_policy_registered =
            crate::polkit::policy_registered(crate::polkit::POLKIT_ACTION_ID);
        let runtime_dir = get_runtime_dir().ok();
        Self {
            vault_mgr,
            last_activity: Mutex::new(Instant::now()),
            auto_lock_duration: Mutex::new(initial_auto_lock_duration(auto_lock_minutes)),
            unlocked_at: Mutex::new(None),
            max_session_lifetime: Mutex::new(Duration::from_secs(12 * 3600)),
            quick_unlock_failures: Mutex::new(0),
            quick_unlock_busy: Mutex::new(()),
            polkit_binary,
            quick_unlock_setting: Mutex::new(config.quick_unlock),
            polkit_policy_registered,
            session_anchor: Mutex::new(None),
            last_boot_delta_secs: Mutex::new(None),
            release_budget: Mutex::new(ReleaseBudget::default()),
            clipboard_program: resolve_clipboard_program(),
            clipboard_offers: Arc::default(),
            paste_sequence_launcher: default_paste_sequence_launcher(),
            clipboard_clear_seconds: config.clipboard_clear_seconds,
            own_executable: crate::peer_identity::own_executable().unwrap_or_default(),
            supervision_programs: SupervisionPrograms::resolve(),
            sleep_inhibitor: Mutex::new(None),
            sleep_monitor_active: AtomicBool::new(false),
            sleep_generation: AtomicU64::new(0),
            sleep_pending: AtomicBool::new(false),
            session_binding: SessionBinding::from_environment(runtime_dir.as_deref()),
            bound_socket: Mutex::new(None),
        }
    }

    /// CLOCK_BOOTTIME minus CLOCK_MONOTONIC in whole seconds. The two clocks
    /// run together while awake; suspend time accrues only to BOOTTIME.
    pub fn boot_delta_secs() -> Option<u64> {
        #[cfg(target_os = "linux")]
        {
            let mut boot = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let mut mono = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let ok = unsafe {
                libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut boot) == 0
                    && libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono) == 0
            };
            if !ok {
                return None;
            }
            let delta = boot.tv_sec - mono.tv_sec;
            Some(delta.unsigned_abs())
        }
        #[cfg(not(target_os = "linux"))]
        None
    }

    /// Pure resume-edge predicate: the delta only grows by whole suspend
    /// periods, so a jump over one second means at least one suspend since
    /// the previous sample. Shrinkage (clock skew between the two reads) is
    /// ignored rather than treated as an event.
    pub fn suspend_happened(prev: Option<u64>, current: Option<u64>) -> bool {
        match (prev, current) {
            (Some(prev), Some(cur)) => cur > prev + 1,
            // First sample after start: if the machine already suspended since
            // boot the cached value is None, but nothing was retained before
            // the daemon started either, so treat it as no event.
            _ => false,
        }
    }

    /// Watchdog step: wipe/hard-lock on suspend regardless of vault state.
    /// Runs every tick, cheap (two clock reads), and is the guarantee behind
    /// ADR decision 4 — the polled PreparingForSleep property alone can be
    /// missed while the daemon is frozen.
    pub fn check_suspend_drift_with(&self, current_delta: Option<u64>) -> bool {
        let prev = self.last_boot_delta_secs.lock().ok().and_then(|g| *g);
        if let Ok(mut cache) = self.last_boot_delta_secs.lock() {
            *cache = current_delta;
        }
        if !Self::suspend_happened(prev, current_delta) {
            return false;
        }
        crate::log_info!(
            "omawarden:daemon",
            "Suspend detected (boottime drift); wiping quick unlock retention"
        );
        // The machine has resumed, so no sleep is pending any more; the
        // lock still counts as a sleep lock for an unlock that straddled it.
        self.sleep_pending.store(false, Ordering::SeqCst);
        self.lock_for_sleep();
        true
    }

    pub fn check_suspend_drift(&self) -> bool {
        self.check_suspend_drift_with(Self::boot_delta_secs())
    }

    pub(crate) fn quick_unlock_enabled(&self) -> bool {
        // A poisoned mutex resolves to false: that is the fail-closed
        // default (unlike quick_unlock_busy, whose guard state is re-derived
        // and therefore safe to recover with into_inner).
        self.quick_unlock_setting
            .lock()
            .ok()
            .map(|g| *g)
            .unwrap_or(false)
    }

    /// `config set --quick-unlock` refreshes the cached setting through this
    /// IPC so the daemon never re-reads config.json on its hot paths.
    /// Editing the file by hand while the daemon runs still needs a restart
    /// (or a `config set`) to be picked up.
    pub fn set_quick_unlock_enabled(&self, enabled: bool) {
        if let Ok(mut setting) = self.quick_unlock_setting.lock() {
            *setting = enabled;
        }
    }

    /// Whether the feature can work at all right now: enabled in settings, a
    /// polkit binary resolved at daemon startup, and the packaged policy
    /// registered. Retention is gated on this too (see `soft_lock`): holding
    /// the key for a prompt that can only fail would be pure exposure with no
    /// way to spend it. (Resolution is cached at startup; installing polkit
    /// or the policy later is picked up at the next daemon start.)
    pub fn quick_unlock_usable(&self) -> bool {
        self.quick_unlock_enabled()
            && !self.polkit_binary.as_os_str().is_empty()
            && self.polkit_policy_registered
    }

    /// Quick unlock availability as advertised over IPC: usable AND a key
    /// currently retained by a soft lock. Including the binary and the policy
    /// keeps the button honest on systems without polkit or with the policy
    /// missing (older package, dev tarball predating this feature): it stays
    /// hidden instead of erroring on click.
    pub fn quick_unlock_ready(&self) -> bool {
        self.quick_unlock_usable() && self.vault_mgr.quick_unlock_available()
    }

    /// ADR-0025: re-unlock the vault behind a polkit system-authentication
    /// check instead of the master password. Fail-closed on every rejection;
    /// three consecutive denials wipe the retained key.
    pub fn perform_quick_unlock(&self) -> Result<usize, &'static str> {
        self.perform_quick_unlock_with_timeout(crate::polkit::DEFAULT_CHECK_TIMEOUT)
    }

    /// Same check with a caller-chosen prompt timeout.
    pub fn perform_quick_unlock_with_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> Result<usize, &'static str> {
        if !self.quick_unlock_enabled() {
            return Err("Quick unlock is disabled in settings.");
        }
        if self.vault_mgr.is_unlocked() {
            // Already unlocked: never re-prompt or re-arm timers.
            return Err("Vault is already unlocked.");
        }
        if self.polkit_binary.as_os_str().is_empty() {
            return Err("System authentication is unavailable right now.");
        }
        // Same gate quick_unlock_ready() advertises: without the policy the
        // pkcheck call can only fail (exit 127, action not registered), so
        // do not even attempt it.
        if !self.polkit_policy_registered {
            return Err("System authentication is unavailable right now.");
        }
        if !self.vault_mgr.quick_unlock_available() {
            return Err("Quick unlock is unavailable: the vault was hard-locked.");
        }
        // One interactive prompt at a time; concurrent callers fail fast and
        // the overlay falls back to the master password field. A panic in an
        // earlier prompt poisons the mutex; recovering the guard (instead of
        // propagating the poison) keeps quick unlock usable — the state this
        // guard protected is re-checked right below.
        let _guard = match self.quick_unlock_busy.try_lock() {
            Ok(g) => g,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err("Quick unlock is already in progress.");
            }
        };
        // Re-check: a wipe may have raced with acquiring the busy lock.
        if !self.vault_mgr.quick_unlock_available() {
            return Err("Quick unlock is unavailable: the vault was hard-locked.");
        }

        match crate::polkit::check(
            crate::polkit::POLKIT_ACTION_ID,
            &self.polkit_binary,
            timeout,
        ) {
            crate::polkit::PolkitOutcome::Authorized => {}
            crate::polkit::PolkitOutcome::Denied => {
                let strike = {
                    match self.quick_unlock_failures.lock() {
                        Ok(mut n) => {
                            *n += 1;
                            *n
                        }
                        Err(_) => MAX_QUICK_UNLOCK_FAILURES,
                    }
                };
                if strike >= MAX_QUICK_UNLOCK_FAILURES {
                    crate::log_warn!(
                        "omawarden:daemon",
                        "Quick unlock denied {} times; wiping retained key",
                        strike
                    );
                    self.vault_mgr.wipe_quick_unlock();
                    if let Ok(mut n) = self.quick_unlock_failures.lock() {
                        *n = 0;
                    }
                }
                return Err("System authentication was denied.");
            }
            crate::polkit::PolkitOutcome::Unavailable(reason) => {
                crate::log_warn!("omawarden:daemon", "polkit unavailable: {}", reason);
                return Err("System authentication is unavailable right now.");
            }
        }

        match self.vault_mgr.quick_unlock_restore() {
            Ok(count) => {
                if let Ok(mut n) = self.quick_unlock_failures.lock() {
                    *n = 0;
                }
                // Rule 9: re-arm the per-unlock anchor so the idle/lifetime
                // watchdogs keep running after a quick unlock. The session
                // anchor is deliberately NOT touched: quick unlocks extend
                // nothing; the 12h ceiling is measured from the master
                // password unlock (ADR-0025 decision 4).
                if let Ok(mut ua) = self.unlocked_at.lock() {
                    *ua = Some(Instant::now());
                }
                self.touch_activity();
                Ok(count)
            }
            Err(e) => {
                crate::log_error!("omawarden:daemon", "Quick unlock restore failed: {}", e);
                Err("Quick unlock failed to restore the vault.")
            }
        }
    }
}

impl DaemonState {
    pub fn set_auto_lock_duration(&self, duration: Duration) {
        if let Ok(mut dur) = self.auto_lock_duration.lock() {
            *dur = duration;
        }
    }

    pub fn check_auto_lock(&self) -> bool {
        // Rule 9 / ADR-0025: the 12h ceiling is anchored to the last
        // master-password unlock and bounds the retained key as well: a vault
        // that stays soft-locked (key retained) past the ceiling is wiped.
        // Quick unlocks re-arm only the per-unlock anchor (idle watchdogs);
        // they never extend the session anchor.
        let session_expired = {
            let anchor = self.session_anchor.lock().ok().and_then(|g| *g);
            let max = self.max_session_lifetime.lock().ok().map(|g| *g);
            matches!(
                (anchor, max),
                (Some(a), Some(max)) if !max.is_zero() && a.elapsed() > max
            )
        };
        if session_expired
            && (self.vault_mgr.is_unlocked() || self.vault_mgr.quick_unlock_available())
        {
            crate::log_info!(
                "omawarden:daemon",
                "Maximum session lifetime reached; locking vault and wiping retention"
            );
            self.lock();
            return true;
        }

        if self.vault_mgr.is_unlocked() {
            // 1. Per-unlock absolute lifetime (unchanged behavior when quick
            // unlock is off: identical to the session anchor in that case).
            let max_lifetime_expired = {
                if let Ok(ua_guard) = self.unlocked_at.lock() {
                    if let Some(unlocked_time) = *ua_guard {
                        if let Ok(max_dur) = self.max_session_lifetime.lock() {
                            !max_dur.is_zero() && unlocked_time.elapsed() > *max_dur
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            };

            if max_lifetime_expired {
                crate::log_info!(
                    "omawarden:daemon",
                    "Maximum session lifetime reached; locking vault"
                );
                self.lock();
                return true;
            }

            // 2. Check idle inactivity timeout
            let idle_expired = {
                if let Ok(dur) = self.auto_lock_duration.lock() {
                    if !dur.is_zero() {
                        if let Ok(last) = self.last_activity.lock() {
                            last.elapsed() > *dur
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            };

            if idle_expired {
                // Idle timeout is a soft lock: with quick unlock enabled the
                // key is retained for a later polkit check (ADR-0025).
                crate::log_info!("omawarden:daemon", "Idle timeout elapsed; locking vault");
                self.soft_lock();
                return true;
            }
        }
        false
    }

    pub fn check_screen_lock(&self) -> bool {
        self.check_screen_lock_with(system_lock_signal)
    }

    pub fn check_screen_lock_with<F>(&self, detector: F) -> bool
    where
        F: FnOnce() -> LockSignal,
    {
        // The detector must also run while soft-locked: a Sleep signal while
        // a key is retained must wipe it (ADR decision 4). The suspend-drift
        // watchdog covers the resume edge this poll can miss.
        if self.vault_mgr.is_unlocked() || self.vault_mgr.quick_unlock_available() {
            match detector() {
                LockSignal::None => {}
                LockSignal::Sleep => {
                    // A suspend must never leave the key retained.
                    crate::log_info!(
                        "omawarden:daemon",
                        "System is going to sleep; hard-locking vault"
                    );
                    self.lock_for_sleep();
                    return true;
                }
                LockSignal::Screen => {
                    if self.vault_mgr.is_unlocked() {
                        // soft_lock() itself hard-locks when quick unlock is off.
                        self.soft_lock();
                        return true;
                    }
                    // Already soft-locked: the screen signal changes nothing.
                }
            }
        }
        false
    }

    pub fn touch_activity(&self) {
        if let Ok(mut act) = self.last_activity.lock() {
            *act = Instant::now();
        }
    }

    /// Hard lock (ADR-0025): wipes the retained key. Used by explicit lock,
    /// logout, stop, sleep, session end, an exhausted release budget and
    /// every other non-soft path. Releases the sleep inhibitor afterwards.
    pub fn lock(&self) {
        if let Ok(mut ua) = self.unlocked_at.lock() {
            *ua = None;
        }
        if let Ok(mut anchor) = self.session_anchor.lock() {
            *anchor = None;
        }
        if let Ok(mut n) = self.quick_unlock_failures.lock() {
            *n = 0;
        }
        self.vault_mgr.hard_lock();
        if let Ok(mut budget) = self.release_budget.lock() {
            budget.reset();
        }
        self.clipboard_offers.withdraw_all();
        self.synchronize_sleep_inhibitor();
    }

    /// Soft lock (ADR-0025): purges decrypted state but retains the user key
    /// in locked memory when quick unlock is enabled in settings. With quick
    /// unlock disabled (the default) or unusable this is a hard lock.
    pub fn soft_lock(&self) {
        if !self.quick_unlock_usable() {
            self.lock();
            return;
        }
        if let Ok(mut ua) = self.unlocked_at.lock() {
            *ua = None;
        }
        self.vault_mgr.soft_lock();
        self.clipboard_offers.withdraw_all();
        self.synchronize_sleep_inhibitor();
    }

    /// The daemon's clipboard: the trusted `wl-copy`, supervised by this
    /// process, with its offers recorded so a lock can withdraw them.
    pub fn clipboard(&self) -> crate::clipboard::ClipboardManager {
        crate::clipboard::ClipboardManager::new(&self.clipboard_program)
            .without_detached_worker()
            .with_offer_registry(Arc::clone(&self.clipboard_offers))
    }

    /// Starts a paste sequence of `stages` that ends no later than
    /// `lifetime`, replacing any sequence still running.
    pub fn start_paste_sequence(
        &self,
        stages: Vec<crate::paste_sequence::StageValue>,
        lifetime: Duration,
    ) -> Result<(), String> {
        let launcher = Arc::clone(&self.paste_sequence_launcher);
        self.clipboard_offers
            .replace_paste_sequence(move || launcher(stages, lifetime))
    }

    /// Master-password unlock. The key derivation can take seconds; a
    /// suspend announced meanwhile wins, and the unlock ends locked.
    pub fn unlock(&self, password: &str) -> Result<usize, String> {
        let sleep_generation = self.sleep_generation.load(Ordering::SeqCst);
        let count = self.vault_mgr.unlock(password)?;
        self.complete_unlock(sleep_generation, count)
    }

    /// Whether a suspend was announced, or a sleep lock taken, since
    /// `sleep_generation` was sampled.
    fn sleep_intervened(&self, sleep_generation: u64) -> bool {
        self.sleep_pending.load(Ordering::SeqCst)
            || self.sleep_generation.load(Ordering::SeqCst) != sleep_generation
    }

    /// Arms the session after the vault decrypted, unless a suspend
    /// intervened: then the vault is hard-locked again and the unlock fails.
    /// A sleep lock that lands after this check locks the armed session, so
    /// every interleaving ends locked.
    fn complete_unlock(&self, sleep_generation: u64, count: usize) -> Result<usize, String> {
        if self.sleep_intervened(sleep_generation) {
            crate::log_info!(
                "omawarden:daemon",
                "The system prepared to sleep during unlock; locking the vault again"
            );
            self.lock();
            return Err("The system went to sleep during unlock. Unlock again.".to_string());
        }
        if let Ok(mut ua_guard) = self.unlocked_at.lock() {
            *ua_guard = Some(Instant::now());
        }
        // A master-password unlock (re)anchors the hard 12h session ceiling.
        if let Ok(mut anchor) = self.session_anchor.lock() {
            *anchor = Some(Instant::now());
        }
        // A successful master unlock supersedes any earlier denials.
        if let Ok(mut n) = self.quick_unlock_failures.lock() {
            *n = 0;
        }
        self.touch_activity();
        self.synchronize_sleep_inhibitor();
        Ok(count)
    }

    pub fn sync(&self) -> Result<usize, String> {
        self.sync_with_client(None)
    }

    /// Synchronizes the vault. Not a user-activity signal: the overlay syncs
    /// in the background after every unlock (ADR 0027).
    pub fn sync_with_client(
        &self,
        client_context: Option<&crate::api::ClientContext>,
    ) -> Result<usize, String> {
        self.vault_mgr.sync_with_client(client_context)
    }

    /// Auto-clear for `copy_field`: the configured value when positive,
    /// otherwise `DEFAULT_COPY_CLEAR_SECONDS`. A released secret always
    /// auto-clears.
    pub fn copy_clear_seconds(&self) -> u64 {
        u64::try_from(self.clipboard_clear_seconds)
            .ok()
            .filter(|seconds| crate::secret_access::COPY_CLEAR_SECONDS_RANGE.contains(seconds))
            .unwrap_or(crate::secret_access::DEFAULT_COPY_CLEAR_SECONDS)
    }

    /// Whether decrypted keys are in memory: an unlocked vault, or a key
    /// retained by a soft lock.
    pub fn key_material_resident(&self) -> bool {
        self.vault_mgr.is_unlocked() || self.vault_mgr.quick_unlock_available()
    }

    /// Holds the logind sleep delay inhibitor exactly while key material is
    /// resident: takes it after an unlock, releases it after a hard lock.
    pub fn synchronize_sleep_inhibitor(&self) {
        let Ok(mut slot) = self.sleep_inhibitor.lock() else {
            return;
        };
        if !self.key_material_resident() {
            drop(slot.take());
            return;
        }
        if slot.as_mut().is_some_and(|held| held.is_held()) {
            return;
        }
        *slot = self.acquire_sleep_inhibitor();
    }

    fn acquire_sleep_inhibitor(&self) -> Option<SleepInhibitor> {
        let programs = &self.supervision_programs;
        let (Some(inhibit), Some(holder)) = (
            programs.systemd_inhibit.as_deref(),
            programs.inhibitor_holder.as_deref(),
        ) else {
            return None;
        };
        SleepInhibitor::acquire(inhibit, holder)
            .map_err(|e| {
                crate::log_warn!(
                    "omawarden:daemon",
                    "Could not take the logind sleep inhibitor: {}",
                    e
                );
            })
            .ok()
    }

    /// logind announced PrepareForSleep(true): hard-lock, which releases the
    /// inhibitor so the suspend proceeds without key material in memory.
    /// Until the resume, no unlock can complete.
    pub fn prepare_for_sleep(&self) {
        crate::log_info!(
            "omawarden:daemon",
            "System is preparing to sleep; hard-locking vault"
        );
        self.sleep_pending.store(true, Ordering::SeqCst);
        self.lock_for_sleep();
    }

    /// logind announced PrepareForSleep(false): the suspend finished or was
    /// cancelled, so unlocking is possible again.
    pub fn resume_from_sleep(&self) {
        self.sleep_pending.store(false, Ordering::SeqCst);
        self.synchronize_sleep_inhibitor();
    }

    /// Hard lock caused by a suspend. The generation is bumped before the
    /// lock, so an unlock still deriving its key sees it once it finishes.
    fn lock_for_sleep(&self) {
        self.sleep_generation.fetch_add(1, Ordering::SeqCst);
        self.lock();
    }

    /// Verifies a client connection: same user and same executable.
    pub fn verify_client(&self, stream: &UnixStream) -> std::io::Result<()> {
        crate::peer_identity::verify_peer(stream, &self.own_executable)
    }

    fn record_bound_socket(&self, path: &Path) {
        let Ok(meta) = fs::symlink_metadata(path) else {
            return;
        };
        if let Ok(mut slot) = self.bound_socket.lock() {
            *slot = Some((path.to_path_buf(), meta.dev(), meta.ino()));
        }
    }

    /// Removes the socket file only if it is still the one this daemon bound.
    pub fn remove_bound_socket(&self) {
        let Some((path, dev, ino)) = self.bound_socket.lock().ok().and_then(|s| s.clone()) else {
            return;
        };
        let still_ours = fs::symlink_metadata(&path)
            .map(|meta| meta.dev() == dev && meta.ino() == ino)
            .unwrap_or(false);
        if still_ours {
            let _ = fs::remove_file(&path);
        }
    }
}

/// Hard-locks, removes this daemon's socket and exits. Used for `stop`,
/// termination signals and the end of the login session.
pub fn terminate_daemon(state: &DaemonState) {
    state.lock();
    state.remove_bound_socket();
    std::process::exit(0);
}

/// Refuses to replace a socket another daemon is still serving. Waits
/// briefly first, so a daemon that is just exiting after `stop` can finish.
fn ensure_socket_not_served(path: &Path) -> std::io::Result<()> {
    for _ in 0..SOCKET_RELEASE_ATTEMPTS {
        if UnixStream::connect(path).is_err() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrInUse,
        format!(
            "another omawarden daemon is already serving '{}'",
            path.display()
        ),
    ))
}

fn bind_daemon_socket(state: &DaemonState) -> std::io::Result<UnixListener> {
    let socket_path = get_socket_path()?;
    if socket_path.exists() {
        validate_socket_path(&socket_path)?;
        ensure_socket_not_served(&socket_path)?;
        let _ = fs::remove_file(&socket_path);
    }
    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
    state.record_bound_socket(&socket_path);
    Ok(listener)
}

fn watchdog_interval(state: &DaemonState) -> Duration {
    if state.vault_mgr.is_unlocked() {
        Duration::from_secs(2)
    } else {
        Duration::from_secs(5)
    }
}

/// Starts the PrepareForSleep monitor when it is not running.
fn ensure_sleep_monitor(state: &Arc<DaemonState>) {
    let Some(program) = state.supervision_programs.dbus_monitor.clone() else {
        return;
    };
    if state.sleep_monitor_active.swap(true, Ordering::SeqCst) {
        return;
    }
    let on_signal = {
        let state = Arc::clone(state);
        move |sleeping: bool| {
            if sleeping {
                state.prepare_for_sleep();
            } else {
                state.resume_from_sleep();
            }
        }
    };
    let on_exit = {
        let state = Arc::clone(state);
        move || state.sleep_monitor_active.store(false, Ordering::SeqCst)
    };
    // A new monitor cannot know about a PrepareForSleep(false) its
    // predecessor missed, so a pending sleep does not outlive the restart.
    state.sleep_pending.store(false, Ordering::SeqCst);
    if let Err(e) = crate::session_supervision::spawn_sleep_monitor(&program, on_signal, on_exit) {
        crate::log_warn!("omawarden:daemon", "Sleep monitor unavailable: {}", e);
        state.sleep_monitor_active.store(false, Ordering::SeqCst);
    }
}

fn terminate_if_session_ended(state: &DaemonState) {
    let loginctl = state.supervision_programs.loginctl.as_deref();
    let Some(reason) =
        crate::session_supervision::detect_session_end(&state.session_binding, loginctl)
    else {
        return;
    };
    crate::log_info!(
        "omawarden:daemon",
        "Login session ended ({}); hard-locking vault and exiting",
        reason
    );
    terminate_daemon(state);
}

fn run_watchdog_tick(state: &Arc<DaemonState>) {
    terminate_if_session_ended(state);
    ensure_sleep_monitor(state);
    // Resume-edge suspend detection must run regardless of lock state: the
    // dominant quick-unlock state (soft-locked) is exactly when the screen
    // detector would otherwise never fire.
    state.check_suspend_drift();
    state.check_auto_lock();
    state.check_screen_lock();
    state.synchronize_sleep_inhibitor();
}

fn spawn_watchdog(state: Arc<DaemonState>) {
    std::thread::spawn(move || loop {
        std::thread::sleep(watchdog_interval(&state));
        run_watchdog_tick(&state);
    });
}

fn admit_connection(mut stream: UnixStream, state: &Arc<DaemonState>, limiter: &ConnectionLimiter) {
    let Some(permit) = limiter.try_admit() else {
        let _ = stream.set_write_timeout(Some(RESPONSE_WRITE_TIMEOUT));
        write_response(&mut stream, crate::daemon_requests::capacity_refusal());
        return;
    };
    let st = Arc::clone(state);
    std::thread::spawn(move || {
        let _permit = permit;
        let _ = handle_client(stream, st);
    });
}

pub fn run_daemon_server(state: Arc<DaemonState>) -> std::io::Result<()> {
    let listener = bind_daemon_socket(&state)?;
    if let Err(e) =
        crate::session_supervision::install_termination_handler(state.clone(), terminate_daemon)
    {
        crate::log_warn!(
            "omawarden:daemon",
            "Termination signals are not handled: {}",
            e
        );
    }
    if !state.session_binding.is_bound() {
        crate::log_warn!(
            "omawarden:daemon",
            "No login session (XDG_SESSION_ID) or Wayland socket to follow; the daemon will not exit at logout"
        );
    }
    // Watch for PrepareForSleep before the first unlock can happen; the
    // watchdog restarts the monitor if it ever exits.
    ensure_sleep_monitor(&state);
    spawn_watchdog(state.clone());

    let limiter = ConnectionLimiter::default();
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => admit_connection(stream, &state, &limiter),
            Err(e) => eprintln!("Socket accept error: {}", e),
        }
    }
    Ok(())
}

/// Same-user check on a socket peer (kept for callers and tests that need
/// only the uid half of caller verification).
pub fn verify_peer_credentials(stream: &UnixStream) -> std::io::Result<()> {
    crate::peer_identity::verify_peer_uid(stream)
}

pub const SCREEN_LOCKER_PROCESS_NAMES: &[&str] = &["hyprlock", "swaylock", "waylock", "gtklock"];

pub fn get_omarchy_shell_cmd() -> Option<PathBuf> {
    if which::which("omarchy-shell").is_ok() {
        return Some(PathBuf::from("omarchy-shell"));
    }
    if let Ok(home) = env::var("HOME") {
        let candidate = PathBuf::from(home).join(".local/share/omarchy/bin/omarchy-shell");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

pub fn is_omarchy_locked() -> bool {
    let cmd_name = match get_omarchy_shell_cmd() {
        Some(cmd) => cmd,
        None => return false,
    };

    if let Ok(output) = Command::new(cmd_name).args(["lock", "isLocked"]).output() {
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout);
            if s.trim() == "true" {
                return true;
            }
        }
    }
    false
}

pub fn is_screen_locker_running() -> bool {
    let locker_regex = SCREEN_LOCKER_PROCESS_NAMES.join("|");
    if let Ok(output) = Command::new("pgrep").args(["-x", &locker_regex]).output() {
        if output.status.success() && !output.stdout.is_empty() {
            return true;
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let file_name = entry.file_name();
                if let Some(name_str) = file_name.to_str() {
                    if name_str.chars().all(|c| c.is_ascii_digit()) {
                        let comm_path = entry.path().join("comm");
                        if let Ok(comm) = fs::read_to_string(comm_path) {
                            let comm = comm.trim();
                            if SCREEN_LOCKER_PROCESS_NAMES.contains(&comm) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    false
}

pub fn is_logind_locked_or_sleeping() -> bool {
    matches!(logind_lock_signal(), LockSignal::Screen | LockSignal::Sleep)
}

/// logind session state as a lock signal. Sleep wins over a locked hint:
/// both together must produce the hard lock.
pub fn logind_lock_signal() -> LockSignal {
    // 1. Check Manager PreparingForSleep
    if let Ok(output) = Command::new("busctl")
        .args([
            "get-property",
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
            "PreparingForSleep",
        ])
        .output()
    {
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout);
            if s.trim() == "b true" {
                return LockSignal::Sleep;
            }
        }
    }

    // 2. Check session LockedHint
    if let Ok(output) = Command::new("busctl")
        .args([
            "get-property",
            "org.freedesktop.login1",
            "/org/freedesktop/login1/session/auto",
            "org.freedesktop.login1.Session",
            "LockedHint",
        ])
        .output()
    {
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout);
            if s.trim() == "b true" {
                return LockSignal::Screen;
            }
        }
    }

    LockSignal::None
}

/// Combine every desktop signal into the strongest applicable lock kind.
pub fn system_lock_signal() -> LockSignal {
    // Sleep dominates: it must hard-lock even if a screen lock is also up.
    let logind = logind_lock_signal();
    if logind == LockSignal::Sleep {
        return LockSignal::Sleep;
    }
    if is_omarchy_locked() || is_screen_locker_running() || logind == LockSignal::Screen {
        return LockSignal::Screen;
    }
    LockSignal::None
}

pub fn is_system_or_screen_locked() -> bool {
    system_lock_signal() != LockSignal::None
}

/// Writes one response line from a buffer that is zeroized afterwards, then
/// zeroizes the response value itself (it may hold a released secret).
fn write_response(stream: &mut UnixStream, mut response: Value) {
    let line = serialize_zeroizing(&response);
    zeroize_json_value(&mut response);
    let _ = stream.write_all(line.as_bytes());
    let _ = stream.write_all(b"\n");
    let _ = stream.flush();
}

/// Parses a request line. `None` means nothing to answer (an empty line) or
/// that an error response was already written.
fn parse_request(line: &[u8], stream: &mut UnixStream) -> Option<Value> {
    if line.iter().all(u8::is_ascii_whitespace) {
        return None;
    }
    match serde_json::from_slice(line) {
        Ok(request) => Some(request),
        Err(_) => {
            write_response(
                stream,
                json!({ "ok": false, "error": "Malformed JSON request" }),
            );
            None
        }
    }
}

fn deliver_outcome(stream: &mut UnixStream, state: &DaemonState, outcome: ActionOutcome) {
    match outcome {
        ActionOutcome::Respond(response) => write_response(stream, response),
        ActionOutcome::RespondThenExit(response) => {
            // Remove the socket before answering, so a replacement daemon
            // started by the caller can bind it without racing this exit.
            state.remove_bound_socket();
            write_response(stream, response);
            std::process::exit(0);
        }
    }
}

fn handle_client(mut stream: UnixStream, state: Arc<DaemonState>) -> std::io::Result<()> {
    if let Err(e) = state.verify_client(&stream) {
        crate::log_error!(
            "omawarden:daemon",
            "Client connection rejected: caller verification failed: {}",
            e
        );
        write_response(
            &mut stream,
            json!({ "ok": false, "error": "Access denied: the client is not this omawarden executable running as the same user" }),
        );
        return Ok(());
    }
    stream.set_write_timeout(Some(RESPONSE_WRITE_TIMEOUT))?;

    let line = match crate::daemon_requests::read_bounded_request(&stream) {
        Ok(line) => line,
        Err(error) => {
            write_response(
                &mut stream,
                json!({ "ok": false, "error": error.message() }),
            );
            return Ok(());
        }
    };
    let Some(mut request) = parse_request(&line, &mut stream) else {
        return Ok(());
    };
    drop(line);

    let outcome = crate::daemon_actions::dispatch(&state, &request);
    // The request may have carried the master password.
    zeroize_json_value(&mut request);
    deliver_outcome(&mut stream, &state, outcome);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_daemon_state_lifecycle() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);

        let state = DaemonState::new(storage_mgr, 15);
        assert!(!state.vault_mgr.is_unlocked());

        // Lock
        state.lock();
        assert!(!state.vault_mgr.is_unlocked());
        assert_eq!(state.vault_mgr.decrypted_items.read().unwrap().len(), 0);
    }

    #[test]
    fn test_daemon_totp_action() {
        let res = crate::totp::generate_totp("JBSWY3DPEHPK3PXP", None, 6, 30);
        assert!(res.is_some());
        let totp_res = res.unwrap();
        assert_eq!(totp_res.code.len(), 6);
    }

    #[test]
    fn test_daemon_totp_action_with_item_query() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);

        let state = DaemonState::new(storage_mgr, 15);
        let test_item = crate::vault::VaultItem {
            id: "item-totp-123".to_string(),
            name: "Github 2FA".to_string(),
            item_type: 1,
            type_name: "login".to_string(),
            sub_title: "user@github.com".to_string(),
            notes: None,
            favorite: false,
            created_at: None,
            updated_at: None,
            folder_id: None,
            folder_name: None,
            organization_id: None,
            organization_name: None,
            collection_ids: None,
            login: Some(serde_json::json!({
                "username": "user",
                "totp": "JBSWY3DPEHPK3PXP"
            })),
            card: None,
            identity: None,
            fields: vec![],
            search_text: "github 2fa user".to_string(),
        };

        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        state
            .vault_mgr
            .decrypted_items
            .write()
            .unwrap()
            .push(test_item);

        // Find by ID
        let found = state.vault_mgr.find_item("item-totp-123", None);
        assert!(found.is_some());
        let seed = found
            .unwrap()
            .login
            .clone()
            .unwrap()
            .get("totp")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let res = crate::totp::generate_totp(&seed, None, 6, 30);
        assert!(res.is_some());
        assert_eq!(res.unwrap().code.len(), 6);

        // Find by Name
        let found_name = state.vault_mgr.find_item("Github", None);
        assert!(found_name.is_some());
    }

    /// Sends one request through `handle_client` over a socket pair.
    fn send_request(state: &Arc<DaemonState>, req: Value) -> Value {
        send_raw_request(state, format!("{}\n", req).as_bytes())
    }

    fn send_raw_request(state: &Arc<DaemonState>, payload: &[u8]) -> Value {
        let (mut client, server) = UnixStream::pair().unwrap();
        let st = state.clone();
        let handle = std::thread::spawn(move || {
            let _ = handle_client(server, st);
        });
        let _ = client.write_all(payload);
        let _ = client.flush();
        let mut line = String::new();
        BufReader::new(client).read_line(&mut line).unwrap();
        handle.join().unwrap();
        serde_json::from_str(&line).unwrap()
    }

    fn state_with_fixture_items() -> (tempfile::TempDir, Arc<DaemonState>) {
        use crate::item_redaction::tests as fixtures;
        let dir = tempdir().unwrap();
        let state = DaemonState::new(StorageManager::new(dir.path().join("data.json")), 15);
        *state.vault_mgr.decrypted_items.write().unwrap() = vec![
            fixtures::login_item(),
            fixtures::card_item(),
            fixtures::identity_item(),
            fixtures::note_item(),
        ];
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        (dir, Arc::new(state))
    }

    #[test]
    fn test_client_touch_override_is_ignored() {
        let dir = tempdir().unwrap();
        let state = Arc::new(DaemonState::new(
            StorageManager::new(dir.path().join("daemon_data.json")),
            15,
        ));
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        let past = Instant::now() - Duration::from_secs(10);

        // A passive action asking to reset the idle timer must not.
        for req in [
            json!({ "action": "ping", "touch": true }),
            json!({ "action": "status", "touch": true }),
            json!({ "action": "list", "touch": true }),
            json!({ "action": "totp", "secret": "JBSWY3DPEHPK3PXP", "touch": true }),
        ] {
            *state.last_activity.lock().unwrap() = past;
            let _ = send_request(&state, req.clone());
            assert_eq!(*state.last_activity.lock().unwrap(), past, "{req}");
        }

        // A user action cannot opt out of resetting it either.
        *state.last_activity.lock().unwrap() = past;
        let res = send_request(
            &state,
            json!({ "action": "search", "query": "x", "touch": false }),
        );
        assert!(res.is_array());
        assert!(*state.last_activity.lock().unwrap() > past);
    }

    #[test]
    fn test_releases_and_unlock_free_actions_do_not_reset_the_idle_timer() {
        let (dir, state) = state_with_fixture_items();
        let program = dir.path().join("mock-wl-copy");
        crate::write_test_executable(&program, "#!/bin/sh\ncat > /dev/null\n");
        let mut state = Arc::try_unwrap(state).ok().unwrap();
        state.clipboard_program = program.to_string_lossy().to_string();
        let state = Arc::new(state);
        let past = Instant::now() - Duration::from_secs(10);
        for req in [
            json!({ "action": "reveal_field", "id": "login-1", "field": "login.password" }),
            json!({ "action": "copy_field", "id": "login-1", "field": "login.password" }),
            json!({ "action": "copy", "text": "fixture-user" }),
            json!({ "action": "generate_password", "length": 20 }),
        ] {
            *state.last_activity.lock().unwrap() = past;
            let res = send_request(&state, req.clone());
            assert_eq!(res["ok"], true, "{req}: {res}");
            assert_eq!(*state.last_activity.lock().unwrap(), past, "{req}");
        }

        // While locked, periodic copy and generate_password calls must not
        // keep an idle timer alive for the next unlock either.
        state.lock();
        *state.last_activity.lock().unwrap() = past;
        let _ = send_request(&state, json!({ "action": "copy", "text": "fixture-user" }));
        let _ = send_request(&state, json!({ "action": "generate_password" }));
        assert_eq!(*state.last_activity.lock().unwrap(), past);
    }

    fn state_with_foreground_clipboard() -> (tempfile::TempDir, Arc<DaemonState>, PathBuf, PathBuf)
    {
        let (dir, state) = state_with_fixture_items();
        let (program, clip_file, args_file) = crate::clipboard::tests::mock_wl_copy(dir.path());
        let mut state = Arc::try_unwrap(state).ok().unwrap();
        state.clipboard_program = program.to_string_lossy().to_string();
        (dir, Arc::new(state), clip_file, args_file)
    }

    #[test]
    fn test_lock_withdraws_the_engine_offer_without_clearing_the_clipboard() {
        use crate::clipboard::tests::wait_until;
        let (_dir, state, clip_file, args_file) = state_with_foreground_clipboard();
        let res = send_request(
            &state,
            json!({ "action": "copy_field", "id": "login-1", "field": "login.password", "clear_after_seconds": 600 }),
        );
        assert_eq!(res["ok"], true, "{res}");
        assert!(clip_file.exists());
        assert_eq!(state.clipboard_offers.served_offers(), 1);

        state.lock();
        assert!(
            wait_until(Duration::from_secs(5), || !clip_file.exists()),
            "the lock withdrew the offer the engine still owned"
        );
        let args = std::fs::read_to_string(&args_file).unwrap();
        assert!(
            !args.lines().any(|line| line == "--clear"),
            "a lock never clears the clipboard blindly: {args}"
        );
    }

    #[test]
    fn test_lock_leaves_a_later_copy_by_another_application() {
        use crate::clipboard::tests::wait_until;
        let (_dir, state, clip_file, args_file) = state_with_foreground_clipboard();
        let res = send_request(
            &state,
            json!({ "action": "copy_field", "id": "card-1", "field": "card.code", "clear_after_seconds": 600 }),
        );
        assert_eq!(res["ok"], true, "{res}");
        std::fs::write(&clip_file, "text_from_another_application").unwrap();
        assert!(wait_until(Duration::from_secs(5), || state
            .clipboard_offers
            .served_offers()
            == 0));

        state.soft_lock();
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        state.lock();
        assert_eq!(
            std::fs::read_to_string(&clip_file).unwrap(),
            "text_from_another_application"
        );
        let args = std::fs::read_to_string(&args_file).unwrap();
        assert!(!args.lines().any(|line| line == "--clear"), "{args}");
    }

    #[test]
    fn test_list_search_and_get_item_are_redacted_over_the_socket() {
        use crate::item_redaction::tests as fixtures;
        let (_dir, state) = state_with_fixture_items();
        let responses = [
            send_request(&state, json!({ "action": "list" })),
            send_request(&state, json!({ "action": "search", "query": "" })),
            send_request(&state, json!({ "action": "get_item", "query": "login-1" })),
            send_request(&state, json!({ "action": "get_item", "query": "card-1" })),
            send_request(
                &state,
                json!({ "action": "get_item", "query": "identity-1" }),
            ),
        ];
        for response in &responses {
            let serialized = response.to_string();
            for secret in [
                fixtures::LOGIN_PASSWORD,
                fixtures::LOGIN_TOTP_SEED,
                fixtures::HISTORY_PASSWORD,
                fixtures::NOTES,
                fixtures::CARD_NUMBER,
                fixtures::CARD_CODE,
                fixtures::IDENTITY_SSN,
                fixtures::PASSPORT_NUMBER,
                fixtures::LICENSE_NUMBER,
                fixtures::HIDDEN_FIELD_VALUE,
            ] {
                assert!(!serialized.contains(secret), "leak in {serialized}");
            }
        }
        assert_eq!(responses[0].as_array().unwrap().len(), 4);
        assert_eq!(responses[2]["item"]["login"]["has_password"], true);
        assert_eq!(responses[3]["item"]["card"]["number_last_four"], "1111");

        let category = send_request(&state, json!({ "action": "list", "category": "card" }));
        assert_eq!(category.as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_search_does_not_match_secret_content() {
        use crate::item_redaction::tests as fixtures;
        let (_dir, state) = state_with_fixture_items();
        for probe in [
            fixtures::NOTES,
            fixtures::LOGIN_PASSWORD,
            "4111111111111111",
        ] {
            let res = send_request(&state, json!({ "action": "search", "query": probe }));
            assert_eq!(res.as_array().unwrap().len(), 0, "{probe} must not match");
        }
    }

    #[test]
    fn test_reveal_and_copy_field_over_the_socket() {
        use crate::item_redaction::tests as fixtures;
        let (_dir, state) = state_with_fixture_items();
        let res = send_request(
            &state,
            json!({ "action": "reveal_field", "id": "card-1", "field": "card.code" }),
        );
        assert_eq!(res["value"], fixtures::CARD_CODE, "{res}");

        *state.vault_mgr.is_unlocked.write().unwrap() = false;
        for action in ["reveal_field", "copy_field"] {
            let res = send_request(
                &state,
                json!({ "action": action, "id": "card-1", "field": "card.code" }),
            );
            assert_eq!(res["ok"], false);
            assert_eq!(res["error_code"], "vault_locked", "{action}: {res}");
        }
    }

    #[test]
    fn test_oversized_request_is_rejected() {
        let dir = tempdir().unwrap();
        let state = Arc::new(DaemonState::new(
            StorageManager::new(dir.path().join("daemon_data.json")),
            15,
        ));
        let mut payload = br#"{"action":"ping","padding":""#.to_vec();
        payload.extend(std::iter::repeat_n(
            b'a',
            crate::daemon_requests::MAX_REQUEST_BYTES,
        ));
        payload.extend_from_slice(b"\"}\n");
        let res = send_raw_request(&state, &payload);
        assert_eq!(res["ok"], false);
        assert!(
            res["error"].as_str().unwrap().contains("65536-byte limit"),
            "{res}"
        );
        assert!(
            res.get("pong").is_none(),
            "the oversized request is not dispatched"
        );
    }

    #[test]
    fn test_client_with_a_foreign_executable_is_refused() {
        let dir = tempdir().unwrap();
        let mut state = DaemonState::new(StorageManager::new(dir.path().join("data.json")), 15);
        // The socket-pair peer is this test binary; pretend the daemon is a
        // different installation so the peer becomes a foreign executable.
        state.own_executable = PathBuf::from("/usr/bin/omawarden-other-installation");
        let state = Arc::new(state);
        let res = send_request(&state, json!({ "action": "ping" }));
        assert_eq!(res["ok"], false);
        assert!(
            res["error"].as_str().unwrap().contains("Access denied"),
            "{res}"
        );
        assert!(res.get("pong").is_none());
    }

    #[test]
    fn test_quick_unlock_is_disabled_by_default_and_soft_lock_is_hard() {
        let _lock = crate::env_lock();
        let dir = tempdir().unwrap();
        let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
        std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());

        assert!(!crate::config::Config::default().quick_unlock);
        let legacy: crate::config::Config = serde_json::from_str("{}").unwrap();
        assert!(
            !legacy.quick_unlock,
            "configs without the key load as disabled"
        );

        let mut daemon_state =
            DaemonState::new(StorageManager::new(dir.path().join("data.json")), 15);
        // Even with polkit fully usable, the default setting must not retain.
        daemon_state.polkit_binary = dir.path().join("pkcheck");
        daemon_state.polkit_policy_registered = true;
        let state = Arc::new(daemon_state);
        assert!(!state.quick_unlock_enabled());

        *state.vault_mgr.user_key.write().unwrap() =
            Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap());
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        state.soft_lock();
        assert!(!state.vault_mgr.quick_unlock_available());
        let res = send_request(&state, json!({ "action": "quick_unlock" }));
        assert_eq!(res["ok"], false);
        assert!(res["error"].as_str().unwrap().contains("disabled"), "{res}");

        old_config.map_or_else(
            || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
            |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
        );
    }

    #[test]
    fn test_sleep_inhibitor_follows_key_material_and_prepare_for_sleep_locks() {
        let dir = tempdir().unwrap();
        let program = dir.path().join("systemd-inhibit-fixture");
        crate::write_test_executable(&program, "#!/bin/sh\nshift 4\nexec \"$@\"\n");
        let mut state = DaemonState::new(StorageManager::new(dir.path().join("data.json")), 15);
        state.supervision_programs.systemd_inhibit = Some(program);
        state.supervision_programs.inhibitor_holder = Some(PathBuf::from("/bin/cat"));
        let state = Arc::new(state);

        state.synchronize_sleep_inhibitor();
        assert!(
            state.sleep_inhibitor.lock().unwrap().is_none(),
            "locked: none held"
        );

        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        state.synchronize_sleep_inhibitor();
        assert!(
            state
                .sleep_inhibitor
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .is_held(),
            "unlocked: the delay inhibitor is held"
        );

        let started = Instant::now();
        state.prepare_for_sleep();
        assert!(!state.vault_mgr.is_unlocked());
        assert!(
            state.sleep_inhibitor.lock().unwrap().is_none(),
            "released after the lock"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "lock and release must finish well within logind's default 5 s delay"
        );
    }

    fn state_with_seeded_vault(password: &str) -> (tempfile::TempDir, Arc<DaemonState>) {
        let dir = tempdir().unwrap();
        let mut state = DaemonState::new(StorageManager::new(dir.path().join("data.json")), 15);
        state.vault_mgr = Arc::new(crate::vault::tests::seeded_vault(dir.path(), password));
        (dir, Arc::new(state))
    }

    #[test]
    fn test_unlock_completing_after_a_sleep_notification_ends_locked() {
        let (_dir, state) = state_with_seeded_vault("master-pw");

        // The interleaving of the race: the unlock samples the sleep
        // generation, PrepareForSleep(true) arrives while the key derivation
        // runs (and locks the still-locked vault), then the derivation
        // finishes and the session would be armed.
        let sleep_generation = state.sleep_generation.load(Ordering::SeqCst);
        state.prepare_for_sleep();
        let count = state.vault_mgr.unlock("master-pw").unwrap();
        assert!(
            state.vault_mgr.is_unlocked(),
            "the vault decrypted meanwhile"
        );
        let result = state.complete_unlock(sleep_generation, count);
        assert!(result.is_err(), "{result:?}");
        assert!(!state.vault_mgr.is_unlocked());
        assert!(state.vault_mgr.user_key.read().unwrap().is_none());
        assert!(state.unlocked_at.lock().unwrap().is_none());
        assert!(state.sleep_inhibitor.lock().unwrap().is_none());

        // While the sleep is pending, a whole new unlock ends locked too.
        assert!(state.unlock("master-pw").is_err());
        assert!(!state.vault_mgr.is_unlocked());

        // After the resume, unlocking works again.
        state.resume_from_sleep();
        assert_eq!(state.unlock("master-pw"), Ok(0));
        assert!(state.vault_mgr.is_unlocked());
    }

    #[test]
    fn test_unlock_straddling_a_detected_suspend_ends_locked() {
        let (_dir, state) = state_with_seeded_vault("master-pw");
        assert!(!state.check_suspend_drift_with(Some(10)), "first sample");
        // A PrepareForSleep(false) that was never delivered.
        state.sleep_pending.store(true, Ordering::SeqCst);
        let sleep_generation = state.sleep_generation.load(Ordering::SeqCst);
        let count = state.vault_mgr.unlock("master-pw").unwrap();
        // The resume edge is detected (BOOTTIME drift) before the unlock
        // arms the session.
        assert!(state.check_suspend_drift_with(Some(20)));
        assert!(state.complete_unlock(sleep_generation, count).is_err());
        assert!(!state.vault_mgr.is_unlocked());
        assert!(
            !state.sleep_pending.load(Ordering::SeqCst),
            "a detected resume clears the pending sleep"
        );
    }

    #[test]
    fn test_initial_auto_lock_rejects_disabled_and_out_of_range_values() {
        assert_eq!(initial_auto_lock_duration(15), Duration::from_secs(900));
        assert_eq!(initial_auto_lock_duration(720), Duration::from_secs(43_200));
        for minutes in [0, 721, u64::MAX] {
            assert_eq!(
                initial_auto_lock_duration(minutes),
                Duration::from_secs(DEFAULT_AUTO_LOCK_MINUTES * 60),
                "{minutes}"
            );
        }
    }

    #[test]
    fn test_validate_runtime_dir_requires_owned_0700_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let runtime = dir.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(validate_runtime_dir(&runtime).is_ok());

        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o755)).unwrap();
        let error = validate_runtime_dir(&runtime).unwrap_err();
        assert!(error.to_string().contains("must be 0700"), "{error}");

        let link = dir.path().join("runtime-link");
        std::os::unix::fs::symlink(&runtime, &link).unwrap();
        assert!(validate_runtime_dir(&link).is_err(), "symlinks are refused");
        assert!(validate_runtime_dir(&dir.path().join("missing")).is_err());
        assert!(validate_runtime_dir(Path::new("relative/runtime")).is_err());
        let file = dir.path().join("file");
        fs::write(&file, b"").unwrap();
        assert!(validate_runtime_dir(&file).is_err());
        // Root's directory is owned by another UID.
        if unsafe { libc::getuid() } != 0 {
            let error = validate_runtime_dir(Path::new("/root")).unwrap_err();
            assert!(error.to_string().contains("UID"), "{error}");
        }
    }

    #[test]
    fn test_get_runtime_dir_fails_without_a_valid_xdg_runtime_dir() {
        let _lock = crate::env_lock();
        let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
        let dir = crate::private_runtime_dir();

        std::env::remove_var("XDG_RUNTIME_DIR");
        let error = get_runtime_dir().unwrap_err();
        assert!(
            error.to_string().contains("XDG_RUNTIME_DIR is not set"),
            "{error}"
        );

        let shared = dir.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", &shared);
        assert!(
            get_runtime_dir().is_err(),
            "no fallback for a shared directory"
        );
        assert!(get_socket_path().is_err());

        std::env::set_var("XDG_RUNTIME_DIR", dir.path());
        assert_eq!(get_runtime_dir().unwrap(), dir.path());

        old_runtime.map_or_else(
            || std::env::remove_var("XDG_RUNTIME_DIR"),
            |v| std::env::set_var("XDG_RUNTIME_DIR", v),
        );
    }

    #[test]
    fn test_ensure_daemon_running_keeps_a_running_daemon_it_should_not_replace() {
        let _lock = crate::env_lock();
        let runtime = crate::private_runtime_dir();
        let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
        std::env::set_var("XDG_RUNTIME_DIR", runtime.path());

        // A daemon that answers every ping the same way; if it were replaced,
        // a second daemon would be spawned and the connection count would
        // show it.
        let listener = std::os::unix::net::UnixListener::bind(get_socket_path().unwrap()).unwrap();
        for reply in [
            json!({ "ok": true, "commit": env!("GIT_HASH"), "unlocked": false }),
            json!({ "ok": true, "commit": "another-build", "unlocked": true }),
        ] {
            let server = {
                let listener = listener.try_clone().unwrap();
                let reply = reply.clone();
                std::thread::spawn(move || {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut line = String::new();
                    BufReader::new(stream.try_clone().unwrap())
                        .read_line(&mut line)
                        .unwrap();
                    assert_eq!(
                        serde_json::from_str::<Value>(&line).unwrap()["action"],
                        "ping"
                    );
                    writeln!(stream, "{reply}").unwrap();
                })
            };
            ensure_daemon_running();
            server.join().unwrap();
        }

        old_runtime.map_or_else(
            || std::env::remove_var("XDG_RUNTIME_DIR"),
            |v| std::env::set_var("XDG_RUNTIME_DIR", v),
        );
    }

    #[test]
    fn test_outdated_daemon_is_only_replaced_while_locked() {
        let ping = |commit: &str, unlocked: Option<bool>| {
            let mut v = json!({ "ok": true, "commit": commit });
            if let Some(u) = unlocked {
                v["unlocked"] = json!(u);
            }
            v
        };
        assert_eq!(
            check_running_daemon(&ping("abc", Some(true)), "abc"),
            DaemonCheck::UpToDate
        );
        assert_eq!(
            check_running_daemon(&ping("old", Some(true)), "abc"),
            DaemonCheck::Defer
        );
        assert_eq!(
            check_running_daemon(&ping("old", Some(false)), "abc"),
            DaemonCheck::Replace
        );
        // Daemons predating the field are replaced as before.
        assert_eq!(
            check_running_daemon(&ping("old", None), "abc"),
            DaemonCheck::Replace
        );
    }

    #[test]
    fn test_background_pings_do_not_prevent_idle_auto_lock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);
        let state = Arc::new(DaemonState::new(storage_mgr, 15));

        // Configure a short timeout (100ms) for testing
        state.set_auto_lock_duration(Duration::from_millis(100));

        // Unlock the vault
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        assert!(state.vault_mgr.is_unlocked());

        // Send repeated pings over 150ms (crossing the 100ms threshold)
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(150) {
            let (mut client, server) = UnixStream::pair().unwrap();
            let st = state.clone();
            let handle = std::thread::spawn(move || {
                let _ = handle_client(server, st);
            });
            let payload = format!("{}\n", json!({ "action": "ping" }));
            client.write_all(payload.as_bytes()).unwrap();
            client.flush().unwrap();
            handle.join().unwrap();
            std::thread::sleep(Duration::from_millis(20));
        }

        // Auto-lock check must lock the vault despite the continuous background pings
        assert!(state.check_auto_lock());
        assert!(!state.vault_mgr.is_unlocked());
    }

    #[test]
    fn test_set_auto_lock_action() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);
        let state = Arc::new(DaemonState::new(storage_mgr, 15));

        let send_req = |req: Value| -> Value {
            let (mut client, server) = UnixStream::pair().unwrap();
            let st = state.clone();
            let handle = std::thread::spawn(move || {
                let _ = handle_client(server, st);
            });
            let payload = format!("{}\n", req);
            client.write_all(payload.as_bytes()).unwrap();
            client.flush().unwrap();

            let mut reader = BufReader::new(client);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            handle.join().unwrap();
            serde_json::from_str(&line).unwrap()
        };

        // Update with minutes
        let res = send_req(json!({ "action": "set_auto_lock", "auto_lock_minutes": 5 }));
        assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            *state.auto_lock_duration.lock().unwrap(),
            Duration::from_secs(300)
        );

        // Update with seconds
        let res = send_req(json!({ "action": "set_auto_lock", "auto_lock_seconds": 90 }));
        assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            *state.auto_lock_duration.lock().unwrap(),
            Duration::from_secs(90)
        );

        // Zero (never lock), too short and too long are refused and change nothing.
        for req in [
            json!({ "action": "set_auto_lock", "auto_lock_seconds": 0 }),
            json!({ "action": "set_auto_lock", "auto_lock_minutes": 0 }),
            json!({ "action": "set_auto_lock", "auto_lock_seconds": 45 }),
            json!({ "action": "set_auto_lock", "auto_lock_seconds": 43_201 }),
            json!({ "action": "set_auto_lock" }),
        ] {
            let res = send_req(req.clone());
            assert_eq!(res["ok"], false, "{req}: {res}");
            assert_eq!(
                *state.auto_lock_duration.lock().unwrap(),
                Duration::from_secs(90),
                "{req}"
            );
        }
    }

    #[test]
    fn test_verify_peer_credentials() {
        let (client, server) = UnixStream::pair().unwrap();
        assert!(verify_peer_credentials(&client).is_ok());
        assert!(verify_peer_credentials(&server).is_ok());
    }

    #[test]
    fn test_suspend_happened_predicate() {
        fn f(prev: Option<u64>, current: Option<u64>) -> bool {
            DaemonState::suspend_happened(prev, current)
        }
        assert!(!f(None, Some(100)), "first sample is never an event");
        assert!(
            !f(Some(100), Some(100)),
            "equal deltas: awake the whole time"
        );
        assert!(
            !f(Some(100), Some(101)),
            "one second of clock skew is not suspend"
        );
        assert!(f(Some(100), Some(103)), "grew by 3s: suspend happened");
        assert!(!f(Some(100), Some(99)), "shrinkage ignored");
        assert!(!f(Some(100), None), "clock unavailable is not an event");
    }

    #[test]
    fn test_suspend_drift_wipes_retained_key_while_soft_locked() {
        let _lock = crate::env_lock();
        let dir = tempdir().unwrap();
        let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
        std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());
        let state = DaemonState::new(StorageManager::new(dir.path().join("daemon_data.json")), 15);
        // The daemon caches the setting at startup; tests mirror the
        // set_quick_unlock IPC instead of rewriting config.json (which the
        // hot paths no longer read).
        state.set_quick_unlock_enabled(true);

        // Soft-locked with a retained key: the dominant quick-unlock state.
        *state.vault_mgr.user_key.write().unwrap() =
            Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap());
        assert!(state.vault_mgr.soft_lock());
        assert!(state.vault_mgr.quick_unlock_available());

        // First tick primes the cache; second tick observes the drift.
        assert!(!state.check_suspend_drift_with(Some(1_000)));
        assert!(
            state.check_suspend_drift_with(Some(1_900)),
            "900s of accumulated suspend time must be detected"
        );
        assert!(
            !state.vault_mgr.quick_unlock_available(),
            "suspend must wipe the retained key even while soft-locked"
        );
        assert!(!state.vault_mgr.is_unlocked());

        old_config.map_or_else(
            || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
            |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
        );
    }

    #[test]
    fn test_suspend_drift_hard_locks_unlocked_vault() {
        let dir = tempdir().unwrap();
        let state = DaemonState::new(StorageManager::new(dir.path().join("daemon_data.json")), 15);
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        assert!(!state.check_suspend_drift_with(Some(10)));
        assert!(state.check_suspend_drift_with(Some(600)));
        assert!(!state.vault_mgr.is_unlocked());
    }

    #[test]
    fn test_session_anchor_ceiling_wipes_retained_key_while_soft_locked() {
        let _lock = crate::env_lock();
        let dir = tempdir().unwrap();
        let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
        std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());
        let state = DaemonState::new(StorageManager::new(dir.path().join("daemon_data.json")), 15);
        state.set_quick_unlock_enabled(true);

        // Unlocked 13h ago (session anchor), then soft-locked with retention.
        *state.session_anchor.lock().unwrap() =
            Some(Instant::now() - Duration::from_secs(13 * 3600));
        *state.vault_mgr.user_key.write().unwrap() =
            Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap());
        assert!(state.vault_mgr.soft_lock());

        assert!(
            state.check_auto_lock(),
            "the 12h ceiling must fire for a retained key past the session anchor"
        );
        assert!(
            !state.vault_mgr.quick_unlock_available(),
            "ceiling must wipe the retained key"
        );
        assert!(
            state.session_anchor.lock().unwrap().is_none(),
            "hard lock clears the anchor"
        );

        old_config.map_or_else(
            || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
            |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
        );
    }

    #[test]
    fn test_quick_unlock_re_arms_unlocked_at_but_not_session_anchor() {
        let _lock = crate::env_lock();
        let dir = tempdir().unwrap();
        let runtime = crate::private_runtime_dir();
        let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
        let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
        std::env::set_var("XDG_RUNTIME_DIR", runtime.path());
        std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());

        let _vault = crate::vault::tests::seeded_vault(dir.path(), "master-pw");
        let mut daemon_state =
            DaemonState::new(StorageManager::new(dir.path().join("data.json")), 15);

        let pk = dir.path().join("mock-pkcheck");
        crate::write_test_executable(&pk, "#!/bin/sh\nexit 0\n");
        daemon_state.polkit_binary = pk;
        daemon_state.polkit_policy_registered = true;
        let state = Arc::new(daemon_state);
        // Mirror the set_quick_unlock IPC the CLI sends after a config write.
        state.set_quick_unlock_enabled(true);

        // Session anchored 13h ago by the master-password unlock.
        *state.session_anchor.lock().unwrap() =
            Some(Instant::now() - Duration::from_secs(13 * 3600));
        *state.vault_mgr.user_key.write().unwrap() =
            Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap());
        assert!(state.vault_mgr.soft_lock());

        assert!(state.perform_quick_unlock().is_ok());
        assert!(
            state.unlocked_at.lock().unwrap().is_some(),
            "quick unlock must re-arm the per-unlock anchor (Rule 9 while unlocked)"
        );

        // The session anchor is untouched, so the ceiling still fires even
        // though the vault was just quick-unlocked.
        assert!(
            state.check_auto_lock(),
            "quick unlock must not extend the 12h session ceiling"
        );
        assert!(!state.vault_mgr.is_unlocked());

        old_runtime.map_or_else(
            || std::env::remove_var("XDG_RUNTIME_DIR"),
            |v| std::env::set_var("XDG_RUNTIME_DIR", v),
        );
        old_config.map_or_else(
            || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
            |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
        );
    }

    #[test]
    fn test_check_screen_lock_custom_detector() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);
        let state = DaemonState::new(storage_mgr, 15);

        // Vault is initially locked: detector should not be invoked or return false
        let mut called = false;
        assert!(!state.check_screen_lock_with(|| {
            called = true;
            LockSignal::Screen
        }));
        assert!(!called);
        assert!(!state.vault_mgr.is_unlocked());

        // Unlock the vault
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        assert!(state.vault_mgr.is_unlocked());

        // No lock signal -> vault remains unlocked
        assert!(!state.check_screen_lock_with(|| LockSignal::None));
        assert!(state.vault_mgr.is_unlocked());

        // Screen signal -> locks
        assert!(state.check_screen_lock_with(|| LockSignal::Screen));
        assert!(!state.vault_mgr.is_unlocked());

        // Subsequent call returns false because already locked
        assert!(!state.check_screen_lock_with(|| LockSignal::Screen));
    }

    #[test]
    fn test_soft_lock_hard_locks_when_quick_unlock_disabled() {
        // ADR-0025: retention exists only when opted in. With quick_unlock
        // disabled, a soft lock must HARD lock: no key may survive in the
        // slot for any later restore to pick up.
        let _lock = crate::env_lock();
        let dir = tempdir().unwrap();
        let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
        std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());

        let mut cfg = crate::config::ConfigManager::default().load();
        cfg.quick_unlock = false;
        fs::write(
            dir.path().join(crate::config::DEFAULT_CONFIG_FILENAME),
            serde_json::to_string(&cfg).unwrap(),
        )
        .unwrap();

        let state = DaemonState::new(StorageManager::new(dir.path().join("daemon_data.json")), 15);
        assert!(!state.quick_unlock_enabled());

        *state.vault_mgr.user_key.write().unwrap() =
            Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap());
        *state.vault_mgr.is_unlocked.write().unwrap() = true;

        state.soft_lock();

        assert!(!state.vault_mgr.is_unlocked());
        assert!(
            state.vault_mgr.user_key.read().unwrap().is_none(),
            "the user key must be purged from the session"
        );
        assert!(
            !state.vault_mgr.quick_unlock_available(),
            "with quick unlock disabled a soft lock must be a hard lock: nothing retained"
        );
        assert!(
            !state.quick_unlock_ready(),
            "readiness must stay false while the feature is disabled"
        );

        old_config.map_or_else(
            || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
            |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
        );
    }

    #[test]
    fn test_soft_lock_hard_locks_when_quick_unlock_is_unusable() {
        // ADR-0025: retention is only worth its exposure when the polkit
        // check can actually run. Enabled-but-unusable (policy missing, no
        // pkcheck) must hard-lock, exactly like disabled: the retained key
        // could never be spent and would just sit in memory.
        let _lock = crate::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
        std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());

        let mut daemon_state =
            DaemonState::new(StorageManager::new(dir.path().join("daemon_data.json")), 15);
        daemon_state.set_quick_unlock_enabled(true);
        // No resolvable pkcheck, no registered policy.
        daemon_state.polkit_binary = std::path::PathBuf::new();
        daemon_state.polkit_policy_registered = false;
        let state = Arc::new(daemon_state);
        assert!(state.quick_unlock_enabled());
        assert!(!state.quick_unlock_usable());

        *state.vault_mgr.user_key.write().unwrap() =
            Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap());
        *state.vault_mgr.is_unlocked.write().unwrap() = true;

        state.soft_lock();

        assert!(!state.vault_mgr.is_unlocked());
        assert!(
            !state.vault_mgr.quick_unlock_available(),
            "an unusable feature must not retain a key nobody can spend"
        );
        assert!(!state.quick_unlock_ready());

        old_config.map_or_else(
            || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
            |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
        );
    }

    #[test]
    fn test_sleep_signal_hard_locks_and_screen_signal_soft_locks() {
        let _lock = crate::env_lock();
        let dir = tempdir().unwrap();
        let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
        std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());
        let mut daemon_state =
            DaemonState::new(StorageManager::new(dir.path().join("daemon_data.json")), 15);
        // Retention requires a usable feature, not just the setting: pin the
        // startup-resolved binary and policy so the host cannot decide this.
        daemon_state.polkit_binary = dir.path().join("pkcheck");
        daemon_state.polkit_policy_registered = true;
        let state = Arc::new(daemon_state);
        let key = crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap();

        // Screen lock with quick unlock enabled: key must survive in the slot.
        state.set_quick_unlock_enabled(true);

        *state.vault_mgr.user_key.write().unwrap() = Some(key.clone());
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        assert!(state.check_screen_lock_with(|| LockSignal::Screen));
        assert!(!state.vault_mgr.is_unlocked());
        assert!(
            state.vault_mgr.quick_unlock_available(),
            "screen lock must retain the key when quick unlock is on"
        );

        // Sleep signal: retention must be wiped even while quick unlock is on.
        *state.vault_mgr.user_key.write().unwrap() = Some(key);
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        assert!(state.check_screen_lock_with(|| LockSignal::Sleep));
        assert!(!state.vault_mgr.is_unlocked());
        assert!(
            !state.vault_mgr.quick_unlock_available(),
            "sleep must hard-lock: no key may survive a suspend"
        );

        old_config.map_or_else(
            || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
            |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
        );
    }

    #[test]
    fn test_quick_unlock_ipc_disabled_and_unavailable() {
        let _lock = crate::env_lock();
        let dir = tempdir().unwrap();
        let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
        let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
        std::env::set_var("XDG_RUNTIME_DIR", dir.path().join("runtime"));
        std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());
        let state = Arc::new(DaemonState::new(
            StorageManager::new(dir.path().join("daemon_data.json")),
            15,
        ));

        let send_req = |req: Value| -> Value {
            let (mut client, server) = UnixStream::pair().unwrap();
            let st = state.clone();
            let handle = std::thread::spawn(move || {
                let _ = handle_client(server, st);
            });
            client.write_all(format!("{}\n", req).as_bytes()).unwrap();
            client.flush().unwrap();
            let mut line = String::new();
            BufReader::new(client).read_line(&mut line).unwrap();
            handle.join().unwrap();
            serde_json::from_str(&line).unwrap()
        };

        let res = send_req(json!({ "action": "quick_unlock" }));
        assert_eq!(res["ok"], false);
        assert!(
            res["error"].as_str().unwrap().contains("disabled"),
            "got: {res}"
        );

        // Enabled but nothing retained (hard-locked vault) must fail closed.
        // Mirror the set_quick_unlock IPC the CLI sends after a config write.
        state.set_quick_unlock_enabled(true);
        let res = send_req(json!({ "action": "quick_unlock" }));
        assert_eq!(res["ok"], false);
        assert!(
            res["error"].as_str().unwrap().contains("unavailable"),
            "got: {res}"
        );

        old_runtime.map_or_else(
            || std::env::remove_var("XDG_RUNTIME_DIR"),
            |v| std::env::set_var("XDG_RUNTIME_DIR", v),
        );
        old_config.map_or_else(
            || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
            |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
        );
    }

    #[test]
    fn test_set_quick_unlock_ipc_refreshes_cache_and_ping_reports_enabled() {
        let _lock = crate::env_lock();
        let dir = tempdir().unwrap();
        let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
        let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
        std::env::set_var("XDG_RUNTIME_DIR", dir.path().join("runtime"));
        std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());
        let mut daemon_state =
            DaemonState::new(StorageManager::new(dir.path().join("data.json")), 15);
        daemon_state.polkit_binary = std::path::PathBuf::new();
        let state = Arc::new(daemon_state);

        let send_req = |req: Value| -> Value {
            let (mut client, server) = UnixStream::pair().unwrap();
            let st = state.clone();
            let handle = std::thread::spawn(move || {
                let _ = handle_client(server, st);
            });
            client.write_all(format!("{}\n", req).as_bytes()).unwrap();
            client.flush().unwrap();
            let mut line = String::new();
            BufReader::new(client).read_line(&mut line).unwrap();
            handle.join().unwrap();
            serde_json::from_str(&line).unwrap()
        };

        // Default cached at startup from config.json: off.
        let ping = send_req(json!({ "action": "ping" }));
        assert_eq!(ping["quick_unlock_enabled"], false);

        // `config set --quick-unlock` writes the file, then sends this IPC;
        // the daemon must never re-read config.json on its hot paths.
        let res = send_req(json!({ "action": "set_quick_unlock", "enabled": true }));
        assert_eq!(res["ok"], true);
        let ping = send_req(json!({ "action": "ping" }));
        assert_eq!(ping["quick_unlock_enabled"], true);
        assert_eq!(
            ping["quick_unlock"], false,
            "enabled alone is not readiness (nothing retained here)"
        );

        // Prime retention, then disable via the IPC: the handler owns the
        // wipe (same trigger family as strikes/suspend/logout), so turning
        // the feature off must not leave a retained key behind even though
        // the caller sent no separate wipe request.
        *state.vault_mgr.user_key.write().unwrap() =
            Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap());
        assert!(state.vault_mgr.soft_lock());
        assert!(state.vault_mgr.quick_unlock_available());
        send_req(json!({ "action": "set_quick_unlock", "enabled": false }));
        let ping = send_req(json!({ "action": "ping" }));
        assert_eq!(ping["quick_unlock_enabled"], false);
        assert!(
            !state.vault_mgr.quick_unlock_available(),
            "disabling through the IPC must wipe the retained key"
        );

        old_runtime.map_or_else(
            || std::env::remove_var("XDG_RUNTIME_DIR"),
            |v| std::env::set_var("XDG_RUNTIME_DIR", v),
        );
        old_config.map_or_else(
            || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
            |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
        );
    }

    #[test]
    fn test_quick_unlock_ipc_authorized_and_three_denies_wipe() {
        let _lock = crate::env_lock();
        let dir = tempdir().unwrap();
        let runtime = crate::private_runtime_dir();
        let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
        let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
        std::env::set_var("XDG_RUNTIME_DIR", runtime.path());
        std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());

        // A real login on disk so a successful polkit check can restore.
        let _vault = crate::vault::tests::seeded_vault(dir.path(), "master-pw");
        let mut daemon_state =
            DaemonState::new(StorageManager::new(dir.path().join("data.json")), 15);

        // Mock pkcheck whose exit code is driven by a file the test flips.
        let pk = dir.path().join("mock-pkcheck");
        crate::write_test_executable(
            &pk,
            format!(
                r#"#!/bin/sh
exit $(cat {})
"#,
                dir.path().join("pk_code").display()
            ),
        );
        daemon_state.polkit_binary = pk.clone();
        daemon_state.polkit_policy_registered = true;
        let state = Arc::new(daemon_state);
        // Mirror the set_quick_unlock IPC the CLI sends after a config write.
        state.set_quick_unlock_enabled(true);

        // Prime retention the way a soft lock would.
        *state.vault_mgr.user_key.write().unwrap() =
            Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap());
        assert!(state.vault_mgr.soft_lock());
        assert_eq!(*state.quick_unlock_failures.lock().unwrap(), 0);

        let send_req = |req: Value| -> Value {
            let (mut client, server) = UnixStream::pair().unwrap();
            let st = state.clone();
            let handle = std::thread::spawn(move || {
                let _ = handle_client(server, st);
            });
            client.write_all(format!("{}\n", req).as_bytes()).unwrap();
            client.flush().unwrap();
            let mut line = String::new();
            BufReader::new(client).read_line(&mut line).unwrap();
            handle.join().unwrap();
            serde_json::from_str(&line).unwrap()
        };

        // 1. polkit authorizes: IPC reports an unlocked vault.
        fs::write(dir.path().join("pk_code"), "0").unwrap();
        let res = send_req(json!({ "action": "quick_unlock" }));
        assert_eq!(res["ok"], true, "got: {res}");
        assert_eq!(res["status"], "unlocked");
        assert_eq!(*state.quick_unlock_failures.lock().unwrap(), 0);

        // 1b. While unlocked the action must not re-prompt (state-machine
        // hole closed in review): it fails fast without touching polkit.
        fs::write(dir.path().join("pk_code"), "0").unwrap();
        let res = send_req(json!({ "action": "quick_unlock" }));
        assert_eq!(res["ok"], false, "got: {res}");
        assert!(
            res["error"].as_str().unwrap().contains("already unlocked"),
            "got: {res}"
        );

        // Back to the soft-locked state for the denial loop.
        assert!(state.vault_mgr.soft_lock());

        // 2. Three denials in a row wipe the retained key.
        fs::write(dir.path().join("pk_code"), "1").unwrap();
        for i in 1..=3 {
            let res = send_req(json!({ "action": "quick_unlock" }));
            assert_eq!(res["ok"], false, "attempt {i}: {res}");
            assert!(
                res["error"].as_str().unwrap().contains("denied"),
                "attempt {i}: {res}"
            );
        }
        assert!(
            !state.vault_mgr.quick_unlock_available(),
            "three denials must wipe the retained key"
        );
        assert_eq!(*state.quick_unlock_failures.lock().unwrap(), 0);

        // 3. After the wipe the action fails closed without calling polkit.
        fs::write(dir.path().join("pk_code"), "0").unwrap();
        let res = send_req(json!({ "action": "quick_unlock" }));
        assert_eq!(res["ok"], false);
        assert!(res["error"].as_str().unwrap().contains("unavailable"));

        // 4. wipe_quick_unlock action is a harmless explicit no-op.
        let res = send_req(json!({ "action": "wipe_quick_unlock" }));
        assert_eq!(res["ok"], true);

        old_runtime.map_or_else(
            || std::env::remove_var("XDG_RUNTIME_DIR"),
            |v| std::env::set_var("XDG_RUNTIME_DIR", v),
        );
        old_config.map_or_else(
            || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
            |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
        );
    }

    #[test]
    fn test_logout_requests_end_retention_with_readiness_false() {
        // ADR-0025 decision 4: logout must zeroize the retained key. The
        // logout flow (main.rs AuthAction::Logout) sends "lock" followed by
        // an explicit "wipe_quick_unlock"; pin the daemon contract both
        // requests rely on: slot empty, readiness false in the ping payload.
        let _lock = crate::env_lock();
        let dir = tempdir().unwrap();
        let runtime = crate::private_runtime_dir();
        let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
        let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
        std::env::set_var("XDG_RUNTIME_DIR", runtime.path());
        std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());

        let state = Arc::new(DaemonState::new(
            StorageManager::new(dir.path().join("daemon_data.json")),
            15,
        ));
        state.set_quick_unlock_enabled(true);

        let send_req = |req: Value| -> Value {
            let (mut client, server) = UnixStream::pair().unwrap();
            let st = state.clone();
            let handle = std::thread::spawn(move || {
                let _ = handle_client(server, st);
            });
            client.write_all(format!("{}\n", req).as_bytes()).unwrap();
            client.flush().unwrap();
            let mut line = String::new();
            BufReader::new(client).read_line(&mut line).unwrap();
            handle.join().unwrap();
            serde_json::from_str(&line).unwrap()
        };

        let prime_retention = |key_byte: u8| {
            *state.vault_mgr.user_key.write().unwrap() =
                Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[key_byte; 64]).unwrap());
            assert!(state.vault_mgr.soft_lock());
            assert!(state.vault_mgr.quick_unlock_available());
        };

        // 1. The "lock" half of the logout flow must already end retention.
        prime_retention(7u8);
        let res = send_req(json!({ "action": "lock" }));
        assert_eq!(res["ok"], true, "got: {res}");
        assert!(
            !state.vault_mgr.quick_unlock_available(),
            "the retained key must be gone after logout's lock request"
        );
        assert!(
            !state.quick_unlock_ready(),
            "readiness must be false after logout's lock request"
        );

        // 2. The explicit "wipe_quick_unlock" half must zeroize on its own.
        prime_retention(9u8);
        let res = send_req(json!({ "action": "wipe_quick_unlock" }));
        assert_eq!(res["ok"], true, "got: {res}");
        assert!(
            !state.vault_mgr.quick_unlock_available(),
            "the retained key must be gone after the explicit wipe request"
        );
        assert!(
            !state.quick_unlock_ready(),
            "readiness must be false after the explicit wipe request"
        );

        // 3. And the ping payload stops advertising quick unlock. It also
        // always carries the memory-protection bit (mlock degradation must
        // be discoverable even though the daemon's stderr is discarded).
        let res = send_req(json!({ "action": "ping" }));
        assert_eq!(res["quick_unlock"], false, "got: {res}");
        assert!(
            res["memory_locked"].is_boolean(),
            "ping must report memory protection state: {res}"
        );

        old_runtime.map_or_else(
            || std::env::remove_var("XDG_RUNTIME_DIR"),
            |v| std::env::set_var("XDG_RUNTIME_DIR", v),
        );
        old_config.map_or_else(
            || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
            |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
        );
    }

    #[test]
    fn test_poisoned_busy_mutex_does_not_jam_quick_unlock() {
        let _lock = crate::env_lock();
        let dir = tempdir().unwrap();
        let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
        std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());

        // A real login on disk so the post-polkit restore can succeed.
        let _vault = crate::vault::tests::seeded_vault(dir.path(), "master-pw");
        let mut daemon_state =
            DaemonState::new(StorageManager::new(dir.path().join("data.json")), 15);

        let pk = dir.path().join("mock-pkcheck");
        crate::write_test_executable(&pk, "#!/bin/sh\nexit 0\n");
        daemon_state.polkit_binary = pk;
        daemon_state.polkit_policy_registered = true;
        // Mirror the set_quick_unlock IPC the CLI sends after a config write.
        daemon_state.set_quick_unlock_enabled(true);

        // Prime retention the way a soft lock would.
        *daemon_state.vault_mgr.user_key.write().unwrap() =
            Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap());
        assert!(daemon_state.vault_mgr.soft_lock());

        // Poison the busy guard the way a panic during an earlier prompt
        // would (the panicking thread held the mutex).
        let state = Arc::new(daemon_state);
        let poisoner = state.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = poisoner.quick_unlock_busy.lock().unwrap();
            panic!("simulated panic while the polkit prompt was up");
        }));
        assert!(
            state.quick_unlock_busy.lock().is_err(),
            "the busy mutex must actually be poisoned by the setup"
        );

        // The next quick unlock must recover instead of failing forever with
        // "already in progress".
        assert!(
            state.perform_quick_unlock().is_ok(),
            "a poisoned busy mutex must not jam quick unlock"
        );

        old_config.map_or_else(
            || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
            |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
        );
    }

    #[test]
    fn test_ping_advertises_quick_unlock_only_when_ready() {
        let _lock = crate::env_lock();
        let dir = tempdir().unwrap();
        let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
        std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());
        let mut daemon_state =
            DaemonState::new(StorageManager::new(dir.path().join("daemon_data.json")), 15);
        // No polkit binary resolvable at startup: never ready, even with the
        // feature enabled and a key retained (readiness honesty — the button
        // must not advertise a prompt that can only fail). Forced empty so
        // the test does not depend on the host having pkcheck.
        daemon_state.polkit_binary = std::path::PathBuf::new();
        daemon_state.polkit_policy_registered = true;
        let state = Arc::new(daemon_state);
        // Disabled by default and nothing retained.
        assert!(!state.quick_unlock_ready());
        // Write the enabled setting to disk and mirror the CLI's
        // set_quick_unlock IPC, so the assert below fails for the reason it
        // names (later constructions reload this file at startup).
        let mut cfg = crate::config::ConfigManager::default().load();
        cfg.quick_unlock = true;
        fs::write(
            dir.path().join(crate::config::DEFAULT_CONFIG_FILENAME),
            serde_json::to_string(&cfg).unwrap(),
        )
        .unwrap();
        state.set_quick_unlock_enabled(true);
        // Enabled but no retained key: still not ready.
        assert!(!state.quick_unlock_ready());
        *state.vault_mgr.quick_unlock_key.write().unwrap() =
            Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[9u8; 64]).unwrap());
        assert!(
            !state.quick_unlock_ready(),
            "no resolvable polkit binary must keep readiness false"
        );

        // With a binary resolved at startup, retention alone completes it.
        drop(state);
        let runtime = crate::private_runtime_dir();
        let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
        std::env::set_var("XDG_RUNTIME_DIR", runtime.path());
        // This construction caches quick_unlock=true from the config file
        // written above: the daemon-startup half of the caching contract.
        daemon_state = DaemonState::new(
            StorageManager::new(dir.path().join("daemon2_data.json")),
            15,
        );
        daemon_state.polkit_binary = dir.path().join("pkcheck");
        // Retention + enabled setting are not enough: an unregistered
        // policy (missing package file) must keep readiness false.
        daemon_state.polkit_policy_registered = false;
        let state = Arc::new(daemon_state);
        assert!(state.quick_unlock_enabled());
        *state.vault_mgr.quick_unlock_key.write().unwrap() =
            Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[9u8; 64]).unwrap());
        assert!(
            !state.quick_unlock_ready(),
            "an unregistered policy must keep readiness false"
        );
        drop(state);

        daemon_state = DaemonState::new(
            StorageManager::new(dir.path().join("daemon3_data.json")),
            15,
        );
        daemon_state.polkit_binary = dir.path().join("pkcheck");
        daemon_state.polkit_policy_registered = true;
        let state = Arc::new(daemon_state);
        *state.vault_mgr.quick_unlock_key.write().unwrap() =
            Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[9u8; 64]).unwrap());
        assert!(state.quick_unlock_ready());

        old_runtime.map_or_else(
            || std::env::remove_var("XDG_RUNTIME_DIR"),
            |v| std::env::set_var("XDG_RUNTIME_DIR", v),
        );
        old_config.map_or_else(
            || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
            |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
        );
    }

    #[test]
    fn test_screen_lock_detection_functions_safe() {
        // Ensure detection functions execute safely without panicking
        let _ = is_omarchy_locked();
        let _ = is_screen_locker_running();
        let _ = is_logind_locked_or_sleeping();
        let _ = is_system_or_screen_locked();
    }

    #[test]
    fn test_validate_socket_path_valid_and_symlink_rejection() {
        let dir = tempdir().unwrap();
        let real_socket = dir.path().join("real.sock");
        fs::write(&real_socket, b"").unwrap();

        // Valid socket file owned by current user
        assert!(validate_socket_path(&real_socket).is_ok());

        // Symlink pointing to the real socket must be rejected
        let symlink_socket = dir.path().join("symlink.sock");
        std::os::unix::fs::symlink(&real_socket, &symlink_socket).unwrap();
        let err = validate_socket_path(&symlink_socket);
        assert!(err.is_err());
        assert_eq!(
            err.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn test_validate_socket_path_parent_symlink_rejection() {
        let dir = tempdir().unwrap();
        let real_dir = dir.path().join("real_runtime");
        fs::create_dir_all(&real_dir).unwrap();

        let symlink_dir = dir.path().join("symlink_runtime");
        std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

        let socket_in_symlink_parent = symlink_dir.join("omawarden.sock");
        let err = validate_socket_path(&socket_in_symlink_parent);
        assert!(err.is_err());
        assert_eq!(
            err.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn test_get_runtime_dir_permissions_and_ownership() {
        let _lock = crate::env_lock();
        let runtime_dir = get_runtime_dir().unwrap();
        assert!(runtime_dir.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = fs::metadata(&runtime_dir).unwrap();
            assert_eq!(meta.uid(), unsafe { libc::getuid() });
        }
    }

    #[test]
    fn test_privileged_actions_require_unlocked_vault() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);
        let state = Arc::new(DaemonState::new(storage_mgr, 15));

        let send_req = |req: Value| -> Value {
            let (mut client, server) = UnixStream::pair().unwrap();
            let st = state.clone();
            let handle = std::thread::spawn(move || {
                let _ = handle_client(server, st);
            });
            let payload = format!("{}\n", req);
            client.write_all(payload.as_bytes()).unwrap();
            client.flush().unwrap();

            let mut reader = BufReader::new(client);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            handle.join().unwrap();
            serde_json::from_str(&line).unwrap()
        };

        let privileged_actions = vec![
            json!({ "action": "list" }),
            json!({ "action": "search", "query": "test" }),
            json!({ "action": "get_item", "query": "test" }),
            json!({ "action": "sync" }),
            json!({ "action": "reveal_field", "id": "test", "field": "notes" }),
            json!({ "action": "copy_field", "id": "test", "field": "notes" }),
        ];

        // 1. While locked, all privileged actions fail with locked error
        for req in &privileged_actions {
            let res = send_req(req.clone());
            assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(false));
            assert!(
                res.get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .contains("locked"),
                "Action '{}' should fail when vault is locked",
                req.get("action").unwrap()
            );
        }

        // 2. Unlock vault
        *state.vault_mgr.is_unlocked.write().unwrap() = true;

        // 3. When unlocked, privileged actions proceed without needing any session token
        let list_res = send_req(json!({ "action": "list" }));
        assert!(list_res.is_array(), "List should succeed when unlocked");

        let search_res = send_req(json!({ "action": "search", "query": "test" }));
        assert!(search_res.is_array(), "Search should succeed when unlocked");
    }

    #[test]
    fn test_max_session_lifetime_auto_lock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);
        let state = DaemonState::new(storage_mgr, 15);

        // Vault unlocked 2 hours ago with max lifetime of 1 hour
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        *state.unlocked_at.lock().unwrap() = Some(Instant::now() - Duration::from_secs(7200));
        *state.max_session_lifetime.lock().unwrap() = Duration::from_secs(3600);

        // Keep last_activity brand new (just now) so idle timeout would NOT trigger
        *state.last_activity.lock().unwrap() = Instant::now();

        // check_auto_lock must trigger because max_session_lifetime has elapsed!
        assert!(state.check_auto_lock());
        assert!(!state.vault_mgr.is_unlocked());
        assert!(state.unlocked_at.lock().unwrap().is_none());
    }

    #[test]
    fn test_handle_client_client_context_parsing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);
        let state = Arc::new(DaemonState::new(storage_mgr, 15));
        *state.vault_mgr.is_unlocked.write().unwrap() = true;

        let send_req = |req: Value| -> Value {
            let (mut client, server) = UnixStream::pair().unwrap();
            let st = Arc::clone(&state);
            let handle = std::thread::spawn(move || {
                let _ = handle_client(server, st);
            });
            let payload = format!("{}\n", req);
            client.write_all(payload.as_bytes()).unwrap();
            client.flush().unwrap();

            let mut reader = BufReader::new(client);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            handle.join().unwrap();
            serde_json::from_str(&line).unwrap()
        };

        // 1. Valid client context in sync request (fails with missing session token error, proving sync_with_client was called)
        let res_valid = send_req(json!({
            "action": "sync",
            "client": {
                "name": "Omarchy_Bitwarden",
                "version": "0.11.2"
            }
        }));
        assert_eq!(res_valid.get("ok").and_then(|v| v.as_bool()), Some(false));
        assert!(res_valid.get("error").is_some());

        // 2. Invalid client context with CRLF injection is rejected/filtered
        let res_injection = send_req(json!({
            "action": "sync",
            "client": {
                "name": "evil\r\nHeader: foo",
                "version": "0.11.2"
            }
        }));
        assert_eq!(
            res_injection.get("ok").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert!(res_injection.get("error").is_some());
    }

    #[test]
    fn test_daemon_generate_password_action() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);
        let state = Arc::new(DaemonState::new(storage_mgr, 15));

        let send_req = |req: Value| -> Value {
            let (mut client, server) = UnixStream::pair().unwrap();
            let st = state.clone();
            let handle = std::thread::spawn(move || {
                let _ = handle_client(server, st);
            });
            let payload = format!("{}\n", req);
            client.write_all(payload.as_bytes()).unwrap();
            client.flush().unwrap();

            let mut reader = BufReader::new(client);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            handle.join().unwrap();
            serde_json::from_str(&line).unwrap()
        };

        // 1. Password generation while locked
        let res_pwd = send_req(json!({
            "action": "generate_password",
            "length": 25,
            "uppercase": true,
            "lowercase": true,
            "numbers": true,
            "special": true
        }));
        assert_eq!(res_pwd.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            res_pwd.get("type").and_then(|v| v.as_str()),
            Some("password")
        );
        let pwd_str = res_pwd
            .get("password")
            .and_then(|v| v.as_str())
            .expect("missing password");
        assert_eq!(pwd_str.len(), 25);
        assert!(res_pwd.get("entropy").and_then(|v| v.as_f64()).unwrap() > 100.0);

        // 2. Passphrase generation while locked
        let res_phrase = send_req(json!({
            "action": "generate_password",
            "passphrase": true,
            "words": 5,
            "separator": ".",
            "capitalize": true
        }));
        assert_eq!(res_phrase.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            res_phrase.get("type").and_then(|v| v.as_str()),
            Some("passphrase")
        );
        let phrase_str = res_phrase
            .get("password")
            .and_then(|v| v.as_str())
            .expect("missing passphrase");
        assert_eq!(phrase_str.split('.').count(), 5);
        assert!(res_phrase.get("entropy").and_then(|v| v.as_f64()).unwrap() > 60.0);
    }
}
