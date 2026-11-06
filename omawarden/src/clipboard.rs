//! Wayland clipboard access through `wl-copy`.
//!
//! A sensitive copy with an auto-clear deadline keeps its `wl-copy` process
//! serving in the foreground (`--foreground`). wl-copy exits by itself as soon
//! as another client takes the selection, so a process that is still running
//! at the deadline still owns the offer, and terminating it withdraws exactly
//! that offer: the compositor drops a selection whose source disconnects.
//! The clipboard is never cleared blindly at the deadline, so text the user
//! copied from another application in the meantime is left alone.
//!
//! Supervision has two forms. In a long-lived process (the daemon) a thread
//! owns the `wl-copy` child and terminates it at the deadline; the child is
//! also bound to that thread with `PR_SET_PDEATHSIG`, so the offer cannot
//! outlive the daemon. A short-lived CLI process instead starts a detached
//! worker (`omawarden copy --clear-after <s> --owner-pid <pid>
//! --owner-start-time <ticks>`) that terminates the same process at the
//! deadline after confirming, through its start time, that the PID has not
//! been reused. The worker's argv carries only those numbers; the secret
//! reaches `wl-copy` over a pipe and never appears in any argv.
//!
//! A lock withdraws only the offers this process still serves, through the
//! same ownership rule (`OfferRegistry`); it never clears the clipboard, so
//! text another application copied after the engine's copy survives a lock.
//!
//! `wl-copy` is resolved from fixed, root-owned locations only (like
//! `pkcheck`), never through `PATH`: a same-user process could otherwise
//! plant a program that receives every copied secret.

use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

/// How long a foreground `wl-copy` is given to fail at start-up (no Wayland
/// display, unsupported option) before its offer is treated as served.
pub const FOREGROUND_STARTUP_GRACE: Duration = Duration::from_millis(150);
/// Interval at which the supervising thread checks whether the offer is
/// still owned.
pub const OWNERSHIP_POLL_INTERVAL: Duration = Duration::from_millis(50);
/// How long a terminated `wl-copy` is given to exit after `SIGTERM` before it
/// receives `SIGKILL`.
pub const TERMINATION_GRACE: Duration = Duration::from_millis(500);
/// Upper bound on waiting for the supervising thread to report start-up.
const STARTUP_REPORT_TIMEOUT: Duration = Duration::from_secs(5);

/// The only locations `wl-copy` is taken from. The file must be a regular
/// file owned by root that group and others cannot write.
pub const TRUSTED_WL_COPY_LOCATIONS: &[&str] = &["/usr/bin/wl-copy", "/usr/local/bin/wl-copy"];

/// Resolves `wl-copy` from `TRUSTED_WL_COPY_LOCATIONS`.
pub fn resolve_trusted_wl_copy() -> Option<PathBuf> {
    crate::session_supervision::resolve_trusted_system_program(TRUSTED_WL_COPY_LOCATIONS)
}

#[derive(Debug, Clone)]
pub struct ClipboardManager {
    pub wl_copy_path: String,
    pub detach_worker: bool,
    /// Where supervised offers are recorded while they are served, so a
    /// lock can withdraw them.
    pub offer_registry: Option<Arc<OfferRegistry>>,
}

/// Supervised offers this process is serving: one entry per foreground
/// `wl-copy` from its start until it exits or is withdrawn.
#[derive(Debug, Default)]
pub struct OfferRegistry {
    offers: Mutex<Vec<OfferOwner>>,
}

impl OfferRegistry {
    fn register(&self, owner: OfferOwner) {
        if let Ok(mut offers) = self.offers.lock() {
            offers.push(owner);
        }
    }

    fn deregister(&self, owner: OfferOwner) {
        if let Ok(mut offers) = self.offers.lock() {
            offers.retain(|served| *served != owner);
        }
    }

    /// Offers currently recorded as served.
    pub fn served_offers(&self) -> usize {
        self.offers.lock().map_or(0, |offers| offers.len())
    }

    /// Withdraws every offer whose `wl-copy` is still running (same PID and
    /// start time). An offer another client already replaced has ended by
    /// itself and is left alone, as is the selection that replaced it.
    /// Returns how many offers were withdrawn.
    pub fn withdraw_all(&self) -> usize {
        let owners = self
            .offers
            .lock()
            .map(|offers| offers.clone())
            .unwrap_or_default();
        let withdrawn = owners
            .into_iter()
            .filter(|owner| withdraw_offer_if_still_owned(*owner))
            .count();
        if withdrawn > 0 {
            crate::log_info!(
                "omawarden:clipboard",
                "Withdrew {} clipboard offer(s) this process still owned.",
                withdrawn
            );
        }
        withdrawn
    }
}

/// The trusted `wl-copy`, or an unavailable manager when none is installed
/// in a trusted location.
impl Default for ClipboardManager {
    fn default() -> Self {
        let program = resolve_trusted_wl_copy()
            .map(|path| path.to_string_lossy().to_string())
            .unwrap_or_default();
        Self::new(&program)
    }
}

/// Identity of a running `wl-copy` that serves one of our offers: its PID
/// and its start time in clock ticks since boot (`/proc/<pid>/stat` field
/// 22), which together survive PID reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfferOwner {
    pub pid: u32,
    pub start_time: u64,
}

/// Outcome of starting a foreground `wl-copy`.
enum ServeStart {
    /// Still serving: the offer is owned until it exits or is terminated.
    Serving(OfferOwner),
    /// Exited successfully during the start-up grace (another client already
    /// took the selection); nothing remains to withdraw.
    AlreadyReplaced,
    Failed,
}

impl ClipboardManager {
    /// A manager for the program at `wl_copy_path`, used as given. Only an
    /// absolute path is ever run; a bare name is not looked up in `PATH`.
    pub fn new(wl_copy_path: &str) -> Self {
        Self {
            wl_copy_path: wl_copy_path.to_string(),
            detach_worker: true,
            offer_registry: None,
        }
    }

    /// Records supervised offers in `registry` while they are served.
    pub fn with_offer_registry(mut self, registry: Arc<OfferRegistry>) -> Self {
        self.offer_registry = Some(registry);
        self
    }

    pub fn without_detached_worker(mut self) -> Self {
        self.detach_worker = false;
        self
    }

    /// Whether the program is an absolute path to an executable file.
    pub fn is_available(&self) -> bool {
        Path::new(&self.wl_copy_path).is_absolute() && which::which(&self.wl_copy_path).is_ok()
    }

    pub fn copy(&self, text: &str, sensitive: bool, timeout_seconds: i64) -> bool {
        self.copy_with_duration(
            text,
            sensitive,
            Duration::from_secs(timeout_seconds.max(0) as u64),
        )
    }

    pub fn copy_with_duration(&self, text: &str, sensitive: bool, timeout: Duration) -> bool {
        if !self.is_available() {
            crate::log_warn!(
                "omawarden:clipboard",
                "Wayland clipboard utility '{}' is not available; wl-copy is only used from {}. Please install 'wl-clipboard'.",
                self.wl_copy_path,
                TRUSTED_WL_COPY_LOCATIONS.join(" or ")
            );
            return false;
        }
        let success = if sensitive && !timeout.is_zero() {
            self.copy_with_supervised_offer(text, timeout)
        } else {
            self.copy_with_forking_offer(text, sensitive)
        };
        if success {
            crate::log_info!(
                "omawarden:clipboard",
                "Copied content to clipboard (sensitive: {}, ttl: {:?})",
                sensitive,
                timeout
            );
        }
        success
    }

    /// A copy without a deadline: wl-copy forks to serve the offer and the
    /// foreground process exits once the content is read.
    fn copy_with_forking_offer(&self, text: &str, sensitive: bool) -> bool {
        let mut cmd = Command::new(&self.wl_copy_path);
        if sensitive {
            cmd.arg("--sensitive");
        }
        let mut child = match cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                log_spawn_failure(&self.wl_copy_path, &e);
                return false;
            }
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(text.as_bytes());
        }
        match child.wait() {
            Ok(status) => status.success(),
            Err(e) => {
                crate::log_error!("omawarden:clipboard", "wl-copy process error: {:?}", e);
                false
            }
        }
    }

    /// A sensitive copy with a deadline: the offer is served by a foreground
    /// wl-copy that a supervising thread (and, for a short-lived process, a
    /// detached worker) withdraws at the deadline if it still owns it.
    fn copy_with_supervised_offer(&self, text: &str, timeout: Duration) -> bool {
        let content = Zeroizing::new(text.to_string());
        let program = self.wl_copy_path.clone();
        let supervision = OfferSupervision {
            timeout,
            bind_to_supervisor: !self.detach_worker,
            registry: self.offer_registry.clone(),
        };
        let (report, outcome) = mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("clipboard-offer".into())
            .spawn(move || {
                supervise_offer(&program, content, supervision, report);
            });
        if spawned.is_err() {
            return false;
        }
        match outcome.recv_timeout(STARTUP_REPORT_TIMEOUT) {
            Ok(ServeStart::Serving(owner)) => {
                self.start_detached_withdrawal_worker(timeout, owner);
                true
            }
            Ok(ServeStart::AlreadyReplaced) => true,
            Ok(ServeStart::Failed) | Err(_) => false,
        }
    }

    /// Detached worker process: withdraws the offer at the deadline even when
    /// this process (a CLI invocation) has already exited.
    fn start_detached_withdrawal_worker(&self, timeout: Duration, owner: OfferOwner) {
        if !self.detach_worker || cfg!(test) {
            return;
        }
        let Ok(current_exe) = std::env::current_exe() else {
            return;
        };
        let is_omawarden = current_exe
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|name| name == "omawarden" || name.starts_with("omawarden-"));
        if !is_omawarden {
            return;
        }
        let mut cmd = Command::new(&current_exe);
        cmd.args([
            "copy",
            "--clear-after",
            &timeout.as_secs().max(1).to_string(),
            "--owner-pid",
            &owner.pid.to_string(),
            "--owner-start-time",
            &owner.start_time.to_string(),
        ]);
        cmd.stdin(Stdio::null())
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

    /// Clears the clipboard unconditionally (lock, suspend, explicit
    /// request). A foreground wl-copy that served one of our offers exits on
    /// its own when the selection is replaced by the empty one.
    pub fn clear(&self) -> bool {
        if !self.is_available() {
            return false;
        }
        match Command::new(&self.wl_copy_path).arg("--clear").output() {
            Ok(output) => {
                let success = output.status.success();
                if success {
                    crate::log_info!("omawarden:clipboard", "Clipboard cleared.");
                }
                success
            }
            Err(e) => {
                crate::log_error!("omawarden:clipboard", "Failed to clear clipboard: {:?}", e);
                false
            }
        }
    }
}

fn log_spawn_failure(program: &str, error: &std::io::Error) {
    crate::log_error!(
        "omawarden:clipboard",
        "Failed to spawn {}: {:?}",
        program,
        error
    );
}

/// How one supervised offer is served and where it is recorded.
struct OfferSupervision {
    timeout: Duration,
    bind_to_supervisor: bool,
    registry: Option<Arc<OfferRegistry>>,
}

/// Body of the supervising thread: starts the foreground wl-copy, records a
/// served offer in the registry before reporting (so a lock right after the
/// copy already sees it), and withdraws the offer at the deadline if the
/// process still owns it.
fn supervise_offer(
    program: &str,
    content: Zeroizing<String>,
    supervision: OfferSupervision,
    report: mpsc::Sender<ServeStart>,
) {
    let deadline = Instant::now() + supervision.timeout;
    let Some(mut child) = spawn_foreground_offer(program, &content, supervision.bind_to_supervisor)
    else {
        let _ = report.send(ServeStart::Failed);
        return;
    };
    drop(content);
    let start = await_startup(&mut child);
    let ServeStart::Serving(owner) = start else {
        let _ = report.send(start);
        return;
    };
    let registry = supervision.registry;
    if let Some(registry) = &registry {
        registry.register(owner);
    }
    let _ = report.send(start);
    withdraw_at_deadline(&mut child, deadline);
    if let Some(registry) = &registry {
        registry.deregister(owner);
    }
}

fn spawn_foreground_offer(
    program: &str,
    content: &Zeroizing<String>,
    bind_to_supervisor: bool,
) -> Option<Child> {
    let mut cmd = Command::new(program);
    cmd.args(["--foreground", "--sensitive"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        cmd.pre_exec(move || {
            if bind_to_supervisor {
                // The offer ends with the supervising thread, so it cannot
                // outlive the daemon that is responsible for withdrawing it.
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            } else {
                // Detach from the terminal so a short-lived CLI caller's
                // hangup does not end the offer before the worker does.
                libc::setsid();
            }
            Ok(())
        });
    }
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            log_spawn_failure(program, &e);
            return None;
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(content.as_bytes());
    }
    Some(child)
}

/// Waits up to `FOREGROUND_STARTUP_GRACE` for an early exit, which is either
/// a failure or an offer that was replaced before the grace ended.
fn await_startup(child: &mut Child) -> ServeStart {
    let grace_end = Instant::now() + FOREGROUND_STARTUP_GRACE;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return ServeStart::AlreadyReplaced,
            Ok(Some(_)) | Err(_) => return ServeStart::Failed,
            Ok(None) if Instant::now() >= grace_end => break,
            Ok(None) => std::thread::sleep(OWNERSHIP_POLL_INTERVAL.min(FOREGROUND_STARTUP_GRACE)),
        }
    }
    // An unreadable start time (0) still lets this thread withdraw the
    // offer; only the detached worker, which cannot verify the PID, skips it.
    ServeStart::Serving(OfferOwner {
        pid: child.id(),
        start_time: process_start_time(child.id()).unwrap_or(0),
    })
}

/// Polls until the offer is replaced (wl-copy exits by itself) or the
/// deadline passes, then terminates the process only if it still runs.
fn withdraw_at_deadline(child: &mut Child, deadline: Instant) {
    loop {
        if !matches!(child.try_wait(), Ok(None)) {
            return;
        }
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        std::thread::sleep(OWNERSHIP_POLL_INTERVAL.min(deadline - now));
    }
    signal_process(child.id(), libc::SIGTERM);
    let grace_end = Instant::now() + TERMINATION_GRACE;
    while matches!(child.try_wait(), Ok(None)) {
        if Instant::now() >= grace_end {
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
        std::thread::sleep(OWNERSHIP_POLL_INTERVAL);
    }
    crate::log_info!(
        "omawarden:clipboard",
        "Auto-clear withdrew the clipboard offer it still owned."
    );
}

fn signal_process(pid: u32, signal: libc::c_int) {
    if let Ok(pid) = libc::pid_t::try_from(pid) {
        unsafe {
            libc::kill(pid, signal);
        }
    }
}

/// Start time of a process in clock ticks since boot (`/proc/<pid>/stat`
/// field 22). The command name in field 2 may contain spaces and
/// parentheses, so fields are counted after its closing parenthesis.
pub fn process_start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_start_time(&stat)
}

/// Field 22 of a `/proc/<pid>/stat` line.
fn parse_start_time(stat: &str) -> Option<u64> {
    const START_TIME_INDEX_AFTER_COMMAND: usize = 19;
    let (_, after_command) = stat.rsplit_once(')')?;
    after_command
        .split_whitespace()
        .nth(START_TIME_INDEX_AFTER_COMMAND)?
        .parse()
        .ok()
}

/// Detached-worker withdrawal: terminates `owner` if that exact process (same
/// PID and start time) is still running. A process that has exited, or a
/// reused PID, is left alone. Returns true when a signal was sent.
pub fn withdraw_offer_if_still_owned(owner: OfferOwner) -> bool {
    if owner.start_time == 0 || process_start_time(owner.pid) != Some(owner.start_time) {
        return false;
    }
    signal_process(owner.pid, libc::SIGTERM);
    true
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// A wl-copy stand-in. `--clear` removes the clipboard file. A copy
    /// writes the clipboard file; in `--foreground` mode it then keeps
    /// serving while the clipboard still holds its own content (another
    /// writer, or `--clear`, replaces the selection and ends it, as with the
    /// real wl-copy), and on SIGTERM it removes the clipboard file only if it
    /// still owns it (the compositor drops a disconnected source's offer).
    pub(crate) fn mock_wl_copy(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
        let clip_file = dir.join("clipboard.txt");
        let args_file = dir.join("args.txt");
        let program = dir.join("mock-wl-copy");
        let script = format!(
            r#"#!/bin/sh
CF="{clip}"
AF="{args}"
echo "$*" >> "$AF"
if [ "$1" = "--clear" ]; then
    rm -f "$CF"
    exit 0
fi
OWN="$CF.$$"
cat > "$OWN"
cp "$OWN" "$CF"
case " $* " in
    *" --foreground "*) ;;
    *) rm -f "$OWN"; exit 0 ;;
esac
trap 'if cmp -s "$OWN" "$CF"; then rm -f "$CF"; fi; rm -f "$OWN"; exit 0' TERM
while cmp -s "$OWN" "$CF"; do sleep 0.02; done
rm -f "$OWN"
exit 0
"#,
            clip = clip_file.display(),
            args = args_file.display()
        );
        crate::write_test_executable(&program, script);
        (program, clip_file, args_file)
    }

    pub(crate) fn wait_until(limit: Duration, condition: impl Fn() -> bool) -> bool {
        let end = Instant::now() + limit;
        while Instant::now() < end {
            if condition() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        condition()
    }

    fn manager(program: &Path) -> ClipboardManager {
        ClipboardManager::new(program.to_str().unwrap()).without_detached_worker()
    }

    #[test]
    fn test_mock_clipboard_copy_and_clear() {
        let dir = tempdir().unwrap();
        let (program, clip_file, args_file) = mock_wl_copy(dir.path());
        let mgr = ClipboardManager::new(program.to_str().unwrap());

        assert!(mgr.copy("super_secret_password", true, 0));
        assert_eq!(
            fs::read_to_string(&clip_file).unwrap(),
            "super_secret_password"
        );
        let args = fs::read_to_string(&args_file).unwrap();
        assert!(args.lines().last().unwrap().contains("--sensitive"));

        assert!(mgr.copy("public_username", false, 0));
        assert_eq!(fs::read_to_string(&clip_file).unwrap(), "public_username");
        let args = fs::read_to_string(&args_file).unwrap();
        assert!(!args.lines().last().unwrap().contains("--sensitive"));

        let multiline_report = "### Title\n\n- item 1\n- item 2\n```\nlog 1\n```\n";
        assert!(mgr.copy(multiline_report, false, 0));
        assert_eq!(fs::read_to_string(&clip_file).unwrap(), multiline_report);

        assert!(mgr.clear());
        assert!(!clip_file.exists());
        let args = fs::read_to_string(&args_file).unwrap();
        assert_eq!(args.lines().last().unwrap(), "--clear");
    }

    #[test]
    fn test_non_existent_wl_copy() {
        let mgr = ClipboardManager::new("non_existent_wl_copy_bin_12345");
        assert!(!mgr.copy("text", false, 0));
        assert!(!mgr.clear());
    }

    #[test]
    fn test_wl_copy_is_never_resolved_through_path() {
        let dir = tempdir().unwrap();
        let (program, _clip_file, _args_file) = mock_wl_copy(dir.path());

        // A bare name or relative path would be looked up in PATH (or the
        // working directory) by the process spawner; neither is ever run.
        for name in ["wl-copy", "./wl-copy", "bin/wl-copy"] {
            let mgr = ClipboardManager::new(name);
            assert!(!mgr.is_available(), "{name}");
            assert!(!mgr.copy("text", false, 0), "{name}");
        }
        assert!(
            manager(&program).is_available(),
            "an injected absolute path is used"
        );
        assert!(!ClipboardManager::new("").copy("text", false, 0));

        if let Some(trusted) = resolve_trusted_wl_copy() {
            assert!(TRUSTED_WL_COPY_LOCATIONS.contains(&trusted.to_str().unwrap()));
        }
        assert_eq!(
            crate::session_supervision::resolve_trusted_system_program(&[program
                .to_str()
                .unwrap()]),
            None,
            "a user-owned program is refused even at a fixed path"
        );
    }

    #[test]
    fn test_sensitive_copy_with_deadline_serves_in_the_foreground() {
        let dir = tempdir().unwrap();
        let (program, clip_file, args_file) = mock_wl_copy(dir.path());
        let mgr = manager(&program);

        assert!(mgr.copy_with_duration("transient_secret", true, Duration::from_millis(400)));
        assert_eq!(fs::read_to_string(&clip_file).unwrap(), "transient_secret");
        let args = fs::read_to_string(&args_file).unwrap();
        assert_eq!(args.lines().last().unwrap(), "--foreground --sensitive");
        assert!(
            !args.contains("transient_secret"),
            "the secret never appears in argv"
        );
    }

    #[test]
    fn test_auto_clear_withdraws_an_offer_it_still_owns() {
        let dir = tempdir().unwrap();
        let (program, clip_file, args_file) = mock_wl_copy(dir.path());
        let mgr = manager(&program);

        assert!(mgr.copy_with_duration("transient_secret", true, Duration::from_millis(300)));
        assert_eq!(fs::read_to_string(&clip_file).unwrap(), "transient_secret");
        assert!(
            wait_until(Duration::from_secs(5), || !clip_file.exists()),
            "the offer was not withdrawn at the deadline"
        );
        let args = fs::read_to_string(&args_file).unwrap();
        assert!(
            !args.lines().any(|line| line == "--clear"),
            "withdrawal terminates the owner instead of clearing blindly: {args}"
        );
    }

    #[test]
    fn test_auto_clear_leaves_content_copied_by_another_application() {
        let dir = tempdir().unwrap();
        let (program, clip_file, args_file) = mock_wl_copy(dir.path());
        let mgr = manager(&program);

        let deadline = Duration::from_millis(400);
        let start = Instant::now();
        assert!(mgr.copy_with_duration("transient_secret", true, deadline));
        // Another application takes the selection before the deadline.
        fs::write(&clip_file, "text_from_another_application").unwrap();

        while Instant::now() < start + deadline + Duration::from_millis(600) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            fs::read_to_string(&clip_file).unwrap(),
            "text_from_another_application"
        );
        let args = fs::read_to_string(&args_file).unwrap();
        assert!(!args.lines().any(|line| line == "--clear"), "{args}");
    }

    #[test]
    fn test_later_copy_replaces_and_keeps_its_own_deadline() {
        let dir = tempdir().unwrap();
        let (program, clip_file, _args_file) = mock_wl_copy(dir.path());
        let mgr = manager(&program);

        let first_deadline = Duration::from_millis(400);
        let start = Instant::now();
        assert!(mgr.copy_with_duration("secret_1", true, first_deadline));
        assert!(mgr.copy_with_duration("secret_2", true, Duration::from_millis(3000)));

        while Instant::now() < start + first_deadline + Duration::from_millis(400) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            fs::read_to_string(&clip_file).unwrap(),
            "secret_2",
            "the first deadline must not withdraw the second offer"
        );
        assert!(
            wait_until(Duration::from_secs(6), || !clip_file.exists()),
            "the second offer was not withdrawn at its own deadline"
        );
    }

    #[test]
    fn test_clear_ends_a_pending_offer_and_later_content_survives() {
        let dir = tempdir().unwrap();
        let (program, clip_file, _args_file) = mock_wl_copy(dir.path());
        let mgr = manager(&program);

        assert!(mgr.copy_with_duration("secret_to_cancel", true, Duration::from_millis(400)));
        assert!(mgr.clear());
        assert!(!clip_file.exists());
        fs::write(&clip_file, "unrelated_user_text").unwrap();

        std::thread::sleep(Duration::from_millis(900));
        assert_eq!(
            fs::read_to_string(&clip_file).unwrap(),
            "unrelated_user_text"
        );
    }

    #[test]
    fn test_registry_withdraws_only_offers_still_owned() {
        let dir = tempdir().unwrap();
        let (program, clip_file, args_file) = mock_wl_copy(dir.path());
        let registry = Arc::new(OfferRegistry::default());
        let mgr = manager(&program).with_offer_registry(Arc::clone(&registry));

        assert!(mgr.copy_with_duration("owned_secret", true, Duration::from_secs(30)));
        assert_eq!(registry.served_offers(), 1);
        assert_eq!(registry.withdraw_all(), 1);
        assert!(
            wait_until(Duration::from_secs(5), || !clip_file.exists()),
            "the owned offer was withdrawn"
        );
        assert!(wait_until(Duration::from_secs(5), || registry
            .served_offers()
            == 0));

        assert!(mgr.copy_with_duration("replaced_secret", true, Duration::from_secs(30)));
        fs::write(&clip_file, "text_from_another_application").unwrap();
        assert!(
            wait_until(Duration::from_secs(5), || registry.served_offers() == 0),
            "a replaced offer ends by itself"
        );
        assert_eq!(registry.withdraw_all(), 0);
        assert_eq!(
            fs::read_to_string(&clip_file).unwrap(),
            "text_from_another_application"
        );
        let args = fs::read_to_string(&args_file).unwrap();
        assert!(!args.lines().any(|line| line == "--clear"), "{args}");
    }

    #[test]
    fn test_parse_start_time_counts_fields_after_the_command_name() {
        let stat = "4242 (wl copy (x)) S 1 4242 4242 0 -1 4194560 120 0 0 0 1 2 0 0 20 0 1 0 987654 1000 200";
        assert_eq!(parse_start_time(stat), Some(987654));
        assert_eq!(parse_start_time("4242 (short) S 1"), None);
        assert_eq!(parse_start_time("no command field"), None);
    }

    #[test]
    fn test_worker_withdrawal_refuses_a_reused_process_identifier() {
        let mut sleeper = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = sleeper.id();
        let start_time = process_start_time(pid).expect("own child is readable");

        let stale = OfferOwner {
            pid,
            start_time: start_time + 1,
        };
        assert!(!withdraw_offer_if_still_owned(stale));
        assert!(
            matches!(sleeper.try_wait(), Ok(None)),
            "a mismatch sends no signal"
        );

        assert!(withdraw_offer_if_still_owned(OfferOwner {
            pid,
            start_time
        }));
        let status = sleeper.wait().unwrap();
        assert!(!status.success(), "the owned process was terminated");
    }
}
