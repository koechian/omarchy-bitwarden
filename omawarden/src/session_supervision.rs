//! Lock triggers that come from the operating system rather than from a
//! client (ADR 0027): suspend, the end of the graphical login session, and
//! termination signals.
//!
//! * **Suspend.** While key material is resident the daemon holds a
//!   systemd-logind *delay* inhibitor for `sleep` (`systemd-inhibit
//!   --what=sleep --mode=delay`). logind then announces `PrepareForSleep(true)`
//!   and waits up to `InhibitDelayMaxSec` for delay inhibitors to be
//!   released. A `dbus-monitor` child delivers that signal to the daemon as
//!   it happens; the daemon hard-locks and releases the inhibitor, and the
//!   machine sleeps with no key in memory. No root is required.
//! * **Session end.** The daemon remembers the logind session
//!   (`XDG_SESSION_ID`) and the Wayland socket it was started under. When
//!   logind reports the session closing or gone, or the compositor's socket
//!   disappears, the daemon hard-locks and exits.
//! * **Termination signals.** SIGTERM, SIGINT and SIGHUP hard-lock before
//!   exit instead of terminating with keys in memory.

use std::io::{self, BufRead, BufReader};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// `--who` reported to logind for the inhibitor.
pub const SLEEP_INHIBITOR_WHO: &str = "omawarden";
/// `--why` reported to logind for the inhibitor.
pub const SLEEP_INHIBITOR_WHY: &str = "Lock the password vault before the system sleeps";
/// D-Bus match rule for logind's PrepareForSleep signal.
pub const PREPARE_FOR_SLEEP_MATCH_RULE: &str = "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Manager',member='PrepareForSleep'";
/// How long releasing the inhibitor may take before its process is killed.
/// Far below logind's default `InhibitDelayMaxSec` of 5 seconds.
pub const INHIBITOR_RELEASE_TIMEOUT: Duration = Duration::from_millis(500);
/// logind session states that mean the login session is over. `closing` is
/// reported after logout while processes of the session remain.
pub const ENDED_SESSION_STATES: &[&str] = &["closing"];

/// Resolves a system program from fixed locations only, requiring a regular
/// file owned by root that group and others cannot write. A PATH lookup
/// would let a same-user process substitute the program.
pub fn resolve_trusted_system_program(candidates: &[&str]) -> Option<PathBuf> {
    candidates.iter().map(Path::new).find_map(|path| {
        let metadata = std::fs::metadata(path).ok()?;
        let trusted = metadata.file_type().is_file()
            && metadata.uid() == 0
            && metadata.permissions().mode() & 0o022 == 0;
        trusted.then(|| path.to_path_buf())
    })
}

/// External programs the supervision uses. Absent programs disable the
/// corresponding mechanism; the BOOTTIME drift watchdog remains as the
/// suspend fallback.
#[derive(Debug, Clone, Default)]
pub struct SupervisionPrograms {
    pub systemd_inhibit: Option<PathBuf>,
    /// Process run under the inhibitor; it exits when its stdin closes.
    pub inhibitor_holder: Option<PathBuf>,
    pub dbus_monitor: Option<PathBuf>,
    pub loginctl: Option<PathBuf>,
}

impl SupervisionPrograms {
    /// Resolves the programs from trusted system locations. Test builds
    /// resolve none, so unit tests never take inhibitors or watch the bus.
    pub fn resolve() -> Self {
        if cfg!(test) {
            return Self::default();
        }
        Self {
            systemd_inhibit: resolve_trusted_system_program(&["/usr/bin/systemd-inhibit"]),
            inhibitor_holder: resolve_trusted_system_program(&["/usr/bin/cat", "/bin/cat"]),
            dbus_monitor: resolve_trusted_system_program(&["/usr/bin/dbus-monitor"]),
            loginctl: resolve_trusted_system_program(&["/usr/bin/loginctl"]),
        }
    }
}

/// A held logind delay inhibitor for sleep. Dropping it releases it.
#[derive(Debug)]
pub struct SleepInhibitor {
    child: Child,
    holder_input: Option<ChildStdin>,
}

impl SleepInhibitor {
    /// Takes the inhibitor by running `systemd-inhibit` around a holder
    /// process that waits on its stdin.
    pub fn acquire(systemd_inhibit: &Path, holder: &Path) -> io::Result<Self> {
        let mut child = Command::new(systemd_inhibit)
            .arg("--what=sleep")
            .arg("--mode=delay")
            .arg(format!("--who={SLEEP_INHIBITOR_WHO}"))
            .arg(format!("--why={SLEEP_INHIBITOR_WHY}"))
            .arg(holder)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let holder_input = child.stdin.take();
        Ok(Self {
            child,
            holder_input,
        })
    }

    /// Whether the inhibitor process is still running.
    pub fn is_held(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn release_now(&mut self) {
        drop(self.holder_input.take());
        let deadline = Instant::now() + INHIBITOR_RELEASE_TIMEOUT;
        while Instant::now() < deadline {
            if !matches!(self.child.try_wait(), Ok(None)) {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for SleepInhibitor {
    fn drop(&mut self) {
        self.release_now();
    }
}

/// Makes the child receive SIGKILL when the thread that spawned it exits,
/// so a monitor never outlives the daemon (`std::process::exit` does not
/// reap children). The daemon spawns from its long-lived watchdog thread.
fn terminate_with_parent(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    unsafe {
        command.pre_exec(|| {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Parses `dbus-monitor` output for PrepareForSleep. dbus-monitor prints a
/// header line naming the member, then one line per argument.
#[derive(Debug, Default)]
pub struct SleepSignalParser {
    expecting_argument: bool,
}

impl SleepSignalParser {
    /// Returns `Some(true)` when sleep begins, `Some(false)` on resume.
    pub fn feed(&mut self, line: &str) -> Option<bool> {
        if line.starts_with("signal ") {
            self.expecting_argument = line.contains("member=PrepareForSleep");
            return None;
        }
        if !self.expecting_argument {
            return None;
        }
        self.expecting_argument = false;
        match line.trim() {
            "boolean true" => Some(true),
            "boolean false" => Some(false),
            _ => None,
        }
    }
}

/// Starts `dbus-monitor` for PrepareForSleep and forwards each signal to
/// `on_signal` from a reader thread. `on_exit` runs when the monitor ends.
pub fn spawn_sleep_monitor<S, E>(dbus_monitor: &Path, on_signal: S, on_exit: E) -> io::Result<()>
where
    S: Fn(bool) + Send + 'static,
    E: FnOnce() + Send + 'static,
{
    let mut command = Command::new(dbus_monitor);
    command
        .arg("--system")
        .arg(PREPARE_FOR_SLEEP_MATCH_RULE)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    terminate_with_parent(&mut command);
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("dbus-monitor has no stdout"))?;
    std::thread::Builder::new()
        .name("sleep-monitor".into())
        .spawn(move || {
            let mut parser = SleepSignalParser::default();
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Some(sleeping) = parser.feed(&line) {
                    on_signal(sleeping);
                }
            }
            let _ = child.kill();
            let _ = child.wait();
            on_exit();
        })?;
    Ok(())
}

/// What logind says about the bound session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogindSessionState {
    Present(String),
    Gone,
    /// The query failed for another reason; never treated as an end.
    Unknown,
}

/// The login session the daemon belongs to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionBinding {
    pub logind_session_id: Option<String>,
    pub wayland_socket: Option<PathBuf>,
}

fn is_valid_session_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn wayland_socket_path(display: &str, runtime_dir: Option<&Path>) -> Option<PathBuf> {
    let display_path = Path::new(display);
    if display_path.is_absolute() {
        return Some(display_path.to_path_buf());
    }
    runtime_dir.map(|dir| dir.join(display))
}

impl SessionBinding {
    /// Binds to the session described by `XDG_SESSION_ID` and
    /// `WAYLAND_DISPLAY`. The Wayland socket is only bound when it exists
    /// now, so a daemon started outside a graphical session is not ended by
    /// a socket that never existed.
    pub fn from_environment(runtime_dir: Option<&Path>) -> Self {
        let logind_session_id = std::env::var("XDG_SESSION_ID")
            .ok()
            .filter(|id| is_valid_session_id(id));
        let wayland_socket = std::env::var("WAYLAND_DISPLAY")
            .ok()
            .filter(|display| !display.is_empty())
            .and_then(|display| wayland_socket_path(&display, runtime_dir))
            .filter(|path| path.exists());
        Self {
            logind_session_id,
            wayland_socket,
        }
    }

    pub fn is_bound(&self) -> bool {
        self.logind_session_id.is_some() || self.wayland_socket.is_some()
    }
}

/// Asks logind for the session's `State` through `loginctl`.
pub fn query_logind_session_state(loginctl: &Path, session_id: &str) -> LogindSessionState {
    let output = Command::new(loginctl)
        .args(["show-session", session_id, "--property=State", "--value"])
        .stdin(Stdio::null())
        .output();
    let Ok(output) = output else {
        return LogindSessionState::Unknown;
    };
    if output.status.success() {
        let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return LogindSessionState::Present(state);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("No session") {
        return LogindSessionState::Gone;
    }
    LogindSessionState::Unknown
}

/// Pure decision: the reason the session has ended, if it has.
pub fn session_end_reason(
    logind_state: &LogindSessionState,
    wayland_socket_bound: bool,
    wayland_socket_exists: bool,
) -> Option<&'static str> {
    match logind_state {
        LogindSessionState::Gone => return Some("the logind session no longer exists"),
        LogindSessionState::Present(state) if ENDED_SESSION_STATES.contains(&state.as_str()) => {
            return Some("the logind session is closing")
        }
        _ => {}
    }
    if wayland_socket_bound && !wayland_socket_exists {
        return Some("the Wayland compositor socket was removed");
    }
    None
}

/// Probes the bound session and reports why it ended, if it did.
pub fn detect_session_end(
    binding: &SessionBinding,
    loginctl: Option<&Path>,
) -> Option<&'static str> {
    let logind_state = match (binding.logind_session_id.as_deref(), loginctl) {
        (Some(id), Some(program)) => query_logind_session_state(program, id),
        _ => LogindSessionState::Unknown,
    };
    let socket_exists = binding.wayland_socket.as_ref().is_some_and(|p| p.exists());
    session_end_reason(
        &logind_state,
        binding.wayland_socket.is_some(),
        socket_exists,
    )
}

/// Write end of the self-pipe the termination signal handler writes to.
static TERMINATION_PIPE_WRITE: AtomicI32 = AtomicI32::new(-1);

extern "C" fn record_termination_signal(_signal: libc::c_int) {
    let fd = TERMINATION_PIPE_WRITE.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = 1u8;
        // write(2) is async-signal-safe; a full pipe means one is pending.
        unsafe {
            libc::write(fd, &byte as *const u8 as *const libc::c_void, 1);
        }
    }
}

fn create_termination_pipe() -> io::Result<(libc::c_int, libc::c_int)> {
    let mut fds = [0 as libc::c_int; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

fn install_signal_handler(signal: libc::c_int) -> io::Result<()> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = record_termination_signal as *const () as libc::sighandler_t;
    action.sa_flags = libc::SA_RESTART;
    unsafe { libc::sigemptyset(&mut action.sa_mask) };
    if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn wait_for_termination_byte(read_fd: libc::c_int) {
    let mut byte = 0u8;
    loop {
        let read = unsafe { libc::read(read_fd, &mut byte as *mut u8 as *mut libc::c_void, 1) };
        if read == 1 {
            return;
        }
        if read < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return;
    }
}

/// Runs `on_terminate` on a dedicated thread when SIGTERM, SIGINT or SIGHUP
/// arrives. Children start with default signal dispositions (handlers do not
/// survive exec), so their behavior is unchanged.
pub fn install_termination_handler<T>(state: Arc<T>, on_terminate: fn(&T)) -> io::Result<()>
where
    T: Send + Sync + 'static,
{
    let (read_fd, write_fd) = create_termination_pipe()?;
    TERMINATION_PIPE_WRITE.store(write_fd, Ordering::SeqCst);
    for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        install_signal_handler(signal)?;
    }
    std::thread::Builder::new()
        .name("termination-signals".into())
        .spawn(move || {
            wait_for_termination_byte(read_fd);
            on_terminate(&state);
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sleep_signal_parser_reads_dbus_monitor_output() {
        let transcript = [
            "signal time=1.0 sender=org.freedesktop.DBus -> destination=:1.9 serial=1 path=/org/freedesktop/DBus; interface=org.freedesktop.DBus; member=NameAcquired",
            "   string \":1.9\"",
            "signal time=2.0 sender=:1.7 -> destination=(null destination) serial=9 path=/org/freedesktop/login1; interface=org.freedesktop.login1.Manager; member=PrepareForSleep",
            "   boolean true",
            "signal time=3.0 sender=:1.7 -> destination=(null destination) serial=10 path=/org/freedesktop/login1; interface=org.freedesktop.login1.Manager; member=PrepareForSleep",
            "   boolean false",
            "signal time=4.0 sender=:1.7 -> destination=(null destination) serial=11 path=/org/freedesktop/login1; interface=org.freedesktop.login1.Manager; member=PrepareForShutdown",
            "   boolean true",
        ];
        let mut parser = SleepSignalParser::default();
        let events: Vec<bool> = transcript.iter().filter_map(|l| parser.feed(l)).collect();
        assert_eq!(
            events,
            vec![true, false],
            "only PrepareForSleep arguments count"
        );
    }

    #[test]
    fn test_session_end_reason_decisions() {
        let active = LogindSessionState::Present("active".into());
        let online = LogindSessionState::Present("online".into());
        let closing = LogindSessionState::Present("closing".into());
        assert_eq!(session_end_reason(&active, true, true), None);
        assert_eq!(session_end_reason(&online, false, false), None, "VT switch");
        assert!(session_end_reason(&closing, true, true).is_some());
        assert!(session_end_reason(&LogindSessionState::Gone, false, false).is_some());
        assert_eq!(
            session_end_reason(&LogindSessionState::Unknown, false, false),
            None,
            "a failed query is never an end"
        );
        assert!(
            session_end_reason(&active, true, false).is_some(),
            "socket removed"
        );
        assert_eq!(
            session_end_reason(&active, false, false),
            None,
            "no socket bound"
        );
    }

    #[test]
    fn test_session_binding_validation_helpers() {
        assert!(is_valid_session_id("1"));
        assert!(is_valid_session_id("c2"));
        assert!(!is_valid_session_id(""));
        assert!(!is_valid_session_id("1; rm -rf"));
        assert!(!is_valid_session_id("../1"));
        let runtime = Path::new("/run/user/1000");
        assert_eq!(
            wayland_socket_path("wayland-1", Some(runtime)),
            Some(PathBuf::from("/run/user/1000/wayland-1"))
        );
        assert_eq!(
            wayland_socket_path("/custom/socket", None),
            Some(PathBuf::from("/custom/socket"))
        );
        assert_eq!(wayland_socket_path("wayland-1", None), None);
    }

    #[test]
    fn test_detect_session_end_reports_removed_wayland_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("wayland-fixture");
        std::fs::write(&socket, b"").unwrap();
        let binding = SessionBinding {
            logind_session_id: None,
            wayland_socket: Some(socket.clone()),
        };
        assert_eq!(detect_session_end(&binding, None), None);
        std::fs::remove_file(&socket).unwrap();
        assert!(detect_session_end(&binding, None).is_some());
    }

    #[test]
    fn test_query_logind_session_state_with_fixture_program() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("loginctl-active");
        crate::write_test_executable(&active, "#!/bin/sh\necho active\n");
        assert_eq!(
            query_logind_session_state(&active, "1"),
            LogindSessionState::Present("active".into())
        );
        let gone = dir.path().join("loginctl-gone");
        crate::write_test_executable(
            &gone,
            "#!/bin/sh\necho \"Failed to get path for session '1': No session '1' known\" >&2\nexit 1\n",
        );
        assert_eq!(
            query_logind_session_state(&gone, "1"),
            LogindSessionState::Gone
        );
        let broken = dir.path().join("loginctl-broken");
        crate::write_test_executable(&broken, "#!/bin/sh\necho 'bus error' >&2\nexit 1\n");
        assert_eq!(
            query_logind_session_state(&broken, "1"),
            LogindSessionState::Unknown
        );
    }

    #[test]
    fn test_sleep_inhibitor_holds_until_released() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("arguments");
        let program = dir.path().join("systemd-inhibit-fixture");
        crate::write_test_executable(
            &program,
            format!(
                "#!/bin/sh\necho \"$@\" > '{}'\nshift 4\nexec \"$@\"\n",
                marker.display()
            ),
        );
        let mut inhibitor = SleepInhibitor::acquire(&program, Path::new("/bin/cat")).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(inhibitor.is_held());
        let arguments = std::fs::read_to_string(&marker).unwrap();
        assert!(
            arguments.contains("--what=sleep --mode=delay --who=omawarden"),
            "{arguments}"
        );
        let started = Instant::now();
        drop(inhibitor);
        assert!(started.elapsed() < INHIBITOR_RELEASE_TIMEOUT + Duration::from_millis(200));
    }

    #[test]
    fn test_resolve_trusted_system_program_rejects_user_owned_files() {
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("fixture-program");
        crate::write_test_executable(&program, "#!/bin/sh\n");
        let candidate = program.to_string_lossy().to_string();
        assert_eq!(resolve_trusted_system_program(&[candidate.as_str()]), None);
        assert_eq!(
            resolve_trusted_system_program(&["/nonexistent/program"]),
            None
        );
    }
}
