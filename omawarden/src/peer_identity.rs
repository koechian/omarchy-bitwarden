//! Caller verification for the daemon socket, in both directions (ADR 0027).
//!
//! The kernel reports the peer's pid and uid through `SO_PEERCRED`. The uid
//! must match ours. The executable is then compared through
//! `/proc/<pid>/exe`, which the kernel only exposes for a *dumpable* peer:
//! omawarden processes mark themselves non-dumpable (ADR 0009), so for a
//! genuine peer the link is concealed, while an ordinary dumpable process
//! (`socat`, a shell, a scripting runtime) exposes it and is rejected when it
//! is not this executable. See ADR 0027 for why a concealed link cannot be
//! verified further without root.

use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

/// Suffix the kernel appends to `/proc/<pid>/exe` once the executable file
/// has been unlinked, typically by a package upgrade replacing the binary.
pub const DELETED_EXECUTABLE_SUFFIX: &str = " (deleted)";

/// Credentials of the process at the other end of a Unix stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
}

/// What `/proc/<pid>/exe` revealed about a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerExecutable {
    /// The link was readable and names this executable.
    Visible(PathBuf),
    /// The kernel refused the read: the peer is non-dumpable.
    Concealed,
    /// The process is gone or `/proc` is unavailable.
    Unavailable,
}

#[cfg(target_os = "linux")]
pub fn read_peer_credentials(stream: &UnixStream) -> io::Result<PeerCredentials> {
    use std::os::unix::io::AsRawFd;
    let mut ucred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut libc::ucred as *mut libc::c_void,
            &mut length,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCredentials {
        pid: ucred.pid,
        uid: ucred.uid,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn read_peer_credentials(_stream: &UnixStream) -> io::Result<PeerCredentials> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "peer credentials are only available on Linux",
    ))
}

/// Removes the kernel's " (deleted)" marker so an upgraded binary still
/// compares equal to the path it was started from.
pub fn normalize_executable_path(raw: &Path) -> PathBuf {
    let bytes = raw.as_os_str().as_bytes();
    let trimmed = bytes
        .strip_suffix(DELETED_EXECUTABLE_SUFFIX.as_bytes())
        .unwrap_or(bytes);
    let path = PathBuf::from(OsStr::from_bytes(trimmed));
    std::fs::canonicalize(&path).unwrap_or(path)
}

/// Whether two executable links name the same program, after normalizing
/// both (upgrade marker removed, symlinks resolved where the file exists).
pub fn executables_match(peer: &Path, own: &Path) -> bool {
    normalize_executable_path(peer) == normalize_executable_path(own)
}

/// The executable of the current process, normalized.
pub fn own_executable() -> io::Result<PathBuf> {
    std::fs::read_link("/proc/self/exe")
        .or_else(|_| std::env::current_exe())
        .map(|path| normalize_executable_path(&path))
}

/// Reads `/proc/<pid>/exe` and classifies the result.
pub fn inspect_peer_executable(pid: i32) -> PeerExecutable {
    match std::fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(path) => PeerExecutable::Visible(path),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => PeerExecutable::Concealed,
        Err(_) => PeerExecutable::Unavailable,
    }
}

fn denied(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

/// Accepts a peer whose executable is this one, or whose executable the
/// kernel conceals because it is non-dumpable. Rejects a visible foreign
/// executable and a peer that has already exited.
pub fn evaluate_peer_executable(executable: &PeerExecutable, own: &Path) -> io::Result<()> {
    match executable {
        PeerExecutable::Visible(path) if executables_match(path, own) => Ok(()),
        PeerExecutable::Visible(path) => Err(denied(format!(
            "peer executable '{}' is not '{}'",
            path.display(),
            own.display()
        ))),
        PeerExecutable::Concealed => Ok(()),
        PeerExecutable::Unavailable => {
            Err(denied("peer process is no longer available".to_string()))
        }
    }
}

fn verify_uid(credentials: &PeerCredentials) -> io::Result<()> {
    let current_uid = unsafe { libc::getuid() };
    if credentials.uid == current_uid {
        return Ok(());
    }
    Err(denied(format!(
        "Peer UID mismatch: expected {}, got {}",
        current_uid, credentials.uid
    )))
}

/// Same-user check only (kept for callers that need nothing more).
pub fn verify_peer_uid(stream: &UnixStream) -> io::Result<()> {
    verify_uid(&read_peer_credentials(stream)?)
}

/// Full caller verification: same uid and the same executable.
pub fn verify_peer(stream: &UnixStream, own: &Path) -> io::Result<()> {
    let credentials = read_peer_credentials(stream)?;
    verify_uid(&credentials)?;
    evaluate_peer_executable(&inspect_peer_executable(credentials.pid), own)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executables_match_tolerates_the_deleted_marker() {
        let own = Path::new("/usr/bin/omawarden-fixture-path");
        assert!(executables_match(own, own));
        assert!(executables_match(
            Path::new("/usr/bin/omawarden-fixture-path (deleted)"),
            own
        ));
        assert!(executables_match(
            own,
            Path::new("/usr/bin/omawarden-fixture-path (deleted)")
        ));
    }

    #[test]
    fn test_executables_match_rejects_a_foreign_executable() {
        let own = Path::new("/usr/bin/omawarden-fixture-path");
        for foreign in [
            "/usr/bin/socat",
            "/usr/bin/python3",
            "/tmp/omawarden-fixture-path",
            "/usr/bin/omawarden-fixture-path-evil",
            "/usr/bin/omawarden-fixture-path (deleted) ",
        ] {
            assert!(
                !executables_match(Path::new(foreign), own),
                "{foreign} must not match"
            );
        }
    }

    #[test]
    fn test_executables_match_resolves_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("omawarden");
        std::fs::write(&real, b"").unwrap();
        let link = dir.path().join("omawarden-link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(executables_match(&link, &real));
    }

    #[test]
    fn test_evaluate_peer_executable_policy() {
        let own = Path::new("/usr/bin/omawarden-fixture-path");
        assert!(evaluate_peer_executable(&PeerExecutable::Visible(own.into()), own).is_ok());
        let foreign = evaluate_peer_executable(
            &PeerExecutable::Visible(PathBuf::from("/usr/bin/socat")),
            own,
        )
        .unwrap_err();
        assert_eq!(foreign.kind(), io::ErrorKind::PermissionDenied);
        assert!(foreign.to_string().contains("/usr/bin/socat"));
        assert!(evaluate_peer_executable(&PeerExecutable::Concealed, own).is_ok());
        assert!(evaluate_peer_executable(&PeerExecutable::Unavailable, own).is_err());
    }

    #[test]
    fn test_verify_peer_accepts_this_process_and_rejects_another_executable() {
        let (client, server) = UnixStream::pair().unwrap();
        let own = own_executable().unwrap();
        assert!(verify_peer(&server, &own).is_ok());
        assert!(verify_peer(&client, &own).is_ok());
        let other = Path::new("/usr/bin/omawarden-other-installation");
        assert!(verify_peer(&server, other).is_err());
        let credentials = read_peer_credentials(&server).unwrap();
        assert_eq!(credentials.pid, std::process::id() as i32);
    }

    #[test]
    fn test_inspect_peer_executable_for_missing_process() {
        assert_eq!(
            inspect_peer_executable(i32::MAX),
            PeerExecutable::Unavailable
        );
    }
}
