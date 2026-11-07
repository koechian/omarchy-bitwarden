//! Bounded request reading and connection admission for the daemon socket
//! (ADR 0027): one JSON line per connection, at most `MAX_REQUEST_BYTES`,
//! delivered in full within `REQUEST_READ_TIMEOUT`, with at most
//! `MAX_CONCURRENT_CONNECTIONS` connections served at once.

use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

/// Largest accepted request line, newline excluded.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// How long a client may take to deliver its whole request line. This is a
/// total deadline, not a per-read timeout: a client trickling one byte at a
/// time still loses its connection slot when it runs out.
pub const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the daemon waits for a client to accept its response.
pub const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// Connections served concurrently; further connections are refused.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 16;

/// Why a request line could not be read.
#[derive(Debug)]
pub enum RequestReadError {
    TooLarge,
    TimedOut,
    Io(io::Error),
}

impl RequestReadError {
    pub fn message(&self) -> String {
        match self {
            RequestReadError::TooLarge => {
                format!("Request exceeds the {MAX_REQUEST_BYTES}-byte limit")
            }
            RequestReadError::TimedOut => format!(
                "Request was not received within {} seconds",
                REQUEST_READ_TIMEOUT.as_secs()
            ),
            RequestReadError::Io(error) => format!("Request could not be read: {error}"),
        }
    }
}

fn classify_read_error(error: io::Error) -> RequestReadError {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => RequestReadError::TimedOut,
        _ => RequestReadError::Io(error),
    }
}

/// A request source whose next read can be bounded in time.
pub trait TimedRead: Read {
    /// Limits the next `read` to `timeout` (never zero).
    fn limit_next_read(&mut self, timeout: Duration) -> io::Result<()>;
}

impl TimedRead for &UnixStream {
    fn limit_next_read(&mut self, timeout: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(timeout))
    }
}

#[cfg(test)]
impl TimedRead for io::Cursor<Vec<u8>> {
    fn limit_next_read(&mut self, _timeout: Duration) -> io::Result<()> {
        Ok(())
    }
}

/// Reads one newline-terminated request of at most `MAX_REQUEST_BYTES`,
/// delivered in full within `REQUEST_READ_TIMEOUT`.
pub fn read_bounded_request<S: TimedRead>(
    source: S,
) -> Result<Zeroizing<Vec<u8>>, RequestReadError> {
    read_bounded_request_within(source, REQUEST_READ_TIMEOUT)
}

/// Reads one request that must arrive in full within `allowance`. Bytes go
/// straight into one zeroizing buffer allocated at its final size, so no
/// intermediate buffer or reallocation leaves a copy of an unlock request
/// (which carries the master password) behind. A line without a newline
/// before end of stream is accepted as the request.
pub fn read_bounded_request_within<S: TimedRead>(
    mut source: S,
    allowance: Duration,
) -> Result<Zeroizing<Vec<u8>>, RequestReadError> {
    let deadline = Instant::now() + allowance;
    let mut buffer = Zeroizing::new(vec![0u8; MAX_REQUEST_BYTES + 1]);
    let mut filled = 0;
    loop {
        if filled == buffer.len() {
            return Err(RequestReadError::TooLarge);
        }
        let read = read_before_deadline(&mut source, &mut buffer[filled..], deadline)?;
        if read == 0 {
            break;
        }
        if let Some(newline) = buffer[filled..filled + read]
            .iter()
            .position(|b| *b == b'\n')
        {
            filled += newline;
            break;
        }
        filled += read;
    }
    // Truncation keeps the capacity, and the whole capacity is zeroized on
    // drop, including anything read past the newline.
    buffer.truncate(filled);
    Ok(buffer)
}

/// One read that may not end later than `deadline`.
fn read_before_deadline<S: TimedRead>(
    source: &mut S,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<usize, RequestReadError> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(RequestReadError::TimedOut);
        }
        source
            .limit_next_read(remaining)
            .map_err(RequestReadError::Io)?;
        match source.read(buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => return result.map_err(classify_read_error),
        }
    }
}

/// Counts connections in service. A slot is held by its `ConnectionPermit`
/// and released when the permit is dropped.
#[derive(Debug, Default)]
pub struct ConnectionLimiter {
    active: Arc<AtomicUsize>,
}

/// Proof that a connection was admitted; dropping it frees the slot.
#[derive(Debug)]
pub struct ConnectionPermit {
    active: Arc<AtomicUsize>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

impl ConnectionLimiter {
    /// Admits a connection when fewer than `MAX_CONCURRENT_CONNECTIONS` are
    /// in service.
    pub fn try_admit(&self) -> Option<ConnectionPermit> {
        let admitted = self
            .active
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |active| {
                (active < MAX_CONCURRENT_CONNECTIONS).then_some(active + 1)
            })
            .is_ok();
        admitted.then(|| ConnectionPermit {
            active: Arc::clone(&self.active),
        })
    }

    pub fn active(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
}

/// The response sent to a connection refused for capacity.
pub fn capacity_refusal() -> serde_json::Value {
    serde_json::json!({
        "ok": false,
        "error": format!(
            "Too many concurrent connections (limit {MAX_CONCURRENT_CONNECTIONS}); try again."
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_bounded_request_accepts_a_line_at_the_limit() {
        let mut payload = vec![b'a'; MAX_REQUEST_BYTES];
        payload.push(b'\n');
        payload.extend_from_slice(b"ignored second line\n");
        let line = read_bounded_request(Cursor::new(payload)).unwrap();
        assert_eq!(line.len(), MAX_REQUEST_BYTES);
    }

    #[test]
    fn test_read_bounded_request_rejects_an_oversized_line() {
        let payload = vec![b'a'; MAX_REQUEST_BYTES + 10];
        assert!(matches!(
            read_bounded_request(Cursor::new(payload)),
            Err(RequestReadError::TooLarge)
        ));
        let mut with_newline = vec![b'a'; MAX_REQUEST_BYTES + 1];
        with_newline.push(b'\n');
        assert!(matches!(
            read_bounded_request(Cursor::new(with_newline)),
            Err(RequestReadError::TooLarge)
        ));
    }

    #[test]
    fn test_read_bounded_request_times_out_on_a_silent_client() {
        let (client, server) = UnixStream::pair().unwrap();
        let result = read_bounded_request_within(&server, Duration::from_millis(50));
        assert!(
            matches!(result, Err(RequestReadError::TimedOut)),
            "{result:?}"
        );
        drop(client);
    }

    #[test]
    fn test_read_bounded_request_enforces_a_total_deadline_on_a_trickling_client() {
        use std::io::Write;
        let (mut client, server) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            // One byte every 40 ms: each read succeeds well inside any
            // per-read timeout, but the line is never completed in time.
            for _ in 0..50 {
                if client.write_all(b"a").is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(40));
            }
        });
        let allowance = Duration::from_millis(200);
        let started = Instant::now();
        let result = read_bounded_request_within(&server, allowance);
        let elapsed = started.elapsed();
        assert!(
            matches!(result, Err(RequestReadError::TimedOut)),
            "{result:?}"
        );
        assert!(
            elapsed < allowance + Duration::from_millis(150),
            "the deadline covers the whole request, not each read: {elapsed:?}"
        );
        drop(server);
        writer.join().unwrap();
    }

    #[test]
    fn test_read_bounded_request_assembles_a_line_from_several_reads() {
        use std::io::Write;
        let (mut client, server) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            for part in [&b"{\"action\":"[..], b"\"ping\"}", b"\nignored"] {
                client.write_all(part).unwrap();
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        let line = read_bounded_request(&server).unwrap();
        assert_eq!(line.as_slice(), b"{\"action\":\"ping\"}");
        assert!(
            line.capacity() > MAX_REQUEST_BYTES,
            "the request stays in the single buffer allocated up front"
        );
        writer.join().unwrap();
    }

    #[test]
    fn test_read_bounded_request_accepts_a_line_without_a_newline() {
        let line = read_bounded_request(Cursor::new(b"{\"action\":\"ping\"}".to_vec())).unwrap();
        assert_eq!(line.as_slice(), b"{\"action\":\"ping\"}");
    }

    #[test]
    fn test_connection_limiter_admits_up_to_the_limit() {
        let limiter = ConnectionLimiter::default();
        let permits: Vec<_> = (0..MAX_CONCURRENT_CONNECTIONS)
            .map(|_| limiter.try_admit().expect("within the limit"))
            .collect();
        assert!(
            limiter.try_admit().is_none(),
            "the next connection is refused"
        );
        drop(permits);
        assert_eq!(limiter.active(), 0);
        assert!(limiter.try_admit().is_some(), "slots are released on drop");
    }
}
