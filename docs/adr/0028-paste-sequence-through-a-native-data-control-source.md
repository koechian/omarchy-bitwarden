# ADR 0028: Paste Sequence Through a Native Data-Control Clipboard Source

## Status
Accepted. Extends [ADR 0027](0027-redacted-item-access-and-per-field-secret-release.md) (per-field release, release budget, clipboard on lock). The wire contract is in [contracts.md section 3.4](../agents/contracts.md#34-reveal_field-copy_field-and-copy_sequence).

## Context
Some logins ask for two secrets of one item in a row: Teleport's `tsh login` prompts for the password, then for the one-time code. With `copy_field` the user copies the password, pastes it, returns to the overlay, copies the TOTP code and pastes again. One action that stages both, so that the first paste yields the password and the second the current code, removes the round trip.

`wl-copy --paste-once` cannot do this. Clipboard watchers (`wl-paste --watch …`, which Omarchy's clipboard history and third-party plugins run) receive every new selection and read it at once, including a selection marked sensitive: in wl-clipboard 2.3.0 (`src/wl-paste.c`) `offer_receive` is called before `CLIPBOARD_STATE=sensitive` is passed to the watch command. Each watcher read consumes a paste-once offer before the user pastes.

## Decision

### 1. The daemon owns the selection itself
For a paste sequence the daemon becomes a Wayland clipboard source through the data-control protocol (`selection_source.rs`), preferring `ext_data_control_manager_v1` and falling back to `zwlr_data_control_manager_v1`. It uses the pure-Rust `wayland-client` backend (no libwayland, no program run, nothing resolved through `PATH`); the connection comes from `WAYLAND_DISPLAY` (or `WAYLAND_SOCKET`). Each stage is a data source offering `text/plain;charset=utf-8`, `text/plain`, `UTF8_STRING`, `TEXT`, `STRING` and `x-kde-passwordManagerHint` (content `secret`, as `wl-copy --sensitive` offers), so history managers that honour the hint skip it. `copy_field` and `copy` keep using `wl-copy`.

### 2. Which read is the user's paste
A pure state machine (`paste_sequence.rs`), driven by events and an injected clock, decides:

- **Settle window** (`SETTLE_WINDOW`, 400 ms): data requests within this time after a stage becomes the selection are watchers reading the new selection. They are served and not counted.
- **Paste**: the first request for a text MIME type after the settle window.
- **Debounce** (`PASTE_DEBOUNCE`, 300 ms): further requests within this time after the paste are served the same value (some clients request a selection more than once for one paste). Then the next stage becomes the selection.
- Requests for `x-kde-passwordManagerHint` never count, and requests on a source that is no longer the current stage are refused.
- After the last stage's paste and debounce, the selection is withdrawn: cleared only while this sequence still owns it, then the source is destroyed.
- `cancelled` on the current stage's source means another client took the selection (the user copied something else). The sequence ends at once and leaves that selection alone.
- A TOTP stage holds the seed and computes the code each time it is served, so it is never stale.

### 3. Lifetime and withdrawal
The sequence ends no later than `clear_after_seconds` (the `copy_field` range and default) after it starts, withdrawing its selection if it still owns it. The daemon records the running sequence in the same `OfferRegistry` that records `wl-copy` offers, so every lock (hard, soft, suspend, exhausted budget), the end of the login session, termination signals and `stop` withdraw it and wait up to one second for it to clear the selection. Any new copy (`copy`, `copy_field`, or another `copy_sequence`) withdraws an active sequence first; only one runs at a time.

### 4. Secrets and budget
Every field is validated before anything is charged: a known identifier, present on the item, copyable (`password_history` is refused). The sequence then costs one release per stage, charged when it is accepted and refunded in full when it cannot start (for example when the compositor offers no data-control protocol, reported as `clipboard_failed`). Values are held in zeroizing buffers on the sequence thread and zeroized when it ends; they never appear in a response, in argv or in a log. Each data request is written by a short-lived thread with a non-blocking descriptor and a two-second deadline (`TRANSFER_WRITE_TIMEOUT`), at most eight at once (`MAX_CONCURRENT_TRANSFERS`), so a reader that never drains its pipe cannot stall the sequence or the daemon.

## Alternatives Considered
- **`wl-copy --paste-once` per stage**: consumed by clipboard watchers, as described above.
- **Pausing or reconfiguring the user's clipboard watchers**: reaches into third-party processes and still races any watcher the engine does not know about.
- **Counting the n-th read as the paste**: the number of watcher reads depends on what the user runs and changes over time; a settle window does not depend on it.
- **libwayland through `wayland-client`'s `system` feature**: adds a C library to the daemon's address space for no gain here.

## Consequences
- **Positive**: one action stages password then code (or any ordered list of up to eight copyable fields); watchers neither consume nor record the stages when they honour the hint; a TOTP stage is always current; the daemon keeps the secrets.
- **Heuristic**: a client that reads the selection more than `SETTLE_WINDOW` after it changed without the user pasting (some applications read the clipboard when they gain focus) counts as a paste and advances the sequence early. A client that requests one paste more than `PASTE_DEBOUNCE` apart counts twice.
- **XWayland**: X11 clients paste through the compositor's XWayland bridge, which requests the data on the X client's behalf; the timing rules apply to those requests in the same way, but bridges that prefetch the selection would count as a paste.
- **Withdrawal race**: between processing the last event and clearing the selection, another client can take the selection; the window is one compositor round trip, and a cancellation that arrives before the clear is honoured.
- **Compositor support**: a compositor without either data-control protocol cannot run a sequence; the request fails with `clipboard_failed` and nothing is charged.
- **Versioning**: the engine that implements this ADR is 0.13.0.
