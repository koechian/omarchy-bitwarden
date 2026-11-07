//! Paste sequence: several secrets of one item staged on the clipboard in
//! order, so that the first paste yields the first value, the second paste
//! the second value, and so on (for example a password, then the current
//! TOTP code). See ADR 0028 and contracts.md section 3.4.
//!
//! This module holds the pure part: the stage values, the MIME types a stage
//! offers, and the state machine that decides, from the data requests the
//! compositor forwards and the passage of time, when the user has pasted a
//! stage and the sequence advances. Time is passed in, so every rule is unit
//! tested without a compositor. `selection_source` drives this machine
//! against the Wayland data-control protocol.
//!
//! Clipboard watchers (`wl-paste --watch`, clipboard history managers) read
//! every new selection as soon as it is set, including a sensitive one. A
//! read that arrives within `SETTLE_WINDOW` of a stage being offered is
//! therefore served but not counted as the user's paste. The first text read
//! after that window is the paste; reads within `PASTE_DEBOUNCE` after it are
//! served with the same value (some clients request a selection more than
//! once for one paste), and then the next stage is offered.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

/// After a stage is offered, data requests within this window are treated
/// as clipboard watchers reading the new selection, not as the user's paste.
pub const SETTLE_WINDOW: Duration = Duration::from_millis(400);
/// After the user's paste is observed, further requests within this window
/// are served with the same value before the next stage is offered.
pub const PASTE_DEBOUNCE: Duration = Duration::from_millis(300);
/// Most stages one sequence may hold.
pub const MAX_SEQUENCE_STAGES: usize = 8;

/// Text MIME types every stage offers, in order of preference.
pub const TEXT_MIME_TYPES: &[&str] = &[
    "text/plain;charset=utf-8",
    "text/plain",
    "UTF8_STRING",
    "TEXT",
    "STRING",
];
/// The KDE password-manager hint (also offered by `wl-copy --sensitive`):
/// clipboard history managers that honour it do not record the selection.
pub const PASSWORD_MANAGER_HINT_MIME: &str = "x-kde-passwordManagerHint";
/// Content served for `PASSWORD_MANAGER_HINT_MIME`.
pub const PASSWORD_MANAGER_HINT_CONTENT: &[u8] = b"secret";

/// TOTP code length and period used when the item's configuration does not
/// state them (the same defaults as `reveal_field` with `login.totp`).
const TOTP_DEFAULT_DIGITS: u32 = 6;
const TOTP_DEFAULT_PERIOD: u64 = 30;

/// Every MIME type a stage offers.
pub fn offered_mime_types() -> impl Iterator<Item = &'static str> {
    TEXT_MIME_TYPES
        .iter()
        .copied()
        .chain(std::iter::once(PASSWORD_MANAGER_HINT_MIME))
}

/// How a requested MIME type is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimeKind {
    /// The stage value; may count as the user's paste.
    Text,
    /// The password-manager hint; never counts as a paste.
    PasswordManagerHint,
    /// Not offered: the request is refused.
    Unsupported,
}

pub fn classify_mime(mime_type: &str) -> MimeKind {
    if TEXT_MIME_TYPES.contains(&mime_type) {
        return MimeKind::Text;
    }
    if mime_type == PASSWORD_MANAGER_HINT_MIME {
        return MimeKind::PasswordManagerHint;
    }
    MimeKind::Unsupported
}

/// The secret one stage serves.
pub enum StageValue {
    /// A fixed text secret (password, card number, custom field, ...).
    Text(Zeroizing<String>),
    /// A TOTP seed or `otpauth://` URI; the code is computed each time the
    /// stage is served, so it is never stale.
    TotpSeed(Zeroizing<String>),
}

impl StageValue {
    /// The bytes served for a text request at `unix_seconds` (the current
    /// time when `None`). `None` when a TOTP seed yields no code.
    pub fn render(&self, unix_seconds: Option<u64>) -> Option<Zeroizing<Vec<u8>>> {
        match self {
            StageValue::Text(text) => Some(Zeroizing::new(text.as_bytes().to_vec())),
            StageValue::TotpSeed(seed) => {
                let generated = crate::totp::generate_totp(
                    seed,
                    unix_seconds,
                    TOTP_DEFAULT_DIGITS,
                    TOTP_DEFAULT_PERIOD,
                )?;
                Some(Zeroizing::new(generated.code.into_bytes()))
            }
        }
    }
}

/// The bytes served for a request of `kind` on a stage holding `value`.
pub fn payload_for(kind: MimeKind, value: &StageValue) -> Option<Zeroizing<Vec<u8>>> {
    match kind {
        MimeKind::Text => value.render(current_unix_seconds()),
        MimeKind::PasswordManagerHint => {
            Some(Zeroizing::new(PASSWORD_MANAGER_HINT_CONTENT.to_vec()))
        }
        MimeKind::Unsupported => None,
    }
}

fn current_unix_seconds() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

/// Whether a data request is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestDisposition {
    Serve,
    Refuse,
}

/// Why a sequence withdraws its selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithdrawalReason {
    /// The last stage was pasted.
    Completed,
    /// The overall deadline (`clear_after_seconds`) passed.
    DeadlineReached,
    /// The daemon asked for it (a lock, a new copy, daemon exit).
    Requested,
}

/// What the driver does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceDirective {
    /// Nothing until `next_wakeup` or the next event.
    Wait,
    /// Offer the stage at this index as the new selection.
    OfferStage(usize),
    /// End the sequence: clear the selection if this sequence still owns
    /// it, then destroy the source.
    Withdraw(WithdrawalReason),
    /// End the sequence without touching the selection: another client
    /// owns it (the user copied something else) or the seat went away.
    Abandon,
}

impl SequenceDirective {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            SequenceDirective::Withdraw(_) | SequenceDirective::Abandon
        )
    }
}

/// Stage, settle, debounce, advance and abort rules of one sequence.
#[derive(Debug)]
pub struct PasteSequenceMachine {
    stage_count: usize,
    current_stage: usize,
    stage_offered_at: Instant,
    paste_observed_at: Option<Instant>,
    deadline: Instant,
    terminal: Option<SequenceDirective>,
    selection_lost: bool,
}

impl PasteSequenceMachine {
    /// A sequence of `stage_count` stages whose first stage is offered at
    /// `offered_at` and which ends no later than `lifetime` after it.
    pub fn new(stage_count: usize, offered_at: Instant, lifetime: Duration) -> Self {
        Self {
            stage_count,
            current_stage: 0,
            stage_offered_at: offered_at,
            paste_observed_at: None,
            deadline: offered_at + lifetime,
            terminal: (stage_count == 0)
                .then_some(SequenceDirective::Withdraw(WithdrawalReason::Completed)),
            selection_lost: false,
        }
    }

    pub fn current_stage(&self) -> usize {
        self.current_stage
    }

    pub fn is_finished(&self) -> bool {
        self.terminal.is_some()
    }

    /// A data request for `stage` with a MIME type of `kind` at `now`.
    /// Only the current stage is served; the first text request after the
    /// settle window is recorded as the user's paste.
    pub fn record_request(
        &mut self,
        stage: usize,
        kind: MimeKind,
        now: Instant,
    ) -> RequestDisposition {
        if self.terminal.is_some() || stage != self.current_stage || kind == MimeKind::Unsupported {
            return RequestDisposition::Refuse;
        }
        if kind == MimeKind::Text && self.is_awaiting_paste(now) {
            self.paste_observed_at = Some(now);
        }
        RequestDisposition::Serve
    }

    fn is_awaiting_paste(&self, now: Instant) -> bool {
        self.paste_observed_at.is_none()
            && now.saturating_duration_since(self.stage_offered_at) >= SETTLE_WINDOW
    }

    /// The source of `stage` was cancelled: another client took the
    /// selection. Cancellation of an earlier stage's source is the expected
    /// result of offering the next stage and is ignored.
    pub fn record_cancelled(&mut self, stage: usize) {
        if stage == self.current_stage {
            self.record_selection_lost();
        }
    }

    /// The seat's data device was destroyed; the selection is gone with it.
    pub fn record_device_finished(&mut self) {
        self.record_selection_lost();
    }

    /// Ownership is tracked even after the sequence has ended, so a
    /// withdrawal decided earlier still leaves a newer selection alone.
    fn record_selection_lost(&mut self) {
        self.selection_lost = true;
        if self.terminal.is_none() {
            self.terminal = Some(SequenceDirective::Abandon);
        }
    }

    /// Whether the current stage's source is still the selection, as far as
    /// the events received so far tell.
    pub fn owns_selection(&self) -> bool {
        !self.selection_lost
    }

    /// The daemon asked for the sequence to end (lock, new copy, exit).
    pub fn record_withdrawal_request(&mut self) {
        if self.terminal.is_none() {
            self.terminal = Some(SequenceDirective::Withdraw(WithdrawalReason::Requested));
        }
    }

    /// Advances time to `now` and returns what the driver does next. A
    /// terminal directive is returned again on every later call.
    pub fn poll(&mut self, now: Instant) -> SequenceDirective {
        if let Some(terminal) = self.terminal {
            return terminal;
        }
        if now >= self.deadline {
            return self.finish(WithdrawalReason::DeadlineReached);
        }
        if !self.debounce_elapsed(now) {
            return SequenceDirective::Wait;
        }
        self.advance(now)
    }

    fn debounce_elapsed(&self, now: Instant) -> bool {
        self.paste_observed_at
            .is_some_and(|pasted| now.saturating_duration_since(pasted) >= PASTE_DEBOUNCE)
    }

    fn advance(&mut self, now: Instant) -> SequenceDirective {
        if self.current_stage + 1 >= self.stage_count {
            return self.finish(WithdrawalReason::Completed);
        }
        self.current_stage += 1;
        self.stage_offered_at = now;
        self.paste_observed_at = None;
        SequenceDirective::OfferStage(self.current_stage)
    }

    fn finish(&mut self, reason: WithdrawalReason) -> SequenceDirective {
        let directive = SequenceDirective::Withdraw(reason);
        self.terminal = Some(directive);
        directive
    }

    /// The next instant at which `poll` may return something other than
    /// `Wait` without a new event: the end of the debounce or the deadline.
    pub fn next_wakeup(&self) -> Instant {
        self.paste_observed_at
            .map(|pasted| (pasted + PASTE_DEBOUNCE).min(self.deadline))
            .unwrap_or(self.deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIFETIME: Duration = Duration::from_secs(30);

    fn millis(value: u64) -> Duration {
        Duration::from_millis(value)
    }

    fn two_stage_machine(start: Instant) -> PasteSequenceMachine {
        PasteSequenceMachine::new(2, start, LIFETIME)
    }

    #[test]
    fn test_watcher_reads_within_the_settle_window_do_not_advance() {
        let start = Instant::now();
        let mut machine = two_stage_machine(start);
        for offset in [0, 50, 200, 399] {
            let now = start + millis(offset);
            assert_eq!(
                machine.record_request(0, MimeKind::Text, now),
                RequestDisposition::Serve
            );
        }
        for offset in [400, 1000, 5000] {
            assert_eq!(
                machine.poll(start + millis(offset)),
                SequenceDirective::Wait
            );
        }
        assert_eq!(machine.current_stage(), 0);
        assert_eq!(machine.next_wakeup(), start + LIFETIME);
    }

    #[test]
    fn test_first_read_after_settle_advances_after_the_debounce() {
        let start = Instant::now();
        let mut machine = two_stage_machine(start);
        let pasted = start + SETTLE_WINDOW + millis(100);
        assert_eq!(
            machine.record_request(0, MimeKind::Text, pasted),
            RequestDisposition::Serve
        );
        assert_eq!(machine.next_wakeup(), pasted + PASTE_DEBOUNCE);
        assert_eq!(machine.poll(pasted + millis(299)), SequenceDirective::Wait);
        assert_eq!(
            machine.poll(pasted + PASTE_DEBOUNCE),
            SequenceDirective::OfferStage(1)
        );
        assert_eq!(machine.current_stage(), 1);
    }

    #[test]
    fn test_duplicate_reads_within_the_debounce_do_not_advance_twice() {
        let start = Instant::now();
        let mut machine = PasteSequenceMachine::new(3, start, LIFETIME);
        let pasted = start + SETTLE_WINDOW;
        machine.record_request(0, MimeKind::Text, pasted);
        for offset in [10, 150, 290] {
            assert_eq!(
                machine.record_request(0, MimeKind::Text, pasted + millis(offset)),
                RequestDisposition::Serve,
                "duplicate requests of one paste are served the same stage"
            );
        }
        assert_eq!(
            machine.next_wakeup(),
            pasted + PASTE_DEBOUNCE,
            "duplicates do not extend the debounce"
        );
        let advanced = pasted + PASTE_DEBOUNCE;
        assert_eq!(machine.poll(advanced), SequenceDirective::OfferStage(1));
        assert_eq!(machine.poll(advanced), SequenceDirective::Wait);
        assert_eq!(machine.current_stage(), 1);
        assert_eq!(
            machine.record_request(0, MimeKind::Text, advanced + millis(10)),
            RequestDisposition::Refuse,
            "a request on the previous stage's source is refused"
        );
    }

    #[test]
    fn test_password_manager_hint_reads_never_count_as_a_paste() {
        let start = Instant::now();
        let mut machine = two_stage_machine(start);
        for offset in [0, 500, 2000] {
            assert_eq!(
                machine.record_request(0, MimeKind::PasswordManagerHint, start + millis(offset)),
                RequestDisposition::Serve
            );
        }
        assert_eq!(machine.poll(start + millis(3000)), SequenceDirective::Wait);
        assert_eq!(machine.current_stage(), 0);
    }

    #[test]
    fn test_unsupported_mime_types_are_refused() {
        let start = Instant::now();
        let mut machine = two_stage_machine(start);
        assert_eq!(
            machine.record_request(0, MimeKind::Unsupported, start + millis(600)),
            RequestDisposition::Refuse
        );
        assert_eq!(machine.poll(start + millis(2000)), SequenceDirective::Wait);
    }

    #[test]
    fn test_cancellation_of_the_current_stage_abandons_the_sequence() {
        let start = Instant::now();
        let mut machine = two_stage_machine(start);
        machine.record_cancelled(0);
        assert_eq!(machine.poll(start + millis(10)), SequenceDirective::Abandon);
        assert_eq!(
            machine.poll(start + LIFETIME),
            SequenceDirective::Abandon,
            "the deadline does not turn an abandoned sequence into a withdrawal"
        );
        assert_eq!(
            machine.record_request(0, MimeKind::Text, start + millis(600)),
            RequestDisposition::Refuse
        );
    }

    #[test]
    fn test_cancellation_of_a_replaced_stage_is_ignored() {
        let start = Instant::now();
        let mut machine = two_stage_machine(start);
        let pasted = start + SETTLE_WINDOW;
        machine.record_request(0, MimeKind::Text, pasted);
        assert_eq!(
            machine.poll(pasted + PASTE_DEBOUNCE),
            SequenceDirective::OfferStage(1)
        );
        machine.record_cancelled(0);
        assert_eq!(
            machine.poll(pasted + PASTE_DEBOUNCE + millis(1)),
            SequenceDirective::Wait
        );
        assert!(machine.owns_selection());
    }

    #[test]
    fn test_deadline_withdraws() {
        let start = Instant::now();
        let mut machine = two_stage_machine(start);
        assert_eq!(
            machine.poll(start + LIFETIME - millis(1)),
            SequenceDirective::Wait
        );
        assert_eq!(
            machine.poll(start + LIFETIME),
            SequenceDirective::Withdraw(WithdrawalReason::DeadlineReached)
        );
        assert!(machine.is_finished());
    }

    #[test]
    fn test_deadline_caps_the_debounce_wakeup() {
        let start = Instant::now();
        let mut machine = PasteSequenceMachine::new(2, start, millis(500));
        machine.record_request(0, MimeKind::Text, start + millis(450));
        assert_eq!(machine.next_wakeup(), start + millis(500));
        assert_eq!(
            machine.poll(start + millis(500)),
            SequenceDirective::Withdraw(WithdrawalReason::DeadlineReached)
        );
    }

    #[test]
    fn test_last_stage_withdraws_after_its_paste() {
        let start = Instant::now();
        let mut machine = two_stage_machine(start);
        let first = start + SETTLE_WINDOW;
        machine.record_request(0, MimeKind::Text, first);
        let second_offered = first + PASTE_DEBOUNCE;
        assert_eq!(
            machine.poll(second_offered),
            SequenceDirective::OfferStage(1)
        );
        machine.record_request(1, MimeKind::Text, second_offered + millis(100));
        assert_eq!(
            machine.poll(second_offered + millis(500)),
            SequenceDirective::Wait,
            "a watcher read of the second stage is not its paste"
        );
        let second_paste = second_offered + SETTLE_WINDOW;
        machine.record_request(1, MimeKind::Text, second_paste);
        assert_eq!(
            machine.poll(second_paste + PASTE_DEBOUNCE),
            SequenceDirective::Withdraw(WithdrawalReason::Completed)
        );
        assert!(machine.is_finished());
    }

    #[test]
    fn test_withdrawal_request_ends_the_sequence() {
        let start = Instant::now();
        let mut machine = two_stage_machine(start);
        machine.record_withdrawal_request();
        assert_eq!(
            machine.poll(start),
            SequenceDirective::Withdraw(WithdrawalReason::Requested)
        );
        assert!(machine.owns_selection());
        machine.record_cancelled(0);
        assert_eq!(
            machine.poll(start),
            SequenceDirective::Withdraw(WithdrawalReason::Requested),
            "the first terminal directive stands"
        );
        assert!(
            !machine.owns_selection(),
            "a cancellation after the decision still prevents clearing a newer selection"
        );
    }

    #[test]
    fn test_device_finished_abandons() {
        let start = Instant::now();
        let mut machine = two_stage_machine(start);
        machine.record_device_finished();
        assert_eq!(machine.poll(start), SequenceDirective::Abandon);
        assert!(SequenceDirective::Abandon.is_terminal());
        assert!(!SequenceDirective::Wait.is_terminal());
    }

    #[test]
    fn test_classify_mime_and_offered_types() {
        for mime in TEXT_MIME_TYPES {
            assert_eq!(classify_mime(mime), MimeKind::Text, "{mime}");
        }
        assert_eq!(
            classify_mime(PASSWORD_MANAGER_HINT_MIME),
            MimeKind::PasswordManagerHint
        );
        for mime in ["image/png", "text/html", ""] {
            assert_eq!(classify_mime(mime), MimeKind::Unsupported, "{mime}");
        }
        let offered: Vec<&str> = offered_mime_types().collect();
        assert_eq!(offered.len(), TEXT_MIME_TYPES.len() + 1);
        assert!(offered.contains(&PASSWORD_MANAGER_HINT_MIME));
    }

    #[test]
    fn test_hint_payload_is_the_sensitive_marker() {
        let value = StageValue::Text(Zeroizing::new("stage-secret".to_string()));
        assert_eq!(
            payload_for(MimeKind::PasswordManagerHint, &value)
                .unwrap()
                .as_slice(),
            b"secret"
        );
        assert_eq!(
            payload_for(MimeKind::Text, &value).unwrap().as_slice(),
            b"stage-secret"
        );
        assert!(payload_for(MimeKind::Unsupported, &value).is_none());
    }

    #[test]
    fn test_totp_stage_computes_the_code_at_each_serve() {
        const SEED: &str = "JBSWY3DPEHPK3PXP";
        let value = StageValue::TotpSeed(Zeroizing::new(SEED.to_string()));
        for timestamp in [59_u64, 1_111_111_109, 1_234_567_890, 2_000_000_000] {
            let expected = crate::totp::generate_totp(SEED, Some(timestamp), 6, 30)
                .unwrap()
                .code;
            let served = value.render(Some(timestamp)).unwrap();
            assert_eq!(served.as_slice(), expected.as_bytes(), "at {timestamp}");
        }
        assert_ne!(
            value.render(Some(59)).unwrap().as_slice(),
            value.render(Some(89)).unwrap().as_slice(),
            "a later period yields a different code"
        );
        let invalid = StageValue::TotpSeed(Zeroizing::new("not base32 !".to_string()));
        assert!(invalid.render(Some(59)).is_none());
    }

    #[test]
    fn test_empty_sequence_is_finished_immediately() {
        let start = Instant::now();
        let mut machine = PasteSequenceMachine::new(0, start, LIFETIME);
        assert_eq!(
            machine.poll(start),
            SequenceDirective::Withdraw(WithdrawalReason::Completed)
        );
    }
}
