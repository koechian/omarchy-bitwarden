//! Native Wayland clipboard source for paste sequences (ADR 0028).
//!
//! `wl-copy --paste-once` cannot stage secrets one paste at a time:
//! clipboard watchers (`wl-paste --watch`) receive every new selection,
//! sensitive ones included, and each read would consume a paste-once offer.
//! This module therefore owns the selection itself through the data-control
//! protocol (`ext_data_control_manager_v1`, or `zwlr_data_control_manager_v1`
//! when the compositor lacks the former), and lets
//! `paste_sequence::PasteSequenceMachine` decide which data request is the
//! user's paste.
//!
//! One thread per sequence holds the Wayland connection, the stage values
//! (zeroized when the thread ends) and the machine. Each data request is
//! answered by a short-lived transfer thread that writes the value to the
//! receiving client's pipe without blocking and gives up after
//! `TRANSFER_WRITE_TIMEOUT`, so a reader that never drains its pipe cannot
//! stall the sequence or the daemon. The connection comes from
//! `WAYLAND_DISPLAY` (or `WAYLAND_SOCKET`); no program is run and nothing is
//! resolved through `PATH`.

use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use wayland_client::globals::{registry_queue_init, GlobalList, GlobalListContents};
use wayland_client::protocol::{wl_registry, wl_seat};
use wayland_client::{
    delegate_noop, event_created_child, Connection, Dispatch, EventQueue, QueueHandle,
};
use wayland_protocols::ext::data_control::v1::client::{
    ext_data_control_device_v1 as ext_device, ext_data_control_manager_v1 as ext_manager,
    ext_data_control_offer_v1 as ext_offer, ext_data_control_source_v1 as ext_source,
};
use wayland_protocols_wlr::data_control::v1::client::{
    zwlr_data_control_device_v1 as wlr_device, zwlr_data_control_manager_v1 as wlr_manager,
    zwlr_data_control_offer_v1 as wlr_offer, zwlr_data_control_source_v1 as wlr_source,
};

use crate::paste_sequence::{
    classify_mime, offered_mime_types, payload_for, PasteSequenceMachine, RequestDisposition,
    SequenceDirective, StageValue, WithdrawalReason,
};

/// Upper bound on the sequence thread reporting that the first stage is
/// offered (or that it could not be).
pub const STARTUP_REPORT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a withdrawal waits for the sequence thread to clear the
/// selection and end.
pub const WITHDRAWAL_WAIT_TIMEOUT: Duration = Duration::from_secs(1);
/// How long one transfer may take to write its value to a client.
pub const TRANSFER_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
/// Transfers served at once; further data requests are refused.
pub const MAX_CONCURRENT_TRANSFERS: usize = 8;
/// Longest single wait of the event loop, so a lost wake-up only delays it.
const MAX_EVENT_WAIT: Duration = Duration::from_millis(500);

/// Starts a paste sequence: a control handle for the running sequence, or a
/// message when the first stage could not be offered.
pub type PasteSequenceLauncher =
    dyn Fn(Vec<StageValue>, Duration) -> Result<Arc<SequenceControl>, String> + Send + Sync;

/// Shared between the daemon and one sequence thread: lets the daemon ask
/// the sequence to withdraw and wait until it has ended.
#[derive(Debug)]
pub struct SequenceControl {
    withdrawal_requested: AtomicBool,
    wake_sender: Mutex<Option<UnixStream>>,
    finished: Mutex<bool>,
    finished_signal: Condvar,
}

impl SequenceControl {
    /// A control and the receiving end of its wake-up channel.
    fn with_wake_channel() -> std::io::Result<(Arc<Self>, UnixStream)> {
        let (sender, receiver) = UnixStream::pair()?;
        sender.set_nonblocking(true)?;
        receiver.set_nonblocking(true)?;
        Ok((Arc::new(Self::new(Some(sender))), receiver))
    }

    fn new(wake_sender: Option<UnixStream>) -> Self {
        Self {
            withdrawal_requested: AtomicBool::new(false),
            wake_sender: Mutex::new(wake_sender),
            finished: Mutex::new(false),
            finished_signal: Condvar::new(),
        }
    }

    /// A control with no sequence thread behind it, for tests that inject a
    /// launcher. It ends when withdrawn.
    #[cfg(test)]
    pub(crate) fn unattended() -> Arc<Self> {
        Arc::new(Self::new(None))
    }

    /// Asks the sequence to withdraw its selection and end.
    pub fn request_withdrawal(&self) {
        self.withdrawal_requested.store(true, Ordering::SeqCst);
        let sender = self.wake_sender.lock().ok();
        match sender.as_ref().and_then(|guard| guard.as_ref()) {
            Some(mut stream) => {
                let _ = stream.write(&[1]);
            }
            None => self.mark_finished(),
        }
    }

    pub fn withdrawal_requested(&self) -> bool {
        self.withdrawal_requested.load(Ordering::SeqCst)
    }

    pub fn is_finished(&self) -> bool {
        self.finished.lock().map_or(true, |finished| *finished)
    }

    fn mark_finished(&self) {
        if let Ok(mut finished) = self.finished.lock() {
            *finished = true;
        }
        self.finished_signal.notify_all();
    }

    /// Waits up to `timeout` for the sequence to end; true when it has.
    pub fn wait_until_finished(&self, timeout: Duration) -> bool {
        let Ok(finished) = self.finished.lock() else {
            return true;
        };
        self.finished_signal
            .wait_timeout_while(finished, timeout, |finished| !*finished)
            .map_or(true, |(finished, _)| *finished)
    }

    /// Requests a withdrawal and waits for it. True when a running sequence
    /// was ended by this call.
    pub fn withdraw_and_wait(&self, timeout: Duration) -> bool {
        if self.is_finished() {
            return false;
        }
        self.request_withdrawal();
        if !self.wait_until_finished(timeout) {
            crate::log_warn!(
                "omawarden:clipboard",
                "The paste sequence did not end within {} ms of its withdrawal.",
                timeout.as_millis()
            );
        }
        true
    }
}

/// Marks the control finished when the sequence thread ends, including by
/// a panic.
struct FinishedOnDrop(Arc<SequenceControl>);

impl Drop for FinishedOnDrop {
    fn drop(&mut self) {
        self.0.mark_finished();
    }
}

/// Starts a paste sequence on the compositor of `WAYLAND_DISPLAY`. Returns
/// once the first stage is the selection; the sequence then runs on its own
/// thread for at most `lifetime`.
pub fn start_paste_sequence(
    stages: Vec<StageValue>,
    lifetime: Duration,
) -> Result<Arc<SequenceControl>, String> {
    if stages.is_empty() {
        return Err("A paste sequence needs at least one stage.".to_string());
    }
    let (control, wake_receiver) = SequenceControl::with_wake_channel()
        .map_err(|e| format!("Could not create the paste sequence wake-up channel: {e}"))?;
    let (report, outcome) = mpsc::channel();
    let thread_control = Arc::clone(&control);
    std::thread::Builder::new()
        .name("paste-sequence".into())
        .spawn(move || {
            let _finished = FinishedOnDrop(Arc::clone(&thread_control));
            run_sequence(stages, lifetime, &thread_control, wake_receiver, report);
        })
        .map_err(|e| format!("Could not start the paste sequence thread: {e}"))?;
    match outcome.recv_timeout(STARTUP_REPORT_TIMEOUT) {
        Ok(Ok(())) => Ok(control),
        Ok(Err(message)) => Err(message),
        Err(_) => {
            control.request_withdrawal();
            Err("The compositor did not accept the clipboard selection in time.".to_string())
        }
    }
}

/// Body of the sequence thread.
fn run_sequence(
    stages: Vec<StageValue>,
    lifetime: Duration,
    control: &SequenceControl,
    wake_receiver: UnixStream,
    report: mpsc::Sender<Result<(), String>>,
) {
    let mut session = match SelectionSession::open(stages, lifetime) {
        Ok(session) => session,
        Err(message) => {
            let _ = report.send(Err(message));
            return;
        }
    };
    let _ = report.send(Ok(()));
    crate::log_info!(
        "omawarden:clipboard",
        "Paste sequence started with {} stage(s) over {}.",
        session.state.stages.len(),
        session.protocol.name()
    );
    session.run(control, &wake_receiver);
}

/// The data-control protocol family in use.
enum DataControl {
    Ext(ext_manager::ExtDataControlManagerV1),
    Wlr(wlr_manager::ZwlrDataControlManagerV1),
}

/// The seat's data device of the chosen family.
enum SelectionDevice {
    Ext(ext_device::ExtDataControlDeviceV1),
    Wlr(wlr_device::ZwlrDataControlDeviceV1),
}

/// One stage's data source; its user data is the stage index.
enum StageSource {
    Ext(ext_source::ExtDataControlSourceV1),
    Wlr(wlr_source::ZwlrDataControlSourceV1),
}

impl DataControl {
    /// The ext manager when advertised, otherwise the wlr manager.
    fn bind(globals: &GlobalList, queue: &QueueHandle<SequenceState>) -> Option<Self> {
        if let Ok(manager) = globals.bind(queue, 1..=1, ()) {
            return Some(DataControl::Ext(manager));
        }
        globals.bind(queue, 1..=1, ()).ok().map(DataControl::Wlr)
    }

    fn name(&self) -> &'static str {
        match self {
            DataControl::Ext(_) => "ext-data-control-v1",
            DataControl::Wlr(_) => "wlr-data-control-unstable-v1",
        }
    }

    fn device(
        &self,
        seat: &wl_seat::WlSeat,
        queue: &QueueHandle<SequenceState>,
    ) -> SelectionDevice {
        match self {
            DataControl::Ext(manager) => {
                SelectionDevice::Ext(manager.get_data_device(seat, queue, ()))
            }
            DataControl::Wlr(manager) => {
                SelectionDevice::Wlr(manager.get_data_device(seat, queue, ()))
            }
        }
    }

    /// A source for `stage` offering every stage MIME type.
    fn stage_source(&self, stage: usize, queue: &QueueHandle<SequenceState>) -> StageSource {
        let source = match self {
            DataControl::Ext(manager) => StageSource::Ext(manager.create_data_source(queue, stage)),
            DataControl::Wlr(manager) => StageSource::Wlr(manager.create_data_source(queue, stage)),
        };
        for mime_type in offered_mime_types() {
            source.offer(mime_type);
        }
        source
    }

    fn destroy(&self) {
        match self {
            DataControl::Ext(manager) => manager.destroy(),
            DataControl::Wlr(manager) => manager.destroy(),
        }
    }
}

impl SelectionDevice {
    /// Makes `source` the selection, or clears the selection with `None`.
    fn set_selection(&self, source: Option<&StageSource>) {
        match (self, source) {
            (SelectionDevice::Ext(device), Some(StageSource::Ext(source))) => {
                device.set_selection(Some(source))
            }
            (SelectionDevice::Wlr(device), Some(StageSource::Wlr(source))) => {
                device.set_selection(Some(source))
            }
            (SelectionDevice::Ext(device), None) => device.set_selection(None),
            (SelectionDevice::Wlr(device), None) => device.set_selection(None),
            // Sources are only ever created by the manager of the device's
            // own family.
            _ => {}
        }
    }

    fn destroy(&self) {
        match self {
            SelectionDevice::Ext(device) => device.destroy(),
            SelectionDevice::Wlr(device) => device.destroy(),
        }
    }
}

impl StageSource {
    fn offer(&self, mime_type: &str) {
        match self {
            StageSource::Ext(source) => source.offer(mime_type.to_string()),
            StageSource::Wlr(source) => source.offer(mime_type.to_string()),
        }
    }

    fn destroy(&self) {
        match self {
            StageSource::Ext(source) => source.destroy(),
            StageSource::Wlr(source) => source.destroy(),
        }
    }
}

/// Event-handling state of one sequence.
struct SequenceState {
    machine: PasteSequenceMachine,
    stages: Vec<StageValue>,
    active_transfers: Arc<AtomicUsize>,
}

impl SequenceState {
    /// A data request: served on a transfer thread, or refused by closing
    /// the descriptor.
    fn handle_send(&mut self, stage: usize, mime_type: &str, descriptor: OwnedFd) {
        let kind = classify_mime(mime_type);
        if self.machine.record_request(stage, kind, Instant::now()) == RequestDisposition::Refuse {
            return;
        }
        let Some(payload) = self
            .stages
            .get(stage)
            .and_then(|value| payload_for(kind, value))
        else {
            return;
        };
        spawn_transfer(descriptor, payload, &self.active_transfers);
    }
}

/// The open connection, bound objects and the source of the current stage.
struct SelectionSession {
    connection: Connection,
    queue: EventQueue<SequenceState>,
    state: SequenceState,
    protocol: DataControl,
    device: SelectionDevice,
    source: Option<StageSource>,
}

impl SelectionSession {
    /// Connects, binds a data-control manager and the seat, and offers the
    /// first stage. Fails with a message when any of it is unavailable or
    /// the compositor rejects the selection.
    fn open(stages: Vec<StageValue>, lifetime: Duration) -> Result<Self, String> {
        let connection = Connection::connect_to_env()
            .map_err(|e| format!("Could not connect to the Wayland compositor: {e}"))?;
        let (globals, queue) = registry_queue_init::<SequenceState>(&connection)
            .map_err(|e| format!("Could not read the Wayland globals: {e}"))?;
        let handle = queue.handle();
        let protocol = DataControl::bind(&globals, &handle).ok_or_else(|| {
            "The compositor offers no clipboard data-control protocol (ext-data-control-v1 or wlr-data-control-unstable-v1).".to_string()
        })?;
        let seat: wl_seat::WlSeat = globals
            .bind(&handle, 1..=1, ())
            .map_err(|_| "The compositor offers no seat.".to_string())?;
        let device = protocol.device(&seat, &handle);
        let state = SequenceState {
            machine: PasteSequenceMachine::new(stages.len(), Instant::now(), lifetime),
            stages,
            active_transfers: Arc::new(AtomicUsize::new(0)),
        };
        let mut session = Self {
            connection,
            queue,
            state,
            protocol,
            device,
            source: None,
        };
        session.offer_stage(0);
        session.confirm_first_stage()?;
        Ok(session)
    }

    /// Waits for the compositor to process the first selection and checks
    /// that it was neither rejected nor immediately replaced.
    fn confirm_first_stage(&mut self) -> Result<(), String> {
        self.queue
            .roundtrip(&mut self.state)
            .map_err(|e| format!("The compositor rejected the clipboard selection: {e}"))?;
        if self.state.machine.is_finished() {
            self.release_objects();
            return Err(
                "The clipboard selection was replaced before it could be used.".to_string(),
            );
        }
        Ok(())
    }

    /// Offers `stage` as the selection and destroys the previous source.
    fn offer_stage(&mut self, stage: usize) {
        let handle = self.queue.handle();
        let source = self.protocol.stage_source(stage, &handle);
        self.device.set_selection(Some(&source));
        if let Some(previous) = self.source.replace(source) {
            previous.destroy();
        }
    }

    /// The event loop: dispatches events, applies the machine's directives
    /// and waits for the next event, wake-up or timer.
    fn run(&mut self, control: &SequenceControl, wake_receiver: &UnixStream) {
        loop {
            if self.queue.dispatch_pending(&mut self.state).is_err() {
                break;
            }
            if control.withdrawal_requested() {
                self.state.machine.record_withdrawal_request();
            }
            let directive = self.state.machine.poll(Instant::now());
            if directive.is_terminal() {
                self.conclude(directive);
                return;
            }
            if let SequenceDirective::OfferStage(stage) = directive {
                self.offer_stage(stage);
                crate::log_info!(
                    "omawarden:clipboard",
                    "Paste sequence advanced to stage {} of {}.",
                    stage + 1,
                    self.state.stages.len()
                );
            }
            if self.await_activity(wake_receiver).is_err() {
                break;
            }
        }
        crate::log_warn!(
            "omawarden:clipboard",
            "The Wayland connection of the paste sequence failed; the sequence ended."
        );
    }

    /// Ends the sequence. A withdrawal clears the selection only while this
    /// sequence still owns it: events still in flight are processed first,
    /// and a cancelled source (another client took the selection) leaves
    /// that client's selection alone.
    fn conclude(&mut self, directive: SequenceDirective) {
        if let SequenceDirective::Withdraw(reason) = directive {
            let _ = self.queue.roundtrip(&mut self.state);
            if self.state.machine.owns_selection() {
                self.device.set_selection(None);
            }
            log_withdrawal(reason);
        } else {
            crate::log_info!(
                "omawarden:clipboard",
                "Paste sequence ended: another application took the clipboard."
            );
        }
        self.release_objects();
        let _ = self.queue.roundtrip(&mut self.state);
    }

    fn release_objects(&mut self) {
        if let Some(source) = self.source.take() {
            source.destroy();
        }
        self.device.destroy();
        self.protocol.destroy();
        let _ = self.connection.flush();
    }

    /// Flushes requests, then waits for compositor events, a wake-up from
    /// the daemon, or the machine's next timer, whichever comes first.
    fn await_activity(&mut self, wake_receiver: &UnixStream) -> Result<(), ()> {
        self.connection.flush().map_err(|_| ())?;
        let Some(guard) = self.queue.prepare_read() else {
            return Ok(());
        };
        let timeout = self
            .state
            .machine
            .next_wakeup()
            .saturating_duration_since(Instant::now())
            .min(MAX_EVENT_WAIT);
        let readiness = poll_readable(&[guard.connection_fd(), wake_receiver.as_fd()], timeout);
        if readiness.first().copied().unwrap_or(false) {
            read_events(guard)?;
        }
        drain_wake_channel(wake_receiver);
        Ok(())
    }
}

fn log_withdrawal(reason: WithdrawalReason) {
    let cause = match reason {
        WithdrawalReason::Completed => "every stage was pasted",
        WithdrawalReason::DeadlineReached => "the auto-clear deadline passed",
        WithdrawalReason::Requested => "the daemon withdrew it",
    };
    crate::log_info!(
        "omawarden:clipboard",
        "Paste sequence withdrew its clipboard selection: {}.",
        cause
    );
}

fn read_events(guard: wayland_client::backend::ReadEventsGuard) -> Result<(), ()> {
    match guard.read() {
        Ok(_) => Ok(()),
        Err(wayland_client::backend::WaylandError::Io(error))
            if error.kind() == ErrorKind::WouldBlock =>
        {
            Ok(())
        }
        Err(_) => Err(()),
    }
}

fn drain_wake_channel(mut wake_receiver: &UnixStream) {
    let mut buffer = [0u8; 64];
    while matches!(wake_receiver.read(&mut buffer), Ok(read) if read > 0) {}
}

/// Polls `descriptors` for readability for at most `timeout`; one flag per
/// descriptor (errors and hang-ups count as readable, so they are read and
/// reported).
fn poll_readable(descriptors: &[BorrowedFd<'_>], timeout: Duration) -> Vec<bool> {
    let mut entries: Vec<libc::pollfd> = descriptors
        .iter()
        .map(|descriptor| libc::pollfd {
            fd: descriptor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    let ready = unsafe {
        libc::poll(
            entries.as_mut_ptr(),
            entries.len() as libc::nfds_t,
            poll_timeout_millis(timeout),
        )
    };
    if ready <= 0 {
        return vec![false; entries.len()];
    }
    entries
        .iter()
        .map(|entry| entry.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0)
        .collect()
}

/// `timeout` in whole milliseconds for `poll`, rounded up so a wait never
/// ends just before the instant it waits for.
fn poll_timeout_millis(timeout: Duration) -> libc::c_int {
    let millis = timeout.as_micros().div_ceil(1000);
    libc::c_int::try_from(millis).unwrap_or(libc::c_int::MAX)
}

/// Releases one transfer slot when the transfer thread ends.
struct TransferSlot(Arc<AtomicUsize>);

impl Drop for TransferSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn reserve_transfer_slot(active: &Arc<AtomicUsize>) -> Option<TransferSlot> {
    active
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
            (count < MAX_CONCURRENT_TRANSFERS).then_some(count + 1)
        })
        .ok()
        .map(|_| TransferSlot(Arc::clone(active)))
}

/// Writes `payload` to `descriptor` on a transfer thread. Refused (the
/// descriptor is closed unwritten) when `MAX_CONCURRENT_TRANSFERS` are
/// already in progress.
fn spawn_transfer(
    descriptor: OwnedFd,
    payload: zeroize::Zeroizing<Vec<u8>>,
    active: &Arc<AtomicUsize>,
) {
    let Some(slot) = reserve_transfer_slot(active) else {
        return;
    };
    let _ = std::thread::Builder::new()
        .name("paste-transfer".into())
        .spawn(move || {
            let _slot = slot;
            let _ = write_with_deadline(File::from(descriptor), &payload, TRANSFER_WRITE_TIMEOUT);
        });
}

/// Writes all of `payload` to a non-blocking `file`, waiting for
/// writability at most until `timeout` has passed. The descriptor is closed
/// when `file` is dropped, which ends the transfer for the reader.
pub(crate) fn write_with_deadline(
    mut file: File,
    payload: &[u8],
    timeout: Duration,
) -> std::io::Result<()> {
    set_nonblocking(&file)?;
    let deadline = Instant::now() + timeout;
    let mut written = 0;
    while written < payload.len() {
        match file.write(&payload[written..]) {
            Ok(0) => return Err(ErrorKind::WriteZero.into()),
            Ok(count) => written += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                await_writable(&file, deadline)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn set_nonblocking(file: &File) -> std::io::Result<()> {
    let descriptor = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn await_writable(file: &File, deadline: Instant) -> std::io::Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ErrorKind::TimedOut.into());
    }
    let mut entry = libc::pollfd {
        fd: file.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    let ready = unsafe { libc::poll(&mut entry, 1, poll_timeout_millis(remaining)) };
    if ready < 0 {
        let error = std::io::Error::last_os_error();
        return if error.kind() == ErrorKind::Interrupted {
            Ok(())
        } else {
            Err(error)
        };
    }
    if ready == 0 {
        return Err(ErrorKind::TimedOut.into());
    }
    Ok(())
}

impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for SequenceState {
    fn event(
        _: &mut Self,
        _: &wl_registry::WlRegistry,
        _: wl_registry::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

delegate_noop!(SequenceState: ignore wl_seat::WlSeat);
delegate_noop!(SequenceState: ext_manager::ExtDataControlManagerV1);
delegate_noop!(SequenceState: wlr_manager::ZwlrDataControlManagerV1);
delegate_noop!(SequenceState: ignore ext_offer::ExtDataControlOfferV1);
delegate_noop!(SequenceState: ignore wlr_offer::ZwlrDataControlOfferV1);

impl Dispatch<ext_source::ExtDataControlSourceV1, usize> for SequenceState {
    fn event(
        state: &mut Self,
        _: &ext_source::ExtDataControlSourceV1,
        event: ext_source::Event,
        stage: &usize,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            ext_source::Event::Send { mime_type, fd } => state.handle_send(*stage, &mime_type, fd),
            ext_source::Event::Cancelled => state.machine.record_cancelled(*stage),
            _ => {}
        }
    }
}

impl Dispatch<wlr_source::ZwlrDataControlSourceV1, usize> for SequenceState {
    fn event(
        state: &mut Self,
        _: &wlr_source::ZwlrDataControlSourceV1,
        event: wlr_source::Event,
        stage: &usize,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            wlr_source::Event::Send { mime_type, fd } => state.handle_send(*stage, &mime_type, fd),
            wlr_source::Event::Cancelled => state.machine.record_cancelled(*stage),
            _ => {}
        }
    }
}

/// Offers announced to the device (including the one for our own source)
/// are not read; they are destroyed as soon as the compositor names them.
impl Dispatch<ext_device::ExtDataControlDeviceV1, ()> for SequenceState {
    fn event(
        state: &mut Self,
        _: &ext_device::ExtDataControlDeviceV1,
        event: ext_device::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            ext_device::Event::Selection { id: Some(offer) }
            | ext_device::Event::PrimarySelection { id: Some(offer) } => offer.destroy(),
            ext_device::Event::Finished => state.machine.record_device_finished(),
            _ => {}
        }
    }

    event_created_child!(SequenceState, ext_device::ExtDataControlDeviceV1, [
        ext_device::EVT_DATA_OFFER_OPCODE => (ext_offer::ExtDataControlOfferV1, ()),
    ]);
}

impl Dispatch<wlr_device::ZwlrDataControlDeviceV1, ()> for SequenceState {
    fn event(
        state: &mut Self,
        _: &wlr_device::ZwlrDataControlDeviceV1,
        event: wlr_device::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            wlr_device::Event::Selection { id: Some(offer) }
            | wlr_device::Event::PrimarySelection { id: Some(offer) } => offer.destroy(),
            wlr_device::Event::Finished => state.machine.record_device_finished(),
            _ => {}
        }
    }

    event_created_child!(SequenceState, wlr_device::ZwlrDataControlDeviceV1, [
        wlr_device::EVT_DATA_OFFER_OPCODE => (wlr_offer::ZwlrDataControlOfferV1, ()),
    ]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_with_deadline_delivers_the_payload_and_closes() {
        let (reader, writer) = UnixStream::pair().unwrap();
        let writer = File::from(OwnedFd::from(writer));
        write_with_deadline(writer, b"stage-value", Duration::from_secs(1)).unwrap();
        let mut received = Vec::new();
        (&reader).read_to_end(&mut received).unwrap();
        assert_eq!(
            received, b"stage-value",
            "the descriptor is closed after the write"
        );
    }

    #[test]
    fn test_write_with_deadline_gives_up_on_a_stalled_reader() {
        let (reader, writer) = UnixStream::pair().unwrap();
        let writer = File::from(OwnedFd::from(writer));
        // Far more than a socket buffer holds, and the reader never reads.
        let payload = vec![b'x'; 8 * 1024 * 1024];
        let started = Instant::now();
        let result = write_with_deadline(writer, &payload, Duration::from_millis(200));
        assert_eq!(result.unwrap_err().kind(), ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(reader);
    }

    #[test]
    fn test_write_with_deadline_stops_when_the_reader_closes() {
        let (reader, writer) = UnixStream::pair().unwrap();
        drop(reader);
        let writer = File::from(OwnedFd::from(writer));
        assert!(write_with_deadline(writer, b"value", Duration::from_secs(1)).is_err());
    }

    #[test]
    fn test_transfer_slots_are_bounded_and_released() {
        let active = Arc::new(AtomicUsize::new(0));
        let slots: Vec<_> = (0..MAX_CONCURRENT_TRANSFERS)
            .map(|_| reserve_transfer_slot(&active).expect("within the limit"))
            .collect();
        assert!(reserve_transfer_slot(&active).is_none());
        drop(slots);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_poll_timeout_rounds_up() {
        assert_eq!(poll_timeout_millis(Duration::ZERO), 0);
        assert_eq!(poll_timeout_millis(Duration::from_micros(1)), 1);
        assert_eq!(poll_timeout_millis(Duration::from_millis(400)), 400);
        assert_eq!(
            poll_timeout_millis(Duration::from_secs(u64::MAX)),
            libc::c_int::MAX
        );
    }

    #[test]
    fn test_control_withdrawal_wakes_and_waits() {
        let (control, wake_receiver) = SequenceControl::with_wake_channel().unwrap();
        assert!(!control.is_finished());
        let thread_control = Arc::clone(&control);
        let worker = std::thread::spawn(move || {
            let _finished = FinishedOnDrop(Arc::clone(&thread_control));
            let ready = poll_readable(&[wake_receiver.as_fd()], Duration::from_secs(5));
            assert_eq!(ready, vec![true]);
            assert!(thread_control.withdrawal_requested());
            drain_wake_channel(&wake_receiver);
        });
        assert!(control.withdraw_and_wait(Duration::from_secs(5)));
        assert!(control.is_finished());
        assert!(
            !control.withdraw_and_wait(Duration::from_secs(1)),
            "a finished sequence is not withdrawn again"
        );
        worker.join().unwrap();
    }

    #[test]
    fn test_unattended_control_finishes_on_withdrawal() {
        let control = SequenceControl::unattended();
        assert!(control.withdraw_and_wait(Duration::from_millis(100)));
        assert!(control.is_finished());
    }

    #[test]
    fn test_empty_sequence_is_refused_without_connecting() {
        assert!(start_paste_sequence(Vec::new(), Duration::from_secs(1)).is_err());
    }
}
