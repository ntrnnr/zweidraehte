//! The micro-System-7 conformance DUT: `zweidraehte-microdevice`'s
//! System 7 family (mask 0705h) in a plain blocking main loop.
//!
//! Structurally the twin of `dut_bcu2` — see that binary's module doc
//! for why the strictly request/response IPC protocol maps directly
//! onto the micro stack's `poll()` runloop. The family differences are
//! all inside the stack: TL Style 3, System 7 tables, both
//! load-control paths, 16 authorization levels.

use std::io::{self, Write};
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use zweidraehte_conformance::dut::common::{
    drain_logs, init_ipc_logger, load_or_seed_snapshot, log_level_from_env, parse_args,
};
use zweidraehte_conformance::dut::micro_group_objects::UINT1_SAMPLE_APPLICATION;
use zweidraehte_conformance::dut::micro_system7_stack::{self, MicroSystem7DutFamily};
use zweidraehte_conformance::ipc::framing::{read_msg_blocking, write_msg_blocking};
use zweidraehte_conformance::ipc::protocol::{CapturedFrame, DutMessage, ExitReason, RunnerMessage};
use zweidraehte_conformance::ipc::shm::SharedMemory;
use zweidraehte_microdevice::device::{Microdevice, PollInput, PollOutput};
use zweidraehte_microdevice::snapshot::MicroSnapshot;

/// `ServiceType::L_Data_Req` — the service every outgoing DUT frame
/// carries.
const L_DATA_REQ: u8 = 0x11;

type Dut = Microdevice<MicroSystem7DutFamily>;

fn main() {
    let (shm_fd, socket_fd) = parse_args("conformance-dut-micro-system7");
    // SAFETY: the fd numbers come from our parent's spawn contract.
    let mut shm = unsafe { SharedMemory::from_raw_fd(shm_fd) }.expect("map shared memory");
    init_ipc_logger(log_level_from_env());

    let time_divisor: u32 = std::env::var("KNX_TIME_DIVISOR").ok().and_then(|v| v.parse().ok()).unwrap_or(1);

    let snapshot = load_or_seed_snapshot(&mut shm, micro_system7_stack::factory_snapshot);
    let mut device: Dut = snapshot.restore(micro_system7_stack::identity(), time_divisor);
    log::info!("micro-System-7 DUT up: IA {}, time divisor {}", device.individual_address(), time_divisor);

    // The primary socket, blocking with a short receive timeout so the
    // loop alternates between command handling and timer ticks.
    // SAFETY: ownership of the fd is ours per the spawn contract; the
    // logger holds its own dup.
    let mut socket = unsafe { UnixStream::from_raw_fd(socket_fd) };
    socket.set_read_timeout(Some(Duration::from_millis(2))).expect("socketpair supports SO_RCVTIMEO");

    let mut frame_seq = 0u32;

    send(&mut socket, &DutMessage::Ready);
    send(&mut socket, &DutMessage::RoiComplete);

    let start = Instant::now();

    loop {
        let now_ms = start.elapsed().as_millis() as u32;
        match read_msg_blocking::<RunnerMessage>(&mut socket) {
            Ok(Some(msg)) => handle_command(msg, &mut device, &mut socket, &mut shm, now_ms),
            // Timeout: nothing pending — fall through to the timer tick.
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
            // EOF or a broken socket: the parent went away.
            Ok(None) => std::process::exit(0),
            Err(e) => {
                log::error!("IPC read failed: {e}");
                std::process::exit(1);
            }
        }

        // Timer tick: TL timeouts, retransmissions, transmit-request
        // scans. Anything produced here belongs to no step.
        let out = UINT1_SAMPLE_APPLICATION.poll(&mut device, PollInput::Timer, now_ms);
        send_unsolicited(&mut socket, &mut frame_seq, out);
    }
}

fn handle_command(msg: RunnerMessage, device: &mut Dut, socket: &mut UnixStream, shm: &mut SharedMemory, now_ms: u32) {
    match msg {
        RunnerMessage::Inject { seq, data } => {
            let out = UINT1_SAMPLE_APPLICATION.poll(device, PollInput::Frame(&data), now_ms);
            let restart = out.restart;
            finish_step(socket, seq, out);
            if let Some(erase_code) = restart {
                exit_with(device, socket, shm, ExitReason::Restart { erase_code });
            }
        }
        RunnerMessage::SetProgrammingMode { seq, enabled } => {
            device.set_programming_mode(enabled);
            finish_step(socket, seq, PollOutput::default());
        }
        RunnerMessage::TriggerRead { seq, asap } => {
            device.set_read_request(asap as u8);
            let out = UINT1_SAMPLE_APPLICATION.poll(device, PollInput::Timer, now_ms);
            finish_step(socket, seq, out);
        }
        RunnerMessage::TriggerWrite { seq, asap } => {
            device.set_transmit_request(asap as u8);
            let out = UINT1_SAMPLE_APPLICATION.poll(device, PollInput::Timer, now_ms);
            finish_step(socket, seq, out);
        }
        RunnerMessage::TriggerSync { seq, .. } => {
            // Data Secure is not part of the micro System 7 profile.
            log::warn!("TriggerSync on the micro-System-7 DUT is a no-op");
            finish_step(socket, seq, PollOutput::default());
        }
        RunnerMessage::PowerCycle => {
            exit_with(device, socket, shm, ExitReason::PowerCycle);
        }
        RunnerMessage::MasterReset { erase_code } => {
            // Factory state; code 03h (FactoryResetWithoutIA) preserves
            // the commissioned address by patching it into the fresh
            // image — on RT8 the IA lives at ADT bytes 1–2.
            let ia = device.individual_address();
            let mut factory = micro_system7_stack::factory_snapshot();
            if erase_code == 0x03 {
                factory.eeprom[1..3].copy_from_slice(ia.as_bytes());
            }
            let time_divisor = std::env::var("KNX_TIME_DIVISOR").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
            *device = factory.restore(micro_system7_stack::identity(), time_divisor);
            let _ = now_ms;
            exit_with(device, socket, shm, ExitReason::MasterReset { erase_code });
        }
    }
}

/// Send the step's frames as its `StepComplete` batch.
fn finish_step(socket: &mut UnixStream, seq: u32, out: PollOutput) {
    if let Some(error) = out.frame_error {
        panic!("micro stack failed to encode output frame: {error}");
    }

    let frames =
        out.frames.iter().map(|frame| CapturedFrame { service_type: L_DATA_REQ, data: frame.to_vec() }).collect();

    send(socket, &DutMessage::StepComplete { seq, frames });
}

fn send_unsolicited(socket: &mut UnixStream, frame_seq: &mut u32, out: PollOutput) {
    if let Some(error) = out.frame_error {
        panic!("micro stack failed to encode unsolicited frame: {error}");
    }

    for frame in &out.frames {
        *frame_seq += 1;

        send(socket, &DutMessage::UnsolicitedFrame {
            frame_seq: *frame_seq,
            frame: CapturedFrame { service_type: L_DATA_REQ, data: frame.to_vec() },
        });
    }
}

/// Flush persistent state and terminate the way the protocol expects:
/// `Exiting`, shutdown-write (so the runner sees EOF after the message
/// drains), exit 0.
fn exit_with(device: &Dut, socket: &mut UnixStream, shm: &mut SharedMemory, reason: ExitReason) -> ! {
    let snapshot = MicroSnapshot::capture(device);
    if let Err(e) = shm.write_state(&snapshot) {
        log::error!("snapshot flush failed: {e}");
    }
    send(socket, &DutMessage::Exiting { reason });
    let _ = socket.flush();
    let _ = socket.shutdown(std::net::Shutdown::Write);
    std::process::exit(0);
}

fn send(socket: &mut UnixStream, msg: &DutMessage) {
    // Flush whatever the logger queued first: it never writes to the socket
    // itself, so that a log record can never land inside a protocol frame.
    // Doing it here also keeps a step's records ahead of its `StepComplete`.
    for record in drain_logs() {
        if write_msg_blocking(socket, &record).is_err() {
            std::process::exit(0);
        }
    }
    if let Err(e) = write_msg_blocking(socket, msg) {
        // The parent closed on us mid-write; nothing to clean up.
        log::debug!("IPC write failed: {e}");
        std::process::exit(0);
    }
}
