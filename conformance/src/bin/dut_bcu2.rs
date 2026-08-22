//! The BCU2 conformance DUT: `zweidraehte-microdevice` in a plain
//! blocking main loop.
//!
//! No embassy, no async, no channels — the point of this binary is to
//! run the micro stack exactly the way its firmware targets do: one
//! owner struct, one `poll()` per input, and the IPC socket standing
//! in for the TPUART. The strictly request/response IPC protocol maps
//! onto that runloop directly:
//!
//! - `Inject` → `poll(Frame)` → the returned frames *are* the
//!   `StepComplete` batch. Single-threaded, so there is no drain
//!   ambiguity and no step barrier — everything a command caused has
//!   been produced by the time `poll()` returns.
//! - Between commands the loop ticks `poll(Timer)` (the socket read
//!   runs a short `SO_RCVTIMEO`); anything a TL timeout produces
//!   becomes an `UnsolicitedFrame`.
//! - `A_Restart` surfaces as `PollOutput::restart`: flush the
//!   snapshot, emit `Exiting`, and let the runner respawn us — the
//!   respawn is the restart, exactly like a power-cycled BCU.

use std::io::{self, Write};
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use zweidraehte_conformance::dut::bcu2_stack;
use zweidraehte_conformance::dut::common::{init_ipc_logger, load_or_seed_snapshot, log_level_from_env, parse_args};
use zweidraehte_conformance::ipc::framing::{read_msg_blocking, write_msg_blocking};
use zweidraehte_conformance::ipc::protocol::{CapturedFrame, DutMessage, ExitReason, RunnerMessage};
use zweidraehte_conformance::ipc::shm::SharedMemory;
use zweidraehte_microdevice::device::{Microdevice, PollInput, PollOutput};
use zweidraehte_microdevice::families::bcu2::Bcu2Family;
use zweidraehte_microdevice::snapshot::MicroSnapshot;

/// `ServiceType::L_Data_Req` — the service every outgoing DUT frame
/// carries. Spelled as the raw byte so this binary does not need the
/// message-buffer machinery for one constant.
const L_DATA_REQ: u8 = 0x11;

fn main() {
    let (shm_fd, socket_fd) = parse_args("conformance-dut-bcu2");
    // SAFETY: the fd numbers come from our parent's spawn contract.
    let mut shm = unsafe { SharedMemory::from_raw_fd(shm_fd) }.expect("map shared memory");
    init_ipc_logger(socket_fd, log_level_from_env());

    let time_divisor: u32 = std::env::var("KNX_TIME_DIVISOR").ok().and_then(|v| v.parse().ok()).unwrap_or(1);

    let snapshot = load_or_seed_snapshot(&mut shm, bcu2_stack::factory_snapshot);
    let mut device: Microdevice<Bcu2Family> = snapshot.restore(bcu2_stack::identity(), time_divisor);
    log::info!("BCU2 DUT up: IA {}, time divisor {}", device.individual_address(), time_divisor);

    // The primary socket, blocking with a short receive timeout so the
    // loop alternates between command handling and timer ticks.
    // SAFETY: ownership of the fd is ours per the spawn contract; the
    // logger holds its own dup.
    let mut socket = unsafe { UnixStream::from_raw_fd(socket_fd) };
    socket.set_read_timeout(Some(Duration::from_millis(2))).expect("socketpair supports SO_RCVTIMEO");

    send(&mut socket, &DutMessage::Ready);
    // The micro stack has no read-on-init scan (TODO in the crate), so
    // the ROI phase is empty by construction.
    send(&mut socket, &DutMessage::RoiComplete);

    let start = Instant::now();
    let mut frame_seq: u32 = 0;

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
        let out = device.poll(PollInput::Timer, now_ms);
        for frame in &out.frames {
            frame_seq += 1;
            send(&mut socket, &DutMessage::UnsolicitedFrame {
                frame_seq,
                frame: CapturedFrame { service_type: L_DATA_REQ, data: frame.to_vec() },
            });
        }
    }
}

fn handle_command(
    msg: RunnerMessage,
    device: &mut Microdevice<Bcu2Family>,
    socket: &mut UnixStream,
    shm: &mut SharedMemory,
    now_ms: u32,
) {
    match msg {
        RunnerMessage::Inject { seq, data } => {
            let out = device.poll(PollInput::Frame(&data), now_ms);
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
            let out = device.poll(PollInput::Timer, now_ms);
            finish_step(socket, seq, out);
        }
        RunnerMessage::TriggerWrite { seq, asap } => {
            device.set_transmit_request(asap as u8);
            let out = device.poll(PollInput::Timer, now_ms);
            finish_step(socket, seq, out);
        }
        RunnerMessage::TriggerSync { seq, .. } => {
            // Data Secure does not exist on mask 0020h.
            log::warn!("TriggerSync on the BCU2 DUT is a no-op");
            finish_step(socket, seq, PollOutput::default());
        }
        RunnerMessage::PowerCycle => {
            exit_with(device, socket, shm, ExitReason::PowerCycle);
        }
        RunnerMessage::MasterReset { erase_code } => {
            // The master-reset service postdates the BCU2; the harness
            // command still works and means "factory state". The one
            // nuance kept: code 03h (FactoryResetWithoutIA) preserves
            // the commissioned address by patching it into the fresh
            // image before the restore.
            let ia = device.individual_address();
            let mut factory = bcu2_stack::factory_snapshot();
            if erase_code == 0x03 {
                factory.eeprom[0x17..0x19].copy_from_slice(ia.as_bytes());
            }
            let time_divisor = std::env::var("KNX_TIME_DIVISOR").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
            *device = factory.restore(bcu2_stack::identity(), time_divisor);
            let _ = now_ms;
            exit_with(device, socket, shm, ExitReason::MasterReset { erase_code });
        }
    }
}

/// Send the step's frames as its `StepComplete` batch.
fn finish_step(socket: &mut UnixStream, seq: u32, out: PollOutput) {
    let frames = out.frames.iter().map(|f| CapturedFrame { service_type: L_DATA_REQ, data: f.to_vec() }).collect();
    send(socket, &DutMessage::StepComplete { seq, frames });
}

/// Flush persistent state and terminate the way the protocol expects:
/// `Exiting`, shutdown-write (so the runner sees EOF after the message
/// drains), exit 0.
fn exit_with(
    device: &Microdevice<Bcu2Family>,
    socket: &mut UnixStream,
    shm: &mut SharedMemory,
    reason: ExitReason,
) -> ! {
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
    if let Err(e) = write_msg_blocking(socket, msg) {
        // The parent closed on us mid-write; nothing to clean up.
        log::debug!("IPC write failed: {e}");
        std::process::exit(0);
    }
}
