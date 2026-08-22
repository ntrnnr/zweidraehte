//! The mask-0021 Data Secure BCU2 micro stack in its blocking runloop.
//!
//! This deliberately has no embassy executor or async device plumbing. The
//! conformance socket stands in for the TPUART while the actual device remains
//! one owner and one `poll()` call per input, exactly like the micro firmware.

use std::io::{self, Write};
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use zweidraehte_conformance::dut::bcu2_secure_stack::{self, Device};
use zweidraehte_conformance::dut::bcu2_stack;
use zweidraehte_conformance::dut::common::{
    drain_logs, init_ipc_logger, load_or_seed_snapshot, log_level_from_env, parse_args,
};
use zweidraehte_conformance::dut::fixture_common::{init_secure_storage, set_seq_shm_ptr};
use zweidraehte_conformance::ipc::framing::{read_msg_blocking, write_msg_blocking};
use zweidraehte_conformance::ipc::protocol::{CapturedFrame, DutMessage, ExitReason, RunnerMessage};
use zweidraehte_conformance::ipc::shm::SharedMemory;
use zweidraehte_microdevice::device::{PollInput, PollOutput};
use zweidraehte_microdevice::frame::SECURE_EXTENDED_FRAME;
use zweidraehte_microdevice::snapshot::SecureMicroSnapshot;
use zweidraehte_proto::security::SiatAccess;

const L_DATA_REQ: u8 = 0x11;

fn main() {
    let (shm_fd, socket_fd) = parse_args("conformance-dut-bcu2-secure");
    // SAFETY: the fd numbers come from the parent's spawn contract.
    let mut shm = unsafe { SharedMemory::from_raw_fd(shm_fd) }.expect("map shared memory");
    init_ipc_logger(log_level_from_env());

    // The sequence resource is deliberately outside the postcard snapshot.
    // It occupies the SHM tail, which `full_reset` zeroes together with the
    // ordinary configuration region.
    set_seq_shm_ptr(shm.seq_region_ptr());
    let _ = init_secure_storage();

    let time_divisor = time_divisor();
    let snapshot = load_or_seed_snapshot(&mut shm, bcu2_secure_stack::factory_snapshot);
    let mut device: Device = snapshot.restore(bcu2_stack::identity(), time_divisor);
    log::info!("secure BCU2 DUT up: IA {}, time divisor {}", device.individual_address(), time_divisor);

    // SAFETY: ownership of the fd is ours; the logger holds its own dup.
    let mut socket = unsafe { UnixStream::from_raw_fd(socket_fd) };
    socket.set_read_timeout(Some(Duration::from_millis(2))).expect("socketpair supports SO_RCVTIMEO");

    send(&mut socket, &DutMessage::Ready);
    send(&mut socket, &DutMessage::RoiComplete);

    let start = Instant::now();
    let mut frame_seq = 0u32;
    loop {
        let now_ms = start.elapsed().as_millis() as u32;
        match read_msg_blocking::<RunnerMessage>(&mut socket) {
            Ok(Some(msg)) => handle_command(msg, &mut device, &mut socket, &mut shm, now_ms),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
            Ok(None) => std::process::exit(0),
            Err(e) => {
                log::error!("IPC read failed: {e}");
                std::process::exit(1);
            }
        }

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
    device: &mut Device,
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
            finish_step(socket, seq, PollOutput::<SECURE_EXTENDED_FRAME>::default());
        }
        RunnerMessage::TriggerRead { seq, asap } => {
            device.set_read_request(asap as u8);
            finish_step(socket, seq, device.poll(PollInput::Timer, now_ms));
        }
        RunnerMessage::TriggerWrite { seq, asap } => {
            device.set_transmit_request(asap as u8);
            finish_step(socket, seq, device.poll(PollInput::Timer, now_ms));
        }
        RunnerMessage::TriggerSync { seq, .. } => {
            // Client commissioning sends the actual S-A_Sync request over the
            // bus. The harness shortcut has no spontaneous-tool equivalent.
            finish_step(socket, seq, PollOutput::<SECURE_EXTENDED_FRAME>::default());
        }
        RunnerMessage::PowerCycle => exit_with(device, socket, shm, ExitReason::PowerCycle),
        RunnerMessage::MasterReset { erase_code } => {
            // Out-of-band reset is harness plumbing. Bus-visible master reset
            // runs through the stack and applies the full erase-code policy.
            let ia = device.individual_address();
            let _ = device.security_state_mut().seq.siat_clear();
            let mut factory = bcu2_secure_stack::factory_snapshot();
            if erase_code == 0x03 {
                factory.base.eeprom[0x17..0x19].copy_from_slice(ia.as_bytes());
            }
            *device = factory.restore(bcu2_stack::identity(), time_divisor());
            exit_with(device, socket, shm, ExitReason::MasterReset { erase_code });
        }
    }
}

fn finish_step<const N: usize>(socket: &mut UnixStream, seq: u32, out: PollOutput<N>) {
    let frames = out.frames.iter().map(|f| CapturedFrame { service_type: L_DATA_REQ, data: f.to_vec() }).collect();
    send(socket, &DutMessage::StepComplete { seq, frames });
}

fn exit_with(device: &Device, socket: &mut UnixStream, shm: &mut SharedMemory, reason: ExitReason) -> ! {
    let snapshot = SecureMicroSnapshot::capture(device);
    if let Err(e) = shm.write_state(&snapshot) {
        log::error!("snapshot flush failed: {e}");
    }
    send(socket, &DutMessage::Exiting { reason });
    let _ = socket.flush();
    let _ = socket.shutdown(std::net::Shutdown::Write);
    std::process::exit(0);
}

fn time_divisor() -> u32 {
    std::env::var("KNX_TIME_DIVISOR").ok().and_then(|value| value.parse().ok()).unwrap_or(1)
}

fn send(socket: &mut UnixStream, msg: &DutMessage) {
    for record in drain_logs() {
        if write_msg_blocking(socket, &record).is_err() {
            std::process::exit(0);
        }
    }
    if let Err(e) = write_msg_blocking(socket, msg) {
        log::debug!("IPC write failed: {e}");
        std::process::exit(0);
    }
}
