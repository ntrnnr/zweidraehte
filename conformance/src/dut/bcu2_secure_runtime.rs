//! The mask-0021 Data Secure BCU2 micro stack in its blocking runloop.
//!
//! This deliberately has no embassy executor or async device plumbing. The
//! conformance socket stands in for the TPUART while the actual device remains
//! one owner and one `poll()` call per input, exactly like the micro firmware.

use std::io::{self, Write};
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::time::Instant;

use super::bcu2_secure_stack::{self, Device};
use super::bcu2_stack;
use super::common::{drain_logs, init_ipc_logger, load_or_seed_snapshot_with_status, log_level_from_env, parse_args};
use super::fixture_common::{configure_polling_socket, init_secure_storage, seed_eitt_boot_siat, set_seq_shm_ptr};
use super::micro_group_objects::MICRO_CONFORMANCE_APPLICATION;
use crate::ipc::framing::{read_msg_blocking, write_msg_blocking};
use crate::ipc::protocol::{CapturedFrame, DutMessage, ExitReason, RunnerMessage};
use crate::ipc::shm::SharedMemory;
use zweidraehte_microdevice::device::{PollInput, PollOutput};
use zweidraehte_microdevice::families::bcu2::offsets;
use zweidraehte_microdevice::frame::SECURE_EXTENDED_FRAME;
use zweidraehte_microdevice::snapshot::SecureMicroSnapshot;
use zweidraehte_proto::messages::apdu::restart::EraseCode;
use zweidraehte_proto::security::{SiatAccess, erase_seq_on_factory_reset};

const L_DATA_REQ: u8 = 0x11;

/// Which persistent boot image the shared secure run loop exposes.
#[derive(Debug, Clone, Copy)]
pub enum BootImage {
    /// The ordinary mixed-width BCU2 application used by the base templates.
    BaseProfile,
    /// The AN158 four-bit-object application used by the Data Secure template.
    DataSecurity,
}

/// Run the secure BCU2 DUT with the requested conformance application.
pub fn run(boot_image: BootImage) -> ! {
    let binary_name = match boot_image {
        BootImage::BaseProfile => "conformance-dut-bcu2-secure-base",
        BootImage::DataSecurity => "conformance-dut-bcu2-secure",
    };
    let (shm_fd, socket_fd) = parse_args(binary_name);
    // SAFETY: the fd numbers come from the parent's spawn contract.
    let mut shm = unsafe { SharedMemory::from_raw_fd(shm_fd) }.expect("map shared memory");
    init_ipc_logger(log_level_from_env());

    // The sequence resource is deliberately outside the postcard snapshot.
    // It occupies the SHM tail, which `full_reset` zeroes together with the
    // ordinary configuration region.
    set_seq_shm_ptr(shm.seq_region_ptr());
    let _ = init_secure_storage();

    let time_divisor = time_divisor();
    let (snapshot, seeded) = match boot_image {
        BootImage::BaseProfile => load_or_seed_snapshot_with_status(&mut shm, bcu2_secure_stack::base_profile_snapshot),
        BootImage::DataSecurity => load_or_seed_snapshot_with_status(&mut shm, bcu2_secure_stack::boot_snapshot),
    };
    if seeded && matches!(boot_image, BootImage::DataSecurity) {
        seed_eitt_boot_siat();
    }
    let mut device: Device = snapshot.restore(bcu2_stack::identity(), time_divisor);
    log::info!("secure BCU2 DUT up: IA {}, time divisor {}", device.individual_address(), time_divisor);

    // SAFETY: ownership of the fd is ours; the logger holds its own dup.
    let mut socket = unsafe { UnixStream::from_raw_fd(socket_fd) };
    let fast_polling = configure_polling_socket(&socket, time_divisor).expect("configure polling DUT command socket");

    let mut frame_seq = 0u32;

    send(&mut socket, &DutMessage::Ready);
    send(&mut socket, &DutMessage::RoiComplete);

    let start = Instant::now();
    loop {
        let now_ms = start.elapsed().as_millis() as u32;
        match read_msg_blocking::<RunnerMessage>(&mut socket) {
            Ok(Some(msg)) => handle_command(msg, boot_image, &mut device, &mut socket, &mut shm, now_ms),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
            Ok(None) => std::process::exit(0),
            Err(e) => {
                log::error!("IPC read failed: {e}");
                std::process::exit(1);
            }
        }

        let out = poll_device(boot_image, &mut device, PollInput::Timer, now_ms);
        send_unsolicited(&mut socket, &mut frame_seq, out);

        if fast_polling {
            std::thread::yield_now();
        }
    }
}

fn handle_command(
    msg: RunnerMessage,
    boot_image: BootImage,
    device: &mut Device,
    socket: &mut UnixStream,
    shm: &mut SharedMemory,
    now_ms: u32,
) {
    match msg {
        RunnerMessage::Inject { seq, data } => {
            let failures_before = *device.security_state().security.failures_log().borrow().counters();
            let out = poll_device(boot_image, device, PollInput::Frame(&data), now_ms);
            let failures = device.security_state().security.failures_log().borrow();
            if *failures.counters() != failures_before
                && let Some(latest) = failures.get_by_index(0)
            {
                log::debug!(
                    "secure admission failure type={} source={:04X} counters={:?}",
                    latest.failure_type,
                    latest.source_addr,
                    failures.counters()
                );
            }
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
            finish_step(socket, seq, poll_device(boot_image, device, PollInput::Timer, now_ms));
        }
        RunnerMessage::TriggerWrite { seq, asap } => {
            let out = match boot_image {
                BootImage::BaseProfile => MICRO_CONFORMANCE_APPLICATION.trigger_write(device, asap as u8, now_ms),
                BootImage::DataSecurity => {
                    device.set_transmit_request(asap as u8);
                    device.poll(PollInput::Timer, now_ms)
                }
            };

            finish_step(socket, seq, out);
        }
        RunnerMessage::TriggerSync { seq, .. } => {
            // Client commissioning sends the actual S-A_Sync request over the
            // bus. The harness shortcut has no spontaneous-tool equivalent.
            finish_step(socket, seq, PollOutput::<SECURE_EXTENDED_FRAME>::default());
        }
        RunnerMessage::PowerCycle => exit_with(device, socket, shm, ExitReason::PowerCycle),
        RunnerMessage::MasterReset { erase_code } => {
            // This out-of-band command models the template operator's local
            // factory reset. It must restore the actual device factory
            // security context (FDSK, Security Mode off), not the
            // operator-provisioned EITT sample image (TK1). Bus-visible
            // master reset runs through the stack and applies the complete
            // erase-code policy.
            let ia = device.individual_address();
            let _ = device.security_state_mut().seq.siat_clear();
            let code = EraseCode::from(erase_code);
            let _ = erase_seq_on_factory_reset(&mut device.security_state_mut().seq, code);
            let mut factory = bcu2_secure_stack::local_factory_snapshot();
            match code {
                EraseCode::FactoryReset => {
                    factory.base.eeprom[offsets::INDIVIDUAL_ADDRESS..offsets::INDIVIDUAL_ADDRESS + 2]
                        .copy_from_slice(&[0xFF, 0xFF]);
                }
                EraseCode::FactoryResetKeepIA => {
                    factory.base.eeprom[offsets::INDIVIDUAL_ADDRESS..offsets::INDIVIDUAL_ADDRESS + 2]
                        .copy_from_slice(ia.as_bytes());
                }
                _ => {}
            }
            *device = factory.restore(bcu2_stack::identity(), time_divisor());
            exit_with(device, socket, shm, ExitReason::MasterReset { erase_code });
        }
    }
}

fn finish_step<const N: usize>(socket: &mut UnixStream, seq: u32, out: PollOutput<N>) {
    if let Some(error) = out.frame_error {
        panic!("micro stack failed to encode output frame: {error}");
    }

    let frames =
        out.frames.iter().map(|frame| CapturedFrame { service_type: L_DATA_REQ, data: frame.to_vec() }).collect();

    send(socket, &DutMessage::StepComplete { seq, frames });
}

fn poll_device(
    boot_image: BootImage,
    device: &mut Device,
    input: PollInput<'_>,
    now_ms: u32,
) -> PollOutput<SECURE_EXTENDED_FRAME> {
    match boot_image {
        BootImage::BaseProfile => MICRO_CONFORMANCE_APPLICATION.poll(device, input, now_ms),
        BootImage::DataSecurity => device.poll(input, now_ms),
    }
}

fn send_unsolicited(socket: &mut UnixStream, frame_seq: &mut u32, out: PollOutput<SECURE_EXTENDED_FRAME>) {
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

fn exit_with(device: &Device, socket: &mut UnixStream, shm: &mut SharedMemory, reason: ExitReason) -> ! {
    send(socket, &DutMessage::Exiting { reason });

    let snapshot = SecureMicroSnapshot::capture(device);
    if let Err(e) = shm.write_state(&snapshot) {
        log::error!("snapshot flush failed: {e}");
    }

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
