//! Example: switch a device's programming mode on or off, addressed
//! by its serial number — the software equivalent of walking over and
//! pressing the button.
//!
//! Usage:
//!     cargo run -p zweidraehte-client --example prog_mode -- \
//!         --server 192.168.1.100:3671 --serial 00C50011AABB on
//!
//! The serial (12 hex chars; `line_scan`/`device_scan` print it)
//! resolves to the device's individual address via
//! `NM_IndividualAddress_SerialNumber_Read`, which every device
//! answers whether or not it is in programming mode. How the mode is
//! then flipped depends on the device generation, read from its
//! descriptor:
//!
//! - System 7 / BCU-era masks keep programming mode as bit 0 of the
//!   memory byte at 0060h (03/05/01) — a read-modify-write preserving
//!   the byte's other bits.
//! - Everything newer exposes it as PID_PROGMODE (54) on the device
//!   object — a plain property write.

mod common;

use clap::Parser;
use common::{TargetArgs, format_serial, parse_hex_array};
use zweidraehte_client::{MaskFamily, MaskVersion, pid};

/// The System 7 / BCU programming-mode byte (03/05/01: 0060h, bit 0).
const BCU_PROG_MODE_ADDR: u16 = 0x0060;

/// Switch a device's programming mode by serial number.
#[derive(Parser)]
struct Args {
    #[command(flatten)]
    target: TargetArgs,

    /// The device's 6-byte serial number, 12 hex chars (see line_scan)
    #[arg(long, value_parser = parse_hex_array::<6>)]
    serial: [u8; 6],

    /// The mode to set
    #[arg(value_enum)]
    mode: Mode,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Mode {
    On,
    Off,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = Args::parse();
    let bus = args.target.to_target().connect().await?;
    let nm = bus.network_management();

    println!("Looking up serial {}…", format_serial(&args.serial));
    let addr = nm.read_individual_address_by_serial(&args.serial).await?;
    println!("Device answers as {addr}.");

    // The descriptor decides which realization of programming mode
    // this generation has.
    let descriptor = nm.device_descriptor_read(addr, 0).await?;
    let mask = MaskVersion::from(u16::from_be_bytes([descriptor[0], descriptor[1]]));

    let now_active = match mask.family() {
        // System B is the property generation; everything else
        // (System 7, the BIMs, and the BCU-era masks the family
        // mapping defaults to System7) keeps the mode in memory.
        MaskFamily::SystemB => {
            // Property realization: PID_PROGMODE on the device object.
            let mut connection = bus.connect_device(addr).await?;
            let result = async {
                connection.property_write(0, pid::device::PROGMODE, 1, 1, &[u8::from(args.mode == Mode::On)]).await?;
                let read_back = connection.property_read(0, pid::device::PROGMODE, 1, 1).await?;
                Ok::<_, zweidraehte_client::Error>(read_back.first().is_some_and(|b| b & 0x01 != 0))
            }
            .await;
            let _ = connection.close().await;
            result?
        }
        _ => {
            // Memory realization: bit 0 of 0060h, other bits preserved.
            let mut connection = bus.connect_device(addr).await?;
            let result = async {
                let byte = connection.memory_read(BCU_PROG_MODE_ADDR, 1).await?[0];
                let new = if args.mode == Mode::On { byte | 0x01 } else { byte & !0x01 };
                if new != byte {
                    connection.memory_write_verify(BCU_PROG_MODE_ADDR, &[new]).await?;
                }
                Ok::<_, zweidraehte_client::Error>(connection.memory_read(BCU_PROG_MODE_ADDR, 1).await?[0] & 0x01 != 0)
            }
            .await;
            let _ = connection.close().await;
            result?
        }
    };

    if now_active == (args.mode == Mode::On) {
        println!("Programming mode on {addr} ({:?}) is now {}.", mask, if now_active { "ON" } else { "OFF" });
    } else {
        return Err(format!(
            "the device reports programming mode {} after the write",
            if now_active { "ON" } else { "OFF" }
        )
        .into());
    }

    bus.disconnect().await?;
    Ok(())
}
