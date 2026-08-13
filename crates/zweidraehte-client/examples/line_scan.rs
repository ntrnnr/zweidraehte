//! Example: sweep one line for present devices — a connectionless
//! `A_DeviceDescriptor_Read` probe per individual address, the way a
//! management tool checks reachability.
//!
//! Usage:
//!     cargo run -p zweidraehte-client --example line_scan -- \
//!         --server 192.168.1.100:3671 --line 1.1
//!
//! Every device must answer a connectionless descriptor read, so a
//! short per-address window suffices; the default 300 ms sweeps a
//! full line in about 80 seconds. Devices 0 (a coupler, if any)
//! through 255 are probed unless `--first`/`--last` narrow the range.

mod common;

use std::time::Duration;

use clap::Parser;
use common::{TargetArgs, format_serial};
use zweidraehte_client::{IndividualAddress, pid};

/// Scan a KNX line for present individual addresses.
#[derive(Parser)]
struct Args {
    #[command(flatten)]
    target: TargetArgs,

    /// The line to sweep, as `area.line` (e.g. 1.1)
    #[arg(short, long, value_parser = parse_line)]
    line: (u8, u8),

    /// First device number to probe
    #[arg(long, default_value_t = 0)]
    first: u8,

    /// Last device number to probe
    #[arg(long, default_value_t = 255)]
    last: u8,

    /// Per-address wait window in milliseconds
    #[arg(long, default_value_t = 300)]
    timeout_ms: u64,
}

/// `area.line`, both four bits.
fn parse_line(s: &str) -> Result<(u8, u8), String> {
    let Some((area, line)) = s.split_once('.') else {
        return Err(format!("'{s}': expected area.line (e.g. 1.1)"));
    };
    let (Ok(area), Ok(line)) = (area.parse::<u8>(), line.parse::<u8>()) else {
        return Err(format!("'{s}': expected two decimal numbers"));
    };
    if area > 15 || line > 15 {
        return Err(format!("'{s}': area and line are 4-bit"));
    }
    Ok((area, line))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = Args::parse();
    if args.first > args.last {
        return Err(format!("--first {} exceeds --last {}", args.first, args.last).into());
    }
    let (area, line) = args.line;
    let window = Duration::from_millis(args.timeout_ms);

    let bus = args.target.to_target().connect().await?;
    let own = bus.assigned_address();
    let nm = bus.network_management();

    let total = u16::from(args.last - args.first) + 1;
    println!("Sweeping {area}.{line}.{}-{} ({total} addresses, {}ms each)…", args.first, args.last, args.timeout_ms);

    let mut found = Vec::new();
    for device in args.first..=args.last {
        let addr = IndividualAddress::new(area, line, device);
        // Our own tunnel address answers by construction; skip the
        // self-probe rather than reporting the client as a device.
        if addr == own {
            println!("  {addr}  (this client's own tunnel address, skipped)");
            continue;
        }
        if nm.is_device_present(addr, window).await? {
            // Present — enrich with the serial number (device object,
            // PID 11). Not every device answers a connectionless
            // property read, so a refusal degrades to just the
            // address.
            match nm.property_read(addr, 0, pid::SERIAL_NUMBER, 1, 1).await {
                Ok(serial) => println!("  {addr}  serial {}", format_serial(&serial)),
                Err(_) => println!("  {addr}  (serial not readable)"),
            }
            found.push(addr);
        }
    }

    println!("{} device(s) present on {area}.{line} (of {total} probed).", found.len());

    bus.disconnect().await?;
    Ok(())
}
