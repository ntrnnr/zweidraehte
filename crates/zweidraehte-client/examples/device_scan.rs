//! Example: scan for devices in programming mode
//! (NM_IndividualAddress_Read).
//!
//! Usage:
//!     cargo run -p zweidraehte-client --example device_scan -- \
//!         --server 192.168.1.100:3671

mod common;

use std::time::Duration;

use clap::Parser;
use common::{TargetArgs, format_serial};
use zweidraehte_client::pid;

/// Scan for KNX devices in programming mode.
#[derive(Parser)]
struct Args {
    #[command(flatten)]
    target: TargetArgs,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = Args::parse();
    let bus = args.target.to_target().connect().await?;

    println!("Scanning for devices in programming mode (3 s)...");
    let found = bus.network_management().read_individual_addresses(Duration::from_secs(3)).await?;

    if found.is_empty() {
        println!("No device answered. Press the programming button on a device and retry.");
    } else {
        for addr in &found {
            // The serial identifies the physical unit — exactly what
            // a later `prog_mode --serial …` invocation needs.
            match bus.network_management().property_read(*addr, 0, pid::SERIAL_NUMBER, 1, 1).await {
                Ok(serial) => println!("  {addr}  serial {}", format_serial(&serial)),
                Err(_) => println!("  {addr}  (serial not readable)"),
            }
        }
        if found.len() > 1 {
            println!(
                "Warning: {} devices are in programming mode — an address write would hit all of them.",
                found.len()
            );
        }
    }

    bus.disconnect().await?;
    Ok(())
}
