//! Example: scan for devices in programming mode
//! (NM_IndividualAddress_Read).
//!
//! Usage:
//!     cargo run -p zweidraehte-client --example device_scan -- \
//!         --server 192.168.1.100:3671
//!     cargo run -p zweidraehte-client --example device_scan -- --usb

mod common;

use std::time::Duration;

use common::BusTarget;

fn parse_target(args: &[String]) -> Result<BusTarget, String> {
    let mut target = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server" | "-s" => {
                i += 1;
                let addr = args.get(i).ok_or("--server requires a value")?;
                target = Some(BusTarget::Ip(addr.parse().map_err(|e| format!("{e}"))?));
            }
            "--usb" => target = Some(common::parse_usb_arg(args, &mut i)?),
            other => return Err(format!("unknown argument: {}", other)),
        }
        i += 1;
    }
    target.ok_or_else(|| format!("usage: device_scan --server <ip:port> | --usb [vid:pid]\n{}", common::TARGET_USAGE))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let target = parse_target(&args)?;
    let bus = target.connect().await?;

    println!("Scanning for devices in programming mode (3 s)...");
    let found = bus.network_management().read_individual_addresses(Duration::from_secs(3)).await?;

    if found.is_empty() {
        println!("No device answered. Press the programming button on a device and retry.");
    } else {
        for addr in &found {
            println!("  {}", addr);
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
