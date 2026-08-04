//! Example: scan for devices in programming mode
//! (NM_IndividualAddress_Read).
//!
//! Usage:
//!     cargo run -p zweidraehte-client --example device_scan -- \
//!         --server 192.168.1.100:3671

use std::net::SocketAddrV4;
use std::time::Duration;

use zweidraehte_client::KnxBus;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let server: SocketAddrV4 = std::env::args()
        .skip_while(|a| a != "--server" && a != "-s")
        .nth(1)
        .ok_or("usage: device_scan --server <ip:port>")?
        .parse()?;

    println!("Connecting to {}...", server);
    let bus = KnxBus::connect_ip(server).await?;

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
