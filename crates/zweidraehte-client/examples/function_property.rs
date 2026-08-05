//! Example: connectionless FunctionPropertyCommand via KNX/IP tunnel.
//!
//! Connects to a KNX/IP interface, sends an `A_FunctionPropertyCommand` to a
//! specified device, and prints the response.
//!
//! Usage:
//!     cargo run -p zweidraehte-client --example function_property -- \
//!         --server 192.168.1.100:3671 \
//!         --device 1.1.1 \
//!         --object 0 \
//!         --property 52 \
//!         --data 01020304
//!
//! `--usb [vid:pid]` connects through a KNX USB interface instead of
//! `--server`. The `--data` argument is hex-encoded service data
//! (optional, defaults to empty).

mod common;

use clap::Parser;
use common::TargetArgs;
use zweidraehte_client::IndividualAddress;

/// Send a connectionless A_FunctionPropertyCommand to a device.
#[derive(Parser)]
struct Config {
    #[command(flatten)]
    target: TargetArgs,

    /// Target device individual address, e.g. 1.1.1
    #[arg(short, long, value_parser = common::parse_ia)]
    device: IndividualAddress,

    /// Interface object index
    #[arg(short, long)]
    object: u8,

    /// Property ID
    #[arg(short, long)]
    property: u16,

    /// Hex-encoded service data
    // Fully qualified `Vec` so clap's derive treats this as one value
    // parsed by `parse_hex_vec`, not as an append-per-occurrence list.
    #[arg(long, default_value = "", value_parser = common::parse_hex_vec)]
    data: std::vec::Vec<u8>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let config = Config::parse();

    // ========================================================================
    // Connect to the bus
    // ========================================================================

    let bus = config.target.to_target().connect().await?;

    println!("Connected. Assigned address: {}", bus.assigned_address());

    // ========================================================================
    // Send FunctionPropertyCommand (connectionless)
    // ========================================================================

    println!(
        "Sending FunctionPropertyCommand to {} (object={}, property={}, data=[{}])",
        config.device,
        config.object,
        config.property,
        hex_string(&config.data),
    );

    let result = bus
        .network_management()
        .function_property_command(config.device, config.object, config.property, &config.data)
        .await;

    match result {
        Ok(response) => {
            println!("Response:");
            println!("  Return code: {:#04x}", response.return_code);
            if response.data.is_empty() {
                println!("  Data: (empty)");
            } else {
                println!("  Data: [{}]", hex_string(&response.data));
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }

    // ========================================================================
    // Disconnect
    // ========================================================================

    bus.disconnect().await?;

    Ok(())
}

/// Format bytes as a hex string with spaces.
fn hex_string(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}
