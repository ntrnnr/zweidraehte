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

use common::BusTarget;
use zweidraehte_client::IndividualAddress;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let config = parse_args(&args)?;

    // ========================================================================
    // Connect to the bus
    // ========================================================================

    let bus = config.target.connect().await?;

    println!("Connected. Assigned address: {}", bus.assigned_address());

    // ========================================================================
    // Send FunctionPropertyCommand (connectionless)
    // ========================================================================

    println!(
        "Sending FunctionPropertyCommand to {} (object={}, property={}, data=[{}])",
        config.device_addr,
        config.object_idx,
        config.property_id,
        hex_string(&config.service_data),
    );

    let result = bus
        .network_management()
        .function_property_command(config.device_addr, config.object_idx, config.property_id, &config.service_data)
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

// ============================================================================
// Argument parsing
// ============================================================================

struct Config {
    target: BusTarget,
    device_addr: IndividualAddress,
    object_idx: u8,
    property_id: u16,
    service_data: Vec<u8>,
}

fn parse_args(args: &[String]) -> Result<Config, Box<dyn std::error::Error>> {
    let mut target: Option<BusTarget> = None;
    let mut device_addr: Option<IndividualAddress> = None;
    let mut object_idx: Option<u8> = None;
    let mut property_id: Option<u16> = None;
    let mut service_data = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server" | "-s" => {
                i += 1;
                target = Some(BusTarget::Ip(args[i].parse()?));
            }
            "--usb" => {
                target = Some(common::parse_usb_arg(args, &mut i)?);
            }
            "--device" | "-d" => {
                i += 1;
                device_addr = Some(parse_individual_address(&args[i])?);
            }
            "--object" | "-o" => {
                i += 1;
                object_idx = Some(args[i].parse()?);
            }
            "--property" | "-p" => {
                i += 1;
                property_id = Some(args[i].parse()?);
            }
            "--data" => {
                i += 1;
                service_data = hex_decode(&args[i])?;
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => {
                eprintln!("Unknown argument: {}", other);
                print_usage();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    Ok(Config {
        target: target.ok_or("--server or --usb is required")?,
        device_addr: device_addr.ok_or("--device is required")?,
        object_idx: object_idx.ok_or("--object is required")?,
        property_id: property_id.ok_or("--property is required")?,
        service_data,
    })
}

fn print_usage() {
    eprintln!(
        "Usage: function_property (--server <ip:port> | --usb [vid:pid]) --device <a.l.d> --object <idx> --property <id> [--data <hex>]"
    );
    eprintln!();
    eprintln!("Options:");
    eprintln!("{}", common::TARGET_USAGE);
    eprintln!("  --device, -d   Target device individual address (e.g. 1.1.1)");
    eprintln!("  --object, -o   Interface object index (0-255)");
    eprintln!("  --property, -p Property ID (0-255)");
    eprintln!("  --data         Hex-encoded service data (optional)");
}

/// Parse "area.line.device" into an IndividualAddress.
fn parse_individual_address(s: &str) -> Result<IndividualAddress, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return Err(format!("Invalid address '{}': expected area.line.device", s).into());
    }
    let area: u8 = parts[0].parse()?;
    let line: u8 = parts[1].parse()?;
    let device: u8 = parts[2].parse()?;
    Ok(IndividualAddress::new(area, line, device))
}

/// Decode a hex string like "01020304" into bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if s.len() % 2 != 0 {
        return Err("Hex string must have even length".into());
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(Into::into)).collect()
}

/// Format bytes as a hex string with spaces.
fn hex_string(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}
