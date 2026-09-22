//! Example: read device information over a KNX Data Secure connection.
//!
//! Connects to a secured device under its tool key (or FDSK, for a
//! factory-fresh device), runs the S-A_Sync handshake, and reads a few
//! properties through wrapped management services.
//!
//! Usage:
//!     cargo run -p zweidraehte-client --features cli --example secure_device_info -- \
//!         --server 192.168.1.100:3671 --ia 1.1.42 \
//!         --fdsk 00112233445566778899AABBCCDDEEFF \
//!         --serial 00FA12345678
//!
//! `--tool-key` replaces `--fdsk` for a commissioned device. Or load
//! everything from an ETS keyring export instead of typing keys:
//!
//!     cargo run -p zweidraehte-client --features cli --example secure_device_info -- \
//!         --server 192.168.1.100:3671 --ia 1.1.42 \
//!         --keyring project.knxkeys --keyring-password secret
//!
//! Sequence counters live in memory and the sync handshake recovers them on
//! every run. Project frontends provide durable project-owned state.

mod common;

use clap::Parser;
use common::TargetArgs;
use zweidraehte_client::security::Keyring;
use zweidraehte_client::{IndividualAddress, SecurityEntry, SecurityStore};

/// Read device information over a KNX Data Secure connection.
#[derive(Parser)]
struct Args {
    #[command(flatten)]
    target: TargetArgs,

    /// Target device individual address, e.g. 1.1.42
    #[arg(long, value_parser = common::parse_ia)]
    ia: IndividualAddress,

    /// Commissioned tool key (32 hex chars)
    #[arg(long, value_parser = common::parse_hex_array::<16>, conflicts_with = "keyring")]
    tool_key: Option<[u8; 16]>,

    /// Factory-default setup key (32 hex chars)
    #[arg(long, value_parser = common::parse_hex_array::<16>, conflicts_with = "keyring")]
    fdsk: Option<[u8; 16]>,

    /// Device KNX serial number (12 hex chars)
    #[arg(long, value_parser = common::parse_hex_array::<6>, conflicts_with = "keyring")]
    serial: Option<[u8; 6]>,

    /// ETS keyring export (.knxkeys) to load keys from
    #[arg(long, requires = "keyring_password")]
    keyring: Option<String>,

    /// Password the keyring was exported with
    #[arg(long, requires = "keyring")]
    keyring_password: Option<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = Args::parse();

    let mut security = SecurityStore::new();
    if let Some((path, password)) = args.keyring.as_deref().zip(args.keyring_password.as_deref()) {
        let keyring = Keyring::load(path, password)?;
        let imported = security.import_keyring(&keyring)?;
        println!("Keyring '{}': imported {} secure device(s).", keyring.project, imported);
    } else {
        if args.tool_key.is_none() && args.fdsk.is_none() {
            return Err("one of --tool-key / --fdsk (or --keyring) is required".into());
        }
        let serial = args.serial.ok_or("--serial is required with manual key material")?;
        security.set_device_security(
            args.ia,
            SecurityEntry::with_credentials(
                zweidraehte_client::DeviceSecurityMode::Secure,
                args.tool_key,
                args.fdsk,
                Some(serial),
            )?,
        );
    }

    let bus = args.target.to_target().connect_with_security(security).await?;

    println!("Connecting securely to {} (S-A_Sync handshake)...", args.ia);
    let mut dev = bus.connect_device(args.ia).await?;
    println!("Secure connection established.");

    let serial = dev.property_read(0, 11, 1, 1).await?;
    println!("  PID_SERIAL_NUMBER: {:02X?}", serial);

    let descriptor = dev.device_descriptor_read(0).await?;
    println!("  Device descriptor: {:02X?}", descriptor);

    let order_info = dev.property_read(0, 15, 1, 1).await;
    match order_info {
        Ok(info) => println!("  PID_ORDER_INFO:    {:02X?}", info),
        Err(e) => println!("  PID_ORDER_INFO:    <not readable: {e}>"),
    }

    dev.close().await?;
    bus.disconnect().await?;
    Ok(())
}
