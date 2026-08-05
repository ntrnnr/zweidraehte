//! Example: read device information over a KNX Data Secure connection.
//!
//! Connects to a secured device under its tool key (or FDSK, for a
//! factory-fresh device), runs the S-A_Sync handshake, and reads a few
//! properties through wrapped management services.
//!
//! Usage:
//!     cargo run -p zweidraehte-client --example secure_device_info -- \
//!         --server 192.168.1.100:3671 --ia 1.1.42 \
//!         --fdsk 00112233445566778899AABBCCDDEEFF \
//!         --serial 00FA12345678 \
//!         [--seq-file ~/.knx-seq.json]
//!
//! `--tool-key` replaces `--fdsk` for a commissioned device. Without
//! `--seq-file` the sequence counters live in memory only and the sync
//! handshake recovers them on every run.

mod common;

use common::BusTarget;
use zweidraehte_client::{IndividualAddress, JsonSeqStore, SecurityEntry, SecurityStore};

struct Args {
    target: BusTarget,
    ia: IndividualAddress,
    entry: SecurityEntry,
    seq_file: Option<String>,
}

fn parse_hex<const N: usize>(s: &str, what: &str) -> Result<[u8; N], String> {
    let s = s.trim();
    if s.len() != N * 2 {
        return Err(format!("{what}: expected {} hex chars, got {}", N * 2, s.len()));
    }
    let mut out = [0u8; N];
    for (i, chunk) in out.iter_mut().enumerate() {
        *chunk = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| format!("{what}: not hex"))?;
    }
    Ok(out)
}

fn parse_ia(s: &str) -> Result<IndividualAddress, String> {
    let parts: Vec<&str> = s.split('.').collect();
    let [area, line, device] = parts[..] else {
        return Err(format!("'{s}': expected a.l.d"));
    };
    Ok(IndividualAddress::new(
        area.parse().map_err(|_| "bad area")?,
        line.parse().map_err(|_| "bad line")?,
        device.parse().map_err(|_| "bad device")?,
    ))
}

fn take_value(args: &[String], i: &mut usize, name: &str) -> Result<String, String> {
    *i += 1;
    args.get(*i).cloned().ok_or_else(|| format!("{name} requires a value"))
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut target = None;
    let mut ia = None;
    let mut tool_key: Option<[u8; 16]> = None;
    let mut fdsk: Option<[u8; 16]> = None;
    let mut serial: Option<[u8; 6]> = None;
    let mut seq_file = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server" | "-s" => {
                let addr = take_value(args, &mut i, "--server")?;
                target = Some(BusTarget::Ip(addr.parse().map_err(|e| format!("{e}"))?));
            }
            "--usb" => target = Some(common::parse_usb_arg(args, &mut i)?),
            "--ia" => ia = Some(parse_ia(&take_value(args, &mut i, "--ia")?)?),
            "--tool-key" => tool_key = Some(parse_hex(&take_value(args, &mut i, "--tool-key")?, "--tool-key")?),
            "--fdsk" => fdsk = Some(parse_hex(&take_value(args, &mut i, "--fdsk")?, "--fdsk")?),
            "--serial" => serial = Some(parse_hex(&take_value(args, &mut i, "--serial")?, "--serial")?),
            "--seq-file" => seq_file = Some(take_value(args, &mut i, "--seq-file")?),
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }

    let usage = format!(
        "usage: secure_device_info --server <ip:port> | --usb [vid:pid]\n\
         \x20   --ia <a.l.d> (--tool-key <32 hex> | --fdsk <32 hex>) --serial <12 hex>\n\
         \x20   [--seq-file <path>]\n{}",
        common::TARGET_USAGE
    );

    let target = target.ok_or_else(|| usage.clone())?;
    let ia = ia.ok_or("--ia is required")?;
    let serial = serial.ok_or("--serial is required (the device's 6-byte KNX serial)")?;
    if tool_key.is_none() && fdsk.is_none() {
        return Err("one of --tool-key / --fdsk is required".into());
    }

    let entry = SecurityEntry { mode: zweidraehte_client::DeviceSecurityMode::Secure, tool_key, fdsk, serial };
    Ok(Args { target, ia, entry, seq_file })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let args = parse_args(&args)?;

    let mut security = match &args.seq_file {
        Some(path) => SecurityStore::with_store(Box::new(JsonSeqStore::open(path)?)),
        None => SecurityStore::new(),
    };
    security.set_device_security(args.ia, args.entry);

    let bus = match &args.target {
        BusTarget::Ip(addr) => {
            println!("Connecting to KNX/IP interface at {}...", addr);
            zweidraehte_client::KnxBus::connect_ip_with_security(*addr, security).await?
        }
        BusTarget::Usb(selector) => {
            println!("Connecting to KNX USB interface ({:?})...", selector);
            zweidraehte_client::KnxBus::connect_usb_with_security(selector, security).await?
        }
    };

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
