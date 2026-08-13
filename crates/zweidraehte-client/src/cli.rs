//! Shared clap building blocks for binaries built on this client
//! (feature `cli`).
//!
//! Every consumer — the crate's own examples, `knx-loader` — takes
//! the same bus-target flags via `#[command(flatten)] target:
//! TargetArgs`:
//!
//! ```text
//! --server, -s <ip:port>   KNX/IP interface (tunneling)
//! --usb[=VID:PID]          KNX USB interface (first known one, or by
//!                          hex VID:PID, e.g. --usb=147B:5120)
//!
//! The `--usb` value requires the `=` spelling: with an optional
//! space-separated value, clap would swallow whatever token follows —
//! `knx-loader --usb unload` must select the subcommand, not fail
//! parsing "unload" as a VID:PID.
//! ```

use std::net::SocketAddrV4;

use crate::{IndividualAddress, KnxBus, UsbSelector};

/// Bus-target flags shared by every consumer. Exactly one of the two
/// access paths must be given (clap enforces the group).
#[derive(Debug, clap::Args)]
#[group(required = true, multiple = false)]
pub struct TargetArgs {
    /// KNX/IP interface address (tunneling), e.g. 192.168.1.100:3671
    #[arg(short, long)]
    server: Option<SocketAddrV4>,

    /// KNX USB interface: first known one, or a hex VID:PID (e.g. --usb=147B:5120)
    #[arg(long, value_name = "VID:PID", num_args = 0..=1, require_equals = true,
          default_missing_value = "auto", value_parser = parse_usb_selector)]
    usb: Option<UsbSelector>,
}

impl TargetArgs {
    pub fn to_target(&self) -> BusTarget {
        match (&self.server, &self.usb) {
            (Some(addr), _) => BusTarget::Ip(*addr),
            (None, Some(selector)) => BusTarget::Usb(selector.clone()),
            (None, None) => unreachable!("clap group requires one target flag"),
        }
    }
}

/// The same flags for binaries with an offline mode (`--dry-run`):
/// the group is optional, and `to_target` says whether one was given.
#[derive(Debug, clap::Args)]
#[group(required = false, multiple = false)]
pub struct OptionalTargetArgs {
    /// KNX/IP interface address (tunneling), e.g. 192.168.1.100:3671
    #[arg(short, long)]
    server: Option<SocketAddrV4>,

    /// KNX USB interface: first known one, or a hex VID:PID (e.g. --usb=147B:5120)
    #[arg(long, value_name = "VID:PID", num_args = 0..=1, require_equals = true,
          default_missing_value = "auto", value_parser = parse_usb_selector)]
    usb: Option<UsbSelector>,
}

impl OptionalTargetArgs {
    pub fn to_target(&self) -> Option<BusTarget> {
        match (&self.server, &self.usb) {
            (Some(addr), _) => Some(BusTarget::Ip(*addr)),
            (None, Some(selector)) => Some(BusTarget::Usb(selector.clone())),
            (None, None) => None,
        }
    }
}

/// Which bus access a binary should open.
#[derive(Debug, Clone)]
pub enum BusTarget {
    Ip(SocketAddrV4),
    Usb(UsbSelector),
}

impl BusTarget {
    /// Logs rather than prints: a raw-mode TUI may own the terminal
    /// while this runs (the connectors log their own detail anyway).
    pub async fn connect(&self) -> crate::Result<KnxBus> {
        match self {
            Self::Ip(addr) => {
                log::info!("Connecting to KNX/IP interface at {addr}...");
                KnxBus::connect_ip(*addr).await
            }
            Self::Usb(selector) => {
                log::info!("Connecting to KNX USB interface ({selector:?})...");
                KnxBus::connect_usb(selector).await
            }
        }
    }
}

/// The `--usb` value: absent value means auto-discovery, otherwise a
/// `VID:PID` pair in hex, e.g. `147B:5120`.
fn parse_usb_selector(s: &str) -> Result<UsbSelector, String> {
    if s == "auto" {
        return Ok(UsbSelector::AutoDiscover);
    }
    let (vid, pid) = s.split_once(':').ok_or_else(|| format!("'{}': expected VID:PID in hex", s))?;
    let vendor_id = u16::from_str_radix(vid, 16).map_err(|_| format!("'{}': VID is not hex", vid))?;
    let product_id = u16::from_str_radix(pid, 16).map_err(|_| format!("'{}': PID is not hex", pid))?;
    Ok(UsbSelector::VidPid { vendor_id, product_id })
}

/// Parse an individual address in `area.line.device` notation.
pub fn parse_ia(s: &str) -> Result<IndividualAddress, String> {
    let parts: Vec<&str> = s.split('.').collect();
    let [area, line, device] = parts[..] else {
        return Err(format!("'{s}': expected area.line.device"));
    };
    let (Ok(area), Ok(line), Ok(device)) = (area.parse::<u8>(), line.parse::<u8>(), device.parse::<u8>()) else {
        return Err(format!("'{s}': expected three decimal numbers"));
    };
    if area > 15 || line > 15 {
        return Err(format!("'{s}': area and line are 4-bit"));
    }
    Ok(IndividualAddress::new(area, line, device))
}

/// Parse a hex string of arbitrary even length.
pub fn parse_hex_vec(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err("odd number of hex chars".into());
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| format!("'{s}': not hex")))
        .collect()
}

/// A KNX serial number for display: the 2-byte manufacturer part,
/// then the 4-byte number, e.g. `00C5:0011AABB`.
pub fn format_serial(serial: &[u8]) -> String {
    if serial.len() != 6 {
        return serial.iter().map(|b| format!("{b:02X}")).collect();
    }
    format!("{:02X}{:02X}:{:02X}{:02X}{:02X}{:02X}", serial[0], serial[1], serial[2], serial[3], serial[4], serial[5])
}

/// Parse exactly `N` hex-encoded bytes.
pub fn parse_hex_array<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let bytes = parse_hex_vec(s)?;
    let len = bytes.len();
    bytes.try_into().map_err(|_| format!("expected {} hex chars, got {}", N * 2, len * 2))
}
