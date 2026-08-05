//! Shared clap building blocks for the examples.
//!
//! Every example takes the same bus-target flags via
//! `#[command(flatten)] target: TargetArgs`:
//!
//! ```text
//! --server, -s <ip:port>   KNX/IP interface (tunneling)
//! --usb [VID:PID]          KNX USB interface (first known one, or by
//!                          hex VID:PID, e.g. --usb 147B:5120)
//! ```

use std::net::SocketAddrV4;

use zweidraehte_client::{IndividualAddress, KnxBus, UsbSelector};

/// Bus-target flags shared by every example. Exactly one of the two
/// access paths must be given (clap enforces the group).
#[derive(clap::Args)]
#[group(required = true, multiple = false)]
pub struct TargetArgs {
    /// KNX/IP interface address (tunneling), e.g. 192.168.1.100:3671
    #[arg(short, long)]
    server: Option<SocketAddrV4>,

    /// KNX USB interface: first known one, or a hex VID:PID (e.g. 147B:5120)
    #[arg(long, value_name = "VID:PID", num_args = 0..=1,
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

/// Which bus access an example should open.
#[derive(Debug, Clone)]
pub enum BusTarget {
    Ip(SocketAddrV4),
    Usb(UsbSelector),
}

impl BusTarget {
    #[allow(dead_code)] // examples with a security store connect by hand
    pub async fn connect(&self) -> zweidraehte_client::Result<KnxBus> {
        match self {
            Self::Ip(addr) => {
                println!("Connecting to KNX/IP interface at {}...", addr);
                KnxBus::connect_ip(*addr).await
            }
            Self::Usb(selector) => {
                println!("Connecting to KNX USB interface ({:?})...", selector);
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
#[allow(dead_code)] // not every example takes a device address
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
#[allow(dead_code)]
pub fn parse_hex_vec(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err("odd number of hex chars".into());
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| format!("'{s}': not hex")))
        .collect()
}

/// Parse exactly `N` hex-encoded bytes.
#[allow(dead_code)]
pub fn parse_hex_array<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let bytes = parse_hex_vec(s)?;
    let len = bytes.len();
    bytes.try_into().map_err(|_| format!("expected {} hex chars, got {}", N * 2, len * 2))
}
