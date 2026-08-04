//! Shared bus-target CLI handling for the examples.
//!
//! Every example accepts the same connection flags:
//!
//! ```text
//! --server, -s <ip:port>   KNX/IP interface (tunneling)
//! --usb [vid:pid]          KNX USB interface (first known one, or by
//!                          hex VID:PID, e.g. --usb 147B:5120)
//! ```

use std::net::SocketAddrV4;

use zweidraehte_client::{KnxBus, UsbSelector};

/// Which bus access an example should open.
#[derive(Debug, Clone)]
pub enum BusTarget {
    Ip(SocketAddrV4),
    Usb(UsbSelector),
}

impl BusTarget {
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

/// Parse a `VID:PID` pair in hex, e.g. `147B:5120`.
pub fn parse_vid_pid(s: &str) -> Result<UsbSelector, String> {
    let (vid, pid) = s.split_once(':').ok_or_else(|| format!("'{}': expected VID:PID in hex", s))?;
    let vendor_id = u16::from_str_radix(vid, 16).map_err(|_| format!("'{}': VID is not hex", vid))?;
    let product_id = u16::from_str_radix(pid, 16).map_err(|_| format!("'{}': PID is not hex", pid))?;
    Ok(UsbSelector::VidPid { vendor_id, product_id })
}

/// Consume an optional `VID:PID` value following `--usb`.
///
/// `args[*i]` is the `--usb` flag itself; if the next argument looks like
/// a VID:PID pair it is consumed, otherwise auto-discovery is used.
pub fn parse_usb_arg(args: &[String], i: &mut usize) -> Result<BusTarget, String> {
    if let Some(next) = args.get(*i + 1)
        && !next.starts_with('-')
        && next.contains(':')
    {
        *i += 1;
        Ok(BusTarget::Usb(parse_vid_pid(next)?))
    } else {
        Ok(BusTarget::Usb(UsbSelector::AutoDiscover))
    }
}

pub const TARGET_USAGE: &str = "  --server, -s <ip:port>   KNX/IP interface address (e.g. 192.168.1.100:3671)
  --usb [vid:pid]          KNX USB interface (first known one, or by hex VID:PID)";
