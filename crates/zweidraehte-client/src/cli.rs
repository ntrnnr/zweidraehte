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
use std::path::{Path, PathBuf};

use crate::security::{Keyring, KnxKeysError};
use crate::{BusTarget, IndividualAddress, UsbSelector};

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

/// Security inputs shared by commissioning frontends.
#[derive(clap::Args, Clone)]
pub struct SecurityArgs {
    /// ETS project keyring (.knxkeys)
    #[arg(long, value_name = "FILE")]
    keyring: Option<PathBuf>,

    /// ETS keyring export password; defaults to KNX_KEYRING_PASSWORD
    #[arg(long, value_name = "PASSWORD")]
    keyring_password: Option<String>,
}

/// Missing CLI credentials or an unreadable ETS keyring.
#[derive(Debug, thiserror::Error)]
pub enum SecurityArgsError {
    #[error("--keyring needs --keyring-password or KNX_KEYRING_PASSWORD")]
    MissingPassword,
    #[error(transparent)]
    Keyring(#[from] KnxKeysError),
}

impl SecurityArgs {
    /// Load only the immutable key source. Used by dry runs, which must not
    /// create a sequence-state directory or otherwise mutate the filesystem.
    pub fn load_keyring(&self) -> Result<Option<Keyring>, SecurityArgsError> {
        let Some(path) = &self.keyring else { return Ok(None) };
        let password = self.keyring_password().ok_or(SecurityArgsError::MissingPassword)?;
        Ok(Some(Keyring::load(path, &password)?))
    }

    pub fn keyring_path(&self) -> Option<&Path> {
        self.keyring.as_deref()
    }

    /// Password supplied for keyring import or export, including the shared
    /// environment-variable fallback used by all commissioning frontends.
    pub fn keyring_password(&self) -> Option<String> {
        self.keyring_password.clone().or_else(|| std::env::var("KNX_KEYRING_PASSWORD").ok())
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
    s.parse().map_err(|error| format!("'{s}': {error}; expected area.line.device"))
}

/// Parse a hex string of arbitrary even length.
pub fn parse_hex_vec(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    // Byte-pair slicing is safe only after excluding multibyte characters.
    if !s.is_ascii() {
        return Err(format!("'{s}': not hex"));
    }
    if !s.len().is_multiple_of(2) {
        return Err("odd number of hex chars".into());
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| format!("'{s}': not hex")))
        .collect()
}

/// Parse exactly `N` hex-encoded bytes.
pub fn parse_hex_array<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let bytes = parse_hex_vec(s)?;
    let len = bytes.len();
    bytes.try_into().map_err(|_| format!("expected {} hex chars, got {}", N * 2, len * 2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_input_is_checked_before_utf8_slicing() {
        assert_eq!(parse_hex_vec(" 01aBcD \n").expect("ASCII hex"), [1, 0xAB, 0xCD]);
        assert!(parse_hex_vec("").expect("empty input").is_empty());
        for invalid in ["a€", "é", "1", "GG", "00 1"] {
            assert!(parse_hex_vec(invalid).is_err(), "{invalid:?}");
        }
        assert!(parse_hex_array::<2>("01").is_err());
        assert_eq!(parse_hex_array::<2>("01AB").expect("fixed hex"), [1, 0xAB]);
    }

    #[test]
    fn hex_parsers_reject_unicode_without_panicking() {
        // Even byte lengths reach the byte-pair loop; these include pairs
        // that split a character and pairs containing a whole character.
        for input in ["0é0", "€0", "😀", "é", "  0é0  "] {
            assert!(parse_hex_vec(input).is_err(), "{input:?}");
            assert!(parse_hex_array::<2>(input).is_err(), "{input:?}");
        }
    }

    #[test]
    fn hex_parsers_preserve_ascii_and_whitespace_handling() {
        assert_eq!(parse_hex_vec(" \t00aBfF\n"), Ok(vec![0x00, 0xab, 0xff]));
        assert_eq!(parse_hex_array::<3>("00aBfF"), Ok([0x00, 0xab, 0xff]));
        assert_eq!(parse_hex_vec("  "), Ok(vec![]));
        assert_eq!(parse_hex_vec("abc"), Err("odd number of hex chars".into()));
        assert!(parse_hex_vec("0g").is_err());
        assert!(parse_hex_array::<2>("00aBfF").is_err());
    }
}
