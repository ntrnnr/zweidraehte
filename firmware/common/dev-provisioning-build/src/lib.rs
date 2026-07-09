//! Build-time helper for the `provision-on-boot` dev feature.
//!
//! When a firmware crate is compiled with `--features provision-on-boot`
//! its `build.rs` calls [`emit_dev_provisioning`]. The helper reads
//! `ZZ_SERIAL_HEX`, `ZZ_FDSK_HEX`, and `ZZ_MAC_HEX` from the
//! environment, falls back to documented defaults when they are
//! absent, and writes a Rust source file at `$OUT_DIR/dev_provisioning.rs`:
//!
//! ```rust,ignore
//! pub const DEV_SERIAL: [u8; 6]  = [0x00, 0xFA, 0x00, 0x01, 0x02, 0x03];
//! pub const DEV_FDSK:   [u8; 16] = [0x00, 0x01, /* ... */ 0x0F];
//! pub const DEV_MAC:    [u8; 6]  = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
//! ```
//!
//! The firmware `main.rs` then `include!(concat!(env!("OUT_DIR"),
//! "/dev_provisioning.rs"))` under `#[cfg(feature = "provision-on-boot")]`
//! and passes the constants to `synthesize_and_write` on first boot.
//!
//! # Defaults
//!
//! Defaults are picked to be obviously-not-production: a serial of
//! `00:FA:00:01:02:03` (manuf "00FA" reserved, device part `0xDEAD0001`
//! pattern is too benign to confuse with a real assignment), an FDSK
//! that's just `0x00..0x0F`, and a locally-administered MAC ending in
//! `..01`. Anyone seeing one of these in ETS knows the unit was never
//! provisioned with [`tools/knx-provision`](../../../tools/knx-provision).

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

const DEFAULT_SERIAL: [u8; 6] = [0x00, 0xFA, 0x00, 0x01, 0x02, 0x03];
const DEFAULT_FDSK: [u8; 16] =
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
const DEFAULT_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

/// Render the three constants and write them to `$OUT_DIR/dev_provisioning.rs`.
///
/// Call this from a firmware `build.rs` only when
/// `CARGO_FEATURE_PROVISION_ON_BOOT` is set. The helper unconditionally
/// emits the file (no env vars required) so that an unset env var is a
/// non-fatal "use the default" rather than a build error.
pub fn emit_dev_provisioning() {
    println!("cargo:rerun-if-env-changed=ZZ_SERIAL_HEX");
    println!("cargo:rerun-if-env-changed=ZZ_FDSK_HEX");
    println!("cargo:rerun-if-env-changed=ZZ_MAC_HEX");

    // SERIAL — 12 hex chars / 6 bytes.
    let serial = match env::var("ZZ_SERIAL_HEX") {
        Ok(s) => decode_hex::<6>("ZZ_SERIAL_HEX", &s).unwrap_or_else(|e| panic!("{e}")),
        Err(_) => DEFAULT_SERIAL,
    };

    // FDSK — 32 hex chars / 16 bytes.
    let fdsk = match env::var("ZZ_FDSK_HEX") {
        Ok(s) => decode_hex::<16>("ZZ_FDSK_HEX", &s).unwrap_or_else(|e| panic!("{e}")),
        Err(_) => DEFAULT_FDSK,
    };

    // MAC — 12 hex chars / 6 bytes.
    let mac = match env::var("ZZ_MAC_HEX") {
        Ok(s) => decode_hex::<6>("ZZ_MAC_HEX", &s).unwrap_or_else(|e| panic!("{e}")),
        Err(_) => DEFAULT_MAC,
    };

    let mut src = String::new();
    write_const(&mut src, "DEV_SERIAL", &serial);
    write_const(&mut src, "DEV_FDSK", &fdsk);
    write_const(&mut src, "DEV_MAC", &mac);

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    fs::write(out.join("dev_provisioning.rs"), src).expect("write dev_provisioning.rs");
}

fn write_const(out: &mut String, name: &str, bytes: &[u8]) {
    write!(out, "pub const {name}: [u8; {}] = [", bytes.len()).unwrap();

    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }

        write!(out, "0x{b:02X}").unwrap();
    }

    out.push_str("];\n");
}

fn decode_hex<const N: usize>(var: &str, s: &str) -> Result<[u8; N], String> {
    if s.len() != 2 * N {
        return Err(format!("{var}: expected {} hex chars, got {}", 2 * N, s.len()));
    }

    let mut out = [0u8; N];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        let hi = nibble(var, chunk[0])?;
        let lo = nibble(var, chunk[1])?;
        out[i] = (hi << 4) | lo;
    }

    Ok(out)
}

fn nibble(var: &str, b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("{var}: non-hex char {:?}", b as char)),
    }
}
