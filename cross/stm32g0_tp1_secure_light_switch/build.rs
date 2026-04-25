//! Compile-time FDSK injection.
//!
//! Reads `ZZ_FDSK_HEX` from the environment (32 hex chars, no
//! separators), validates it, and emits a `fdsk.rs` include in OUT_DIR
//! that declares `pub const FDSK_BYTES: [u8; 16] = [...];`. The
//! firmware picks this up via `include!(concat!(env!("OUT_DIR"),
//! "/fdsk.rs"))`.
//!
//! Deliberately panics at build time if the env var is missing or
//! malformed — there is no all-zero fallback. An insecure device is
//! easy to deploy by accident if the build silently succeeds without a
//! real FDSK.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // Re-run when the env var changes so a new key rebuilds.
    println!("cargo:rerun-if-env-changed=ZZ_FDSK_HEX");

    let hex = env::var("ZZ_FDSK_HEX").unwrap_or_else(|_| {
        panic!(
            "\n\n\
             ========================================================================\n\
             stm32g0_tp1_secure_light_switch: ZZ_FDSK_HEX is required\n\
             ========================================================================\n\
             This crate builds a KNX Data Secure device. It needs a 16-byte Factory\n\
             Default Setup Key (FDSK) compiled into the firmware. Generate one with:\n\
             \n\
                 ZZ_FDSK_HEX=$(openssl rand -hex 16) cargo build --release\n\
             \n\
             The FDSK is written to the chip's identity flash page on first boot\n\
             and paired with ETS during commissioning.\n\
             ========================================================================\n\n"
        )
    });

    let bytes = decode_hex(&hex).unwrap_or_else(|msg| {
        panic!(
            "\nstm32g0_tp1_secure_light_switch: ZZ_FDSK_HEX invalid: {msg}\n\
             Expected exactly 32 hex chars (no 0x prefix, no spaces/dashes).\n"
        )
    });

    let rendered: String = bytes.iter().map(|b| format!("0x{b:02X}")).collect::<Vec<_>>().join(", ");
    let src = format!("pub const FDSK_BYTES: [u8; 16] = [{rendered}];\n");

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    fs::write(out.join("fdsk.rs"), src).expect("write fdsk.rs");

    // Standard embedded linker args — no memory.x of our own since
    // embassy-stm32's "memory-x" feature provides it.
    println!("cargo:rustc-link-arg-bins=--nmagic");
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
    println!("cargo:rustc-link-arg-bins=-Tdefmt.x");
}

fn decode_hex(s: &str) -> Result<[u8; 16], String> {
    if s.len() != 32 {
        return Err(format!("wrong length: got {} chars, want 32", s.len()));
    }
    let mut out = [0u8; 16];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("non-hex char: {:?}", b as char)),
    }
}
