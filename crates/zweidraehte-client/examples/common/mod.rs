//! The shared bus-target flags now live in the library's `cli`
//! module (select `--features cli` when running an example); this shim keeps every example's `mod
//! common;` include working unchanged.

#[allow(unused_imports)] // not every example uses every helper
pub use zweidraehte_client::cli::*;

/// A KNX serial number for display, e.g. `00C5:0011AABB`; other lengths
/// print as plain hex, since a device may answer with a malformed value.
#[allow(dead_code)] // not every example prints serial numbers
pub fn format_serial(serial: &[u8]) -> String {
    match <[u8; 6]>::try_from(serial) {
        Ok(serial) => zweidraehte_proto::dpt::KNXSerialNumber::from(serial).to_string(),
        Err(_) => serial.iter().map(|byte| format!("{byte:02X}")).collect(),
    }
}
