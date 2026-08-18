//! Fixed BCU2 EEPROM offsets that only the BCU2 management code needs
//! (not part of the family seam because no other family has them).

/// Product manufacturer code (2 bytes) — never overwritten by ETS,
/// surfaced as `PID_MANUFACTURER_ID` on the device object.
pub const MAN_DATA: usize = 0x01;
/// ApplicationID: AP manufacturer (2), DevType (2), Version (1).
pub const APPLICATION_ID: usize = 0x03;
/// Required PEI type, surfaced as `PID_PEI_TYPE`.
pub const PEI_TYPE: usize = 0x09;
/// Port A direction bits, surfaced as `PID_PORT_CONFIGURATION`.
pub const PORT_ADDR: usize = 0x0C;
/// ManagementStyle byte ETS reads once to detect BCU1-compat mode.
/// A native BCU2 reports 48h. ETS never writes it.
pub const MANAGEMENT_STYLE: usize = 0x15;
/// The device's own individual address, stored inside the address
/// table blob (offset 0x16 length byte + 1).
pub const INDIVIDUAL_ADDRESS: usize = 0x17;
