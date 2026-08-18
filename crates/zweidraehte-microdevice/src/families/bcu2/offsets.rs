//! Fixed BCU2 EEPROM offsets that only the BCU2 management code needs
//! (not part of the family seam because no other family has them).

/// The option register. Reads and writes are bit-inverted (the
/// hardware stores the complement; a factory-erased cell reads FFh).
pub const OPTION_REG: usize = 0x00;
/// Product manufacturer code (2 bytes) — never overwritten by ETS,
/// surfaced as `PID_MANUFACTURER_ID` on the device object.
pub const MAN_DATA: usize = 0x01;
/// RunError byte: 00h halts the application, FFh clears all error
/// flags (active-low bits).
pub const RUN_ERROR: usize = 0x0D;
/// ApplicationID: AP manufacturer (2), DevType (2), Version (1).
pub const APPLICATION_ID: usize = 0x03;
/// Required PEI type, surfaced as `PID_PEI_TYPE`.
pub const PEI_TYPE: usize = 0x09;
/// Port A direction bits, surfaced as `PID_PORT_CONFIGURATION`.
pub const PORT_ADDR: usize = 0x0C;
/// Pointer byte to the association table (value + 0100h).
pub const ASSOC_TAB_PTR: usize = 0x11;
/// Pointer byte to the group object table (value + 0100h).
pub const COMMS_TAB_PTR: usize = 0x12;
/// ManagementStyle byte ETS reads once to detect BCU1-compat mode.
/// A native BCU2 reports 48h. ETS never writes it.
pub const MANAGEMENT_STYLE: usize = 0x15;
/// The device's own individual address, stored inside the address
/// table blob (offset 0x16 length byte + 1).
pub const INDIVIDUAL_ADDRESS: usize = 0x17;
