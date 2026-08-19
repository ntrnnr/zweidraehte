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
/// RunError value with every (active-low) error bit clear — the
/// running state; ETS writes 00h to halt and restores FFh after a
/// download.
pub const RUN_ERROR_ALL_CLEAR: u8 = 0xFF;
/// RunError value with every (active-low) error bit raised — the
/// halted state.
pub const RUN_ERROR_HALTED: u8 = 0x00;
/// RoutingCnt: hop count in bits 6..4; the factory value is count 6.
pub const ROUTING_COUNT: usize = 0x0E;
pub const ROUTING_COUNT_DEFAULT: u8 = 0x60;
/// Retry limits: BUSY retries in the high nibble, NAK retries in the
/// low; the factory value is three of each.
pub const TX_RETRY: usize = 0x0F;
pub const TX_RETRY_DEFAULT: u8 = 0x33;
/// ApplicationID: AP manufacturer (2), DevType (2), Version (1).
pub const APPLICATION_ID: usize = 0x03;
/// The DevType field inside the ApplicationID block (non-zero marks
/// an application as present).
pub const APPLICATION_ID_DEV_TYPE: usize = APPLICATION_ID + 2;
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
/// The ManagementStyle value of a native BCU2.
pub const MANAGEMENT_STYLE_NATIVE: u8 = 0x48;
/// The device's own individual address, stored inside the address
/// table blob (offset 0x16 length byte + 1).
pub const INDIVIDUAL_ADDRESS: usize = 0x17;
