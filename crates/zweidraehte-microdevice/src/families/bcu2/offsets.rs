//! Fixed BCU2 EEPROM offsets that only the BCU2 management code needs
//! (not part of the family seam because no other family has them).

/// The option register. Reads and writes are bit-inverted (the
/// hardware stores the complement; a factory-erased cell reads FFh).
pub const OPTION_REG: usize = 0x00;
/// Product manufacturer code (2 bytes), surfaced as `PID_MANUFACTURER_ID`.
/// Mask 0021h permits a level-0 Property write; mask 0020h is read-only.
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
/// Pointer to the user save routine (09/04/01 §5.1.2.12.5.7).
pub const USER_SAVE_PTR: usize = 0x15;
/// Value used by the ETS 0020h/0021h mask-procedure fixtures.
pub const USER_SAVE_PTR_DEFAULT: u8 = 0x48;
/// The device's own individual address, stored inside the address
/// table blob (offset 0x16 length byte + 1).
pub const INDIVIDUAL_ADDRESS: usize = 0x17;

// The mask keeps permanent management state in its system-reserved EEPROM
// tail (0470h..04DFh). Keeping these values in the already-present BCU2 image
// avoids adding unused RAM fields to BCU1 and System 7 compositions.
/// Permanent `PID_SERVICE_CONTROL` backing (2 bytes, big-endian).
pub const SERVICE_CONTROL: usize = 0x370;
/// Permanent `PID_POLL_GROUP_SETTINGS` backing (3 bytes).
pub const POLL_GROUP_SETTINGS: usize = SERVICE_CONTROL + 2;
/// Validity bits for factory identity overrides in the system EEPROM tail.
pub(crate) const IDENTITY_OVERRIDE_FLAGS: usize = POLL_GROUP_SETTINGS + 3;
/// `PID_SERIAL_NUMBER` has a persisted override.
pub(crate) const SERIAL_NUMBER_VALID: u8 = 1 << 0;
/// `PID_ORDER_INFO` has a persisted override.
pub(crate) const ORDER_INFO_VALID: u8 = 1 << 1;

/// Permanent mask-0021h `PID_SERIAL_NUMBER` backing (6 bytes).
pub(crate) const SERIAL_NUMBER: usize = IDENTITY_OVERRIDE_FLAGS + 1;
/// Permanent mask-0021h `PID_ORDER_INFO` backing (10 bytes).
pub(crate) const ORDER_INFO: usize = SERIAL_NUMBER + 6;
/// Permanent mask-0021h `PID_MANUFACTURER_DATA` backing (4 bytes).
pub(crate) const MANUFACTURER_DATA: usize = ORDER_INFO + 10;
