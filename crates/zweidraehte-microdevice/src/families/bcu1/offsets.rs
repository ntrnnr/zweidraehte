//! Fixed BCU1 EEPROM offsets that only the BCU1 code needs (not part
//! of the family seam because no other family has them). The cell map
//! is 09_04_01 §3.1.10, mirrored in `BCU1_PLAN.md`.

/// The option register. Reads and writes are bit-inverted (the
/// hardware stores the complement; a factory-erased cell reads FFh,
/// matching the spec's "bits 7..3 shall all be 1").
pub const OPTION_REG: usize = 0x00;
/// TP1 BCU1 manufacturing data (3 bytes) — the BCU's own, never
/// overwritten by a download.
pub const MAN_DATA: usize = 0x01;
/// Application manufacturer code — a single byte on BCU1, unlike the
/// two-byte codes everywhere after it.
pub const MANUFACT: usize = 0x04;
/// Device type number (2 bytes). Non-zero marks an application as
/// present; the unload sequence zeroes DevTyp + Version.
pub const DEV_TYP: usize = 0x05;
/// Software version number.
pub const VERSION: usize = 0x07;
/// Upper limit of the EEPROM area covered by the EE_EXOR checksum:
/// the checked range is offsets `CHECK_LIM..(CheckLim value - 1)`
/// inclusive, legal values 09h–FFh (09_04_01 §3.1.10.3.7).
pub const CHECK_LIM: usize = 0x08;
/// Smallest legal CheckLim value; anything below means the checked
/// range is empty.
pub const CHECK_LIM_MIN: usize = 0x09;
/// The factory CheckLim: FFh checks the whole EEPROM below EE_EXOR.
pub const CHECK_LIM_WHOLE_EEPROM: u8 = 0xFF;
/// Required PEI type (ETS writes it; hardware PEI via ADC channel 4).
pub const PEI_TYPE: usize = 0x09;
/// RunError byte: 00h halts the application, FFh clears all error
/// flags (active-low bits).
pub const RUN_ERROR: usize = 0x0D;
/// RunError value with every (active-low) error bit clear — the
/// running state.
pub const RUN_ERROR_ALL_CLEAR: u8 = 0xFF;
/// RoutingCnt: hop count in bits 6..4; the factory value is count 6.
pub const ROUTING_COUNT: usize = 0x0E;
pub const ROUTING_COUNT_DEFAULT: u8 = 0x60;
/// Retry limits: BUSY retries in the high nibble, NAK retries in the
/// low; the factory value is three of each.
pub const TX_RETRY: usize = 0x0F;
pub const TX_RETRY_DEFAULT: u8 = 0x33;
/// Pointer byte to the association table (value + 0100h), valid range
/// 19h–FEh.
pub const ASSOC_TAB_PTR: usize = 0x11;
/// Pointer byte to the group object table (value + 0100h).
pub const COMMS_TAB_PTR: usize = 0x12;
/// The device's own individual address, stored inside the address
/// table blob (offset 0x16 length byte + 1).
pub const INDIVIDUAL_ADDRESS: usize = 0x17;
/// The EE_EXOR checksum octet. The BCU maintains it itself on every
/// write inside the checked range (hardware-confirmed: ETS never
/// writes 01FFh, see `BCU1_PLAN.md`).
pub const EE_EXOR: usize = 0xFF;
