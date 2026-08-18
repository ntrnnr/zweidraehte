//! The BCU2 instance of the family seam.

use zweidraehte_proto::transport::TlStyle;

use crate::family::{LsmPath, MicroDeviceFamily};

/// BCU2 / System 2, TP1, mask version 0020h.
///
/// The concrete numbers are the mask 0020h resource map (09_04_01
/// §5.1.2.12, mirrored in `BCU2_PLAN.md` and the client's `MV_0020`
/// mask fixture).
pub struct Bcu2Family;

/// The BCU2 EEPROM: 0100h..=04DFh. ETS sees 0100h–046Fh; the tail is
/// reserved for system software but must still answer memory reads.
pub const BCU2_EEPROM_SIZE: usize = 0x03E0;

impl MicroDeviceFamily for Bcu2Family {
    type EepromStore = [u8; BCU2_EEPROM_SIZE];
    fn blank_eeprom() -> Self::EepromStore {
        [0; BCU2_EEPROM_SIZE]
    }

    const DD0: u16 = 0x0020;
    const TL_STYLE: TlStyle = TlStyle::Style1;
    const AUTH_LEVELS: usize = 4;
    const MAX_APDU: usize = 15;

    const EEPROM_BASE: u16 = 0x0100;
    const EEPROM_SIZE: usize = BCU2_EEPROM_SIZE;

    const OPTION_REG_OFFSET: usize = 0x00;
    const OPTION_REG_INVERTED: bool = true;
    const RUN_ERROR_OFFSET: usize = 0x0D;
    const ASSOC_TAB_PTR_OFFSET: usize = 0x11;
    const COMMS_TAB_PTR_OFFSET: usize = 0x12;
    const ADDR_TABLE_OFFSET: usize = 0x16;

    // RT2: the length byte counts the IA slot, so a table holding only
    // the IA (length 1) has no group addresses — group traffic muted.
    const MUTE_LENGTH: u8 = 1;
    fn ga_count(length_byte: u8) -> u8 {
        length_byte.saturating_sub(1)
    }

    // RT2 group object table: [count:1][ram_flags_ptr:1] then
    // [data_ptr:1][config:1][type:1] per entry.
    const COT_HEADER_LEN: usize = 2;
    const COT_ENTRY_LEN: usize = 3;
    const COT_CFG_OFFSET: usize = 1;
    const COT_TYPE_OFFSET: usize = 2;

    // Machines 1..=3 (ADT, AST, application) live behind
    // PID_LOAD_STATE_CONTROL on interface objects 1..=3.
    const LSM_PATH: LsmPath = LsmPath::Property { obj_base: 1 };
    const LSM_COUNT: usize = 3;
    const OBJECT_COUNT: u8 = 4;
    fn object_type(idx: u8) -> u16 {
        // Interface object types happen to equal the object indices for
        // the BCU2 roster: Device (0), Address Table (1), Association
        // Table (2), Application Program (3).
        idx as u16
    }
}
