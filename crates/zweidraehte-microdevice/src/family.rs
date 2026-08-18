//! The family seam: everything one BCU-era management model decides.
//!
//! The stack core (runloop, group communication, transport layer,
//! memory-service dispatch, authorization flow) is generic over
//! [`MicroDeviceFamily`]; the family owns the fixed memory map, the
//! table wire codings, the load-state-machine path, the interface
//! object roster, and the device descriptor. [`Bcu2Family`] is the
//! first instance; a micro-System-7 family (masks 0705h/2705h/5705h,
//! RT8/M112 tables, memory-mapped load controls, 16 authorization
//! levels) slots in later without touching the core.

use zweidraehte_proto::transport::TlStyle;

/// How load-control records reach the device's load state machines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsmPath {
    /// Records are written to `PID_LOAD_STATE_CONTROL` on the table /
    /// application interface objects (BCU2, System B). `obj_base` is
    /// the interface object index of machine 1 (the address table).
    Property { obj_base: u8 },
    /// Records are written to a memory-mapped load-control window and
    /// the state is read back from status bytes (System 7, BIM M112).
    MemoryMapped { control_addr: u16, status_base: u16 },
}

/// Compile-time description of one BCU-era management model.
///
/// Everything here is a constant or a `const fn`-shaped pure function:
/// the core monomorphizes over the family, so the family costs no RAM
/// and no dispatch.
pub trait MicroDeviceFamily: 'static {
    // ── Identity ─────────────────────────────────────────────────────

    /// Device Descriptor Type 0 (mask version).
    const DD0: u16;
    /// Transport layer style mandated by 06 Profiles §4.1.2 for this
    /// profile (Style 1 for BCU2 / System 2).
    const TL_STYLE: TlStyle;
    /// Number of authorization levels (BCU2: 4, System 7: 16).
    const AUTH_LEVELS: usize;
    /// Maximum APDU length. BCU2 has no MaxApduLength resource, so the
    /// spec default of 15 octets applies.
    const MAX_APDU: usize;

    // ── Memory windows ───────────────────────────────────────────────

    /// KNX address of EEPROM offset 0.
    const EEPROM_BASE: u16;
    /// Number of EEPROM bytes the device owns.
    const EEPROM_SIZE: usize;

    // ── Fixed EEPROM offsets (from `EEPROM_BASE`) ───────────────────

    /// The option register. Reads and writes are bit-inverted on BCU2
    /// (the hardware stores the complement; a factory-erased cell
    /// reads back FFh).
    const OPTION_REG_OFFSET: usize;
    const OPTION_REG_INVERTED: bool;
    /// RunError byte: 00h halts the application, FFh clears all error
    /// flags (active-low bits).
    const RUN_ERROR_OFFSET: usize;
    /// Pointer byte to the association table (value + `EEPROM_BASE`).
    const ASSOC_TAB_PTR_OFFSET: usize;
    /// Pointer byte to the group object table (value + `EEPROM_BASE`).
    const COMMS_TAB_PTR_OFFSET: usize;
    /// Start of the address table blob.
    const ADDR_TABLE_OFFSET: usize;

    // ── Address table count semantics ────────────────────────────────

    /// Value of the leading count byte that mutes group communication.
    /// RT2's length counts the IA slot, so 1 means "IA only, no GAs";
    /// RT8 counts only GAs, so 0 mutes.
    const MUTE_LENGTH: u8;
    /// Number of group addresses encoded by the leading count byte.
    fn ga_count(length_byte: u8) -> u8;

    // ── Group object table coding ────────────────────────────────────

    /// Header bytes before the entries: count byte + RAM-flags pointer
    /// (1-byte pointer on BCU2, 2-byte big-endian on System 7).
    const COT_HEADER_LEN: usize;
    /// Bytes per entry: data pointer + config + type (3 on BCU2,
    /// 4 on System 7 where the data pointer is two bytes).
    const COT_ENTRY_LEN: usize;
    /// Offset of the config octet within an entry.
    const COT_CFG_OFFSET: usize;
    /// Offset of the type octet within an entry.
    const COT_TYPE_OFFSET: usize;

    // ── Management model ─────────────────────────────────────────────

    /// How load-control records reach the load state machines.
    const LSM_PATH: LsmPath;
    /// Number of load state machines (BCU2: ADT, AST, application).
    const LSM_COUNT: usize;
    /// Number of interface objects (BCU2: Device, Address Table,
    /// Association Table, Application Program).
    const OBJECT_COUNT: u8;
    /// Interface object type of object index `idx` (only called with
    /// `idx < OBJECT_COUNT`).
    fn object_type(idx: u8) -> u16;
}

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

/// Fixed BCU2 EEPROM offsets that only the BCU2 management code needs
/// (not part of the family seam because no other family has them).
pub mod bcu2_offsets {
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
}
