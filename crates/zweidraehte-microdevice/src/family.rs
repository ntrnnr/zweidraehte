//! The family seam: everything one BCU-era management model decides.
//!
//! The stack core (runloop, group communication, transport layer,
//! memory-service dispatch, authorization flow) is generic over
//! [`MicroDeviceFamily`]; the family owns the fixed memory map, the
//! table wire codings, the load-state-machine path, the interface
//! object roster, and the device descriptor. The instances live in
//! [`crate::families`]: BCU2 today, a micro-System-7 family (masks
//! 0705h/2705h/5705h, RT8/M112 tables, memory-mapped load controls,
//! 16 authorization levels) slots in later without touching the core.

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
