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

use heapless::Vec;
use zweidraehte_proto::transport::TlStyle;

use crate::device::DeviceIdentity;
use crate::management::{ManagementState, ServiceResult};

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
    // ── Storage ──────────────────────────────────────────────────────

    /// The backing array for this family's EEPROM image, always
    /// `[u8; Self::EEPROM_SIZE]`. An associated type so each family
    /// sizes its own storage without `generic_const_exprs`.
    type EepromStore: AsRef<[u8]> + AsMut<[u8]>;
    /// A factory-blank (all-zero) EEPROM image.
    fn blank_eeprom() -> Self::EepromStore;

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

    /// Start of the address table blob.
    const ADDR_TABLE_OFFSET: usize;
    /// EEPROM-array offset of the device's own individual address
    /// (2 bytes, big-endian). Both families keep it inside the address
    /// table blob; where in the blob differs (RT2 stores it behind the
    /// length byte, RT8 defines bytes 1–2 as the IA).
    fn ia_eeprom_offset() -> usize;

    // ── Table location resolution ────────────────────────────────────
    //
    // How a family finds its association and group object tables is
    // the widest management-model split in the crate: BCU2 reads
    // one-byte pointer cells inside the image, System 7 tracks the
    // association table through the machine's `table_ref` (written by
    // the download's allocation record) and takes the group object
    // table address from the product definition.

    /// EEPROM-array offset where the association table starts.
    fn assoc_table_offset(eeprom: &[u8], mgmt: &ManagementState) -> usize;
    /// EEPROM-array offset where the group object table starts.
    fn cot_table_offset(eeprom: &[u8], mgmt: &ManagementState) -> usize;

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

    /// How load-control records reach the load state machines. The
    /// property path (`PID_LOAD_STATE_CONTROL` on the objects from
    /// `LSM_OBJ_BASE`) works on every family; `MemoryMapped` says a
    /// memory window *additionally* exists, which the family serves
    /// through its memory intercept hooks.
    const LSM_PATH: LsmPath;
    /// Interface object index of machine 0 (the address table).
    const LSM_OBJ_BASE: u8;
    /// Number of load state machines (BCU2: ADT, AST, application;
    /// System 7 adds the second application program).
    const LSM_COUNT: usize;
    /// Number of interface objects (BCU2: Device, Address Table,
    /// Association Table, Application Program).
    const OBJECT_COUNT: u8;
    /// Interface object type of object index `idx` (only called with
    /// `idx < OBJECT_COUNT`).
    fn object_type(idx: u8) -> u16;

    // ── Run state model ──────────────────────────────────────────────

    /// Whether the application program currently runs. BCU2 derives
    /// this from the RunError EEPROM byte plus the load state; System 7
    /// has no RunError byte and derives it from the load state alone.
    fn is_app_running(eeprom: &[u8], mgmt: &ManagementState) -> bool;
    /// `PID_RUN_STATE_CONTROL` read on interface object `obj`, `None`
    /// where the object carries no run state machine.
    fn run_state_read(obj: u8, eeprom: &[u8], mgmt: &ManagementState) -> Option<u8>;
    /// `PID_RUN_STATE_CONTROL` write; returns whether the write was
    /// accepted.
    fn run_state_write(obj: u8, value: u8, eeprom: &mut [u8], mgmt: &mut ManagementState) -> bool;

    // ── Load-state-machine side effects ──────────────────────────────

    /// Mask-defined side effect on the resource itself when machine
    /// `machine` transitions to Unloaded (address table collapses to
    /// the mute length, association table empties, the application
    /// un-marks itself as present).
    fn unload_side_effect(machine: usize, eeprom: &mut [u8], mgmt: &mut ManagementState);

    // ── Memory-map intercepts ────────────────────────────────────────
    //
    // The generic memory service maps page-0 RAM, the EEPROM window
    // and RAM2; anything else a family's memory map contains (BCU2's
    // inverted option register, System 7's load-control window and
    // load-status bytes) intercepts here, checked before the generic
    // mapping.

    /// Family override for a single-byte memory read.
    fn special_byte_read(_addr: u16, _eeprom: &[u8], _mgmt: &ManagementState) -> Option<u8> {
        None
    }
    /// Family override for a single-byte memory write; `true` when the
    /// write was consumed.
    fn special_byte_write(_addr: u16, _value: u8, _eeprom: &mut [u8], _mgmt: &mut ManagementState) -> bool {
        false
    }
    /// Record-level intercept of a whole `A_Memory_Write`, for windows
    /// whose semantics need the complete record rather than a byte
    /// stream (System 7's load-control window). `true` when consumed.
    fn memory_write_intercept(_addr: u16, _data: &[u8], _eeprom: &mut [u8], _mgmt: &mut ManagementState) -> bool {
        false
    }

    // ── Property surface beyond the generic set ──────────────────────

    /// Family-specific property read (single-element properties only,
    /// like everything on these masks). `None` falls through to the
    /// negative response.
    fn property_read_hook(
        _obj: u8,
        _prop_id: u16,
        _eeprom: &[u8],
        _identity: &DeviceIdentity,
        _mgmt: &ManagementState,
    ) -> Option<Vec<u8, 10>> {
        None
    }
    /// Family-specific property write. `Some(accepted)` answers,
    /// `None` falls through to the negative response.
    fn property_write_hook(
        _obj: u8,
        _prop_id: u16,
        _data: &[u8],
        _eeprom: &mut [u8],
        _mgmt: &mut ManagementState,
    ) -> Option<bool> {
        None
    }

    // ── Family-specific services ─────────────────────────────────────

    /// Management APCIs outside the generic set (BCU2's `A_ADC_Read`).
    fn extra_service(_base: u16, _small6: u8, _payload: &[u8]) -> Option<ServiceResult> {
        None
    }

    /// Whether `A_Key_Write` may target this authorization level.
    /// System 7 refuses its free-access level 15, which owns no key.
    fn key_write_level_valid(level: u8) -> bool {
        usize::from(level) < Self::AUTH_LEVELS
    }

    /// Device Descriptor Type 2, for families that answer it (System 7).
    fn device_descriptor2(_eeprom: &[u8], _identity: &DeviceIdentity, _mgmt: &ManagementState) -> Option<[u8; 14]> {
        None
    }
}
