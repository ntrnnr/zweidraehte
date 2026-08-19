//! The family seam: everything one BCU-era management model decides.
//!
//! The stack core (runloop, group communication, transport layer,
//! memory-service dispatch, authorization flow) is generic over
//! [`MicroDeviceFamily`]; the family owns the fixed memory map, the
//! table wire codings, the load and run state behavior, the interface
//! object roster, and the device descriptor. The instances live in
//! [`crate::families`]: BCU2 (masks 0020h/0021h/0025h), micro-System-7
//! (System 7 tables, memory-mapped load controls, 16 authorization
//! levels), and BCU1 (mask 0012h — no properties, no load state
//! machines, no authorization).

use heapless::Vec;
use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::memory::MemoryRegion;
use zweidraehte_proto::properties::{PropertyAccess, PropertyDescriptor};
use zweidraehte_proto::tables::association::SendingAssociation;
use zweidraehte_proto::transport::TlStyle;

use crate::device::DeviceIdentity;
use crate::frame::ApciCode;
use crate::management::{ManagementState, ServiceResult};

/// A compile-time memory-region policy.
///
/// Profiles with product- or fixture-specific memory protection can provide a
/// zero-sized implementation and select it as a type parameter without adding
/// runtime state or dynamic dispatch.
pub trait MemoryAccessPolicy: 'static {
    const REGIONS: &'static [MemoryRegion];
}

/// The state that backs one property in the generic management server.
///
/// A family roster selects one of these behaviors for every property it
/// exposes. [`FamilySpecific`](Self::FamilySpecific) is the escape hatch for
/// values whose storage really is profile-specific; their data still cannot
/// exist without a descriptor in the same roster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PropertyBacking {
    /// The interface object's mask-defined type number.
    ObjectType,
    /// `ManagementState::device_control`.
    DeviceControl,
    /// The fixed BCU-era service-control view.
    ServiceControl,
    /// The programming-mode bit shared with memory address 0060h.
    ProgrammingMode,
    /// The micro stack's firmware revision.
    FirmwareRevision,
    /// Boot identity serial number.
    SerialNumber,
    /// Boot identity order information.
    OrderInfo,
    /// Boot identity hardware type.
    HardwareType,
    /// The stack's fixed TP1 standard-frame APDU limit.
    MaxApduLength,
    /// One of the family's load state machines.
    LoadState,
    /// The load state machine's allocated table address.
    TableReference,
    /// One of the family's run state machines.
    RunState,
    /// Storage and encoding handled by the family's property hooks.
    FamilySpecific,
}

/// One entry in a BCU family's ordered interface-object property roster.
///
/// The index passed to [`MicroDeviceFamily::property_spec`] is the observable
/// property index. Keeping the descriptor and backing together makes value
/// lookup, PID lookup, and by-index description enumeration use the same
/// inventory.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct PropertySpec {
    /// Wire metadata returned by the property-description service.
    pub descriptor: PropertyDescriptor,
    /// Generic behavior or family hook that serves the value.
    pub backing: PropertyBacking,
}

impl PropertySpec {
    /// Define a read-only property for the plaintext BCU-era management
    /// model.
    ///
    /// The micro stack has no Data Secure property policy layer, so its
    /// descriptors use [`AccessPolicy::OPEN`]. The regular property-
    /// description service transmits the legacy read/write levels below.
    pub const fn read_only(pid: u16, pdt: u8, read_level: u8, backing: PropertyBacking) -> Self {
        Self {
            descriptor: PropertyDescriptor::new(
                pid,
                pdt,
                1,
                PropertyAccess::ReadOnly,
                read_level,
                0,
                AccessPolicy::OPEN,
            ),
            backing,
        }
    }

    /// Define a read-write property for the plaintext BCU-era management
    /// model.
    pub const fn read_write(pid: u16, pdt: u8, read_level: u8, write_level: u8, backing: PropertyBacking) -> Self {
        Self {
            descriptor: PropertyDescriptor::new(
                pid,
                pdt,
                1,
                PropertyAccess::ReadWrite,
                read_level,
                write_level,
                AccessPolicy::OPEN,
            ),
            backing,
        }
    }
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
    /// Number of authorization levels (BCU2: 4, System 7: 16). Zero
    /// means the family predates `A_Authorize` entirely (BCU1): the
    /// authorize and key-write services are then not answered at all.
    const AUTH_LEVELS: usize;
    /// Whether the device answers connectionless (unnumbered)
    /// device-oriented management. A BCU2 serves its management
    /// exclusively connection-oriented; System 7 also answers
    /// connectionless property and descriptor reads.
    const CONNECTIONLESS_MANAGEMENT: bool;
    // ── Memory windows ───────────────────────────────────────────────

    /// KNX address of EEPROM offset 0.
    const EEPROM_BASE: u16;
    /// Number of EEPROM bytes the device owns.
    const EEPROM_SIZE: usize;
    /// The second RAM window (BCU2: E0h bytes at 0900h; System 7: the
    /// 100h-byte resource window at 0700h). Must fit
    /// [`crate::device::RAM2_CEILING`].
    const RAM2_BASE: u16;
    const RAM2_SIZE: usize;
    /// Complete absolute memory-access map for the management service.
    ///
    /// Storage dispatch remains fixed in the core; these regions state
    /// which complete requests may reach it and at what authorization
    /// level. Gaps are inaccessible rather than zero-filled phantom
    /// memory.
    const MEMORY_REGIONS: &'static [MemoryRegion];

    // ── Fixed EEPROM offsets (from `EEPROM_BASE`) ───────────────────

    /// Start of the address table blob.
    const ADDR_TABLE_OFFSET: usize;
    /// EEPROM-array offset of the device's own individual address
    /// (2 bytes, big-endian). The supported BCU-era families keep it at
    /// bytes 1–2 of their address-table blob.
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

    /// Realization-specific sending-association selection. RT1 and RT2
    /// both index the slot whose number equals the ASAP, but only RT2
    /// validates that the row names the requested ASAP. System 7's
    /// compact table is searched instead.
    const SENDING_ASSOCIATION: SendingAssociation;

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

    /// One entry in the ordered property roster of an interface object.
    ///
    /// Entries must be contiguous from index zero. Returning `None` ends a
    /// by-index scan; BCU1 returns it immediately because it has no property
    /// model.
    fn property_spec(_object_index: u8, _property_index: u8) -> Option<PropertySpec> {
        None
    }

    /// Find a property and its observable index by PID.
    ///
    /// Families normally implement only [`property_spec`](Self::property_spec);
    /// this default walks that one roster so PID and index lookup cannot drift.
    fn property_spec_by_id(object_index: u8, pid: u16) -> Option<(u8, PropertySpec)> {
        for index in 0..=u8::MAX {
            let spec = Self::property_spec(object_index, index)?;
            if spec.descriptor.pid == pid {
                return Some((index, spec));
            }
        }
        None
    }

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
    /// Side effect when machine `machine` reaches Loaded — the LSM's
    /// Loaded event cascades into the run state machine on families
    /// whose application objects carry one (System 7: a freshly loaded
    /// application runs, clearing any earlier Stop).
    fn load_completed_side_effect(_machine: usize, _eeprom: &mut [u8], _mgmt: &mut ManagementState) {}
    /// Whether an `AllocAbsDataSeg` segment fits the device's storage.
    /// A rejected allocation throws the machine into Error, which is
    /// how a client learns the device cannot hold what the product
    /// asks for.
    ///
    /// The default checks a segment against the window it starts in —
    /// EEPROM, page-0 RAM (the BCU-era templates allocate the group
    /// object values there), or the second RAM window — and accepts
    /// segments outside every backed window untouched, the way real
    /// masks accept allocations in regions the system software owns.
    fn abs_segment_fits(start: u16, length: u16) -> bool {
        let end = u32::from(start) + u32::from(length);
        if start >= Self::EEPROM_BASE && usize::from(start - Self::EEPROM_BASE) < Self::EEPROM_SIZE {
            return end <= u32::from(Self::EEPROM_BASE) + Self::EEPROM_SIZE as u32;
        }
        if usize::from(start) < crate::device::RAM_SIZE {
            return end <= crate::device::RAM_SIZE as u32;
        }
        if start >= Self::RAM2_BASE && usize::from(start - Self::RAM2_BASE) < Self::RAM2_SIZE {
            return end <= u32::from(Self::RAM2_BASE) + Self::RAM2_SIZE as u32;
        }
        true
    }

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
    fn extra_service(_code: ApciCode, _small6: u8, _payload: &[u8]) -> Option<ServiceResult> {
        None
    }

    /// Whether `A_Key_Write` may target this authorization level.
    /// The least-privileged level owns no key on either authorization
    /// model, so it cannot be written.
    fn key_write_level_valid(level: u8) -> bool {
        usize::from(level) < Self::AUTH_LEVELS.saturating_sub(1)
    }

    /// Device Descriptor Type 2, for families that answer it (System 7).
    fn device_descriptor2(_eeprom: &[u8], _identity: &DeviceIdentity, _mgmt: &ManagementState) -> Option<[u8; 14]> {
        None
    }
}
