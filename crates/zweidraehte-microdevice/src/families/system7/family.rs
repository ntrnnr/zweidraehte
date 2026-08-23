//! The System 7 instance of the family seam.

use core::marker::PhantomData;

use heapless::Vec;
use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::dpt::{
    DeviceControl, PDT_Generic05, PDT_Generic06, PDT_Generic10, PDT_UnsignedChar, PDT_UnsignedInt, ProgrammingMode,
    PropertyDataDefinition,
};
use zweidraehte_proto::memory::{MemoryPermission, MemoryRegion};
use zweidraehte_proto::messages::apdu::load_control::{LoadEvent, LoadState, MemLoadControlRecord, RunEvent, RunState};
use zweidraehte_proto::pid::{self, pdt};
use zweidraehte_proto::tables::address::BCU_ADDRESS_TABLE_MUTE_LENGTH;
use zweidraehte_proto::tables::association::SendingAssociation;
use zweidraehte_proto::tables::com_object::BcuComObjectTableFormat;

use super::offsets;
use crate::device::DeviceIdentity;
use crate::family::{MemoryAccessPolicy, MicroDeviceFamily, PropertyBacking, PropertySpec};
use crate::frame::ApciCode;
use crate::management::{ManagementState, Reply, ServiceResult, dispatch_lsm_event};
use crate::transport::Style3;

/// System 7 TP1, mask version 0705h.
///
/// The management model is fixed by the mask; the memory layout mostly
/// is not, so the product parameterizes the family:
///
/// - `EEPROM_LEN` — how much of the 4000h–CFFFh user-EEPROM window
///   this product actually backs, starting at 4000h. Reads outside the
///   backing answer 00h and writes are dropped, like unpopulated
///   memory on real silicon.
/// - `COT_ADDR` — the group object table's address. The System 7 table has
///   no device-side location resource and no interface object; ETS
///   knows the address from the product database, so the device and
///   the product definition must agree on it at compile time.
/// - `MANUFACTURER_ID` — the immutable Device Object identity. Keeping it in
///   the type avoids a RAM field and prevents a download from overwriting it.
/// - `APPLICATION_ID`, `APPLICATION_VERSION`, and `PEI_TYPE` — the immutable
///   Application Program identity. These likewise remain compile-time data;
///   carrying them in [`DeviceIdentity`] would charge every micro profile six
///   bytes of RAM for System 7-only Properties.
/// - `P` — an optional compile-time memory-access policy. Products use
///   [`StandardSystem7MemoryPolicy`]; fixtures can substitute protected
///   regions without adding runtime state or changing family behavior.
pub struct System7Family<
    const EEPROM_LEN: usize,
    const COT_ADDR: u16,
    const MANUFACTURER_ID: u16,
    const APPLICATION_ID: u16,
    const APPLICATION_VERSION: u8,
    const PEI_TYPE: u8,
    P = StandardSystem7MemoryPolicy<EEPROM_LEN>,
>(PhantomData<P>);

/// The mask's regular memory surface for a product with `EEPROM_LEN`
/// bytes of user EEPROM.
pub struct StandardSystem7MemoryPolicy<const EEPROM_LEN: usize>;

impl<const EEPROM_LEN: usize> MemoryAccessPolicy for StandardSystem7MemoryPolicy<EEPROM_LEN> {
    const REGIONS: &'static [MemoryRegion] = &[
        MemoryRegion::open(0x0000, crate::device::RAM_SIZE as u32),
        MemoryRegion::open(offsets::OPTION_REG_ADDR, 1),
        MemoryRegion::open(offsets::LOAD_CONTROL_ADDR, offsets::LOAD_CONTROL_MAX as u32),
        MemoryRegion::open(0x0700, 0x100),
        MemoryRegion::open(offsets::ADT_ADDR, EEPROM_LEN as u32),
        MemoryRegion::read_only(offsets::LOAD_STATUS_ADDR, 4, MemoryPermission::Open),
    ];
}

/// Machine roster: 0 = group address table, 1 = association table,
/// 2 = application program, 3 = the optional interface program. Both
/// program objects carry run state machines.
const APP_MACHINE: usize = 2;

// The roster is deliberately smaller than the full stack's extensible System 7
// object model: it contains the fixed properties the BCU-era download and
// diagnostics paths actually serve. The common prefix (ObjectType,
// DeviceControl, OrderInfo) retains the full object's indices.
const DEVICE_PROPERTIES: &[PropertySpec] = &[
    PropertySpec::read_only(pid::OBJECT_TYPE, PDT_UnsignedInt::ID, 3, PropertyBacking::ObjectType),
    PropertySpec::read_write(pid::DEVICE_CONTROL, DeviceControl::ID, 3, 3, PropertyBacking::DeviceControl),
    PropertySpec::read_only(pid::ORDER_INFO, PDT_Generic10::ID, 3, PropertyBacking::OrderInfo),
    // Annex A.2.3 makes this property mandatory and writable at product-
    // manufacturer level for MV-0705. `Microdevice` updates the boot identity;
    // each platform's low-write configuration snapshot persists the result.
    PropertySpec::read_write(pid::device::HARDWARE_TYPE, PDT_Generic06::ID, 3, 1, PropertyBacking::HardwareType),
    PropertySpec::read_write(pid::device::PROGMODE, ProgrammingMode::ID, 3, 3, PropertyBacking::ProgrammingMode),
    PropertySpec::read_only(pid::SERIAL_NUMBER, PDT_Generic06::ID, 3, PropertyBacking::SerialNumber),
    PropertySpec::read_only(pid::FIRMWARE_REVISION, PDT_UnsignedChar::ID, 3, PropertyBacking::FirmwareRevision),
    PropertySpec::read_only_with_policy(
        pid::device::MAX_APDU_LENGTH,
        PDT_UnsignedInt::ID,
        3,
        AccessPolicy::OPEN,
        PropertyBacking::MaxApduLength,
    ),
    PropertySpec::read_only(pid::MANUFACTURER_ID, PDT_UnsignedInt::ID, 3, PropertyBacking::FamilySpecific),
];

const TABLE_PROPERTIES: &[PropertySpec] = &[
    PropertySpec::read_only(pid::OBJECT_TYPE, PDT_UnsignedInt::ID, 3, PropertyBacking::ObjectType),
    PropertySpec::read_write(pid::LOAD_STATE_CONTROL, pdt::CONTROL, 3, 3, PropertyBacking::LoadState),
    // Annex A.2.4/A.2.5 specifies literal 3/3 for MV-0705. The mask
    // supports 16 authorization levels, but its free runtime level is 15;
    // these management Properties intentionally remain at controller level.
    PropertySpec::read_write(pid::TABLE_REFERENCE, pdt::UNSIGNED_LONG, 3, 3, PropertyBacking::TableReference),
];

const APPLICATION_PROPERTIES: &[PropertySpec] = &[
    PropertySpec::read_only(pid::OBJECT_TYPE, PDT_UnsignedInt::ID, 3, PropertyBacking::ObjectType),
    PropertySpec::read_write(pid::LOAD_STATE_CONTROL, pdt::CONTROL, 3, 3, PropertyBacking::LoadState),
    PropertySpec::read_write(pid::RUN_STATE_CONTROL, pdt::CONTROL, 3, 3, PropertyBacking::RunState),
    PropertySpec::read_only(pid::TABLE_REFERENCE, pdt::UNSIGNED_LONG, 3, PropertyBacking::TableReference),
    PropertySpec::read_only(pid::PROGRAM_VERSION, PDT_Generic05::ID, 3, PropertyBacking::FamilySpecific),
    PropertySpec::read_only(pid::PEI_TYPE, PDT_UnsignedChar::ID, 3, PropertyBacking::FamilySpecific),
];

const INTERFACE_PROGRAM_PROPERTIES: &[PropertySpec] = &[
    PropertySpec::read_only(pid::OBJECT_TYPE, PDT_UnsignedInt::ID, 3, PropertyBacking::ObjectType),
    PropertySpec::read_write(pid::LOAD_STATE_CONTROL, pdt::CONTROL, 3, 3, PropertyBacking::LoadState),
    PropertySpec::read_write(pid::RUN_STATE_CONTROL, pdt::CONTROL, 3, 3, PropertyBacking::RunState),
    PropertySpec::read_only(pid::TABLE_REFERENCE, pdt::UNSIGNED_LONG, 3, PropertyBacking::TableReference),
];

impl<
    const EEPROM_LEN: usize,
    const COT_ADDR: u16,
    const MANUFACTURER_ID: u16,
    const APPLICATION_ID: u16,
    const APPLICATION_VERSION: u8,
    const PEI_TYPE: u8,
    P: MemoryAccessPolicy,
> System7Family<EEPROM_LEN, COT_ADDR, MANUFACTURER_ID, APPLICATION_ID, APPLICATION_VERSION, PEI_TYPE, P>
{
    /// Is this interface object the application or interface program?
    fn program_machine_of(obj: u8) -> Option<usize> {
        let machine = usize::from(obj.checked_sub(Self::LSM_OBJ_BASE)?);
        (APP_MACHINE..Self::LSM_COUNT).contains(&machine).then_some(machine)
    }

    /// Does this machine index name a program object (and thus carry a
    /// run state machine)?
    fn is_program_machine(machine: usize) -> bool {
        (APP_MACHINE..Self::LSM_COUNT).contains(&machine)
    }
}

impl<
    const EEPROM_LEN: usize,
    const COT_ADDR: u16,
    const MANUFACTURER_ID: u16,
    const APPLICATION_ID: u16,
    const APPLICATION_VERSION: u8,
    const PEI_TYPE: u8,
    P: MemoryAccessPolicy,
> MicroDeviceFamily
    for System7Family<EEPROM_LEN, COT_ADDR, MANUFACTURER_ID, APPLICATION_ID, APPLICATION_VERSION, PEI_TYPE, P>
{
    type EepromStore = [u8; EEPROM_LEN];
    fn blank_eeprom() -> Self::EepromStore {
        [0; EEPROM_LEN]
    }

    const DD0: u16 = 0x0705;
    type Transport = Style3;
    const AUTH_LEVELS: usize = 16;
    const CONNECTIONLESS_PROPERTIES: bool = true;
    const CONNECTIONLESS_DEVICE_DESCRIPTOR: bool = true;
    // PID_SERIAL_NUMBER is present in the Device Object, which makes the
    // corresponding read/write AL services mandatory (06 Profiles §6.3).
    const SERIAL_NUMBER_ADDRESSING: bool = true;

    const EEPROM_BASE: u16 = offsets::ADT_ADDR;
    const EEPROM_SIZE: usize = EEPROM_LEN;
    // The 100h-byte resource window at 0700h ("resources from 0700h").
    const RAM2_BASE: u16 = 0x0700;
    const RAM2_SIZE: usize = 0x100;
    const MEMORY_REGIONS: &'static [MemoryRegion] = P::REGIONS;

    fn memory_access_policy(address: u16, length: usize) -> AccessPolicy {
        P::security_policy(address, length)
    }

    // RT8 coding: the table starts the user EEPROM, and the IA is defined as
    // bytes 1–2 of the blob (4001h–4002h) — there is no separate cell.
    const ADDR_TABLE_OFFSET: usize = 0;
    fn ia_eeprom_offset() -> usize {
        1
    }

    /// The association table is wherever the download's allocation
    /// record put it. Before any allocation (`table_ref` 0) there is no
    /// table; an out-of-range offset makes every accessor read a zero
    /// count, which is exactly "no table".
    fn assoc_table_offset(_eeprom: &[u8], mgmt: &ManagementState) -> usize {
        mgmt.lsm[1].table_ref.checked_sub(Self::EEPROM_BASE).map(usize::from).unwrap_or(EEPROM_LEN)
    }

    fn cot_table_offset(_eeprom: &[u8], _mgmt: &ManagementState) -> usize {
        COT_ADDR.checked_sub(Self::EEPROM_BASE).map(usize::from).unwrap_or(EEPROM_LEN)
    }

    const SENDING_ASSOCIATION: SendingAssociation = SendingAssociation::FirstMatch;

    const COM_OBJECT_TABLE_FORMAT: BcuComObjectTableFormat = BcuComObjectTableFormat::System7;

    // Machines 1..=4 (ADT, AST, application, interface program) answer on interface objects
    // 1..=4 through PID_LOAD_STATE_CONTROL — what ETS drives — and
    // additionally through the memory window at 0104h.
    const LSM_OBJ_BASE: u8 = 1;
    const LSM_COUNT: usize = 4;
    const OBJECT_COUNT: u8 = 5;
    fn object_type(idx: u8) -> u16 {
        // Device (0), Address Table (1), Association Table (2),
        // Application Program (3), Interface Program (4) — the types
        // equal the indices, as on BCU2.
        idx as u16
    }

    fn property_spec(object_index: u8, property_index: u8) -> Option<PropertySpec> {
        let roster = match object_index {
            0 => DEVICE_PROPERTIES,
            1 | 2 => TABLE_PROPERTIES,
            3 => APPLICATION_PROPERTIES,
            4 => INTERFACE_PROGRAM_PROPERTIES,
            _ => return None,
        };
        roster.get(usize::from(property_index)).copied()
    }

    fn property_read_hook(
        obj: u8,
        prop_id: u16,
        _eeprom: &[u8],
        _identity: &DeviceIdentity,
        _mgmt: &ManagementState,
    ) -> Option<Vec<u8, 10>> {
        let mut value = Vec::new();
        match (obj, prop_id) {
            (0, pid::MANUFACTURER_ID) => {
                let _ = value.extend_from_slice(&MANUFACTURER_ID.to_be_bytes());
            }
            (3, pid::PROGRAM_VERSION) => {
                let _ = value.extend_from_slice(&MANUFACTURER_ID.to_be_bytes());
                let _ = value.extend_from_slice(&APPLICATION_ID.to_be_bytes());
                let _ = value.push(APPLICATION_VERSION);
            }
            (3, pid::PEI_TYPE) => {
                let _ = value.push(PEI_TYPE);
            }
            _ => return None,
        }
        Some(value)
    }

    /// No RunError byte on System 7: the application runs when its
    /// machine is Loaded and no RUNCONTROL_STOP is standing.
    fn is_app_running(_eeprom: &[u8], mgmt: &ManagementState) -> bool {
        mgmt.lsm[APP_MACHINE].state == LoadState::Loaded && !mgmt.run_stopped[APP_MACHINE]
    }

    /// 03/05/01 §4.24.2.3.3 Table 97: a loaded application is Running
    /// unless explicitly stopped, in which case it is Terminated. Unloaded
    /// machines report Halted.
    fn run_state_read(obj: u8, _eeprom: &[u8], mgmt: &ManagementState) -> Option<u8> {
        let machine = Self::program_machine_of(obj)?;
        let state = if mgmt.lsm[machine].state != LoadState::Loaded {
            RunState::Halted
        } else if mgmt.run_stopped[machine] {
            RunState::Terminated
        } else {
            RunState::Running
        };
        Some(state.into())
    }

    fn run_state_write(obj: u8, value: u8, _eeprom: &mut [u8], mgmt: &mut ManagementState) -> bool {
        let Some(machine) = Self::program_machine_of(obj) else { return false };
        // 03/05/01 §4.24.2.3.2 Table 96: only Ready, Restart and Stop
        // may arrive from a client — the internal events sharing the
        // byte space are refused.
        match RunEvent::from(value) {
            RunEvent::Ready => {}
            RunEvent::Restart => mgmt.run_stopped[machine] = false,
            RunEvent::Stop => {
                if mgmt.lsm[machine].state == LoadState::Loaded {
                    mgmt.run_stopped[machine] = true;
                }
            }
            // Unknown events are ignored by the state machine.  They are not
            // a malformed property write and therefore still receive the
            // unchanged state in the positive response.
            _ => {}
        }
        true
    }

    fn unload_side_effect(machine: usize, eeprom: &mut [u8], mgmt: &mut ManagementState) {
        match machine {
            // The RT8 coding mutes at length 1: the IA at bytes 1–2 survives,
            // while no GA remains counted.
            0 => {
                if let Some(count) = eeprom.get_mut(Self::ADDR_TABLE_OFFSET) {
                    *count = BCU_ADDRESS_TABLE_MUTE_LENGTH;
                }
            }
            // The association table's storage is dynamic; dropping the
            // reference is the unload (`dispatch_lsm_event` zeroes
            // `table_ref` right after this hook). Zero the blob's count
            // too, so re-allocating the same segment later starts from
            // an empty table rather than the stale one.
            1 => {
                let off = Self::assoc_table_offset(eeprom, mgmt);
                if let Some(count) = eeprom.get_mut(off) {
                    *count = 0;
                }
            }
            // Unloading a program halts its run state machine.
            m if Self::is_program_machine(m) => mgmt.run_stopped[machine] = false,
            _ => {}
        }
    }

    /// The LSM's Loaded event cascades into the run state machine: a
    /// freshly loaded application runs (03/05/01 §4.24, RunEvent
    /// Loaded), clearing any Stop left from the previous program.
    fn load_completed_side_effect(machine: usize, _eeprom: &mut [u8], mgmt: &mut ManagementState) {
        if Self::is_program_machine(machine) {
            mgmt.run_stopped[machine] = false;
        }
    }

    /// The option register (not inverted, kept outside the EEPROM
    /// window) and the read-only load-status bytes at B6EAh — one
    /// `LoadState` octet per machine.
    fn special_byte_read(addr: u16, _eeprom: &[u8], mgmt: &ManagementState) -> Option<u8> {
        if addr == offsets::OPTION_REG_ADDR {
            return Some(mgmt.option_reg);
        }
        let machine = usize::from(addr.checked_sub(offsets::LOAD_STATUS_ADDR)?);
        (machine < Self::LSM_COUNT).then(|| mgmt.lsm[machine].state.into())
    }

    fn special_byte_write(addr: u16, value: u8, _eeprom: &mut [u8], mgmt: &mut ManagementState) -> bool {
        if addr == offsets::OPTION_REG_ADDR {
            mgmt.option_reg = value;
            return true;
        }
        // The load-status bytes are write-protected: consume the write
        // so it cannot land anywhere.
        (offsets::LOAD_STATUS_ADDR..offsets::LOAD_STATUS_ADDR + Self::LSM_COUNT as u16).contains(&addr)
    }

    /// The memory-mapped load-control window (03/05/02 §3.31.2):
    /// `[machine:4][event:4]` in the first octet, then the same segment
    /// payload the property path carries — except that an
    /// `AdditionalLoadControls` memory record inserts a segment ID
    /// octet between the segment type and the start address, which the
    /// property record does not have. This procedure supports one
    /// segment per machine and the ID is 00h, so it is dropped and the
    /// re-framed record drives the same state machine the property
    /// path drives.
    fn memory_write_intercept(addr: u16, data: &[u8], eeprom: &mut [u8], mgmt: &mut ManagementState) -> bool {
        let window = offsets::LOAD_CONTROL_ADDR..offsets::LOAD_CONTROL_ADDR + offsets::LOAD_CONTROL_MAX as u16;
        if !window.contains(&addr) {
            return false;
        }
        // A record not starting at the window base is malformed;
        // oversized or empty records are dropped the same way. All are
        // consumed — nothing may fall through into the byte mapper.
        if addr != offsets::LOAD_CONTROL_ADDR || data.is_empty() || data.len() > offsets::LOAD_CONTROL_MAX {
            return true;
        }
        let (machine, event) = MemLoadControlRecord::split_tag(data[0]);
        let machine = usize::from(machine);
        if machine == 0 || machine > Self::LSM_COUNT {
            return true;
        }
        let mut record = [0u8; offsets::LOAD_CONTROL_MAX];
        record[0] = event.into();
        let len = if event == LoadEvent::AdditionalLoadControls && data.len() >= 3 {
            record[1] = data[1]; // segment type; data[1 + 1] is the segment ID
            record[2..data.len() - 1].copy_from_slice(&data[3..]);
            data.len() - 1
        } else {
            record[1..data.len()].copy_from_slice(&data[1..]);
            data.len()
        };
        dispatch_lsm_event::<Self>(machine - 1, &record[..len], eeprom, mgmt);
        true
    }

    /// System 7 keeps the BCU-era analog service and mandates application
    /// identification for mask 0705h (06 Profiles §4.3.8). This minimal
    /// profile declares manufacturer-device ID 00h and two zero-valued
    /// manufacturer-specific octets; products needing another declaration
    /// can make it part of a future product-specific family parameter.
    fn extra_service<const N: usize>(code: ApciCode, small6: u8, payload: &[u8]) -> Option<ServiceResult<N>> {
        if let Some(adc) = crate::families::adc_read_stub(code, small6, payload) {
            return Some(adc);
        }
        match code {
            ApciCode::UserManufacturerInfoRead => {
                Some(ServiceResult::Reply(Reply::new(ApciCode::UserManufacturerInfoResponse, 0, &[0, 0, 0])))
            }
            ApciCode::UserManufacturerInfoResponse => Some(ServiceResult::None),
            _ => None,
        }
    }
}
