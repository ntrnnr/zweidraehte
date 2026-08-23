//! The BCU2 instance of the family seam.

use core::marker::PhantomData;

use heapless::Vec;
use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::dpt::{
    DeviceControl, PDT_Generic04, PDT_Generic05, PDT_Generic06, PDT_Generic10, PDT_PollGroupSettings, PDT_UnsignedChar,
    PDT_UnsignedInt, PropertyDataDefinition,
};
use zweidraehte_proto::memory::MemoryRegion;
use zweidraehte_proto::messages::apdu::load_control::{LoadState, RunEvent, RunState};
use zweidraehte_proto::pid::{self, pdt};
use zweidraehte_proto::tables::address::BCU_ADDRESS_TABLE_MUTE_LENGTH;
use zweidraehte_proto::tables::association::SendingAssociation;
use zweidraehte_proto::tables::com_object::BcuComObjectTableFormat;

use super::offsets;
use crate::device::DeviceIdentity;
use crate::family::{MemoryAccessPolicy, MicroDeviceFamily, PropertyBacking, PropertySpec};
use crate::frame::ApciCode;
use crate::management::{ManagementState, ServiceResult};
use crate::transport::Style1;

/// BCU2 / System 2, TP1 — masks 0020h (the default) and 0021h.
///
/// 09/04/01 §5.1.2.1 names these as the two TP1 BCU2 mask versions. It
/// specifies the 0021h implementation and says only that 0020h has a
/// different amount of user RAM; exact 0020h compatibility additionally
/// follows the ETS mask procedure exercised by this crate's fixtures.
///
/// DD0 0025h is catalogued as BCU2/System 2 in 03/05/01 §4.1.2, but the
/// BCU2 hardware chapter and the RT2 resource definitions (§§4.16.4,
/// 4.17.4 and 4.18.4) do not include it. It therefore must not silently
/// inherit this family's 0021h memory map.
pub struct Bcu2Family<const MASK: u16 = 0x0020, P = StandardBcu2MemoryPolicy>(PhantomData<P>);

/// The complete memory surface of an ordinary BCU2 product.
///
/// A zero-sized policy parameter keeps fixture-specific permission windows
/// out of shipping devices and lets a plain composition optimize away the
/// Data-Secure policy function entirely.
pub struct StandardBcu2MemoryPolicy;

impl MemoryAccessPolicy for StandardBcu2MemoryPolicy {
    const REGIONS: &'static [MemoryRegion] = &[
        MemoryRegion::open(0x0000, crate::device::RAM_SIZE as u32),
        MemoryRegion::open(0x0100, BCU2_EEPROM_SIZE as u32),
        MemoryRegion::open(0x0900, 0xD0),
    ];
}

/// The BCU2 EEPROM: 0100h..=04DFh. ETS sees 0100h–046Fh; the tail is
/// reserved for system software but must still answer memory reads.
pub const BCU2_EEPROM_SIZE: usize = 0x03E0;

impl<const MASK: u16, P: MemoryAccessPolicy> Bcu2Family<MASK, P> {
    /// Evaluated wherever `DD0` is, so instantiating the family with a
    /// mask that is not a BCU2 sibling fails at compile time instead
    /// of quietly claiming BCU2 semantics for it.
    const MASK_IS_BCU2: () = assert!(MASK == 0x0020 || MASK == 0x0021, "Bcu2Family covers masks 0020h and 0021h only",);

    /// The Application Program interface object: the last of the
    /// machines behind `LSM_OBJ_BASE` (index 3 on the BCU2 roster).
    const APP_OBJECT: u8 = Self::LSM_OBJ_BASE + Self::LSM_COUNT as u8 - 1;

    /// Device-object roster shared by the two supported masks, apart from
    /// optional resources selected by the concrete composition.
    fn device_property(index: u8) -> Option<PropertySpec> {
        // 06 Profiles Annex A.2.3: masks 0020h/0021h use level 0 for
        // writable Device Object controls.
        let privileged_write = 0;
        match index {
            0 => Some(PropertySpec::read_only(pid::OBJECT_TYPE, PDT_UnsignedInt::ID, 3, PropertyBacking::ObjectType)),
            1 => Some(PropertySpec::read_write(
                pid::DEVICE_CONTROL,
                DeviceControl::ID,
                3,
                privileged_write,
                PropertyBacking::DeviceControl,
            )),
            2 => Some(PropertySpec::read_write(
                pid::SERVICE_CONTROL,
                PDT_UnsignedInt::ID,
                3,
                privileged_write,
                PropertyBacking::FamilySpecific,
            )),
            3 => Some(PropertySpec::read_only(
                pid::FIRMWARE_REVISION,
                PDT_UnsignedChar::ID,
                3,
                PropertyBacking::FirmwareRevision,
            )),
            4 => Some(PropertySpec::read_only(pid::SERIAL_NUMBER, PDT_Generic06::ID, 3, PropertyBacking::SerialNumber)),
            5 => Some(PropertySpec::read_only(pid::ORDER_INFO, PDT_Generic10::ID, 3, PropertyBacking::OrderInfo)),
            6 => Some(PropertySpec::read_only(
                pid::MANUFACTURER_ID,
                PDT_UnsignedInt::ID,
                3,
                PropertyBacking::FamilySpecific,
            )),
            7 => Some(PropertySpec::read_only(pid::PEI_TYPE, PDT_UnsignedChar::ID, 3, PropertyBacking::FamilySpecific)),
            8 => Some(PropertySpec::read_write(
                pid::PORT_CONFIGURATION,
                PDT_UnsignedChar::ID,
                3,
                privileged_write,
                PropertyBacking::FamilySpecific,
            )),
            9 => Some(PropertySpec::read_write(
                pid::POLL_GROUP_SETTINGS,
                PDT_PollGroupSettings::ID,
                3,
                privileged_write,
                PropertyBacking::FamilySpecific,
            )),
            10 => Some(PropertySpec::read_only(
                pid::MANUFACTURER_DATA,
                PDT_Generic04::ID,
                3,
                PropertyBacking::FamilySpecific,
            )),
            // PID 56 is conditional on long-frame support (06 Profiles
            // Annex A.2.3 note 57), not on Data Secure. Our only long-frame
            // BCU2 composition currently uses mask 0021h, so keeping it in
            // that concrete roster avoids charging the standard-frame 0020h
            // target for an optional Property.
            11 if MASK == 0x0021 => Some(PropertySpec::read_only_with_policy(
                pid::device::MAX_APDU_LENGTH,
                PDT_UnsignedInt::ID,
                3,
                AccessPolicy::OPEN,
                PropertyBacking::MaxApduLength,
            )),
            _ => None,
        }
    }

    fn table_property(index: u8) -> Option<PropertySpec> {
        // Annex A.2.4/A.2.5: 0020h and 0021h use level 1.
        let load_write = 1;
        match index {
            0 => Some(PropertySpec::read_only(pid::OBJECT_TYPE, pdt::UNSIGNED_INT, 3, PropertyBacking::ObjectType)),
            1 => Some(PropertySpec::read_write(
                pid::LOAD_STATE_CONTROL,
                pdt::CONTROL,
                3,
                load_write,
                PropertyBacking::LoadState,
            )),
            2 => Some(PropertySpec::read_only(
                pid::TABLE_REFERENCE,
                pdt::UNSIGNED_LONG,
                3,
                PropertyBacking::TableReference,
            )),
            _ => None,
        }
    }

    fn application_property(index: u8) -> Option<PropertySpec> {
        // Annex A.2.6: 0020h and 0021h use level 0.
        let control_write = 0;
        match index {
            0 => Some(PropertySpec::read_only(pid::OBJECT_TYPE, pdt::UNSIGNED_INT, 3, PropertyBacking::ObjectType)),
            1 => Some(PropertySpec::read_write(
                pid::LOAD_STATE_CONTROL,
                pdt::CONTROL,
                3,
                control_write,
                PropertyBacking::LoadState,
            )),
            2 => Some(PropertySpec::read_write(
                pid::RUN_STATE_CONTROL,
                pdt::CONTROL,
                3,
                control_write,
                PropertyBacking::RunState,
            )),
            3 => Some(PropertySpec::read_only(
                pid::TABLE_REFERENCE,
                pdt::UNSIGNED_LONG,
                3,
                PropertyBacking::TableReference,
            )),
            4 => Some(PropertySpec::read_only(
                pid::PROGRAM_VERSION,
                PDT_Generic05::ID,
                3,
                PropertyBacking::FamilySpecific,
            )),
            5 => Some(PropertySpec::read_write(
                pid::PEI_TYPE,
                PDT_UnsignedChar::ID,
                3,
                control_write,
                PropertyBacking::FamilySpecific,
            )),
            _ => None,
        }
    }
}

impl<const MASK: u16, P: MemoryAccessPolicy> MicroDeviceFamily for Bcu2Family<MASK, P> {
    type EepromStore = [u8; BCU2_EEPROM_SIZE];
    fn blank_eeprom() -> Self::EepromStore {
        [0; BCU2_EEPROM_SIZE]
    }

    const DD0: u16 = {
        let () = Self::MASK_IS_BCU2;
        MASK
    };
    type Transport = Style1;
    const AUTH_LEVELS: usize = 4;
    // Property procedures may use either point-to-point mode on every BCU2
    // (03/05/02 §§3.25--3.28). Device Descriptor and direct memory access
    // remain connection-oriented in the base profile (06 Profiles §§4.2.1,
    // 4.3); Data Secure adds only the narrow DD bootstrap handled by the
    // module-aware dispatcher.
    const CONNECTIONLESS_PROPERTIES: bool = true;
    const SERIAL_NUMBER_ADDRESSING: bool = true;

    const EEPROM_BASE: u16 = 0x0100;
    const EEPROM_SIZE: usize = BCU2_EEPROM_SIZE;
    const RAM2_BASE: u16 = 0x0900;
    // 09/04/01 Figure 16: 208 bytes at 0900h. The previous E0h widened
    // direct-memory access beyond the BCU2 RAM2 region.
    const RAM2_SIZE: usize = 0xD0;
    const MEMORY_REGIONS: &'static [MemoryRegion] = P::REGIONS;

    fn memory_access_policy(address: u16, length: usize) -> AccessPolicy {
        P::security_policy(address, length)
    }

    const ADDR_TABLE_OFFSET: usize = 0x16;
    fn ia_eeprom_offset() -> usize {
        offsets::INDIVIDUAL_ADDRESS
    }

    // Both tables hang off one-byte pointer cells relative to 0100h.
    fn assoc_table_offset(eeprom: &[u8], _mgmt: &ManagementState) -> usize {
        usize::from(eeprom.get(offsets::ASSOC_TAB_PTR).copied().unwrap_or(0))
    }
    fn cot_table_offset(eeprom: &[u8], _mgmt: &ManagementState) -> usize {
        usize::from(eeprom.get(offsets::COMMS_TAB_PTR).copied().unwrap_or(0))
    }

    const SENDING_ASSOCIATION: SendingAssociation = SendingAssociation::IndexedChecked;

    const COM_OBJECT_TABLE_FORMAT: BcuComObjectTableFormat = BcuComObjectTableFormat::Rt2;

    // Machines 1..=3 (ADT, AST, application) live behind
    // PID_LOAD_STATE_CONTROL on interface objects 1..=3.
    const LSM_OBJ_BASE: u8 = 1;
    const LSM_COUNT: usize = 3;
    const OBJECT_COUNT: u8 = 4;
    const DETECT_OWN_INDIVIDUAL_ADDRESS: bool = true;

    fn object_type(idx: u8) -> u16 {
        // Interface object types happen to equal the object indices for
        // the BCU2 roster: Device (0), Address Table (1), Association
        // Table (2), Application Program (3).
        idx as u16
    }

    fn property_spec(object_index: u8, property_index: u8) -> Option<PropertySpec> {
        match object_index {
            0 => Self::device_property(property_index),
            1 | 2 => Self::table_property(property_index),
            3 => Self::application_property(property_index),
            _ => None,
        }
    }

    fn individual_address_write_enabled(eeprom: &[u8]) -> bool {
        let base = offsets::SERVICE_CONTROL;
        let service_control = u16::from_be_bytes([eeprom[base], eeprom[base + 1]]);
        let bit_set = service_control & (1 << 2) != 0;
        if MASK == 0x0021 { !bit_set } else { bit_set }
    }

    /// The application program runs when it is loaded, its persistent
    /// RunError byte carries no active (low) error bits, and the volatile
    /// Run State Machine has not received `RUNCONTROL_STOP`.
    fn is_app_running(eeprom: &[u8], mgmt: &ManagementState) -> bool {
        eeprom.get(offsets::RUN_ERROR).copied() == Some(offsets::RUN_ERROR_ALL_CLEAR)
            && mgmt.lsm[Self::LSM_COUNT - 1].state == LoadState::Loaded
            && !mgmt.run_stopped[Self::LSM_COUNT - 1]
    }

    fn run_state_read(obj: u8, eeprom: &[u8], mgmt: &ManagementState) -> Option<u8> {
        if obj != Self::APP_OBJECT {
            return None;
        }
        let machine = Self::LSM_COUNT - 1;
        let state = if mgmt.lsm[machine].state != LoadState::Loaded {
            RunState::Halted
        } else if mgmt.run_stopped[machine] {
            // 03/05/01 §4.24.2.3.3 Table 97 footnote a explicitly
            // selects Terminated for BCU2 after Stop.
            RunState::Terminated
        } else if Self::is_app_running(eeprom, mgmt) {
            RunState::Running
        } else {
            RunState::Halted
        };
        Some(state.into())
    }

    fn run_state_write(obj: u8, value: u8, _eeprom: &mut [u8], mgmt: &mut ManagementState) -> bool {
        if obj != Self::APP_OBJECT {
            return false;
        }
        let machine = Self::LSM_COUNT - 1;
        // RunError is persistent application validity/configuration. Run
        // Control is a volatile diagnostic state machine; conflating the two
        // made STOP survive a power cycle and prevented the mandatory
        // power-up transition of a loaded application.
        match RunEvent::from(value) {
            RunEvent::Ready => {}
            RunEvent::Restart => mgmt.run_stopped[machine] = false,
            RunEvent::Stop if mgmt.lsm[machine].state == LoadState::Loaded => {
                mgmt.run_stopped[machine] = true;
            }
            // Unknown events are ignored, but the property write itself is
            // still successful and reports the unchanged state.
            _ => {}
        }
        true
    }

    fn unload_side_effect(machine: usize, eeprom: &mut [u8], mgmt: &mut ManagementState) {
        match machine {
            0 => {
                eeprom[Self::ADDR_TABLE_OFFSET] = BCU_ADDRESS_TABLE_MUTE_LENGTH;
            }
            1 => {
                let assoc = Self::assoc_table_offset(eeprom, mgmt);
                if assoc < Self::EEPROM_SIZE {
                    eeprom[assoc] = 0;
                }
            }
            2 => {
                // Clearing the ApplicationID's DevType+Version is what
                // un-marks the program as present.
                let dev_type = offsets::APPLICATION_ID_DEV_TYPE;
                eeprom[dev_type..dev_type + 3].fill(0);
                mgmt.run_stopped[machine] = false;
            }
            _ => {}
        }
    }

    fn load_completed_side_effect(machine: usize, _eeprom: &mut [u8], mgmt: &mut ManagementState) {
        if machine == Self::LSM_COUNT - 1 {
            mgmt.run_stopped[machine] = false;
        }
    }

    fn special_byte_read(addr: u16, eeprom: &[u8], _mgmt: &ManagementState) -> Option<u8> {
        crate::families::option_reg_read(addr, Self::EEPROM_BASE, offsets::OPTION_REG, eeprom)
    }
    fn special_byte_write(addr: u16, value: u8, eeprom: &mut [u8], _mgmt: &mut ManagementState) -> bool {
        crate::families::option_reg_write(addr, value, Self::EEPROM_BASE, offsets::OPTION_REG, eeprom)
    }

    fn property_read_hook(
        obj: u8,
        prop_id: u16,
        eeprom: &[u8],
        _identity: &DeviceIdentity,
        _mgmt: &ManagementState,
    ) -> Option<Vec<u8, 10>> {
        let mut v: Vec<u8, 10> = Vec::new();
        match (obj, prop_id) {
            (0, pid::MANUFACTURER_ID) => {
                let _ = v.extend_from_slice(&eeprom[offsets::MAN_DATA..offsets::MAN_DATA + 2]);
            }
            (0, pid::SERVICE_CONTROL) => {
                let base = offsets::SERVICE_CONTROL;
                let _ = v.extend_from_slice(&eeprom[base..base + 2]);
            }
            (0, pid::PEI_TYPE) => {
                // This is the actually connected external interface. The
                // MCU product has none; the application's required PEI is a
                // distinct Property on object 3.
                let _ = v.push(0);
            }
            (0, pid::PORT_CONFIGURATION) => {
                let _ = v.push(eeprom[offsets::PORT_ADDR]);
            }
            (0, pid::POLL_GROUP_SETTINGS) => {
                let base = offsets::POLL_GROUP_SETTINGS;
                let _ = v.extend_from_slice(&eeprom[base..base + 3]);
            }
            (0, pid::MANUFACTURER_DATA) => {
                let _ = v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            }
            (3, pid::PROGRAM_VERSION) => {
                let base = offsets::APPLICATION_ID;
                let _ = v.extend_from_slice(&eeprom[base..base + 5]);
            }
            (3, pid::PEI_TYPE) => {
                let _ = v.push(eeprom[offsets::PEI_TYPE]);
            }
            _ => return None,
        }
        Some(v)
    }

    fn property_write_hook(
        obj: u8,
        prop_id: u16,
        data: &[u8],
        eeprom: &mut [u8],
        _mgmt: &mut ManagementState,
    ) -> Option<bool> {
        match (obj, prop_id) {
            (0, pid::SERVICE_CONTROL) => Some(if let [high, low] = data {
                // Bits 0 and 1 are abandoned and shall read zero; bits 3..7
                // are reserved. This MCU has no EMI, for which Resources
                // §4.2.8 requires all high-octet services to stay disabled.
                // Only the mask-specific IA-write gate is meaningful here.
                let _ = high;
                let value = u16::from_be_bytes([0xFF, *low & 0x04]);
                let base = offsets::SERVICE_CONTROL;
                eeprom[base..base + 2].copy_from_slice(&value.to_be_bytes());
                true
            } else {
                false
            }),
            (0, pid::PORT_CONFIGURATION) => Some(if let [value] = data {
                eeprom[offsets::PORT_ADDR] = *value;
                true
            } else {
                false
            }),
            (0, pid::POLL_GROUP_SETTINGS) => Some(if let [group_hi, group_lo, control] = data {
                // 03/05/01 §4.2.18: bits 6..4 are reserved. Retain the
                // polling-disable flag and slot while normalizing them.
                // TODO: Apply this setting once the link driver exposes
                // BCU2 fast-poll services; this is permanent configuration,
                // not a substitute for the link-layer implementation.
                let base = offsets::POLL_GROUP_SETTINGS;
                eeprom[base..base + 3].copy_from_slice(&[*group_hi, *group_lo, *control & 0x8F]);
                true
            } else {
                false
            }),
            (3, pid::PEI_TYPE) => Some(if let [value] = data {
                eeprom[offsets::PEI_TYPE] = *value;
                true
            } else {
                false
            }),
            _ => None,
        }
    }

    /// A BCU2 exposes its analog channels through `A_ADC_Read`.
    fn extra_service<const N: usize>(code: ApciCode, small6: u8, payload: &[u8]) -> Option<ServiceResult<N>> {
        crate::families::adc_read_stub(code, small6, payload)
    }
}
