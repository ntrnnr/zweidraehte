//! The BCU2 instance of the family seam.

use heapless::Vec;
use zweidraehte_proto::messages::apdu::load_control::LoadState;
use zweidraehte_proto::pid;
use zweidraehte_proto::transport::TlStyle;

use super::offsets;
use crate::device::DeviceIdentity;
use crate::family::{LsmPath, MicroDeviceFamily};
use crate::frame::apci;
use crate::management::{ManagementState, Reply, ServiceResult};

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
    const RAM2_BASE: u16 = 0x0900;
    const RAM2_SIZE: usize = 0xE0;

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

    // RT2: the length byte counts the IA slot, so a table holding only
    // the IA (length 1) has no group addresses — group traffic muted.
    const MUTE_LENGTH: u8 = 1;
    fn ga_count(length_byte: u8) -> u8 {
        length_byte.saturating_sub(1)
    }
    const SENDING_ASSOC_INDEXED: bool = true;

    // RT2 group object table: [count:1][ram_flags_ptr:1] then
    // [data_ptr:1][config:1][type:1] per entry.
    const COT_HEADER_LEN: usize = 2;
    const COT_ENTRY_LEN: usize = 3;
    const COT_CFG_OFFSET: usize = 1;
    const COT_TYPE_OFFSET: usize = 2;

    // Machines 1..=3 (ADT, AST, application) live behind
    // PID_LOAD_STATE_CONTROL on interface objects 1..=3.
    const LSM_PATH: LsmPath = LsmPath::Property { obj_base: 1 };
    const LSM_OBJ_BASE: u8 = 1;
    const LSM_COUNT: usize = 3;
    const OBJECT_COUNT: u8 = 4;
    fn object_type(idx: u8) -> u16 {
        // Interface object types happen to equal the object indices for
        // the BCU2 roster: Device (0), Address Table (1), Association
        // Table (2), Application Program (3).
        idx as u16
    }

    /// The application program runs when it is loaded and the RunError
    /// byte carries no active (low) error bits. ETS halts the device by
    /// writing 00h there and clears it back to FFh after the download.
    fn is_app_running(eeprom: &[u8], mgmt: &ManagementState) -> bool {
        eeprom.get(offsets::RUN_ERROR).copied() == Some(0xFF)
            && mgmt.lsm[Self::LSM_COUNT - 1].state == LoadState::Loaded
    }

    fn run_state_read(obj: u8, eeprom: &[u8], mgmt: &ManagementState) -> Option<u8> {
        (obj == 3).then(|| if Self::is_app_running(eeprom, mgmt) { 0x01 } else { 0x00 })
    }

    fn run_state_write(obj: u8, value: u8, eeprom: &mut [u8], _mgmt: &mut ManagementState) -> bool {
        if obj != 3 {
            return false;
        }
        // Run control: 1 restarts, 2 stops. The BCU2 run state is a
        // consequence of RunError + load state, so the controls only
        // touch RunError.
        match value {
            0x01 => eeprom[offsets::RUN_ERROR] = 0xFF,
            0x02 => eeprom[offsets::RUN_ERROR] = 0x00,
            _ => {}
        }
        true
    }

    fn unload_side_effect(machine: usize, eeprom: &mut [u8], mgmt: &mut ManagementState) {
        match machine {
            0 => eeprom[Self::ADDR_TABLE_OFFSET] = Self::MUTE_LENGTH,
            1 => {
                let assoc = Self::assoc_table_offset(eeprom, mgmt);
                if assoc < Self::EEPROM_SIZE {
                    eeprom[assoc] = 0;
                }
            }
            2 => {
                // Clearing the ApplicationID's DevType+Version is what
                // un-marks the program as present.
                let dev_type = offsets::APPLICATION_ID + 2;
                eeprom[dev_type..dev_type + 3].fill(0);
            }
            _ => {}
        }
    }

    // The option register stores the complement of what the client
    // reads and writes.
    fn special_byte_read(addr: u16, eeprom: &[u8], _mgmt: &ManagementState) -> Option<u8> {
        (addr == Self::EEPROM_BASE + offsets::OPTION_REG as u16).then(|| !eeprom[offsets::OPTION_REG])
    }
    fn special_byte_write(addr: u16, value: u8, eeprom: &mut [u8], _mgmt: &mut ManagementState) -> bool {
        if addr == Self::EEPROM_BASE + offsets::OPTION_REG as u16 {
            eeprom[offsets::OPTION_REG] = !value;
            return true;
        }
        false
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
            (0, pid::PEI_TYPE) => {
                let _ = v.push(eeprom[offsets::PEI_TYPE]);
            }
            (0, pid::PORT_CONFIGURATION) => {
                let _ = v.push(eeprom[offsets::PORT_ADDR]);
            }
            (0, pid::POLL_GROUP_SETTINGS) => {
                let _ = v.extend_from_slice(&[0x00, 0x00, 0x00]);
            }
            (0, pid::MANUFACTURER_DATA) => {
                let _ = v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            }
            (3, pid::PROGRAM_VERSION) => {
                let base = offsets::APPLICATION_ID;
                let _ = v.extend_from_slice(&eeprom[base..base + 5]);
            }
            _ => return None,
        }
        Some(v)
    }

    /// A BCU2 exposes its analog channels through A_ADC_Read; this
    /// stack has no analog hardware behind them, so every channel
    /// converts to zero. The reply shape is what matters: clients use
    /// the service as a liveness probe on the connection.
    fn extra_service(base: u16, small6: u8, payload: &[u8]) -> Option<ServiceResult> {
        if base != apci::ADC_READ {
            return None;
        }
        let read_count = payload.first().copied().unwrap_or(1);
        Some(ServiceResult::Reply(Reply::new(apci::ADC_RESPONSE, small6, &[read_count, 0x00, 0x00])))
    }
}
