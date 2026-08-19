//! The System 7 instance of the family seam.

use heapless::Vec;
use zweidraehte_proto::messages::apdu::load_control::{LoadState, RunState};
use zweidraehte_proto::pid;
use zweidraehte_proto::transport::TlStyle;

use super::offsets;
use crate::device::DeviceIdentity;
use crate::family::{LsmPath, MicroDeviceFamily};
use crate::management::{ManagementState, dispatch_lsm_event};

/// System 7 / BIM M112, TP1, mask version 0705h.
///
/// The management model is fixed by the mask; the memory layout mostly
/// is not, so the product parameterizes the family:
///
/// - `EEPROM_LEN` — how much of the 4000h–CFFFh user-EEPROM window
///   this product actually backs, starting at 4000h. Reads outside the
///   backing answer 00h and writes are dropped, like unpopulated
///   memory on real silicon.
/// - `COT_ADDR` — the group object table's address. The M112 table has
///   no device-side location resource and no interface object; ETS
///   knows the address from the product database, so the device and
///   the product definition must agree on it at compile time.
pub struct System7Family<const EEPROM_LEN: usize, const COT_ADDR: u16>;

/// Machine roster: 0 = group address table, 1 = association table,
/// 2 = application program, 3 = application program 2. The two
/// application machines carry run state machines.
const APP_MACHINE: usize = 2;

impl<const EEPROM_LEN: usize, const COT_ADDR: u16> System7Family<EEPROM_LEN, COT_ADDR> {
    /// Is this interface object one of the two application program
    /// objects (indices 3 and 4, machines 2 and 3)?
    fn app_machine_of(obj: u8) -> Option<usize> {
        (obj == 3 || obj == 4).then(|| usize::from(obj) - 1)
    }
}

impl<const EEPROM_LEN: usize, const COT_ADDR: u16> MicroDeviceFamily for System7Family<EEPROM_LEN, COT_ADDR> {
    type EepromStore = [u8; EEPROM_LEN];
    fn blank_eeprom() -> Self::EepromStore {
        [0; EEPROM_LEN]
    }

    const DD0: u16 = 0x0705;
    const TL_STYLE: TlStyle = TlStyle::Style3;
    const AUTH_LEVELS: usize = 16;
    const CONNECTIONLESS_MANAGEMENT: bool = true;
    const PROGMODE_PROPERTY: bool = true;
    const MAX_APDU: usize = 15;

    const EEPROM_BASE: u16 = offsets::ADT_ADDR;
    const EEPROM_SIZE: usize = EEPROM_LEN;
    // The 100h-byte resource window at 0700h ("resources from 0700h").
    const RAM2_BASE: u16 = 0x0700;
    const RAM2_SIZE: usize = 0x100;

    // RT8: the table starts the user EEPROM, and the IA is defined as
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

    // RT8 count semantics: the leading byte counts group addresses
    // only (the IA slot is not counted), so 0 mutes.
    const MUTE_LENGTH: u8 = 0;
    fn ga_count(length_byte: u8) -> u8 {
        length_byte
    }
    const SENDING_ASSOC_INDEXED: bool = false;

    // M112 group object table: [count:1][ram_flags_ptr:2BE] then
    // [data_ptr:2BE][config:1][type:1] per entry.
    const COT_HEADER_LEN: usize = 3;
    const COT_ENTRY_LEN: usize = 4;
    const COT_CFG_OFFSET: usize = 2;
    const COT_TYPE_OFFSET: usize = 3;

    // Machines 1..=4 (ADT, AST, App, App2) answer on interface objects
    // 1..=4 through PID_LOAD_STATE_CONTROL — what ETS drives — and
    // additionally through the memory window at 0104h.
    const LSM_PATH: LsmPath =
        LsmPath::MemoryMapped { control_addr: offsets::LOAD_CONTROL_ADDR, status_base: offsets::LOAD_STATUS_ADDR };
    const LSM_OBJ_BASE: u8 = 1;
    const LSM_COUNT: usize = 4;
    const OBJECT_COUNT: u8 = 5;
    fn object_type(idx: u8) -> u16 {
        // Device (0), Address Table (1), Association Table (2),
        // Application Program (3), Interface Program (4) — the types
        // equal the indices, as on BCU2.
        idx as u16
    }

    /// No RunError byte on System 7: the application runs when its
    /// machine is Loaded and no RUNCONTROL_STOP is standing.
    fn is_app_running(_eeprom: &[u8], mgmt: &ManagementState) -> bool {
        mgmt.lsm[APP_MACHINE].state == LoadState::Loaded && !mgmt.run_stopped[APP_MACHINE]
    }

    /// 03/05/01 §4.24.2.3.3 Table 97: a loaded application is Running
    /// unless explicitly stopped, in which case it is Terminated — the
    /// HALTED intermediate of BCU2/System 2 is unreachable from the
    /// bus. Unloaded machines report Halted.
    fn run_state_read(obj: u8, _eeprom: &[u8], mgmt: &ManagementState) -> Option<u8> {
        let machine = Self::app_machine_of(obj)?;
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
        let Some(machine) = Self::app_machine_of(obj) else { return false };
        // §4.24.2.3.2 Table 96: 0 = no-op, 1 = restart, 2 = stop.
        // Anything else is not a run event a client may raise.
        match value {
            0x00 => {}
            0x01 => mgmt.run_stopped[machine] = false,
            0x02 => {
                if mgmt.lsm[machine].state == LoadState::Loaded {
                    mgmt.run_stopped[machine] = true;
                }
            }
            _ => return false,
        }
        true
    }

    fn unload_side_effect(machine: usize, eeprom: &mut [u8], mgmt: &mut ManagementState) {
        match machine {
            // RT8 mute: zero the GA count. The IA at bytes 1–2 survives
            // — an unloaded device keeps its commissioning.
            0 => {
                if let Some(count) = eeprom.get_mut(Self::ADDR_TABLE_OFFSET) {
                    *count = 0;
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
            // Unloading an application halts its run state machine.
            2 | 3 => mgmt.run_stopped[machine] = false,
            _ => {}
        }
    }

    /// The LSM's Loaded event cascades into the run state machine: a
    /// freshly loaded application runs (03/05/01 §4.24, RunEvent
    /// Loaded), clearing any Stop left from the previous program.
    fn load_completed_side_effect(machine: usize, _eeprom: &mut [u8], mgmt: &mut ManagementState) {
        if machine == 2 || machine == 3 {
            mgmt.run_stopped[machine] = false;
        }
    }

    /// Fifteen settable keys for sixteen levels: the free-access level
    /// 15 owns no key, and `A_Key_Write` targeting it answers FFh.
    fn key_write_level_valid(level: u8) -> bool {
        usize::from(level) < Self::AUTH_LEVELS - 1
    }

    /// The properties a System 7 download actually reads beyond the
    /// generic set: the identity guard and the APDU negotiation.
    /// TODO: PID_PROGMODE (54), PID_MCB_TABLE (27) and PID_IO_LIST
    /// (71) when a test or tool is seen relying on them.
    fn property_read_hook(
        obj: u8,
        prop_id: u16,
        _eeprom: &[u8],
        identity: &DeviceIdentity,
        _mgmt: &ManagementState,
    ) -> Option<Vec<u8, 10>> {
        let mut v: Vec<u8, 10> = Vec::new();
        match (obj, prop_id) {
            (0, pid::device::HARDWARE_TYPE) => {
                let _ = v.extend_from_slice(&identity.hardware_type);
            }
            (0, pid::device::MAX_APDU_LENGTH) => {
                let _ = v.extend_from_slice(&(Self::MAX_APDU as u16).to_be_bytes());
            }
            _ => return None,
        }
        Some(v)
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
        let machine = usize::from(data[0] >> 4);
        let event = data[0] & 0x0F;
        if machine == 0 || machine > Self::LSM_COUNT {
            return true;
        }
        let mut record = [0u8; offsets::LOAD_CONTROL_MAX];
        record[0] = event;
        let len = if event == 0x03 && data.len() >= 3 {
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
}
