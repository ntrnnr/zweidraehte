//! The BCU1 instance of the family seam.

use zweidraehte_proto::memory::MemoryRegion;
use zweidraehte_proto::tables::association::SendingAssociation;
use zweidraehte_proto::tables::com_object::BcuComObjectTableFormat;
use zweidraehte_proto::transport::TlStyle;

use super::offsets;
use crate::family::MicroDeviceFamily;
use crate::frame::ApciCode;
use crate::management::{ManagementState, ServiceResult};

/// BCU1 / System 1, TP1, mask version 0012h.
///
/// The oldest management model in the crate, and the simplest: fully
/// memory-mapped (no interface objects, no properties, no load state
/// machines), no `A_Authorize` (resources are plain `remote local1`
/// access — the service is a BCU2 addition), transport layer Style 2.
/// A download is a direct `A_Memory_Write` sequence with client-side
/// read-back; "application loaded" is nothing but DevTyp ≠ 0 in the
/// EEPROM header.
///
/// The concrete numbers are the mask 0012h resource map (09_04_01
/// §3.1.10, mirrored in `BCU1_PLAN.md` and the client's `MV_0012`
/// mask fixture). The RT1 table layouts are RT2's octet for octet, so
/// every table constant below matches BCU2's.
pub struct Bcu1Family;

/// The BCU1 EEPROM: one 256-byte segment, 0100h..=01FFh.
pub const BCU1_EEPROM_SIZE: usize = 0x100;

impl MicroDeviceFamily for Bcu1Family {
    type EepromStore = [u8; BCU1_EEPROM_SIZE];
    fn blank_eeprom() -> Self::EepromStore {
        [0; BCU1_EEPROM_SIZE]
    }

    const DD0: u16 = 0x0012;
    const TL_STYLE: TlStyle = TlStyle::Style2;
    /// BCU1 predates `A_Authorize`; zero levels switches the service
    /// off entirely.
    const AUTH_LEVELS: usize = 0;

    const EEPROM_BASE: u16 = 0x0100;
    const EEPROM_SIZE: usize = BCU1_EEPROM_SIZE;
    /// No second RAM window on BCU1 — everything lives in page 0 and
    /// the one EEPROM segment.
    const RAM2_BASE: u16 = 0;
    const RAM2_SIZE: usize = 0;
    const MEMORY_REGIONS: &'static [MemoryRegion] = &[
        MemoryRegion::open(0x0000, crate::device::RAM_SIZE as u32),
        MemoryRegion::open(Self::EEPROM_BASE, Self::EEPROM_SIZE as u32),
    ];

    const ADDR_TABLE_OFFSET: usize = 0x16;
    fn ia_eeprom_offset() -> usize {
        offsets::INDIVIDUAL_ADDRESS
    }

    // Both tables hang off one-byte pointer cells relative to 0100h,
    // exactly as on BCU2.
    fn assoc_table_offset(eeprom: &[u8], _mgmt: &ManagementState) -> usize {
        usize::from(eeprom.get(offsets::ASSOC_TAB_PTR).copied().unwrap_or(0))
    }
    fn cot_table_offset(eeprom: &[u8], _mgmt: &ManagementState) -> usize {
        usize::from(eeprom.get(offsets::COMMS_TAB_PTR).copied().unwrap_or(0))
    }

    const SENDING_ASSOCIATION: SendingAssociation = SendingAssociation::Indexed;

    const COM_OBJECT_TABLE_FORMAT: BcuComObjectTableFormat = BcuComObjectTableFormat::Rt1;

    // No load state machines and no interface objects: the management
    // surface is memory access, the device descriptor, restart, and
    // A_ADC_Read — nothing else.
    const LSM_OBJ_BASE: u8 = 0;
    const LSM_COUNT: usize = 0;
    const OBJECT_COUNT: u8 = 0;
    fn object_type(_idx: u8) -> u16 {
        // Only called with idx < OBJECT_COUNT — never on BCU1.
        0
    }

    /// The application runs when RunError carries no active (low)
    /// error bits and an application is present at all — which on a
    /// mask without load state machines is DevTyp ≠ 0 (the unload
    /// sequence zeroes DevTyp + Version to un-mark the program).
    fn is_app_running(eeprom: &[u8], _mgmt: &ManagementState) -> bool {
        eeprom.get(offsets::RUN_ERROR).copied() == Some(offsets::RUN_ERROR_ALL_CLEAR)
            && eeprom.get(offsets::DEV_TYP..offsets::DEV_TYP + 2).is_some_and(|d| d != [0, 0])
    }

    fn run_state_read(_obj: u8, _eeprom: &[u8], _mgmt: &ManagementState) -> Option<u8> {
        None
    }
    fn run_state_write(_obj: u8, _value: u8, _eeprom: &mut [u8], _mgmt: &mut ManagementState) -> bool {
        false
    }
    fn unload_side_effect(_machine: usize, _eeprom: &mut [u8], _mgmt: &mut ManagementState) {}

    fn special_byte_read(addr: u16, eeprom: &[u8], _mgmt: &ManagementState) -> Option<u8> {
        crate::families::option_reg_read(addr, Self::EEPROM_BASE, offsets::OPTION_REG, eeprom)
    }

    /// Beyond the option-register inversion, this is where the BCU's
    /// checksum duty lives: 09_04_01 §3.1.10.3.7 — "each time a value
    /// is written to this area the checksum shall be automatically
    /// updated". ETS relies on it and never writes 01FFh itself
    /// (hardware-confirmed, `BCU1_PLAN.md`).
    fn special_byte_write(addr: u16, value: u8, eeprom: &mut [u8], _mgmt: &mut ManagementState) -> bool {
        if crate::families::option_reg_write(addr, value, Self::EEPROM_BASE, offsets::OPTION_REG, eeprom) {
            return true;
        }
        let Some(off) = addr.checked_sub(Self::EEPROM_BASE).map(usize::from) else {
            return false;
        };
        if off >= offsets::CHECK_LIM && off < checked_range_end(eeprom) {
            eeprom[off] = value;
            update_ee_exor(eeprom);
            return true;
        }
        false
    }

    /// A BCU1 exposes its analog channels through `A_ADC_Read` just
    /// like BCU2 (the PEI hardware detection runs over them).
    fn extra_service<const N: usize>(code: ApciCode, small6: u8, payload: &[u8]) -> Option<ServiceResult<N>> {
        crate::families::adc_read_stub(code, small6, payload)
    }
}

/// One-past-the-end offset of the EE_EXOR-checked range: the spec
/// range "108h to (CheckLim − 1)" inclusive, empty when CheckLim holds
/// an out-of-spec value (legal 09h–FFh).
fn checked_range_end(eeprom: &[u8]) -> usize {
    let lim = usize::from(eeprom[offsets::CHECK_LIM]);
    if lim >= offsets::CHECK_LIM_MIN { lim } else { offsets::CHECK_LIM }
}

/// Recompute the EE_EXOR checksum over the checked range.
///
/// TODO: the spec names the routine but not the polarity; plain XOR of
/// the range is the natural reading of "EXOR" and is what the boot
/// image seeds, but it has not been byte-compared against real silicon
/// (the client never reads 01FFh, so nothing downstream depends on it
/// yet).
pub(super) fn update_ee_exor(eeprom: &mut [u8]) {
    let mut x = 0u8;
    for &b in &eeprom[offsets::CHECK_LIM..checked_range_end(eeprom)] {
        x ^= b;
    }
    eeprom[offsets::EE_EXOR] = x;
}
