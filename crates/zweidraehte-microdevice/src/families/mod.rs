//! One module per BCU-era management model.
//!
//! Each family owns everything the core is generic over: the
//! [`crate::family::MicroDeviceFamily`] impl, the family's fixed EEPROM
//! offsets, and the device-definition type whose `build_eeprom` bakes
//! the boot image.

pub mod bcu1;
pub mod bcu2;
pub mod builder;
pub mod system7;

use crate::frame::ApciCode;
use crate::management::{Reply, ServiceResult};

/// One group object as the RT1/RT2 tables store it — the same three
/// octets on BCU1 and BCU2. (System 7's M112 table widens the data
/// pointer to 16 bits and has its own descriptor.)
#[derive(Debug, Clone, Copy)]
pub struct CoDescriptor {
    /// Page-0 RAM address of the value.
    pub data_ptr: u8,
    /// Config octet (`ComObjectFlags` coding).
    pub config: u8,
    /// Type octet (`ComObjectType` coding).
    pub value_type: u8,
}

/// Read the option register through the BCU's bit inversion: the
/// hardware stores the complement of what the bus sees, so a
/// factory-erased cell reads FFh. Shared by the BCU1 and BCU2
/// `special_byte_read` hooks.
pub(crate) fn option_reg_read(addr: u16, base: u16, offset: usize, eeprom: &[u8]) -> Option<u8> {
    (addr == base + offset as u16).then(|| !eeprom[offset])
}

/// The write half of the option-register inversion. Returns whether
/// the write was consumed.
pub(crate) fn option_reg_write(addr: u16, value: u8, base: u16, offset: usize, eeprom: &mut [u8]) -> bool {
    if addr == base + offset as u16 {
        eeprom[offset] = !value;
        true
    } else {
        false
    }
}

/// The BCU-era `A_ADC_Read` answer BCU1 and BCU2 share: this stack has
/// no analog hardware behind the service, so every channel converts to
/// zero. The reply shape is what matters — clients use the service as
/// a liveness probe on the connection.
pub(crate) fn adc_read_stub(code: ApciCode, small6: u8, payload: &[u8]) -> Option<ServiceResult> {
    if code != ApciCode::AdcRead {
        return None;
    }
    let read_count = payload.first().copied().unwrap_or(1);
    Some(ServiceResult::Reply(Reply::new(ApciCode::AdcResponse, small6, &[read_count, 0x00, 0x00])))
}
