//! One module per BCU-era management model.
//!
//! Each family owns everything the core is generic over: the
//! [`crate::family::MicroDeviceFamily`] impl, the family's fixed EEPROM
//! offsets, and the device-definition type whose `build_eeprom` bakes
//! the boot image.

pub mod bcu1;
pub mod bcu2;
pub mod system7;

use crate::frame::apci;
use crate::management::{Reply, ServiceResult};

/// The BCU-era `A_ADC_Read` answer BCU1 and BCU2 share: this stack has
/// no analog hardware behind the service, so every channel converts to
/// zero. The reply shape is what matters — clients use the service as
/// a liveness probe on the connection.
pub(crate) fn adc_read_stub(base: u16, small6: u8, payload: &[u8]) -> Option<ServiceResult> {
    if base != apci::ADC_READ {
        return None;
    }
    let read_count = payload.first().copied().unwrap_or(1);
    Some(ServiceResult::Reply(Reply::new(apci::ADC_RESPONSE, small6, &[read_count, 0x00, 0x00])))
}
