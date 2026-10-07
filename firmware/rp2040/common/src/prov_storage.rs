//! RP2040 identity from the `KNXP` factory-provisioning record.
//!
//! Mirrors `firmware/stm32/common/src/prov_storage.rs`. The record's
//! codec and flash I/O live in [`zweidraehte_device::provisioning`]; the
//! [`rp_identity_loader!`](crate::rp_identity_loader) reads it from
//! [`PROVISIONING_SECTOR`](crate::PROVISIONING_SECTOR) through
//! [`RpFlashIo`](crate::RpFlashIo), and this module maps it to the identity
//! shapes the firmware consumes.

use zweidraehte_device::provisioning::{ProvisioningError, ProvisioningRecord, tag};

use crate::storage::{FlashIdentityData, FlashSecureIdentityData};

/// Build a [`FlashIdentityData`] from a parsed record + the chip's SPI
/// flash unique ID.
///
/// The unique ID is *not* in the provisioning record — it is hardware
/// state read by the caller via `flash.blocking_unique_id()`. Keeping
/// it out of the record means re-provisioning a board with a different
/// chip works without invalidating per-device seeds derived from the
/// unique ID.
pub fn identity_from_record(rec: &ProvisioningRecord, unique_id: [u8; 8]) -> FlashIdentityData {
    FlashIdentityData { serial_number: rec.serial, mac: rec.mac, unique_id }
}

/// Build a [`FlashSecureIdentityData`] from a parsed record + the chip's
/// SPI flash unique ID.
///
/// The secure counterpart of [`identity_from_record`]: in addition to the
/// serial / MAC / unique-ID triple it requires the `FDSK` tag (the
/// Factory Default Setup Key) to be present in the record, failing with
/// [`ProvisioningError::MissingRequiredTag`] otherwise. As with the
/// insecure path, the `unique_id` is hardware state read by the caller
/// (via `flash.blocking_unique_id()`), not part of the record.
pub fn secure_identity_from_record(
    rec: &ProvisioningRecord,
    unique_id: [u8; 8],
) -> Result<FlashSecureIdentityData, ProvisioningError> {
    let fdsk = rec.fdsk.ok_or(ProvisioningError::MissingRequiredTag(tag::FDSK))?;
    Ok(FlashSecureIdentityData { serial_number: rec.serial, mac: rec.mac, unique_id, fdsk })
}
