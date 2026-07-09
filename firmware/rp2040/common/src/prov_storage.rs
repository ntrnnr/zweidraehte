//! RP2040 flash IO for the `KNXP` factory-provisioning record.
//!
//! Mirrors `firmware/stm32/common/src/prov_storage.rs`. Same record format
//! (defined in [`zweidraehte_device::provisioning`]), different flash
//! driver and a different sector layout — RP2040 erases at a 4 KiB
//! sector granularity, doesn't have STM32's doubleword write
//! restriction.
//!
//! # Flash slot
//!
//! Last 4 KiB sector of flash (`0x1FF000 .. 0x200000` on a 2 MB chip).
//! Sitting at the very end means the config region below it can grow
//! freely without ever overlapping the (write-once) provisioning data.

use embassy_rp::flash::{self, Flash};
use embassy_rp::peripherals::FLASH;

use zweidraehte_device::provisioning::{self, PROV_BUF_LEN, ProvisioningError, ProvisioningRecord, tag};

use crate::storage::{FLASH_SIZE, FlashError, FlashIdentityData, FlashSecureIdentityData, SECTOR_SIZE};

/// Offset of the provisioning sector — the very last 4 KiB sector of
/// flash. Pinned at the top so the (growable) config region below
/// can never collide with it.
pub const PROVISIONING_SECTOR_OFFSET: u32 = (FLASH_SIZE - SECTOR_SIZE) as u32;

/// Read and parse the `KNXP` sector.
///
/// `Ok` carries an integrity-checked record (CRC matches, mandatory
/// SERIAL tag present). The caller is responsible for asserting any
/// device-class invariants (e.g. IP devices need MAC; secure devices
/// need FDSK) before constructing an identity struct.
///
/// # Panics
/// Panics on flash I/O failure. RP2040 flash reads run from the cached
/// XIP mapping — the only realistic failure mode is the chip itself
/// being in a broken state, which has no boot-time recovery.
#[cfg(feature = "rp2040")]
pub fn read_provisioning(
    flash: &mut Flash<'static, FLASH, flash::Blocking, FLASH_SIZE>,
) -> Result<ProvisioningRecord, ProvisioningError> {
    let mut buf = [0u8; PROV_BUF_LEN];
    flash.blocking_read(PROVISIONING_SECTOR_OFFSET, &mut buf).expect("provisioning sector read");
    provisioning::parse(&buf)
}

/// Encode `record` and write it to the provisioning sector.
///
/// Erases the 4 KiB sector first, then writes the encoded record. RP2040
/// flash has no doubleword write restriction; the encoded length is used
/// directly.
#[cfg(feature = "rp2040")]
pub fn write_provisioning(
    flash: &mut Flash<'static, FLASH, flash::Blocking, FLASH_SIZE>,
    record: &ProvisioningRecord,
) -> Result<(), FlashError> {
    let mut buf = [0xFFu8; PROV_BUF_LEN];
    let n = provisioning::write(record, &mut buf).map_err(|_| FlashError::WriteFailed)?;

    flash
        .blocking_erase(PROVISIONING_SECTOR_OFFSET, PROVISIONING_SECTOR_OFFSET + SECTOR_SIZE as u32)
        .map_err(|_| FlashError::EraseFailed)?;
    flash.blocking_write(PROVISIONING_SECTOR_OFFSET, &buf[..n]).map_err(|_| FlashError::WriteFailed)?;
    Ok(())
}

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

// ================================================================================
// Dev `provision-on-boot` synthesizer
// ================================================================================

/// Write a freshly-built `KNXP` record using the supplied identity
/// fields. Used only by the `provision-on-boot` dev path.
#[cfg(all(feature = "rp2040", feature = "provision-on-boot"))]
pub fn synthesize_and_write(
    flash: &mut Flash<'static, FLASH, flash::Blocking, FLASH_SIZE>,
    serial: [u8; 6],
    fdsk: Option<[u8; 16]>,
    mac: Option<[u8; 6]>,
) -> Result<(), FlashError> {
    let record = ProvisioningRecord { serial, fdsk, mac };
    write_provisioning(flash, &record)
}
