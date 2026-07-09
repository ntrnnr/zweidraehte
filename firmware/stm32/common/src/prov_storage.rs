//! STM32 flash IO for the `KNXP` factory-provisioning record.
//!
//! The provisioning record carries the device's KNX serial, optional
//! FDSK (Data Secure devices), and optional MAC (IP devices). Format
//! and codec live in
//! [`zweidraehte_device::provisioning`]; this module is the thin
//! flash-side wrapper that knows where on the chip the record lives
//! and how to map it to the existing `FlashIdentityData` /
//! `FlashSecureIdentityData` struct shapes the rest of the firmware
//! consumes.
//!
//! # Flash slot
//!
//! Last page on the chip (`FLASH_END - PAGE_SIZE .. FLASH_END`).
//! Pinning provisioning at the very top means the config region below
//! it can grow freely without colliding with the (write-once)
//! provisioning data.
//!
//! # Boot path
//!
//! Production firmware calls [`read_provisioning`] and either succeeds
//! or panics. With the `provision-on-boot` feature, missing / corrupt
//! records are replaced by [`synthesize_and_write`] using fields
//! supplied at compile time by the dev `build.rs`.

use embassy_stm32::flash::{Blocking, Flash};

use zweidraehte_device::provisioning::{self, PROV_BUF_LEN, ProvisioningError, ProvisioningRecord, tag};

use crate::storage::{FlashError, FlashIdentityData, FlashSecureIdentityData};

/// Doubleword alignment required by STM32 flash writes.
const WRITE_ALIGN: usize = 8;

/// Offset of the provisioning page from the flash base.
///
/// Last page on the chip (`FLASH_SIZE - PAGE_SIZE`).
/// `embassy-stm32`'s `Flash::blocking_*` API takes offsets relative to
/// the flash base (`0x0800_0000` on STM32G0).
pub const fn provisioning_offset<const FLASH_SIZE: u32, const PAGE_SIZE: u32>() -> u32 {
    FLASH_SIZE - PAGE_SIZE
}

/// Read and parse the `KNXP` page.
///
/// On `Ok` the returned record is integrity-checked (CRC matches) and
/// carries at minimum a serial number. `Err` covers every kind of
/// missing or malformed record — the caller decides whether to panic
/// (production) or fall back to the dev synthesizer
/// (`provision-on-boot`).
///
/// # Panics
/// Panics on flash I/O failure. Reading flash that is mapped into the
/// CPU's address space cannot fail under normal operation, so a panic
/// here means the chip itself is in an unexpected state and there is
/// no meaningful recovery at boot time.
pub fn read_provisioning<const FLASH_SIZE: u32, const PAGE_SIZE: u32>(
    flash: &mut Flash<'static, Blocking>,
) -> Result<ProvisioningRecord, ProvisioningError> {
    let offset = provisioning_offset::<FLASH_SIZE, PAGE_SIZE>();
    let mut buf = [0u8; PROV_BUF_LEN];
    flash.blocking_read(offset, &mut buf).expect("provisioning page read");
    provisioning::parse(&buf)
}

/// Encode `record` and write it to the provisioning page.
///
/// Erases the page first, then writes the encoded record padded up to
/// a doubleword boundary with `0xFF` (the STM32 G0 flash write unit is
/// 8 bytes). Any pre-existing record is overwritten.
pub fn write_provisioning<const FLASH_SIZE: u32, const PAGE_SIZE: u32>(
    flash: &mut Flash<'static, Blocking>,
    record: &ProvisioningRecord,
) -> Result<(), FlashError> {
    let mut buf = [0xFFu8; PROV_BUF_LEN];
    let n = provisioning::write(record, &mut buf).map_err(|_| FlashError::WriteFailed)?;
    // Pad up to doubleword for the flash write API.
    let padded = (n + WRITE_ALIGN - 1) & !(WRITE_ALIGN - 1);
    debug_assert!(padded <= PROV_BUF_LEN);

    let offset = provisioning_offset::<FLASH_SIZE, PAGE_SIZE>();
    flash.blocking_erase(offset, offset + PAGE_SIZE).map_err(|_| FlashError::EraseFailed)?;
    flash.blocking_write(offset, &buf[..padded]).map_err(|_| FlashError::WriteFailed)?;
    Ok(())
}

/// Build a [`FlashIdentityData`] from a parsed record.
///
/// Plain devices need only the serial; any FDSK / MAC tags in the
/// record are ignored here.
pub fn identity_from_record(rec: &ProvisioningRecord) -> FlashIdentityData {
    FlashIdentityData { serial_number: rec.serial }
}

/// Build a [`FlashSecureIdentityData`] from a parsed record.
///
/// Errors with [`ProvisioningError::MissingRequiredTag`] if the record
/// has no FDSK — secure firmware cannot operate without one.
pub fn secure_identity_from_record(rec: &ProvisioningRecord) -> Result<FlashSecureIdentityData, ProvisioningError> {
    let fdsk = rec.fdsk.ok_or(ProvisioningError::MissingRequiredTag(tag::FDSK))?;
    Ok(FlashSecureIdentityData { serial_number: rec.serial, fdsk })
}

// ================================================================================
// Dev `provision-on-boot` synthesizer
// ================================================================================
//
// Off in production builds. When on, the firmware calls
// `synthesize_and_write` if `read_provisioning` fails — typical on a
// freshly flashed chip. The serial / FDSK / MAC come from the
// firmware's `build.rs` (env-overridable, with hardcoded fallbacks
// chosen to be obviously-not-production).

/// Write a freshly-built `KNXP` record using the supplied identity
/// fields. Used only by the `provision-on-boot` dev path; the
/// production firmware never calls this.
#[cfg(feature = "provision-on-boot")]
pub fn synthesize_and_write<const FLASH_SIZE: u32, const PAGE_SIZE: u32>(
    flash: &mut Flash<'static, Blocking>,
    serial: [u8; 6],
    fdsk: Option<[u8; 16]>,
    mac: Option<[u8; 6]>,
) -> Result<(), FlashError> {
    let record = ProvisioningRecord { serial, fdsk, mac };
    write_provisioning::<FLASH_SIZE, PAGE_SIZE>(flash, &record)
}

// ================================================================================
// Secure-identity boot helper
// ================================================================================

/// Read the secure device identity (serial + FDSK) from the `KNXP` page — the
/// boot step every secure STM32 firmware runs.
///
/// Production builds panic on a missing/invalid record. With `provision-on-boot`,
/// a missing record is filled in by writing the supplied dev defaults and
/// re-reading.
///
/// `dev_defaults` carries `(serial, fdsk, mac)` from the firmware's `build.rs`.
/// Each device crate's `dev_provisioning` constants live in its own `OUT_DIR`,
/// so they are passed in rather than referenced here. The parameter is read
/// only under the feature; production callers pass `None` and the dev-synth arm
/// is compiled out.
pub fn load_secure_identity<const FLASH_SIZE: u32, const PAGE_SIZE: u32>(
    flash: &mut Flash<'static, Blocking>,
    #[cfg_attr(not(feature = "provision-on-boot"), allow(unused_variables))] dev_defaults: Option<(
        [u8; 6],
        [u8; 16],
        [u8; 6],
    )>,
) -> FlashSecureIdentityData {
    match read_provisioning::<FLASH_SIZE, PAGE_SIZE>(flash) {
        Ok(rec) => secure_identity_from_record(&rec).unwrap_or_else(|e| defmt::panic!("KNXP missing FDSK: {:?}", e)),

        #[cfg(feature = "provision-on-boot")]
        Err(e) => {
            defmt::warn!("no KNXP record ({:?}); writing dev defaults from build.rs", e);
            let (serial, fdsk, mac) = dev_defaults.expect("provision-on-boot requires dev defaults");
            synthesize_and_write::<FLASH_SIZE, PAGE_SIZE>(flash, serial, Some(fdsk), Some(mac))
                .expect("write dev KNXP");
            let rec = read_provisioning::<FLASH_SIZE, PAGE_SIZE>(flash).expect("re-read freshly written KNXP");
            secure_identity_from_record(&rec)
                .unwrap_or_else(|e| defmt::panic!("KNXP missing FDSK after dev synth: {:?}", e))
        }

        #[cfg(not(feature = "provision-on-boot"))]
        Err(e) => defmt::panic!("no valid KNXP record: {:?}", e),
    }
}

/// Shared boot-identity loader for the non-secure STM32 firmware: read the
/// `KNXP` provisioning record; under `provision-on-boot`, a missing record is
/// filled in by writing the supplied dev serial (no FDSK, no MAC) and
/// re-reading.
///
/// `dev_serial` carries the serial from the firmware's `build.rs` — the
/// non-secure counterpart of [`load_secure_identity`]'s `dev_defaults`, with
/// the same feature-gating rules.
pub fn load_plain_identity<const FLASH_SIZE: u32, const PAGE_SIZE: u32>(
    flash: &mut Flash<'static, Blocking>,
    #[cfg_attr(not(feature = "provision-on-boot"), allow(unused_variables))] dev_serial: Option<[u8; 6]>,
) -> FlashIdentityData {
    match read_provisioning::<FLASH_SIZE, PAGE_SIZE>(flash) {
        Ok(rec) => identity_from_record(&rec),

        #[cfg(feature = "provision-on-boot")]
        Err(e) => {
            defmt::warn!("no KNXP record ({:?}); writing dev defaults from build.rs", e);
            let serial = dev_serial.expect("provision-on-boot requires a dev serial");
            synthesize_and_write::<FLASH_SIZE, PAGE_SIZE>(flash, serial, None, None).expect("write dev KNXP");
            let rec = read_provisioning::<FLASH_SIZE, PAGE_SIZE>(flash).expect("re-read freshly written KNXP");
            identity_from_record(&rec)
        }

        #[cfg(not(feature = "provision-on-boot"))]
        Err(e) => defmt::panic!("no valid KNXP record: {:?}", e),
    }
}

/// Emit the device-local boot-identity loader — the STM32 counterpart of
/// `rp-common`'s `rp_identity_loader!`.
///
/// The flavour picks the identity shape and the emitted fn name: `plain` →
/// `fn load_identity(…) -> FlashIdentityData`, `secure` →
/// `fn load_secure_identity(…) -> FlashSecureIdentityData`. Both delegate to
/// the shared boot logic ([`load_plain_identity`] / [`load_secure_identity`])
/// with the G0 flash geometry consts; the only device-local piece is the
/// `provision-on-boot` dev defaults, read from the caller's
/// `dev_provisioning` module (rendered into each crate's `OUT_DIR` by its
/// `build.rs`, which is why the macro references it unhygienically rather
/// than taking the values as arguments).
///
/// ```ignore
/// stm32_common::stm32_identity_loader!(secure);
/// ```
#[macro_export]
macro_rules! stm32_identity_loader {
    (plain) => {
        fn load_identity(
            flash: &mut ::embassy_stm32::flash::Flash<'static, ::embassy_stm32::flash::Blocking>,
        ) -> $crate::FlashIdentityData {
            #[cfg(feature = "provision-on-boot")]
            let dev_serial = Some(dev_provisioning::DEV_SERIAL);
            #[cfg(not(feature = "provision-on-boot"))]
            let dev_serial = None;

            $crate::load_plain_identity::<{ $crate::STM32G0_FLASH_SIZE }, { $crate::STM32G0_PAGE_SIZE }>(
                flash, dev_serial,
            )
        }
    };
    (secure) => {
        fn load_secure_identity(
            flash: &mut ::embassy_stm32::flash::Flash<'static, ::embassy_stm32::flash::Blocking>,
        ) -> $crate::FlashSecureIdentityData {
            #[cfg(feature = "provision-on-boot")]
            let dev_defaults =
                Some((dev_provisioning::DEV_SERIAL, dev_provisioning::DEV_FDSK, dev_provisioning::DEV_MAC));
            #[cfg(not(feature = "provision-on-boot"))]
            let dev_defaults = None;

            $crate::load_secure_identity::<{ $crate::STM32G0_FLASH_SIZE }, { $crate::STM32G0_PAGE_SIZE }>(
                flash,
                dev_defaults,
            )
        }
    };
}
