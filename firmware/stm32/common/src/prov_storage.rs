//! STM32 flash IO for the `KNXP` factory-provisioning record.
//!
//! The provisioning record carries the device's KNX serial, optional
//! FDSK (Data Secure devices), and optional MAC (IP devices). Format
//! codec and flash I/O live in [`zweidraehte_device::provisioning`];
//! this module maps the record to the `FlashIdentityData` /
//! `FlashSecureIdentityData` shapes the rest of the firmware consumes,
//! at [`PROVISIONING_PAGE`].
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
//! Production firmware reads the record and either succeeds or panics.
//! With the `provision-on-boot` feature, a missing or corrupt record is
//! replaced by one built from fields the dev `build.rs` supplies at
//! compile time.

use zweidraehte_device::provisioning::{self, ProvisioningError, ProvisioningRecord, tag};

use crate::StmFlashIo;
use crate::storage::{FlashIdentityData, FlashSecureIdentityData, PROVISIONING_PAGE};

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
pub fn load_secure_identity(
    mut flash: StmFlashIo,
    #[cfg_attr(not(feature = "provision-on-boot"), allow(unused_variables))] dev_defaults: Option<(
        [u8; 6],
        [u8; 16],
        [u8; 6],
    )>,
) -> FlashSecureIdentityData {
    match provisioning::load(&mut flash, PROVISIONING_PAGE) {
        Ok(rec) => secure_identity_from_record(&rec).unwrap_or_else(|e| defmt::panic!("KNXP missing FDSK: {:?}", e)),

        #[cfg(feature = "provision-on-boot")]
        Err(e) => {
            defmt::warn!("no KNXP record ({:?}); writing dev defaults from build.rs", e);
            let (serial, fdsk, mac) = dev_defaults.expect("provision-on-boot requires dev defaults");
            let rec = ProvisioningRecord { serial, fdsk: Some(fdsk), mac: Some(mac) };
            provisioning::store(&mut flash, PROVISIONING_PAGE, &rec).expect("write dev KNXP");
            let rec = provisioning::load(&mut flash, PROVISIONING_PAGE).expect("re-read freshly written KNXP");
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
pub fn load_plain_identity(
    mut flash: StmFlashIo,
    #[cfg_attr(not(feature = "provision-on-boot"), allow(unused_variables))] dev_serial: Option<[u8; 6]>,
) -> FlashIdentityData {
    match provisioning::load(&mut flash, PROVISIONING_PAGE) {
        Ok(rec) => identity_from_record(&rec),

        #[cfg(feature = "provision-on-boot")]
        Err(e) => {
            defmt::warn!("no KNXP record ({:?}); writing dev defaults from build.rs", e);
            let serial = dev_serial.expect("provision-on-boot requires a dev serial");
            let rec = ProvisioningRecord::from_serial(serial);
            provisioning::store(&mut flash, PROVISIONING_PAGE, &rec).expect("write dev KNXP");
            let rec = provisioning::load(&mut flash, PROVISIONING_PAGE).expect("re-read freshly written KNXP");
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
/// over the device's flash cell; the only device-local piece is the
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
            flash: &'static ::core::cell::RefCell<
                ::embassy_stm32::flash::Flash<'static, ::embassy_stm32::flash::Blocking>,
            >,
        ) -> $crate::FlashIdentityData {
            #[cfg(feature = "provision-on-boot")]
            let dev_serial = Some(dev_provisioning::DEV_SERIAL);
            #[cfg(not(feature = "provision-on-boot"))]
            let dev_serial = None;

            $crate::load_plain_identity($crate::StmFlashIo::new(flash), dev_serial)
        }
    };
    (secure) => {
        fn load_secure_identity(
            flash: &'static ::core::cell::RefCell<
                ::embassy_stm32::flash::Flash<'static, ::embassy_stm32::flash::Blocking>,
            >,
        ) -> $crate::FlashSecureIdentityData {
            #[cfg(feature = "provision-on-boot")]
            let dev_defaults =
                Some((dev_provisioning::DEV_SERIAL, dev_provisioning::DEV_FDSK, dev_provisioning::DEV_MAC));
            #[cfg(not(feature = "provision-on-boot"))]
            let dev_defaults = None;

            $crate::load_secure_identity($crate::StmFlashIo::new(flash), dev_defaults)
        }
    };
}
