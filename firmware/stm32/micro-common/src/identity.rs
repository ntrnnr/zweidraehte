//! The secure targets' serial and FDSK, from the `KNXP` factory record.
//!
//! Production firmware refuses to boot without a valid record written by
//! `knx-provision`. With the `provision-on-boot` feature, a missing record is
//! replaced by one built from the development defaults the target's
//! `build.rs` renders; after that first boot the unit looks factory
//! provisioned.

use zweidraehte_nv::provisioning::{self, ProvisioningRecord};

use crate::flash::{PROVISIONING_PAGE, RawFlash};

/// What a secure target needs from its factory record.
#[derive(Clone, Copy)]
pub struct SecureIdentity {
    pub serial_number: [u8; 6],
    pub fdsk: [u8; 16],
}

/// Why the identity could not be loaded.
///
/// The variants carry no detail on purpose: the caller panics on any of them
/// with `Debug` output, and formatting the record's parse error would link
/// `core::fmt`'s integer and struct formatting (about 1.6 KiB) into a target
/// whose recovery is the same either way: re-provision the board.
#[derive(Debug)]
pub enum IdentityError {
    /// The provisioning page holds no valid record.
    Unprovisioned,
    /// Storing the development record failed.
    #[cfg(feature = "provision-on-boot")]
    Store,
    /// The record has no FDSK, which a secure device cannot run without.
    MissingFdsk,
}

/// Read the identity from the provisioning page.
///
/// `dev_defaults` carries the development serial and FDSK from the target's
/// `build.rs`; they live in the target's `OUT_DIR`, so they are passed in.
/// Only `provision-on-boot` builds read it; production callers pass `None`.
pub fn load_secure_identity(
    #[cfg_attr(not(feature = "provision-on-boot"), allow(unused_variables))] dev_defaults: Option<([u8; 6], [u8; 16])>,
) -> Result<SecureIdentity, IdentityError> {
    match provisioning::load(&mut RawFlash, PROVISIONING_PAGE) {
        Ok(record) => identity_from_record(&record),

        #[cfg(feature = "provision-on-boot")]
        Err(_) => {
            let (serial, fdsk) = dev_defaults.expect("provision-on-boot requires dev defaults");
            let record = ProvisioningRecord { serial, fdsk: Some(fdsk), mac: None };
            provisioning::store(&mut RawFlash, PROVISIONING_PAGE, &record).map_err(|_| IdentityError::Store)?;
            identity_from_record(&record)
        }

        #[cfg(not(feature = "provision-on-boot"))]
        Err(_) => Err(IdentityError::Unprovisioned),
    }
}

fn identity_from_record(record: &ProvisioningRecord) -> Result<SecureIdentity, IdentityError> {
    let fdsk = record.fdsk.ok_or(IdentityError::MissingFdsk)?;
    Ok(SecureIdentity { serial_number: record.serial, fdsk })
}
