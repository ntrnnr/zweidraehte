//! The secure targets' serial and FDSK, from the `KNXP` factory record.
//!
//! Production firmware refuses to boot without a valid record written by
//! `knx-provision`. With the `provision-on-boot` feature, a missing record is
//! replaced by one built from the development defaults the target's
//! `build.rs` renders; after that first boot the unit looks factory
//! provisioned.

use zweidraehte_nv::stores::provisioning::{self, ProvisioningRecord};

use crate::flash::{PROVISIONING_PAGE, RawFlash};

/// What a secure target needs from its factory record.
#[derive(Clone, Copy)]
pub struct SecureIdentity {
    pub serial_number: [u8; 6],
    pub fdsk: [u8; 16],
}

/// Read the identity from the provisioning page.
///
/// `None` covers every failure: no valid record, a record without the FDSK
/// a secure device cannot run without, or (under `provision-on-boot`) a
/// failed store of the development record. The caller panics on it, the
/// recovery is the same for all three (re-provision the board), and an
/// error type the panic formats would cost flash: formatting the record's
/// parse error alone links about 1.6 KiB of `core::fmt`.
///
/// `dev_defaults` carries the development serial and FDSK from the target's
/// `build.rs`; they live in the target's `OUT_DIR`, so they are passed in.
/// Only `provision-on-boot` builds read it; production callers pass `None`.
pub fn load_secure_identity(
    #[cfg_attr(not(feature = "provision-on-boot"), allow(unused_variables))] dev_defaults: Option<([u8; 6], [u8; 16])>,
) -> Option<SecureIdentity> {
    match provisioning::load(&mut RawFlash, PROVISIONING_PAGE) {
        Ok(record) => identity_from_record(&record),

        #[cfg(feature = "provision-on-boot")]
        Err(_) => {
            let (serial, fdsk) = dev_defaults.expect("provision-on-boot requires dev defaults");
            let record = ProvisioningRecord { serial, fdsk: Some(fdsk), mac: None };
            provisioning::store(&mut RawFlash, PROVISIONING_PAGE, &record).ok()?;
            identity_from_record(&record)
        }

        #[cfg(not(feature = "provision-on-boot"))]
        Err(_) => None,
    }
}

fn identity_from_record(record: &ProvisioningRecord) -> Option<SecureIdentity> {
    Some(SecureIdentity { serial_number: record.serial, fdsk: record.fdsk? })
}
