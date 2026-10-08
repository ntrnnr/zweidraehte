//! Low-write System 7 and Security IO configuration in internal flash.
//!
//! The configuration page is rewritten after a restart response has left the
//! UART or after a standalone individual-address write;
//! `stm32_micro_common::config_page` frames it, and a torn or corrupt record
//! fails its CRC and boots factory-fresh. The separate final page contains
//! the write-once `KNXP` serial/FDSK identity. High-write sequence state
//! never enters this record; it stays in the external FRAM owned by
//! `SequenceStore`.

use stm32_micro_common::SecureIdentity;
use stm32_micro_common::config_page::{self, ConfigError};
use zweidraehte_microdevice::device::DeviceIdentity;
use zweidraehte_microdevice::family::MicroDeviceFamily;
use zweidraehte_microdevice::persist::{self, StoredManagement};
use zweidraehte_microdevice::security::DataSecureState;
use zweidraehte_proto::security::SecurityConfig;

use crate::{Device, Fam, GROUP_KEY_CAPACITY, GROUP_OBJECT_CAPACITY, SequenceStore};

const CONFIG_MAGIC: [u8; 4] = *b"S7SC";
/// Version 3: the shared `persist` layout, without the separate security length.
const CONFIG_VERSION: u8 = 3;

const EEPROM_SIZE: usize = <Fam as MicroDeviceFamily>::EEPROM_SIZE;

const RECORD_LEN: usize = persist::management_len::<Fam>();
// EEPROM dominates the record. This leaves more than 400 octets for the
// postcard security tables without putting a full flash page on the stack.
const CONFIG_CAPACITY: usize = 1536;
const _: () =
    assert!(config_page::capacity(RECORD_LEN) <= CONFIG_CAPACITY, "the staging buffer holds the management record");

pub type StoredSecurity = SecurityConfig<GROUP_KEY_CAPACITY, 0, GROUP_OBJECT_CAPACITY>;

/// The payload: the management record, then the postcard-encoded Security
/// IO tables in the rest of it.
pub struct RestoredConfig {
    management: StoredManagement<'static, Fam>,
    security: StoredSecurity,
}

impl RestoredConfig {
    fn factory(eeprom: [u8; EEPROM_SIZE], fdsk: [u8; 16]) -> Self {
        Self {
            management: StoredManagement::factory(eeprom),
            security: StoredSecurity { tool_key: fdsk, ..StoredSecurity::default() },
        }
    }

    pub fn into_device(self, identity: DeviceIdentity, fdsk: [u8; 16], sequence: SequenceStore) -> Device {
        let security = DataSecureState::from_config(fdsk, sequence, self.security);
        self.management.into_device(identity, security)
    }
}

#[cfg(feature = "provision-on-boot")]
mod development_identity {
    include!(concat!(env!("OUT_DIR"), "/dev_provisioning.rs"));
}

/// The serial and FDSK from the `KNXP` page. `provision-on-boot` builds
/// store the development defaults when the page holds no record.
pub fn load_identity() -> Option<SecureIdentity> {
    #[cfg(feature = "provision-on-boot")]
    let dev_defaults = {
        // TP1 does not consume a MAC; naming the generated value keeps the
        // common development-provisioning source warning-free.
        let _ = development_identity::DEV_MAC;
        Some((development_identity::DEV_SERIAL, development_identity::DEV_FDSK))
    };
    #[cfg(not(feature = "provision-on-boot"))]
    let dev_defaults = None;

    stm32_micro_common::load_secure_identity(dev_defaults)
}

pub fn load(default_eeprom: [u8; EEPROM_SIZE], fdsk: [u8; 16]) -> RestoredConfig {
    config_page::load(CONFIG_MAGIC, CONFIG_VERSION)
        .and_then(decode)
        .unwrap_or_else(|| RestoredConfig::factory(default_eeprom, fdsk))
}

fn decode(payload: &'static [u8]) -> Option<RestoredConfig> {
    let (management, security) = payload.split_at_checked(RECORD_LEN)?;

    Some(RestoredConfig {
        management: StoredManagement::decode(management)?,
        security: postcard::from_bytes(security).ok()?,
    })
}

pub fn save(device: &Device) -> Result<(), ConfigError> {
    config_page::save::<CONFIG_CAPACITY>(CONFIG_MAGIC, CONFIG_VERSION, |payload| {
        let (management, security) = payload.split_at_mut(RECORD_LEN);
        persist::encode(device, management);

        // Postcard fails only when the tables outgrow the buffer.
        let security_len = postcard::to_slice(&device.security_state().to_config(), security).ok()?.len();
        Some(RECORD_LEN + security_len)
    })
}
