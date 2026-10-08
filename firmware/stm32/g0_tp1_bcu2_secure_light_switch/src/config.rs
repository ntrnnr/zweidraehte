//! Low-write persistent state and factory identity in the last flash pages.
//!
//! The configuration page is rewritten after a restart response has left the
//! UART or immediately after a standalone individual-address write has been
//! acknowledged; `stm32_micro_common::config_page` frames it, and a torn or
//! corrupt record fails its CRC and boots factory-fresh. High-frequency
//! sequence counters remain on FRAM. The final page is the shared `KNXP`
//! factory record written by `knx-provision`.

use stm32_micro_common::SecureIdentity;
use stm32_micro_common::config_page::{self, ConfigError};
use zweidraehte_microdevice::device::DeviceIdentity;
use zweidraehte_microdevice::families::bcu2::{BCU2_EEPROM_SIZE, Bcu2Family};
use zweidraehte_microdevice::persist::{self, StoredManagement};
use zweidraehte_microdevice::security::DataSecureState;
use zweidraehte_proto::security::SecurityConfig;

use crate::{Device, GROUP_KEY_CAPACITY, GROUP_OBJECT_CAPACITY, SequenceStore};

const CONFIG_MAGIC: [u8; 4] = *b"B2CF";
/// Version 2: the shared `persist` layout, without the separate security length.
const CONFIG_VERSION: u8 = 2;

type Fam = Bcu2Family<0x0021>;

const RECORD_LEN: usize = persist::management_len::<Fam>();
/// The whole page: the Security IO tables vary in length.
const CONFIG_CAPACITY: usize = stm32_micro_common::PAGE_SIZE as usize;
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
    fn factory(eeprom: [u8; BCU2_EEPROM_SIZE], fdsk: [u8; 16]) -> Self {
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

pub fn load(default_eeprom: [u8; BCU2_EEPROM_SIZE], fdsk: [u8; 16]) -> RestoredConfig {
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
