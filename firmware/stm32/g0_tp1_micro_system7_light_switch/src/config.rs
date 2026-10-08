//! Low-write System 7 configuration in the flash page below `KNXP`.
//!
//! ETS finishes a download with `A_Restart`; standalone individual-address
//! writes have no restart, so the main loop snapshots them after their TPUART
//! acknowledgement. The record is the micro stack's management state
//! (`zweidraehte_microdevice::persist`) in the page that
//! `stm32_micro_common::config_page` frames; a torn or corrupt record fails
//! its CRC and the device boots factory-fresh.

use stm32_micro_common::config_page::{self, ConfigError};
use zweidraehte_microdevice::family::MicroDeviceFamily;
use zweidraehte_microdevice::persist::{self, StoredManagement};

use crate::{Device, Fam};

const CONFIG_MAGIC: [u8; 4] = *b"S7P1";
/// Version 4: the shared `persist` layout.
const CONFIG_VERSION: u8 = 4;

const EEPROM_SIZE: usize = <Fam as MicroDeviceFamily>::EEPROM_SIZE;
const RECORD_LEN: usize = persist::management_len::<Fam>();

pub fn load(default_eeprom: [u8; EEPROM_SIZE]) -> StoredManagement<'static, Fam> {
    config_page::load(CONFIG_MAGIC, CONFIG_VERSION)
        .and_then(StoredManagement::decode)
        .unwrap_or_else(|| StoredManagement::factory(default_eeprom))
}

pub fn save(device: &Device) -> Result<(), ConfigError> {
    config_page::save::<{ config_page::capacity(RECORD_LEN) }>(CONFIG_MAGIC, CONFIG_VERSION, |payload| {
        persist::encode(device, payload);
        Some(RECORD_LEN)
    })
}
