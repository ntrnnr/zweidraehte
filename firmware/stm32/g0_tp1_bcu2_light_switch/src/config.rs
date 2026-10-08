//! Low-write BCU2 configuration in the flash page below `KNXP`.
//!
//! ETS finishes a download with `A_Restart`; standalone individual-address
//! writes have no restart, so the main loop snapshots them immediately after
//! their TPUART acknowledgement. The record is the micro stack's management
//! state (`zweidraehte_microdevice::persist`) in the page that
//! `stm32_micro_common::config_page` frames; a torn or corrupt record fails
//! its CRC and the device boots factory-fresh.

use stm32_micro_common::config_page::{self, ConfigError};
use zweidraehte_microdevice::families::bcu2::{BCU2_EEPROM_SIZE, Bcu2Family};
use zweidraehte_microdevice::persist::{self, StoredManagement};

use crate::Device;

const CONFIG_MAGIC: [u8; 4] = *b"B2P1";
/// Version 2: the shared `persist` layout.
const CONFIG_VERSION: u8 = 2;

const RECORD_LEN: usize = persist::management_len::<Bcu2Family>();

pub fn load(default_eeprom: [u8; BCU2_EEPROM_SIZE]) -> StoredManagement<'static, Bcu2Family> {
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
