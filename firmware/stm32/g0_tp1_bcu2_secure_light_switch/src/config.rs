//! Low-write persistent state and factory identity in the last flash pages.
//!
//! The configuration page is rewritten after a restart response has left the
//! UART or immediately after a standalone individual-address write has been
//! acknowledged. High-frequency sequence counters remain on FRAM. The final
//! page is the shared `KNXP` factory record written by `knx-provision`.

use core::sync::atomic::{Ordering, compiler_fence};

use stm32_metapac::FLASH;
use zweidraehte_microdevice::device::DeviceIdentity;
use zweidraehte_microdevice::families::bcu2::{BCU2_EEPROM_SIZE, Bcu2Family};
use zweidraehte_microdevice::security::DataSecureState;
use zweidraehte_proto::messages::apdu::load_control::LoadState;
use zweidraehte_proto::provisioning::{self, PROV_BUF_LEN, ProvisioningRecord};
use zweidraehte_proto::security::SecurityConfig;
use zweidraehte_proto::util::crc::crc32;

use crate::fram_store::FramStore;
use crate::{Device, GROUP_KEY_CAPACITY, GROUP_OBJECT_CAPACITY};

const FLASH_BASE: usize = 0x0800_0000;
const PAGE_SIZE: usize = 2 * 1024;
const CONFIG_ADDRESS: usize = FLASH_BASE + 508 * 1024;
const PROVISIONING_ADDRESS: usize = FLASH_BASE + 510 * 1024;
const CONFIG_BANK2_PAGE: u8 = 126;
#[cfg(feature = "provision-on-boot")]
const PROVISIONING_BANK2_PAGE: u8 = 127;

const CONFIG_MAGIC: [u8; 4] = *b"B2CF";
const CONFIG_VERSION: u8 = 1;
const HEADER_SIZE: usize = 8;
const AUTH_LEVELS: usize = 16;
const LSM_COUNT: usize = 4;

pub type StoredSecurity = SecurityConfig<GROUP_KEY_CAPACITY, 0, GROUP_OBJECT_CAPACITY>;

#[derive(Debug)]
pub enum ConfigError {
    #[cfg(not(feature = "provision-on-boot"))]
    Provisioning,
    MissingFdsk,
    Encode,
    TooLarge,
    Flash,
    Verify,
}

#[derive(Clone, Copy)]
pub struct SecureIdentity {
    pub serial_number: [u8; 6],
    pub fdsk: [u8; 16],
}

pub struct RestoredConfig {
    pub eeprom: [u8; BCU2_EEPROM_SIZE],
    auth_keys: [[u8; 4]; AUTH_LEVELS],
    lsm_states: [u8; LSM_COUNT],
    table_refs: [u16; LSM_COUNT],
    option_reg: u8,
    pub security: StoredSecurity,
}

impl RestoredConfig {
    fn factory(eeprom: [u8; BCU2_EEPROM_SIZE], fdsk: [u8; 16]) -> Self {
        Self {
            eeprom,
            auth_keys: [[0xFF; 4]; AUTH_LEVELS],
            lsm_states: [u8::from(LoadState::Unloaded); LSM_COUNT],
            table_refs: [0; LSM_COUNT],
            option_reg: 0,
            security: StoredSecurity { tool_key: fdsk, ..StoredSecurity::default() },
        }
    }

    pub fn into_device(self, identity: DeviceIdentity, fdsk: [u8; 16], sequence: FramStore) -> Device {
        let security = DataSecureState::from_config(fdsk, sequence, self.security);
        let mut device = Device::with_security(self.eeprom, identity, 1, security);
        device.mgmt.auth_keys.copy_from_slice(&self.auth_keys);
        for (i, lsm) in device.mgmt.lsm.iter_mut().enumerate() {
            lsm.state = LoadState::try_from(self.lsm_states[i]).unwrap_or(LoadState::Unloaded);
            lsm.table_ref = self.table_refs[i];
        }
        device.mgmt.option_reg = self.option_reg;
        device.mgmt.reset_connection_auth::<Bcu2Family<0x0021>>();
        device
    }
}

pub fn load_identity() -> Result<SecureIdentity, ConfigError> {
    let bytes = flash_slice(PROVISIONING_ADDRESS, PROV_BUF_LEN);
    match provisioning::parse(bytes) {
        Ok(record) => identity_from_record(record),
        Err(_) => provision_development_identity(),
    }
}

fn identity_from_record(record: ProvisioningRecord) -> Result<SecureIdentity, ConfigError> {
    Ok(SecureIdentity { serial_number: record.serial, fdsk: record.fdsk.ok_or(ConfigError::MissingFdsk)? })
}

#[cfg(feature = "provision-on-boot")]
mod development_identity {
    include!(concat!(env!("OUT_DIR"), "/dev_provisioning.rs"));
}

#[cfg(not(feature = "provision-on-boot"))]
fn provision_development_identity() -> Result<SecureIdentity, ConfigError> {
    Err(ConfigError::Provisioning)
}

#[cfg(feature = "provision-on-boot")]
fn provision_development_identity() -> Result<SecureIdentity, ConfigError> {
    // TP1 does not consume a MAC; naming the generated value keeps the common
    // development-provisioning source warning-free.
    let _ = development_identity::DEV_MAC;
    let record = ProvisioningRecord {
        serial: development_identity::DEV_SERIAL,
        fdsk: Some(development_identity::DEV_FDSK),
        mac: None,
    };
    let mut encoded = [0u8; PROV_BUF_LEN];
    let len = provisioning::write(&record, &mut encoded).map_err(|_| ConfigError::Encode)?;
    let padded = len.next_multiple_of(8);
    let mut page = [0xFFu8; PAGE_SIZE];
    page[..len].copy_from_slice(&encoded[..len]);
    program_flash_page(PROVISIONING_ADDRESS, PROVISIONING_BANK2_PAGE, &page[..padded])?;
    identity_from_record(record)
}

pub fn load(default_eeprom: [u8; BCU2_EEPROM_SIZE], fdsk: [u8; 16]) -> RestoredConfig {
    parse_config(flash_slice(CONFIG_ADDRESS, PAGE_SIZE))
        .unwrap_or_else(|| RestoredConfig::factory(default_eeprom, fdsk))
}

fn parse_config(page: &[u8]) -> Option<RestoredConfig> {
    if page[..4] != CONFIG_MAGIC || page[4] != CONFIG_VERSION {
        return None;
    }
    let total = usize::from(u16::from_le_bytes([page[6], page[7]]));
    if !(HEADER_SIZE + 4..=PAGE_SIZE).contains(&total) {
        return None;
    }
    let expected = u32::from_le_bytes(page[total - 4..total].try_into().ok()?);
    if crc32(&page[..total - 4]) != expected {
        return None;
    }

    let mut cursor = HEADER_SIZE;
    let mut eeprom = [0u8; BCU2_EEPROM_SIZE];
    eeprom.copy_from_slice(take(page, &mut cursor, BCU2_EEPROM_SIZE)?);

    let mut auth_keys = [[0u8; 4]; AUTH_LEVELS];
    for key in &mut auth_keys {
        key.copy_from_slice(take(page, &mut cursor, 4)?);
    }

    let mut lsm_states = [0u8; LSM_COUNT];
    lsm_states.copy_from_slice(take(page, &mut cursor, LSM_COUNT)?);
    let mut table_refs = [0u16; LSM_COUNT];
    for reference in &mut table_refs {
        let bytes = take(page, &mut cursor, 2)?;
        *reference = u16::from_le_bytes([bytes[0], bytes[1]]);
    }
    // Keep the byte in the version-1 record layout, but ignore values from
    // older firmware: PID_DEVICE_CONTROL is reset to zero at startup.
    let _device_control = *take(page, &mut cursor, 1)?.first()?;
    let option_reg = *take(page, &mut cursor, 1)?.first()?;
    let sec_len_bytes = take(page, &mut cursor, 2)?;
    let sec_len = usize::from(u16::from_le_bytes([sec_len_bytes[0], sec_len_bytes[1]]));
    if cursor.checked_add(sec_len)?.checked_add(4)? != total {
        return None;
    }
    let security = postcard::from_bytes(take(page, &mut cursor, sec_len)?).ok()?;

    Some(RestoredConfig { eeprom, auth_keys, lsm_states, table_refs, option_reg, security })
}

pub fn save(device: &Device) -> Result<(), ConfigError> {
    let mut page = [0xFFu8; PAGE_SIZE];
    page[..4].copy_from_slice(&CONFIG_MAGIC);
    page[4] = CONFIG_VERSION;
    let mut cursor = HEADER_SIZE;

    put(&mut page, &mut cursor, device.eeprom())?;
    for key in &device.mgmt.auth_keys {
        put(&mut page, &mut cursor, key)?;
    }
    for lsm in &device.mgmt.lsm {
        put(&mut page, &mut cursor, &[u8::from(lsm.state)])?;
    }
    for lsm in &device.mgmt.lsm {
        put(&mut page, &mut cursor, &lsm.table_ref.to_le_bytes())?;
    }
    put(&mut page, &mut cursor, &[0, device.mgmt.option_reg])?;

    let sec_len_pos = cursor;
    cursor += 2;
    let sec_start = cursor;
    let sec_len = postcard::to_slice(&device.security_state().to_config(), &mut page[sec_start..PAGE_SIZE - 4])
        .map_err(|_| ConfigError::Encode)?
        .len();
    if sec_len > u16::MAX as usize {
        return Err(ConfigError::TooLarge);
    }
    page[sec_len_pos..sec_len_pos + 2].copy_from_slice(&(sec_len as u16).to_le_bytes());
    cursor += sec_len;

    let total = cursor.checked_add(4).ok_or(ConfigError::TooLarge)?;
    if total > PAGE_SIZE || total > u16::MAX as usize {
        return Err(ConfigError::TooLarge);
    }
    page[6..8].copy_from_slice(&(total as u16).to_le_bytes());
    let crc = crc32(&page[..cursor]);
    page[cursor..total].copy_from_slice(&crc.to_le_bytes());

    let programmed = total.next_multiple_of(8);
    program_flash_page(CONFIG_ADDRESS, CONFIG_BANK2_PAGE, &page[..programmed])
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, count: usize) -> Option<&'a [u8]> {
    let end = cursor.checked_add(count)?;
    let result = bytes.get(*cursor..end)?;
    *cursor = end;
    Some(result)
}

fn put(destination: &mut [u8], cursor: &mut usize, bytes: &[u8]) -> Result<(), ConfigError> {
    let end = cursor.checked_add(bytes.len()).ok_or(ConfigError::TooLarge)?;
    destination.get_mut(*cursor..end).ok_or(ConfigError::TooLarge)?.copy_from_slice(bytes);
    *cursor = end;
    Ok(())
}

fn flash_slice(address: usize, len: usize) -> &'static [u8] {
    // SAFETY: both addresses are fixed pages inside the STM32G0B0RE's
    // memory-mapped flash and remain readable for the whole program.
    unsafe { core::slice::from_raw_parts(address as *const u8, len) }
}

fn program_flash_page(address: usize, bank2_page: u8, data: &[u8]) -> Result<(), ConfigError> {
    if !data.len().is_multiple_of(8) || data.len() > PAGE_SIZE {
        return Err(ConfigError::TooLarge);
    }

    wait_flash();
    if FLASH.cr().read().lock() {
        FLASH.keyr().write_value(0x4567_0123);
        FLASH.keyr().write_value(0xCDEF_89AB);
    }
    clear_flash_status();

    FLASH.cr().modify(|w| {
        w.set_per(true);
        w.set_bker(true);
        w.set_pnb(u16::from(bank2_page));
        w.set_strt(true);
    });
    wait_flash();
    FLASH.cr().modify(|w| w.set_per(false));
    if flash_failed() {
        FLASH.cr().modify(|w| w.set_lock(true));
        return Err(ConfigError::Flash);
    }

    for (offset, doubleword) in data.chunks_exact(8).enumerate() {
        clear_flash_status();
        FLASH.cr().modify(|w| w.set_pg(true));
        let target = (address + offset * 8) as *mut u32;
        let low = u32::from_le_bytes(doubleword[..4].try_into().expect("four-byte low word"));
        let high = u32::from_le_bytes(doubleword[4..].try_into().expect("four-byte high word"));
        cortex_m::interrupt::free(|_| {
            compiler_fence(Ordering::SeqCst);
            // SAFETY: the page was erased above, the address is 8-byte
            // aligned, and STM32G0 double-word programming requires these two
            // adjacent 32-bit writes while interrupts are excluded.
            unsafe {
                core::ptr::write_volatile(target, low);
                core::ptr::write_volatile(target.add(1), high);
            }
            compiler_fence(Ordering::SeqCst);
        });
        wait_flash();
        FLASH.cr().modify(|w| w.set_pg(false));
        if flash_failed() {
            FLASH.cr().modify(|w| w.set_lock(true));
            return Err(ConfigError::Flash);
        }
    }
    FLASH.cr().modify(|w| w.set_lock(true));

    if flash_slice(address, data.len()) != data {
        return Err(ConfigError::Verify);
    }
    Ok(())
}

fn wait_flash() {
    while {
        let status = FLASH.sr().read();
        status.bsy() || status.bsy2() || status.cfgbsy()
    } {}
}

fn clear_flash_status() {
    // Read and write back the status register: every error/EOP flag is
    // write-one-to-clear, matching the STM32 reference driver.
    FLASH.sr().modify(|_| {});
}

fn flash_failed() -> bool {
    let status = FLASH.sr().read();
    status.operr()
        || status.progerr()
        || status.wrperr()
        || status.pgaerr()
        || status.sizerr()
        || status.pgserr()
        || status.miserr()
        || status.fasterr()
}
