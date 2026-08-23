//! Low-write System 7 configuration in a reserved internal-flash page.
//!
//! ETS finishes a download with `A_Restart`; standalone individual-address
//! writes have no restart, so the main loop snapshots them after their TPUART
//! acknowledgement. A CRC rejects torn or corrupt records on the next boot.

use core::sync::atomic::{Ordering, compiler_fence};

use stm32_metapac::FLASH;
use zweidraehte_microdevice::device::DeviceIdentity;
use zweidraehte_microdevice::family::MicroDeviceFamily;
use zweidraehte_proto::messages::apdu::load_control::LoadState;
use zweidraehte_proto::util::crc::crc32;

use crate::{Device, Fam};

const FLASH_BASE: usize = 0x0800_0000;
const PAGE_SIZE: usize = 2 * 1024;
const CONFIG_ADDRESS: usize = FLASH_BASE + 508 * 1024;
const CONFIG_BANK2_PAGE: u8 = 126;

const CONFIG_MAGIC: [u8; 4] = *b"S7P1";
const CONFIG_VERSION: u8 = 2;
const HEADER_SIZE: usize = 8;
const EEPROM_SIZE: usize = <Fam as MicroDeviceFamily>::EEPROM_SIZE;
const AUTH_LEVELS: usize = <Fam as MicroDeviceFamily>::AUTH_LEVELS;
const LSM_COUNT: usize = <Fam as MicroDeviceFamily>::LSM_COUNT;
const CONFIG_SIZE: usize =
    HEADER_SIZE + EEPROM_SIZE + AUTH_LEVELS * 4 + LSM_COUNT + LSM_COUNT * 2 + 1 + 6 + size_of::<u32>();
const PROGRAMMED_SIZE: usize = CONFIG_SIZE.next_multiple_of(8);
const _: () = assert!(PROGRAMMED_SIZE <= PAGE_SIZE);

pub enum ConfigError {
    TooLarge,
    Flash,
    Verify,
}

pub struct RestoredConfig {
    eeprom: [u8; EEPROM_SIZE],
    auth_keys: [[u8; 4]; AUTH_LEVELS],
    lsm_states: [u8; LSM_COUNT],
    table_refs: [u16; LSM_COUNT],
    option_reg: u8,
    hardware_type: Option<[u8; 6]>,
}

impl RestoredConfig {
    fn factory(eeprom: [u8; EEPROM_SIZE]) -> Self {
        Self {
            eeprom,
            auth_keys: [[0xFF; 4]; AUTH_LEVELS],
            lsm_states: [u8::from(LoadState::Unloaded); LSM_COUNT],
            table_refs: [0; LSM_COUNT],
            option_reg: 0,
            hardware_type: None,
        }
    }

    pub fn into_device(self, mut identity: DeviceIdentity) -> Device {
        if let Some(hardware_type) = self.hardware_type {
            identity.hardware_type = hardware_type;
        }
        let mut device = Device::new(self.eeprom, identity, 1);
        device.mgmt.auth_keys.copy_from_slice(&self.auth_keys);
        for (i, lsm) in device.mgmt.lsm.iter_mut().enumerate() {
            lsm.state = LoadState::try_from(self.lsm_states[i]).unwrap_or(LoadState::Unloaded);
            lsm.table_ref = self.table_refs[i];
        }
        device.mgmt.option_reg = self.option_reg;
        device.mgmt.reset_connection_auth::<Fam>();
        device
    }
}

pub fn load(default_eeprom: [u8; EEPROM_SIZE]) -> RestoredConfig {
    parse_config(flash_slice(CONFIG_ADDRESS, PAGE_SIZE)).unwrap_or_else(|| RestoredConfig::factory(default_eeprom))
}

fn parse_config(page: &[u8]) -> Option<RestoredConfig> {
    if page[..4] != CONFIG_MAGIC || page[4] != CONFIG_VERSION {
        return None;
    }
    let total = usize::from(u16::from_le_bytes([page[6], page[7]]));
    if total != CONFIG_SIZE {
        return None;
    }
    let expected = u32::from_le_bytes(page[total - 4..total].try_into().ok()?);
    if crc32(&page[..total - 4]) != expected {
        return None;
    }

    let mut cursor = HEADER_SIZE;
    let mut eeprom = [0u8; EEPROM_SIZE];
    eeprom.copy_from_slice(take(page, &mut cursor, EEPROM_SIZE)?);

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
    let option_reg = *take(page, &mut cursor, 1)?.first()?;
    let mut hardware_type = [0u8; 6];
    hardware_type.copy_from_slice(take(page, &mut cursor, 6)?);
    if cursor.checked_add(4)? != total {
        return None;
    }

    Some(RestoredConfig { eeprom, auth_keys, lsm_states, table_refs, option_reg, hardware_type: Some(hardware_type) })
}

pub fn save(device: &Device) -> Result<(), ConfigError> {
    // Only the encoded record needs RAM; erasing still covers the complete
    // hardware page. Avoiding a 2 KiB page buffer matters on this target.
    let mut page = [0xFFu8; PROGRAMMED_SIZE];
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
    put(&mut page, &mut cursor, &[device.mgmt.option_reg])?;
    put(&mut page, &mut cursor, device.hardware_type())?;

    let total = cursor.checked_add(4).ok_or(ConfigError::TooLarge)?;
    if total != CONFIG_SIZE {
        return Err(ConfigError::TooLarge);
    }
    page[6..8].copy_from_slice(&(total as u16).to_le_bytes());
    let crc = crc32(&page[..cursor]);
    page[cursor..total].copy_from_slice(&crc.to_le_bytes());

    if flash_slice(CONFIG_ADDRESS, page.len()) == page {
        return Ok(());
    }
    program_flash_page(CONFIG_ADDRESS, CONFIG_BANK2_PAGE, &page)
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
    // SAFETY: this is a reserved page inside STM32G0B0RE memory-mapped flash
    // and remains readable for the complete program lifetime.
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
            // SAFETY: the page was erased, the target is 8-byte aligned, and
            // G0 double-word programming requires these adjacent writes.
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
    // Every error/EOP flag is write-one-to-clear.
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
