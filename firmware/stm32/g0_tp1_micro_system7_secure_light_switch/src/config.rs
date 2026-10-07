//! Low-write System 7 and Security IO configuration in internal flash.
//!
//! The separate final page contains the write-once `KNXP` serial/FDSK
//! identity. High-write sequence state never enters this record; it stays in
//! the external FRAM owned by `SequenceStore`.

use stm32_micro_common::{PAGE_SIZE, PROVISIONING_PAGE, RawFlash, SecureIdentity};
use zweidraehte_microdevice::device::DeviceIdentity;
use zweidraehte_microdevice::family::MicroDeviceFamily;
use zweidraehte_microdevice::security::DataSecureState;
use zweidraehte_nv::{Area, SectorIo};
use zweidraehte_proto::messages::apdu::load_control::LoadState;
use zweidraehte_proto::security::SecurityConfig;
use zweidraehte_proto::util::crc::crc32;

use crate::{Device, Fam, GROUP_KEY_CAPACITY, GROUP_OBJECT_CAPACITY, SequenceStore};

/// The configuration record's page, directly below the `KNXP` page.
const CONFIG_PAGE: Area = Area::new(PROVISIONING_PAGE.offset - PAGE_SIZE, PAGE_SIZE);
/// The page's length, for buffers and record bounds.
const PAGE_LEN: usize = PAGE_SIZE as usize;

const CONFIG_MAGIC: [u8; 4] = *b"S7SC";
const CONFIG_VERSION: u8 = 2;
/// The downloaded program version: presence flag plus five octets.
const PROGRAM_VERSION_SIZE: usize = 1 + 5;
const HEADER_SIZE: usize = 8;
const EEPROM_SIZE: usize = <Fam as MicroDeviceFamily>::EEPROM_SIZE;
const AUTH_LEVELS: usize = <Fam as MicroDeviceFamily>::AUTH_LEVELS;
const LSM_COUNT: usize = <Fam as MicroDeviceFamily>::LSM_COUNT;
// EEPROM dominates the record. This leaves more than 400 octets for the
// postcard security tables without putting a full flash page on the stack.
const CONFIG_RECORD_CAPACITY: usize = 1536;
const _: () = assert!(CONFIG_RECORD_CAPACITY <= PAGE_LEN);

pub type StoredSecurity = SecurityConfig<GROUP_KEY_CAPACITY, 0, GROUP_OBJECT_CAPACITY>;

#[derive(Debug)]
pub enum ConfigError {
    Encode,
    TooLarge,
    Flash,
}

pub struct RestoredConfig {
    eeprom: [u8; EEPROM_SIZE],
    auth_keys: [[u8; 4]; AUTH_LEVELS],
    lsm_states: [u8; LSM_COUNT],
    table_refs: [u16; LSM_COUNT],
    option_reg: u8,
    hardware_type: Option<[u8; 6]>,
    program_version: Option<[u8; 5]>,
    security: StoredSecurity,
}

impl RestoredConfig {
    fn factory(eeprom: [u8; EEPROM_SIZE], fdsk: [u8; 16]) -> Self {
        Self {
            eeprom,
            auth_keys: [[0xFF; 4]; AUTH_LEVELS],
            lsm_states: [u8::from(LoadState::Unloaded); LSM_COUNT],
            table_refs: [0; LSM_COUNT],
            option_reg: 0,
            hardware_type: None,
            program_version: None,
            security: StoredSecurity { tool_key: fdsk, ..StoredSecurity::default() },
        }
    }

    pub fn into_device(self, mut identity: DeviceIdentity, fdsk: [u8; 16], sequence: SequenceStore) -> Device {
        if let Some(hardware_type) = self.hardware_type {
            identity.hardware_type = hardware_type;
        }
        let security = DataSecureState::from_config(fdsk, sequence, self.security);
        let mut device = Device::with_security(self.eeprom, identity, 1, security);
        device.mgmt.auth_keys.copy_from_slice(&self.auth_keys);
        for (index, lsm) in device.mgmt.lsm.iter_mut().enumerate() {
            lsm.state = LoadState::try_from(self.lsm_states[index]).unwrap_or(LoadState::Unloaded);
            lsm.table_ref = self.table_refs[index];
        }
        device.mgmt.option_reg = self.option_reg;
        device.mgmt.program_version = self.program_version;
        device.mgmt.reset_connection_auth::<Fam>();
        device
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
    parse_config(RawFlash::slice(CONFIG_PAGE.offset, PAGE_LEN))
        .unwrap_or_else(|| RestoredConfig::factory(default_eeprom, fdsk))
}

fn parse_config(page: &[u8]) -> Option<RestoredConfig> {
    if page[..4] != CONFIG_MAGIC || page[4] != CONFIG_VERSION {
        return None;
    }
    let total = usize::from(u16::from_le_bytes([page[6], page[7]]));
    if !(HEADER_SIZE + 4..=CONFIG_RECORD_CAPACITY).contains(&total) {
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
    let program_version = decode_program_version(take(page, &mut cursor, PROGRAM_VERSION_SIZE)?)?;

    let sec_len_bytes = take(page, &mut cursor, 2)?;
    let sec_len = usize::from(u16::from_le_bytes([sec_len_bytes[0], sec_len_bytes[1]]));
    if cursor.checked_add(sec_len)?.checked_add(4)? != total {
        return None;
    }
    let security = postcard::from_bytes(take(page, &mut cursor, sec_len)?).ok()?;

    Some(RestoredConfig {
        eeprom,
        auth_keys,
        lsm_states,
        table_refs,
        option_reg,
        hardware_type: Some(hardware_type),
        program_version,
        security,
    })
}

/// `[flag][id:5]`: flag 0 means no download has announced one yet.
fn encode_program_version(program_version: Option<[u8; 5]>) -> [u8; PROGRAM_VERSION_SIZE] {
    let mut encoded = [0u8; PROGRAM_VERSION_SIZE];
    if let Some(id) = program_version {
        encoded[0] = 1;
        encoded[1..].copy_from_slice(&id);
    }
    encoded
}

/// Inverse of [`encode_program_version`]; `None` for an unknown flag.
fn decode_program_version(encoded: &[u8]) -> Option<Option<[u8; 5]>> {
    match encoded.split_first()? {
        (0, _) => Some(None),
        (1, id) => Some(Some(id.try_into().ok()?)),
        _ => None,
    }
}

pub fn save(device: &Device) -> Result<(), ConfigError> {
    let mut record = [0xFFu8; CONFIG_RECORD_CAPACITY];
    record[..4].copy_from_slice(&CONFIG_MAGIC);
    record[4] = CONFIG_VERSION;
    let mut cursor = HEADER_SIZE;

    put(&mut record, &mut cursor, device.eeprom())?;
    for key in &device.mgmt.auth_keys {
        put(&mut record, &mut cursor, key)?;
    }
    for lsm in &device.mgmt.lsm {
        put(&mut record, &mut cursor, &[u8::from(lsm.state)])?;
    }
    for lsm in &device.mgmt.lsm {
        put(&mut record, &mut cursor, &lsm.table_ref.to_le_bytes())?;
    }
    put(&mut record, &mut cursor, &[device.mgmt.option_reg])?;
    put(&mut record, &mut cursor, device.hardware_type())?;
    put(&mut record, &mut cursor, &encode_program_version(device.mgmt.program_version))?;

    let sec_len_pos = cursor;
    cursor += 2;
    let sec_start = cursor;
    let sec_len =
        postcard::to_slice(&device.security_state().to_config(), &mut record[sec_start..CONFIG_RECORD_CAPACITY - 4])
            .map_err(|_| ConfigError::Encode)?
            .len();
    if sec_len > u16::MAX as usize {
        return Err(ConfigError::TooLarge);
    }
    record[sec_len_pos..sec_len_pos + 2].copy_from_slice(&(sec_len as u16).to_le_bytes());
    cursor += sec_len;

    let total = cursor.checked_add(4).ok_or(ConfigError::TooLarge)?;
    if total > CONFIG_RECORD_CAPACITY || total > u16::MAX as usize {
        return Err(ConfigError::TooLarge);
    }
    record[6..8].copy_from_slice(&(total as u16).to_le_bytes());
    let crc = crc32(&record[..cursor]);
    record[cursor..total].copy_from_slice(&crc.to_le_bytes());

    let programmed = total.next_multiple_of(8);
    if RawFlash::slice(CONFIG_PAGE.offset, programmed) == &record[..programmed] {
        return Ok(());
    }
    RawFlash.erase(CONFIG_PAGE.offset, CONFIG_PAGE.end()).map_err(|_| ConfigError::Flash)?;
    RawFlash.write(CONFIG_PAGE.offset, &record[..programmed]).map_err(|_| ConfigError::Flash)
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
