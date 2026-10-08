//! The persistent management state as one fixed-layout byte record.
//!
//! What survives a power cycle on real hardware is the EEPROM image plus the
//! management state the mask keeps in hidden EEPROM: authorization keys,
//! load states and table references, the option register, and the two
//! identity values a download may rewrite. RAM (group object values, flags,
//! programming mode, `PID_DEVICE_CONTROL`) is volatile and deliberately
//! absent.
//!
//! Firmware decides *where* and *when* the record goes — the STM32 micro
//! targets write it to one flash page after a restart or an IA change — so
//! this module only encodes and restores it. Every family uses the same
//! layout, sized by its own constants:
//!
//! ```text
//! eeprom[EEPROM_SIZE]
//! auth_keys[AUTH_LEVELS] × 4
//! lsm_state[LSM_COUNT]
//! table_ref[LSM_COUNT] × 2 (little-endian)
//! option_reg
//! hardware_type: present flag, 6 octets      (DOWNLOAD_IDENTITY only)
//! program_version: present flag, 5 octets    (DOWNLOAD_IDENTITY only)
//! ```
//!
//! Keys and load state machines are stored for the family's counts only:
//! every service indexes them below `F::AUTH_LEVELS` / `F::LSM_COUNT`, and
//! the remaining slots of the shared ceiling arrays stay at their factory
//! value.
//!
//! The layout carries no version of its own. The firmware's record header
//! does, and a changed layout must bump it: the device then boots
//! factory-fresh, as there is no migration.
//!
//! The conformance DUTs keep their serde [`snapshot`](crate::snapshot)
//! format, which also carries a secure profile's sequence store.

use zweidraehte_proto::messages::apdu::load_control::LoadState;

use crate::device::{DeviceIdentity, Microdevice};
use crate::family::MicroDeviceFamily;
use crate::security::SecurityModule;

/// Octets of a present flag plus a hardware type.
const HARDWARE_TYPE_LEN: usize = 1 + 6;

/// Octets of a present flag plus a program version.
const PROGRAM_VERSION_LEN: usize = 1 + 5;

/// The encoded length of family `F`'s management record.
pub const fn management_len<F: MicroDeviceFamily>() -> usize {
    let download_identity = if F::DOWNLOAD_IDENTITY { HARDWARE_TYPE_LEN + PROGRAM_VERSION_LEN } else { 0 };
    F::EEPROM_SIZE + F::AUTH_LEVELS * 4 + F::LSM_COUNT * 3 + 1 + download_identity
}

/// Encode `device`'s persistent management state into the first
/// [`management_len`] octets of `out`.
///
/// # Panics
///
/// If `out` is shorter than [`management_len`]: a sizing mistake of the
/// caller's buffer.
pub fn encode<F: MicroDeviceFamily, const N: usize, SEC: SecurityModule>(
    device: &Microdevice<F, N, SEC>,
    out: &mut [u8],
) {
    let mut writer = Writer { out: &mut out[..management_len::<F>()], at: 0 };
    let mgmt = &device.mgmt;

    writer.put(device.eeprom.as_ref());

    for key in &mgmt.auth_keys[..F::AUTH_LEVELS] {
        writer.put(key);
    }

    for lsm in &mgmt.lsm[..F::LSM_COUNT] {
        writer.put(&[u8::from(lsm.state)]);
    }
    for lsm in &mgmt.lsm[..F::LSM_COUNT] {
        writer.put(&lsm.table_ref.to_le_bytes());
    }

    writer.put(&[mgmt.option_reg]);

    if F::DOWNLOAD_IDENTITY {
        // The hardware type is always captured: restoring it is what keeps
        // a value written by a download across a reboot.
        writer.put(&[1]);
        writer.put(&device.identity.hardware_type);

        match mgmt.program_version {
            Some(version) => {
                writer.put(&[1]);
                writer.put(&version);
            }
            None => writer.put(&[0; PROGRAM_VERSION_LEN]),
        }
    }

    debug_assert_eq!(writer.at, management_len::<F>(), "the layout constants match what encode writes");
}

/// A management record checked for length, ready to bring up a device.
///
/// It borrows the record rather than decoding it into a copy: the targets
/// read it from memory-mapped flash, and the micro targets would otherwise
/// hold the EEPROM-sized record twice during boot.
pub struct StoredManagement<'a, F: MicroDeviceFamily> {
    eeprom: F::EepromStore,
    /// Everything after the EEPROM image; `None` on a factory-fresh device.
    management: Option<&'a [u8]>,
}

impl<'a, F: MicroDeviceFamily> StoredManagement<'a, F> {
    /// Offsets into the record after the EEPROM image.
    const KEYS_AT: usize = 0;
    const STATES_AT: usize = Self::KEYS_AT + F::AUTH_LEVELS * 4;
    const REFS_AT: usize = Self::STATES_AT + F::LSM_COUNT;
    const OPTION_AT: usize = Self::REFS_AT + F::LSM_COUNT * 2;
    const HARDWARE_TYPE_AT: usize = Self::OPTION_AT + 1;
    const PROGRAM_VERSION_AT: usize = Self::HARDWARE_TYPE_AT + HARDWARE_TYPE_LEN;

    /// A never-programmed device over the product's default EEPROM image:
    /// factory keys, every table unloaded, the compiled-in identity.
    pub fn factory(eeprom: F::EepromStore) -> Self {
        Self { eeprom, management: None }
    }

    /// Check a record written by [`encode`] for the same family. Returns
    /// `None` unless `bytes` is exactly [`management_len`] long.
    pub fn decode(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() != management_len::<F>() {
            return None;
        }

        let (image, management) = bytes.split_at(F::EEPROM_SIZE);
        let mut eeprom = F::blank_eeprom();
        eeprom.as_mut().copy_from_slice(image);

        Some(Self { eeprom, management: Some(management) })
    }

    /// Bring up a device from this state. `identity` is the product's
    /// compiled-in identity; a stored hardware type replaces its value.
    ///
    /// A load state the stack does not know restores as Unloaded, so a
    /// damaged state octet costs a re-download rather than a wrong state.
    ///
    /// `time_divisor` compresses the TL timeouts for the conformance
    /// harness; firmware passes 1.
    pub fn into_device<const N: usize, SEC: SecurityModule>(
        self,
        identity: DeviceIdentity,
        time_divisor: u32,
        security: SEC::State,
    ) -> Microdevice<F, N, SEC> {
        // Construct first and branch once afterwards. Branching on the
        // record before construction as well lets LLVM split this into two
        // paths that each call the large `with_security`, about 200 octets
        // on the BCU2 targets. Construction reads only the serial number and
        // order info, so the hardware type can follow it.
        let mut device = Microdevice::with_security(self.eeprom, identity, time_divisor, security);
        let Some(record) = self.management else {
            return device;
        };

        if F::DOWNLOAD_IDENTITY && record[Self::HARDWARE_TYPE_AT] != 0 {
            device.identity.hardware_type.copy_from_slice(&record[Self::HARDWARE_TYPE_AT + 1..][..6]);
        }

        let mgmt = &mut device.mgmt;

        for (level, key) in mgmt.auth_keys[..F::AUTH_LEVELS].iter_mut().enumerate() {
            key.copy_from_slice(&record[Self::KEYS_AT + level * 4..][..4]);
        }

        for (machine, lsm) in mgmt.lsm[..F::LSM_COUNT].iter_mut().enumerate() {
            lsm.state = LoadState::try_from(record[Self::STATES_AT + machine]).unwrap_or(LoadState::Unloaded);

            let table_ref = Self::REFS_AT + machine * 2;
            lsm.table_ref = u16::from_le_bytes([record[table_ref], record[table_ref + 1]]);
        }

        mgmt.option_reg = record[Self::OPTION_AT];

        if F::DOWNLOAD_IDENTITY && record[Self::PROGRAM_VERSION_AT] != 0 {
            let mut program_version = [0; 5];
            program_version.copy_from_slice(&record[Self::PROGRAM_VERSION_AT + 1..][..5]);
            mgmt.program_version = Some(program_version);
        }

        // `with_security` resolved the disconnected access level from the
        // factory keys. Resolve it again from the restored ones.
        mgmt.reset_connection_auth::<F>();

        device
    }
}

/// A cursor over the record being encoded. The lengths are fixed by the
/// family, so running out of room is a bug, not an input error.
struct Writer<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) {
        let end = self.at + bytes.len();
        self.out[self.at..end].copy_from_slice(bytes);
        self.at = end;
    }
}
