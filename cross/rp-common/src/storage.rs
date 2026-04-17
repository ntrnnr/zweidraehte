//! Flash-based persistent storage and device identity for RP2040/RP2350.
//!
//! # Flash Layout
//!
//! The last two 4 KiB sectors of the 2 MB flash are reserved:
//!
//! ```text
//! 0x1FE000 .. 0x1FF000  — Identity sector (serial number, unique ID)
//! 0x1FF000 .. 0x200000  — Config storage sector (device state)
//! ```
//!
//! The identity sector is written once on first boot and survives both
//! firmware updates and factory resets. The config sector stores
//! ETS-programmed device state via [`RpFlashStorage`].
//!
//! # Identity Sector Format
//!
//! ```text
//! [magic: 4B "KNXI"][serial_number: 6B][unique_id: 8B]
//! ```
//!
//! # Config Sector Format
//!
//! ```text
//! [magic: 4B "KNXS"][len: 2B little-endian][postcard payload][...]
//! ```
//!
//! The magic bytes guard against reading uninitialized flash (all 0xFF).
//!
//! # Wear Leveling
//!
//! Not implemented — KNX configuration writes are rare (only during ETS
//! programming), so the ~100K erase cycle limit is not a concern in
//! practice.
//!
//! # Flash Stall Warning
//!
//! `blocking_erase` and `blocking_write` disable XIP and interrupts on
//! RP2040, stalling all tasks for the duration. This is acceptable for
//! rare config saves but would disrupt real-time KNX communication if
//! done frequently.

use embassy_rp::flash::{self, Flash};
use embassy_rp::peripherals::FLASH;
use serde::{Deserialize, Serialize};

use zweidraehte_device::bcus::system_b::HasDeviceConfig;
use zweidraehte_device::storage::DeviceIdentity;

// ================================================================================
// Constants
// ================================================================================

const FLASH_SIZE: usize = 2 * 1024 * 1024; // 2MB
const SECTOR_SIZE: usize = 4096;

// -- Config sector constants --------------------------------------------------

const CONFIG_MAGIC: [u8; 4] = *b"KNXS";
/// Header: 4 bytes magic + 2 bytes payload length.
const CONFIG_HEADER_SIZE: usize = 6;

// -- Identity sector constants ------------------------------------------------

/// Offset of the identity sector from the start of flash (second-to-last sector).
const IDENTITY_SECTOR_OFFSET: u32 = (FLASH_SIZE - 2 * SECTOR_SIZE) as u32;
const IDENTITY_MAGIC: [u8; 4] = *b"KNXI";
/// Total size of the identity record: 4B magic + 6B serial + 8B unique ID.
const IDENTITY_RECORD_SIZE: usize = 4 + 6 + 8;

// ================================================================================
// RpFlashStorage
// ================================================================================

/// Persistent storage backed by RP2040/RP2350 internal flash.
///
/// `S` is the **runtime** state type (e.g., `PicoEthState`). The storage
/// internally converts to/from the serializable [`S::Config`] form
/// using the stored [`DeviceIdentity`].
///
/// `STORAGE_SIZE` controls how many bytes at the end of flash are reserved
/// for device state. It must be a non-zero multiple of the 4 KiB sector
/// size. Increase it if your device's serialized state exceeds the default
/// 4 KiB (minus 6 bytes header).
pub struct RpFlashStorage<S, I, const STORAGE_SIZE: usize = 4096> {
    flash: Flash<'static, FLASH, flash::Blocking, FLASH_SIZE>,
    identity: I,
    dirty: bool,
    _phantom: core::marker::PhantomData<S>,
}

impl<S, I, const STORAGE_SIZE: usize> RpFlashStorage<S, I, STORAGE_SIZE> {
    /// Offset of the storage region from the start of flash.
    const STORAGE_OFFSET: u32 = (FLASH_SIZE - STORAGE_SIZE) as u32;

    // Compile-time validation of the storage region size.
    const _VALIDATE: () = {
        assert!(STORAGE_SIZE > 0, "STORAGE_SIZE must be non-zero");
        assert!(STORAGE_SIZE % SECTOR_SIZE == 0, "STORAGE_SIZE must be a multiple of the 4 KiB flash sector size",);
        assert!(STORAGE_SIZE <= FLASH_SIZE, "STORAGE_SIZE exceeds total flash size",);
        // The identity sector occupies the second-to-last 4 KiB sector.
        // Config storage must not overlap it.
        assert!(
            STORAGE_SIZE <= SECTOR_SIZE,
            "STORAGE_SIZE exceeds one sector — would overlap the identity sector",
        );
    };

    /// Create a new flash storage instance.
    pub fn new(flash: Flash<'static, FLASH, flash::Blocking, FLASH_SIZE>, identity: I) -> Self {
        // Force the compile-time validation constants to be evaluated.
        let _ = Self::_VALIDATE;
        Self { flash, identity, dirty: false, _phantom: core::marker::PhantomData }
    }

    /// Get the device identity used for restoring state.
    pub fn identity(&self) -> &I {
        &self.identity
    }
}

impl<S, I, const STORAGE_SIZE: usize> RpFlashStorage<S, I, STORAGE_SIZE>
where
    S: HasDeviceConfig,
    S::Config: Serialize + for<'de> Deserialize<'de>,
{
    /// Read and deserialize the persisted state from flash without
    /// constructing the runtime state.
    ///
    /// This is useful for inspecting persisted configuration (e.g., the
    /// IP assignment method) before the platform layer is fully
    /// initialized. For the normal boot path, call this method and pass
    /// the result into the stack's `StateInit` envelope for state construction.
    pub fn load_config(&mut self) -> Result<Option<S::Config>, FlashError> {
        let mut region = [0u8; STORAGE_SIZE];
        self.flash.blocking_read(Self::STORAGE_OFFSET, &mut region).map_err(|_| FlashError::ReadFailed)?;

        if region[0..4] != CONFIG_MAGIC {
            return Ok(None);
        }

        let len = u16::from_le_bytes([region[4], region[5]]) as usize;
        if len == 0 || CONFIG_HEADER_SIZE + len > region.len() {
            return Ok(None);
        }

        let payload = &region[CONFIG_HEADER_SIZE..CONFIG_HEADER_SIZE + len];
        match postcard::from_bytes::<S::Config>(payload) {
            Ok(persisted) => Ok(Some(persisted)),
            Err(_) => {
                defmt::warn!("Flash storage: postcard deserialization failed, returning None");
                Ok(None)
            }
        }
    }
}

impl<S, I, const STORAGE_SIZE: usize> RpFlashStorage<S, I, STORAGE_SIZE>
where
    S: HasDeviceConfig,
    S::Config: Serialize + for<'de> Deserialize<'de>,
    I: DeviceIdentity,
{
    /// Save the current runtime state to flash.
    ///
    /// Converts to the persisted form via [`HasDeviceConfig::to_config`],
    /// serializes with postcard, then erases and writes the flash sector.
    pub fn save(&mut self, state: &S) -> Result<(), FlashError> {
        let persisted = state.to_config();

        // Serialize into a stack buffer. Reserve header bytes at the front.
        let mut buf = [0u8; STORAGE_SIZE];
        buf[0..4].copy_from_slice(&CONFIG_MAGIC);

        let payload = postcard::to_slice(&persisted, &mut buf[CONFIG_HEADER_SIZE..])
            .expect("serialized state exceeds flash storage region — increase STORAGE_SIZE");
        let len = payload.len();
        buf[4..6].copy_from_slice(&(len as u16).to_le_bytes());

        // Erase the region, then write.
        self.flash
            .blocking_erase(Self::STORAGE_OFFSET, Self::STORAGE_OFFSET + STORAGE_SIZE as u32)
            .map_err(|_| FlashError::EraseFailed)?;
        self.flash
            .blocking_write(Self::STORAGE_OFFSET, &buf[..CONFIG_HEADER_SIZE + len])
            .map_err(|_| FlashError::WriteFailed)?;

        self.dirty = false;
        Ok(())
    }

    /// Mark the storage as having unsaved changes.
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Returns whether there are unsaved changes.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
}

// ================================================================================
// Error type
// ================================================================================

#[derive(Debug, defmt::Format)]
pub enum FlashError {
    ReadFailed,
    EraseFailed,
    WriteFailed,
}

// ================================================================================
// Flash Identity Provisioning
// ================================================================================

/// Data read from (or provisioned into) the flash identity sector.
///
/// Contains the KNX serial number and the raw SPI flash unique ID.
/// The unique ID can be used to derive MAC addresses and entropy seeds.
#[derive(Debug, Clone, defmt::Format)]
pub struct FlashIdentityData {
    /// KNX serial number: 2 bytes manufacturer ID (big-endian) + 4 bytes
    /// device-specific (XOR-folded from the 8-byte flash unique ID).
    pub serial_number: [u8; 6],
    /// Raw 8-byte SPI flash unique ID. Stored for derivation of MAC
    /// addresses and entropy seeds beyond the KNX serial number.
    pub unique_id: [u8; 8],
}

impl DeviceIdentity for FlashIdentityData {
    fn serial_number(&self) -> &[u8; 6] {
        &self.serial_number
    }
}

impl FlashIdentityData {
    /// Derive a locally-administered unicast MAC address.
    ///
    /// The `oui` parameter provides the 3-byte vendor prefix. Bit 1 of
    /// the first octet (locally administered) is forced set, and bit 0
    /// (multicast) is forced clear, regardless of the input value. The
    /// remaining 3 bytes are taken from the unique ID.
    pub fn derive_mac_address(&self, oui: [u8; 3]) -> [u8; 6] {
        [
            (oui[0] | 0x02) & 0xFE, // locally administered, unicast
            oui[1],
            oui[2],
            self.unique_id[0],
            self.unique_id[1],
            self.unique_id[2],
        ]
    }

    /// Derive a deterministic `u64` seed from the unique ID.
    ///
    /// Suitable for embassy-net's IGMP random delay and similar uses
    /// where a per-device seed is needed.
    pub fn derive_seed(&self) -> u64 {
        u64::from_le_bytes(self.unique_id)
    }
}

/// Read the device identity from flash, or provision it on first boot.
///
/// On first boot (identity sector erased / all `0xFF`), this function:
/// 1. Reads the SPI flash chip's unique ID (8 bytes)
/// 2. XOR-folds it into 4 device-specific bytes (`uid[0..4] ^ uid[4..8]`)
/// 3. Prepends the `manufacturer_id` to form a 6-byte KNX serial number
/// 4. Writes the identity sector to flash (one-time, brief XIP stall)
///
/// On subsequent boots, reads and returns the stored identity.
///
/// # Panics
///
/// Panics if flash I/O fails. Identity provisioning is critical for device
/// operation — there is no meaningful fallback at boot time.
#[cfg(feature = "rp2040")]
pub fn read_or_provision_identity(
    flash: &mut Flash<'static, FLASH, flash::Blocking, FLASH_SIZE>,
    manufacturer_id: [u8; 2],
) -> FlashIdentityData {
    // Read just the identity record from the sector.
    let mut buf = [0u8; IDENTITY_RECORD_SIZE];
    flash
        .blocking_read(IDENTITY_SECTOR_OFFSET, &mut buf)
        .expect("identity sector read");

    // If the magic matches, the identity has already been provisioned.
    if buf[0..4] == IDENTITY_MAGIC {
        let mut serial_number = [0u8; 6];
        serial_number.copy_from_slice(&buf[4..10]);
        let mut unique_id = [0u8; 8];
        unique_id.copy_from_slice(&buf[10..18]);

        defmt::info!("Identity loaded: serial={=[u8]:02x}", serial_number);
        return FlashIdentityData { serial_number, unique_id };
    }

    // First boot — read the SPI flash chip's unique ID and derive the
    // KNX serial number from it.
    defmt::info!("Identity sector empty, provisioning from flash unique ID...");

    let mut unique_id = [0u8; 8];
    flash
        .blocking_unique_id(&mut unique_id)
        .expect("flash unique ID read");

    // XOR-fold 8 bytes into 4 for the device-specific portion.
    let device_bytes = [
        unique_id[0] ^ unique_id[4],
        unique_id[1] ^ unique_id[5],
        unique_id[2] ^ unique_id[6],
        unique_id[3] ^ unique_id[7],
    ];

    let serial_number = [
        manufacturer_id[0],
        manufacturer_id[1],
        device_bytes[0],
        device_bytes[1],
        device_bytes[2],
        device_bytes[3],
    ];

    // Write the identity record to flash.
    let mut write_buf = [0u8; IDENTITY_RECORD_SIZE];
    write_buf[0..4].copy_from_slice(&IDENTITY_MAGIC);
    write_buf[4..10].copy_from_slice(&serial_number);
    write_buf[10..18].copy_from_slice(&unique_id);

    flash
        .blocking_erase(IDENTITY_SECTOR_OFFSET, IDENTITY_SECTOR_OFFSET + SECTOR_SIZE as u32)
        .expect("identity sector erase");
    flash
        .blocking_write(IDENTITY_SECTOR_OFFSET, &write_buf)
        .expect("identity sector write");

    defmt::info!(
        "Identity provisioned: serial={=[u8]:02x}, uid={=[u8]:02x}",
        serial_number,
        unique_id,
    );

    FlashIdentityData { serial_number, unique_id }
}
