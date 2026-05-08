//! Flash-based persistent storage and device identity for RP2040/RP2350.
//!
//! # Flash Layout
//!
//! The provisioning sector lives at the very top of flash; config
//! storage occupies the sectors immediately below it. With the default
//! 4 KiB `STORAGE_SIZE` the layout for a 2 MB chip is:
//!
//! ```text
//! 0x1FE000 .. 0x1FF000  — Config storage (KNXS)            [grows backward]
//! 0x1FF000 .. 0x200000  — Provisioning sector (KNXP)       [last sector, fixed]
//! ```
//!
//! Putting provisioning last and config below it means bumping
//! `STORAGE_SIZE` to fit a larger config grows the region toward lower
//! addresses without ever touching the (write-once) provisioning data.
//!
//! The provisioning sector is written once on the production line by
//! the host-side `knx-provision` tool over SWD. Format and codec live
//! in [`zweidraehte_device::provisioning`]; the read/write helpers and
//! struct conversions live in [`crate::prov_storage`]. The config
//! sector stores ETS-programmed device state via [`RpFlashStorage`].
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

pub(crate) const FLASH_SIZE: usize = 2 * 1024 * 1024; // 2MB
pub(crate) const SECTOR_SIZE: usize = 4096;

// -- Config sector constants --------------------------------------------------

const CONFIG_MAGIC: [u8; 4] = *b"KNXS";
/// Header: 4 bytes magic + 2 bytes payload length.
const CONFIG_HEADER_SIZE: usize = 6;

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
    ///
    /// The provisioning sector occupies the last `SECTOR_SIZE` bytes,
    /// so config storage starts `SECTOR_SIZE + STORAGE_SIZE` from the
    /// flash end and grows toward lower addresses as `STORAGE_SIZE`
    /// increases.
    const STORAGE_OFFSET: u32 = (FLASH_SIZE - SECTOR_SIZE - STORAGE_SIZE) as u32;

    // Compile-time validation of the storage region size.
    const _VALIDATE: () = {
        assert!(STORAGE_SIZE > 0, "STORAGE_SIZE must be non-zero");
        assert!(STORAGE_SIZE % SECTOR_SIZE == 0, "STORAGE_SIZE must be a multiple of the 4 KiB flash sector size",);
        // Reserve room for both the config region *and* the trailing
        // provisioning sector at the top of flash.
        assert!(
            STORAGE_SIZE + SECTOR_SIZE <= FLASH_SIZE,
            "STORAGE_SIZE + provisioning sector exceeds total flash size",
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
// Device identity (sourced from the KNXP provisioning sector)
// ================================================================================

/// Identity record built from a parsed `KNXP` provisioning record.
///
/// Carries the KNX serial, an optional MAC address (populated for IP
/// devices), and the SPI flash chip's unique ID. The unique ID is read
/// from hardware at boot (not stored in `KNXP`) so that
/// [`derive_seed`](FlashIdentityData::derive_seed) keeps working without
/// pulling extra fields into the provisioning record.
#[derive(Debug, Clone, defmt::Format)]
pub struct FlashIdentityData {
    /// KNX serial number: 2 bytes manufacturer ID (big-endian) + 4 bytes
    /// device-specific (assigned at provisioning time).
    pub serial_number: [u8; 6],

    /// Ethernet MAC address from the `KNXP` record. `None` on devices
    /// that don't need one (TP1-only).
    pub mac: Option<[u8; 6]>,

    /// Raw 8-byte SPI flash unique ID. Read from hardware at boot for
    /// per-device entropy seeds.
    pub unique_id: [u8; 8],
}

impl DeviceIdentity for FlashIdentityData {
    fn serial_number(&self) -> &[u8; 6] {
        &self.serial_number
    }
}

impl FlashIdentityData {
    /// Return the MAC address sourced from the `KNXP` record.
    ///
    /// # Panics
    /// Panics if the record had no MAC tag — wiring an Ethernet device
    /// with a missing MAC is a configuration error the firmware cannot
    /// recover from at boot.
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac.expect("KNXP record missing MAC tag — re-provision this device")
    }

    /// Derive a deterministic `u64` seed from the unique ID.
    ///
    /// Suitable for embassy-net's IGMP random delay and similar uses
    /// where a per-device seed is needed.
    pub fn derive_seed(&self) -> u64 {
        u64::from_le_bytes(self.unique_id)
    }
}
