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

use core::cell::RefCell;

use embassy_rp::flash::{self, Flash};
use embassy_rp::peripherals::FLASH;
use serde::{Deserialize, Serialize};

use zweidraehte_device::bcus::system_b::HasDeviceConfig;
use zweidraehte_device::storage::{DeviceIdentity, SecureDeviceIdentity};

// ================================================================================
// Constants
// ================================================================================

pub const FLASH_SIZE: usize = 2 * 1024 * 1024; // 2MB
pub const SECTOR_SIZE: usize = 4096;

// -- Sequence-number log region ----------------------------------------------
//
// The wear-levelled Data Secure sequence/SIAT store ([`crate::flash_seq`] / `RpWearLeveledKv`)
// gets its own multi-sector region carved out *below* the config sector. Like
// the config / provisioning regions these offsets are pure software convention
// — the linker hands the whole flash to `FLASH` via `memory.x`. The full map
// at the top of flash is:
//
// ```text
// 0x1F6000 .. 0x1FE000  — Sequence-number log (KNXQ), 8 sectors = 32 KiB
// 0x1FE000 .. 0x1FF000  — Config storage (KNXS)
// 0x1FF000 .. 0x200000  — Provisioning sector (KNXP, write-once)
// ```

/// Number of 4 KiB sectors reserved for the sequence-number append log.
///
/// Eight sectors give the log ~341 records/sector × 8 ≈ 2700 appends before a
/// single sector is re-erased, so even with the sending watermark disabled the
/// flash endurance budget is comfortable.
pub const SEQ_SECTOR_COUNT: usize = 8;

/// Total byte size of the sequence-number log region.
pub const SEQ_REGION_SIZE: usize = SEQ_SECTOR_COUNT * SECTOR_SIZE;

/// Offset of the sequence-number log region from the start of flash.
///
/// Sits immediately below the config sector (which itself sits below the
/// write-once provisioning sector), so growing either of the two top regions
/// never disturbs the log's start address unless their sizes change.
pub const SEQ_REGION_OFFSET: u32 = (FLASH_SIZE - SECTOR_SIZE - SECTOR_SIZE - SEQ_REGION_SIZE) as u32;

// Compile-time guard: the log region must not run into the config sector that
// sits directly above it. (The config sector's own offset is
// `FLASH_SIZE - SECTOR_SIZE - STORAGE_SIZE`, but `STORAGE_SIZE` is a per-device
// const generic; the default 4 KiB is what the secure light switch uses, so we
// check against that here. A device that enlarges its config region must also
// move the log.)
const _SEQ_REGION_FITS: () = {
    assert!(
        SEQ_REGION_OFFSET as usize + SEQ_REGION_SIZE <= FLASH_SIZE - SECTOR_SIZE - SECTOR_SIZE,
        "sequence-number log region overlaps the config or provisioning sector",
    );
};

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
    /// Shared handle to the one `FLASH` peripheral.
    ///
    /// The RP2040 has a single `FLASH` peripheral, but this device needs flash
    /// access from two independent owners: this config store (which lives
    /// outside the KNX stack) and the wear-levelled sequence/SIAT store
    /// ([`crate::RpWearLeveledKv`], which lives inside it). Both
    /// borrow the same `&'static RefCell<Flash<…>>`. The `RefCell` is sound
    /// because embassy's executor is single-threaded and every flash operation
    /// is synchronous (`blocking_*`, never held across an `.await`), so two
    /// borrows can never overlap.
    flash: &'static RefCell<Flash<'static, FLASH, flash::Blocking, FLASH_SIZE>>,
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

    /// Create a new flash storage instance over a shared `Flash` handle.
    pub fn new(flash: &'static RefCell<Flash<'static, FLASH, flash::Blocking, FLASH_SIZE>>, identity: I) -> Self {
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
        self.flash.borrow_mut().blocking_read(Self::STORAGE_OFFSET, &mut region).map_err(|_| FlashError::ReadFailed)?;

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
        let mut flash = self.flash.borrow_mut();
        flash
            .blocking_erase(Self::STORAGE_OFFSET, Self::STORAGE_OFFSET + STORAGE_SIZE as u32)
            .map_err(|_| FlashError::EraseFailed)?;
        flash
            .blocking_write(Self::STORAGE_OFFSET, &buf[..CONFIG_HEADER_SIZE + len])
            .map_err(|_| FlashError::WriteFailed)?;
        drop(flash);

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

/// Device identity for an RP2040 KNX **Data Secure** device.
///
/// The secure counterpart of [`FlashIdentityData`]: it carries the same
/// serial / MAC / unique-ID triple **plus** the 16-byte Factory Default
/// Setup Key (FDSK) that seeds the device's tool key and (for IP Secure)
/// the Device Authentication Code. The FDSK lives in the `KNXP`
/// provisioning record (the `FDSK` tag); see
/// [`secure_identity_from_record`](crate::secure_identity_from_record).
///
/// This is the RP2040 analogue of `stm32-common`'s `FlashSecureIdentityData`;
/// the difference is the extra `mac` / `unique_id` fields (IP devices need
/// a MAC, and the seed comes from the SPI-flash unique ID rather than an
/// on-chip UID register).
#[derive(Debug, Clone, defmt::Format)]
pub struct FlashSecureIdentityData {
    /// KNX serial number: 2 bytes manufacturer ID (big-endian) + 4 bytes
    /// device-specific.
    pub serial_number: [u8; 6],

    /// Ethernet MAC address from the `KNXP` record. `None` on devices
    /// that don't need one — but IP Secure devices always do.
    pub mac: Option<[u8; 6]>,

    /// Raw 8-byte SPI flash unique ID. Read from hardware at boot for
    /// per-device entropy seeds.
    pub unique_id: [u8; 8],

    /// Factory Default Setup Key (FDSK). Seeds the Data Secure tool key
    /// and the IP Secure Device Authentication Code on first
    /// commissioning.
    pub fdsk: [u8; 16],
}

impl DeviceIdentity for FlashSecureIdentityData {
    fn serial_number(&self) -> &[u8; 6] {
        &self.serial_number
    }
}

impl SecureDeviceIdentity for FlashSecureIdentityData {
    fn fdsk(&self) -> &[u8; 16] {
        &self.fdsk
    }
}

impl FlashSecureIdentityData {
    /// Return the MAC address sourced from the `KNXP` record.
    ///
    /// # Panics
    /// Panics if the record had no MAC tag — wiring an Ethernet device
    /// with a missing MAC is a configuration error the firmware cannot
    /// recover from at boot.
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac.expect("KNXP record missing MAC tag — re-provision this device")
    }

    /// Derive a deterministic `u64` seed from the unique ID. Same as
    /// [`FlashIdentityData::derive_seed`].
    pub fn derive_seed(&self) -> u64 {
        u64::from_le_bytes(self.unique_id)
    }
}
