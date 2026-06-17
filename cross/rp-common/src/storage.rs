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
//! The magic + length + postcard codec is shared with the STM32 target and
//! lives once in [`embedded_common::persist::ConfigStore`]; [`RpFlashStorage`]
//! is that store fixed to the RP2040 config-sector layout. RP2040 flash writes
//! are byte-granular, so the config store uses `WRITE_ALIGN = 1` (no padding).
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

use embedded_common::persist::ConfigStore;

use zweidraehte_device::storage::{DeviceIdentity, SecureDeviceIdentity};

use crate::flash_seq::RpFlashIo;

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

// -- Config sector layout -----------------------------------------------------

/// Bytes reserved at the end of flash (above the provisioning sector) for the
/// device config. One 4 KiB sector — the only size any current RP target uses.
pub const RP_STORAGE_SIZE: usize = SECTOR_SIZE;

/// Offset of the config sector from flash start: one sector below the
/// write-once provisioning sector (which is the last sector on the chip).
pub const RP_CONFIG_OFFSET: u32 = (FLASH_SIZE - SECTOR_SIZE - RP_STORAGE_SIZE) as u32;

// ================================================================================
// RpFlashStorage
// ================================================================================

/// Persistent device-config storage on RP2040/RP2350 internal flash.
///
/// A [`ConfigStore`] over the [`RpFlashIo`] medium, fixed to the RP2040 config
/// sector and `WRITE_ALIGN = 1` (RP2040 flash writes are byte-granular). Type
/// parameters: `S` the runtime state (`S::Config` is the persisted form), `I`
/// the device identity.
///
/// `RpFlashIo` shares the single `FLASH` peripheral with the wear-levelled
/// sequence/SIAT store ([`crate::RpWearLeveledKv`]) via a `&'static RefCell`;
/// soundness of that sharing is documented on [`RpFlashIo`].
///
/// A device whose serialized state exceeds one sector adds a sibling alias with
/// a larger `RP_STORAGE_SIZE` (and must move the sequence-log region — see the
/// `_SEQ_REGION_FITS` guard above, which only checks the default size).
pub type RpFlashStorage<S, I> = ConfigStore<RpFlashIo, S, I, RP_CONFIG_OFFSET, RP_STORAGE_SIZE, 1>;

/// This crate's flash error type — the shared config-store error.
pub use embedded_common::persist::ConfigStoreError as FlashError;

/// Build an [`RpFlashStorage`] over the shared `Flash` handle.
///
/// A free constructor because [`RpFlashStorage`] is a type alias (no inherent
/// `new`): it wraps the shared `&'static RefCell<Flash>` in the [`RpFlashIo`]
/// adapter first. The same handle is shared with the wear-levelled sequence
/// store; see [`RpFlashIo`] for the soundness argument.
pub fn rp_flash_storage<S, I>(
    flash: &'static core::cell::RefCell<
        embassy_rp::flash::Flash<'static, embassy_rp::peripherals::FLASH, embassy_rp::flash::Blocking, FLASH_SIZE>,
    >,
    identity: I,
) -> RpFlashStorage<S, I> {
    RpFlashStorage::new(RpFlashIo::new(flash), identity)
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
