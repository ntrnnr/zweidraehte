//! Flash-based persistent device-config storage and device identity for STM32
//! targets.
//!
//! # Flash Layout
//!
//! The provisioning page lives at the very top of flash; the config
//! page sits immediately below it. With the STM32G0's 2 KB page on a
//! 512 KiB chip:
//!
//! ```text
//! FLASH_END - 2*PAGE_SIZE .. FLASH_END - PAGE_SIZE   — Config page (KNXS)        [grows backward]
//! FLASH_END -   PAGE_SIZE .. FLASH_END               — Provisioning page (KNXP)  [last page, fixed]
//! ```
//!
//! Pinning provisioning at the very last page and putting config below
//! it means future config-region growth (more pages, larger postcard
//! payload) extends toward lower addresses without ever touching the
//! (write-once) provisioning data.
//!
//! The provisioning page is written once on the production line by the
//! host-side `knx-provision` tool over SWD. Format and codec live in
//! [`zweidraehte_device::provisioning`]; the read/write helpers and
//! struct conversions live in [`crate::prov_storage`]. The config page
//! stores ETS-programmed device state.
//!
//! # Config codec
//!
//! The magic + length + postcard codec is shared with the RP2040 target and
//! lives once in [`zweidraehte_device::storage::ConfigStore`]; a device's
//! [`StmConfigRegion`] opens that store over [`StmFlashIo`] at its
//! auto-derived offset on the [`StmFlash`] chip. The family's 8-byte
//! doubleword write granularity is a fact of the
//! [`StmFlashIo`](crate::flash_io::StmFlashIo) adapter
//! (`SectorIo::WRITE_ALIGN = 8`).
//!
//! # Flash Stall Warning
//!
//! `blocking_erase` and `blocking_write` suspend CPU execution for several
//! milliseconds per page. Following the same policy as `pico_tp1`, we
//! save only in the restart handler — never periodically — so a stall
//! cannot corrupt the TPUART UART timing.

use zweidraehte_device::provisioning;
use zweidraehte_device::storage::region::Chip;
use zweidraehte_device::storage::{DeviceIdentity, SecureDeviceIdentity};

use crate::flash_io::StmFlashIo;

// ================================================================================
// STM32G0 config-region layout
// ================================================================================

/// Total internal flash on the STM32G0B0RE.
pub const STM32G0_FLASH_SIZE: u32 = 512 * 1024;
/// STM32G0 flash erase-page size.
pub const STM32G0_PAGE_SIZE: u32 = 2 * 1024;
/// Config region size — one erase page. A compile-time const because it sizes
/// the `[u8; REGION_SIZE]` buffer inside
/// [`ConfigStore`](zweidraehte_device::storage::ConfigStore); the region's
/// *offset* is auto-derived by the storage layer from the placement list.
pub const STM32G0_CONFIG_SIZE: usize = STM32G0_PAGE_SIZE as usize;

/// The config region every STM32G0 device places — one erase page, carrying
/// the device's runtime state type `S` as its payload:
///
/// ```ignore
/// type Cfg = Placed<StmConfigRegion<MyDeviceState>, StmFlash, StorageMap>;
/// ```
///
/// The store type and its `open` derive from the region (`StoreOf<Cfg>` /
/// `Cfg::open(StmFlashIo::new(flash))`).
pub type StmConfigRegion<S> = zweidraehte_device::storage::region::ConfigRegion<STM32G0_CONFIG_SIZE, S>;

// ================================================================================
// StmFlash — the storage layer's view of the STM32G0 internal flash chip
// ================================================================================

/// The STM32G0 internal flash, as a [`Chip`] the storage layer packs regions
/// onto.
///
/// `BASE` is the config page — two pages below the top of flash; the last page
/// is the write-once provisioning page owned by [`crate::prov_storage`]. Every
/// STM32G0 device has exactly one flash region (the config blob); the FRAM-secure
/// variants keep their SIAT on the separate [`Fram`](crate::fram_seq::Fram) chip,
/// so a single-region pack lands the config at `BASE`. `CAPACITY` stops one page
/// below the top so the per-chip guard protects the provisioning page.
///
/// A new STM32 family with a different page/flash size adds a sibling `Chip`
/// impl with its own `BASE`/`CAPACITY`.
#[derive(Clone, Copy)]
pub struct StmFlash;

impl Chip for StmFlash {
    const TAG: u32 = 0;
    const BASE: u32 = STM32G0_FLASH_SIZE - 2 * STM32G0_PAGE_SIZE;
    const CAPACITY: u32 = STM32G0_FLASH_SIZE - STM32G0_PAGE_SIZE;
    const SECTOR_SIZE: u32 = STM32G0_PAGE_SIZE;
    type Io = StmFlashIo;
}

/// This crate's flash error type — the shared config-store error.
pub use zweidraehte_device::storage::ConfigStoreError as FlashError;

// ================================================================================
// Device identity (sourced from the KNXP provisioning page)
// ================================================================================

/// Identity record for a plain (non-secure) device.
///
/// Built from the parsed `KNXP` record by
/// [`crate::prov_storage::identity_from_record`]. Holds just the KNX
/// serial — no FDSK, no MAC.
#[derive(Debug, Clone, defmt::Format)]
pub struct FlashIdentityData {
    /// KNX serial number: 2 bytes manufacturer ID (big-endian) followed by
    /// 4 bytes assigned at provisioning time.
    pub serial_number: [u8; 6],
}

impl DeviceIdentity for FlashIdentityData {
    fn serial_number(&self) -> &[u8; 6] {
        &self.serial_number
    }
}

/// Derive a deterministic `u64` seed from the live STM32 factory UID.
///
/// Used for embassy-net's IGMP delay and other per-device entropy needs
/// that don't require crypto-strength randomness. The UID is not stored in
/// the provisioning record; the peripheral is read at call time.
fn derive_seed_from_uid() -> u64 {
    let uid = embassy_stm32::uid::uid();
    let mut buf = [0u8; 8];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = uid[i] ^ uid[(i + 4) % 12];
    }
    u64::from_le_bytes(buf)
}

impl FlashIdentityData {
    /// Deterministic per-device seed — see [`derive_seed_from_uid`].
    pub fn derive_seed(&self) -> u64 {
        derive_seed_from_uid()
    }
}

/// Identity record for a KNX Data Secure device.
///
/// Mirrors [`FlashIdentityData`] and adds the 16-byte FDSK from the
/// provisioning record. Built by
/// [`crate::prov_storage::secure_identity_from_record`].
#[derive(Debug, Clone, defmt::Format)]
pub struct FlashSecureIdentityData {
    pub serial_number: [u8; 6],
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
    /// Deterministic per-device seed — see [`derive_seed_from_uid`].
    pub fn derive_seed(&self) -> u64 {
        derive_seed_from_uid()
    }

    /// Hyphenated Base32 ETS label code. Thin shim over
    /// [`provisioning::fdsk_string`]; kept on the type for ergonomic
    /// `identity_data.fdsk_string()` calls in firmware.
    pub fn fdsk_string(&self) -> [u8; 41] {
        provisioning::fdsk_string(&self.serial_number, &self.fdsk)
    }
}
