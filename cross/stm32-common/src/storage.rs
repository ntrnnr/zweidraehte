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
//! lives once in [`embedded_common::persist::ConfigStore`]; [`StmFlashStorage`]
//! is that store fixed to the STM32G0 layout (config offset / page size) and
//! the family's 8-byte doubleword write granularity (`WRITE_ALIGN = 8`). The
//! medium is the owned-`Flash` [`StmFlashIo`](crate::flash_io::StmFlashIo)
//! adapter.
//!
//! # Flash Stall Warning
//!
//! `blocking_erase` and `blocking_write` suspend CPU execution for several
//! milliseconds per page. Following the same policy as `pico_tp1`, we
//! save only in the restart handler — never periodically — so a stall
//! cannot corrupt the TPUART UART timing.

use embassy_stm32::flash::{Blocking, Flash};

use embedded_common::persist::ConfigStore;

use zweidraehte_device::provisioning;
use zweidraehte_device::storage::{DeviceIdentity, SecureDeviceIdentity};

use crate::flash_io::StmFlashIo;

// ================================================================================
// STM32G0 config-region layout
// ================================================================================

/// Total internal flash on the STM32G0B0RE.
pub const STM32G0_FLASH_SIZE: u32 = 512 * 1024;
/// STM32G0 flash erase-page size.
pub const STM32G0_PAGE_SIZE: u32 = 2 * 1024;
/// Offset of the config page: two pages below the top of flash (the last page
/// is the write-once provisioning page owned by [`crate::prov_storage`]).
pub const STM32G0_CONFIG_OFFSET: u32 = STM32G0_FLASH_SIZE - 2 * STM32G0_PAGE_SIZE;
/// Config region size — one erase page.
pub const STM32G0_CONFIG_SIZE: usize = STM32G0_PAGE_SIZE as usize;

// ================================================================================
// StmFlashStorage
// ================================================================================

/// Persistent device-config storage on STM32G0 internal flash.
///
/// A [`ConfigStore`] over the [`StmFlashIo`] medium, fixed to the STM32G0
/// config region and the family's 8-byte doubleword write alignment. Type
/// parameters: `S` the runtime state (`S::Config` is the persisted form),
/// `I` the device identity.
///
/// A new STM32 chip family with a different page size or flash size adds a
/// sibling alias with its own `*_CONFIG_OFFSET`/`*_CONFIG_SIZE` constants
/// rather than re-introducing flash-size generics (which a bare type alias
/// can't compute over).
pub type StmFlashStorage<S, I> = ConfigStore<StmFlashIo, S, I, STM32G0_CONFIG_OFFSET, STM32G0_CONFIG_SIZE, 8>;

/// This crate's flash error type — the shared config-store error.
pub use embedded_common::persist::ConfigStoreError as FlashError;

/// Build an [`StmFlashStorage`] over an owned `Flash` peripheral.
///
/// A free constructor because [`StmFlashStorage`] is a type alias (no inherent
/// `new`): it wraps the `Flash` in the [`StmFlashIo`] adapter first.
pub fn stm_flash_storage<S, I>(flash: Flash<'static, Blocking>, identity: I) -> StmFlashStorage<S, I> {
    StmFlashStorage::new(StmFlashIo::new(flash), identity)
}

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

impl FlashIdentityData {
    /// Derive a deterministic `u64` seed from the live STM32 factory UID.
    ///
    /// Used for embassy-net's IGMP delay and other per-device entropy
    /// needs that don't require crypto-strength randomness. The UID is
    /// not stored in the provisioning record; the peripheral is read
    /// at call time.
    pub fn derive_seed(&self) -> u64 {
        let uid = embassy_stm32::uid::uid();
        let mut buf = [0u8; 8];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = uid[i] ^ uid[(i + 4) % 12];
        }
        u64::from_le_bytes(buf)
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
    /// Same as [`FlashIdentityData::derive_seed`].
    pub fn derive_seed(&self) -> u64 {
        let uid = embassy_stm32::uid::uid();
        let mut buf = [0u8; 8];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = uid[i] ^ uid[(i + 4) % 12];
        }
        u64::from_le_bytes(buf)
    }

    /// Hyphenated Base32 ETS label code. Thin shim over
    /// [`provisioning::fdsk_string`]; kept on the type for ergonomic
    /// `identity_data.fdsk_string()` calls in firmware.
    pub fn fdsk_string(&self) -> [u8; 41] {
        provisioning::fdsk_string(&self.serial_number, &self.fdsk)
    }
}
