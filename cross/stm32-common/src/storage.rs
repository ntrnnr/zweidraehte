//! Flash-based persistent storage and device identity for STM32 targets.
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
//! stores ETS-programmed device state via [`StmFlashStorage`].
//!
//! # Config Page Format
//!
//! ```text
//! [magic: 4B "KNXS"][len: 2B little-endian][postcard payload]
//! ```
//!
//! The magic bytes guard against reading uninitialized flash (all `0xFF`).
//!
//! # Write Granularity
//!
//! STM32 flash on the G0 family writes 8 bytes (one doubleword) at a
//! time. All writes are padded up to a multiple of 8 bytes with `0xFF`,
//! which is the erased value and therefore a valid post-erase content.
//!
//! # Flash Stall Warning
//!
//! `blocking_erase` and `blocking_write` suspend CPU execution for several
//! milliseconds per page. Following the same policy as `pico_tp1`, we
//! save only in the restart handler — never periodically — so a stall
//! cannot corrupt the TPUART UART timing.

use embassy_stm32::flash::{Blocking, Flash};
use serde::{Deserialize, Serialize};

use zweidraehte_device::bcus::system_b::HasDeviceConfig;
use zweidraehte_device::provisioning;
use zweidraehte_device::storage::{DeviceIdentity, SecureDeviceIdentity};

// ================================================================================
// Constants
// ================================================================================

/// Doubleword alignment required by STM32 flash writes.
const WRITE_ALIGN: usize = 8;

// -- Config page constants ----------------------------------------------------

const CONFIG_MAGIC: [u8; 4] = *b"KNXS";
/// 4 bytes magic + 2 bytes payload length.
const CONFIG_HEADER_SIZE: usize = 6;

// ================================================================================
// StmFlashStorage
// ================================================================================

/// Persistent storage backed by STM32 internal flash.
///
/// Type parameters:
/// - `S` — runtime state type (e.g. `Stm32G0Tp1State`). Converted to/from
///   its serializable `S::Config` via [`HasDeviceConfig`].
/// - `I` — device identity (typically [`FlashIdentityData`]).
/// - `FLASH_SIZE` — total flash in bytes. For STM32G0B0RE this is
///   `512 * 1024`.
/// - `PAGE_SIZE` — flash erase-page size in bytes. STM32G0 = 2048, STM32G4
///   = 2048 or 4096, STM32F4 = variable. Check the datasheet.
///
/// The two last pages of flash are used; nothing overlapping those
/// regions can be written by firmware (reserve them in `memory.x` if the
/// linker would otherwise place code there — embassy-stm32's
/// `"memory-x"` feature leaves the whole flash available).
pub struct StmFlashStorage<S, I, const FLASH_SIZE: u32, const PAGE_SIZE: u32> {
    flash: Flash<'static, Blocking>,
    identity: I,
    dirty: bool,
    _phantom: core::marker::PhantomData<S>,
}

impl<S, I, const FLASH_SIZE: u32, const PAGE_SIZE: u32> StmFlashStorage<S, I, FLASH_SIZE, PAGE_SIZE> {
    // Offset (not absolute address) of the config page.
    //
    // The provisioning page sits at the very last page (`FLASH_SIZE -
    // PAGE_SIZE`, owned by `crate::prov_storage`); the config page is
    // immediately below it. If we ever need a larger config region,
    // grow this downward into more pages — provisioning stays put.
    const CONFIG_OFFSET: u32 = FLASH_SIZE - 2 * PAGE_SIZE;

    const _VALIDATE: () = {
        assert!(PAGE_SIZE > 0, "PAGE_SIZE must be non-zero");
        assert!(FLASH_SIZE >= 2 * PAGE_SIZE, "FLASH_SIZE must hold two reserved pages");
        assert!(FLASH_SIZE % PAGE_SIZE == 0, "FLASH_SIZE must be a multiple of PAGE_SIZE");
    };

    pub fn new(flash: Flash<'static, Blocking>, identity: I) -> Self {
        let _ = Self::_VALIDATE;
        Self { flash, identity, dirty: false, _phantom: core::marker::PhantomData }
    }

    pub fn identity(&self) -> &I {
        &self.identity
    }
}

impl<S, I, const FLASH_SIZE: u32, const PAGE_SIZE: u32> StmFlashStorage<S, I, FLASH_SIZE, PAGE_SIZE>
where
    S: HasDeviceConfig,
    S::Config: Serialize + for<'de> Deserialize<'de>,
{
    /// Read and deserialize the persisted config from flash.
    ///
    /// `None` means either the config page is erased (first boot) or its
    /// magic bytes do not match. Postcard deserialization failures are
    /// treated the same as a missing config — the device starts fresh.
    pub fn load_config(&mut self) -> Result<Option<S::Config>, FlashError> {
        // We only need the header plus the payload length worth of
        // bytes, but reading the full page is simpler and costs nothing.
        // Allocate at most PAGE_SIZE on the stack. PAGE_SIZE is 2 KiB on
        // G0 — comfortably fits even on the smallest M0+ stack.
        assert!(PAGE_SIZE <= 4096, "PAGE_SIZE too large for stack buffer");
        let mut region = [0u8; 4096];
        let region = &mut region[..PAGE_SIZE as usize];

        self.flash.blocking_read(Self::CONFIG_OFFSET, region).map_err(|_| FlashError::ReadFailed)?;

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

impl<S, I, const FLASH_SIZE: u32, const PAGE_SIZE: u32> StmFlashStorage<S, I, FLASH_SIZE, PAGE_SIZE>
where
    S: HasDeviceConfig,
    S::Config: Serialize + for<'de> Deserialize<'de>,
    I: DeviceIdentity,
{
    /// Serialize `state` and persist it to the config page.
    ///
    /// Erases the page and writes header + postcard payload, padded up to
    /// a doubleword boundary with `0xFF`. Clears the dirty flag on success.
    pub fn save(&mut self, state: &S) -> Result<(), FlashError> {
        let persisted = state.to_config();

        // One page worth of stack buffer — same bound as `load_config`.
        assert!(PAGE_SIZE <= 4096, "PAGE_SIZE too large for stack buffer");
        let mut buf = [0xFFu8; 4096];
        let buf = &mut buf[..PAGE_SIZE as usize];

        buf[0..4].copy_from_slice(&CONFIG_MAGIC);

        let payload = postcard::to_slice(&persisted, &mut buf[CONFIG_HEADER_SIZE..])
            .expect("serialized state exceeds flash page size");
        let len = payload.len();
        buf[4..6].copy_from_slice(&(len as u16).to_le_bytes());

        // Pad up to a doubleword so the STM32 flash write accepts it.
        let used = CONFIG_HEADER_SIZE + len;
        let padded = (used + WRITE_ALIGN - 1) & !(WRITE_ALIGN - 1);

        self.flash
            .blocking_erase(Self::CONFIG_OFFSET, Self::CONFIG_OFFSET + PAGE_SIZE)
            .map_err(|_| FlashError::EraseFailed)?;
        self.flash.blocking_write(Self::CONFIG_OFFSET, &buf[..padded]).map_err(|_| FlashError::WriteFailed)?;

        self.dirty = false;
        Ok(())
    }

    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

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
