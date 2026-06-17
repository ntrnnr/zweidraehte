//! Generic device-config store over the [`FlashIo`] seam.
//!
//! ETS-programmed device state is persisted as a single postcard blob in a
//! flash region: a magic + length header followed by the serialised
//! [`HasDeviceConfig::Config`]. The codec is parameterised by the region's
//! flash offset/size and the medium's write granularity, so a target supplies
//! only a [`FlashIo`] adapter plus a type alias fixing those constants.
//!
//! This is a *separate concern* from the wear-levelled / verbatim
//! [`KeyValueStore`](super::KeyValueStore) backends in this module: those hold
//! the hot per-frame security counters; this holds the rarely-written ETS
//! config. They share only the [`FlashIo`] seam.
//!
//! # Region format
//!
//! ```text
//! [magic: 4B "KNXS"][len: 2B LE][postcard payload][0xFF padding…]
//! ```
//!
//! The magic guards against reading uninitialised flash (all `0xFF`). A blank
//! region, a magic mismatch, or a postcard decode failure all read back as
//! `None` — the device starts fresh and ETS re-downloads.

use core::marker::PhantomData;

use serde::{Deserialize, Serialize};

use zweidraehte_device::bcus::system_b::HasDeviceConfig;
use zweidraehte_device::storage::DeviceIdentity;

use super::flash_io::FlashIo;

/// Magic guarding the config region against uninitialised (`0xFF`) flash.
const CONFIG_MAGIC: [u8; 4] = *b"KNXS";
/// Header width: 4 bytes magic + 2 bytes little-endian payload length.
const CONFIG_HEADER_SIZE: usize = 6;

/// Failure modes of a config-store flash access.
///
/// Unit variants: the underlying HAL error carries device-specific detail the
/// caller can't act on (a config read/erase/write either lands or the device
/// boots fresh), so it is discarded at the seam.
#[derive(Debug, defmt::Format)]
pub enum ConfigStoreError {
    ReadFailed,
    EraseFailed,
    WriteFailed,
}

/// Postcard-blob device-config store over a fixed flash region.
///
/// Type parameters:
/// - `F` — the [`FlashIo`] medium adapter (owns or shares the flash handle).
/// - `S` — runtime state type; converted to/from its serialisable
///   [`HasDeviceConfig::Config`].
/// - `I` — device identity (e.g. the per-crate `FlashSecureIdentityData`),
///   carried for `save` and exposed via [`identity`](Self::identity).
/// - `REGION_OFFSET` — byte offset of the config region from flash start.
/// - `REGION_SIZE` — region size in bytes; also the stack buffer size and the
///   erase granule (one page/sector).
/// - `WRITE_ALIGN` — write-granularity padding. Writes are padded up to this
///   many bytes with `0xFF` (the erased value). STM32 flash needs 8 (one
///   doubleword); media with byte-granular writes (RP2040) use the default 1.
pub struct ConfigStore<
    F: FlashIo,
    S,
    I,
    const REGION_OFFSET: u32,
    const REGION_SIZE: usize,
    const WRITE_ALIGN: usize = 1,
> {
    io: F,
    identity: I,
    dirty: bool,
    _phantom: PhantomData<S>,
}

impl<F: FlashIo, S, I, const REGION_OFFSET: u32, const REGION_SIZE: usize, const WRITE_ALIGN: usize>
    ConfigStore<F, S, I, REGION_OFFSET, REGION_SIZE, WRITE_ALIGN>
{
    // The region must hold a header plus at least one aligned write, and the
    // alignment must be a power of two for the round-up mask to be valid.
    const _VALIDATE: () = {
        assert!(REGION_SIZE > 0, "REGION_SIZE must be non-zero");
        assert!(WRITE_ALIGN > 0 && WRITE_ALIGN.is_power_of_two(), "WRITE_ALIGN must be a power of two");
        assert!(REGION_SIZE >= CONFIG_HEADER_SIZE + WRITE_ALIGN, "REGION_SIZE too small for the config header");
    };

    /// Build the store over an already-configured [`FlashIo`] adapter and the
    /// device identity sourced from provisioning.
    pub fn new(io: F, identity: I) -> Self {
        let _ = Self::_VALIDATE;
        Self { io, identity, dirty: false, _phantom: PhantomData }
    }

    /// The device identity carried alongside the persisted config.
    pub fn identity(&self) -> &I {
        &self.identity
    }

    /// Mark the store as having unsaved runtime changes (the device polls
    /// [`is_dirty`](Self::is_dirty) to decide when to `save`).
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Whether there are unsaved changes since the last successful `save`.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
}

impl<F: FlashIo, S, I, const REGION_OFFSET: u32, const REGION_SIZE: usize, const WRITE_ALIGN: usize>
    ConfigStore<F, S, I, REGION_OFFSET, REGION_SIZE, WRITE_ALIGN>
where
    S: HasDeviceConfig,
    S::Config: Serialize + for<'de> Deserialize<'de>,
{
    /// Read and deserialise the persisted config.
    ///
    /// Returns `None` for a blank region (missing magic), an out-of-range
    /// length, or a postcard decode failure — in every case the device boots
    /// fresh. Reading the whole region into a stack buffer is simpler than a
    /// two-step header-then-payload read and costs nothing: `REGION_SIZE` is
    /// one page/sector.
    pub fn load_config(&mut self) -> Result<Option<S::Config>, ConfigStoreError> {
        let mut region = [0u8; REGION_SIZE];
        self.io.read(REGION_OFFSET, &mut region).map_err(|_| ConfigStoreError::ReadFailed)?;

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
                defmt::warn!("ConfigStore: postcard deserialization failed, returning None");
                Ok(None)
            }
        }
    }
}

impl<F: FlashIo, S, I, const REGION_OFFSET: u32, const REGION_SIZE: usize, const WRITE_ALIGN: usize>
    ConfigStore<F, S, I, REGION_OFFSET, REGION_SIZE, WRITE_ALIGN>
where
    S: HasDeviceConfig,
    S::Config: Serialize + for<'de> Deserialize<'de>,
    I: DeviceIdentity,
{
    /// Serialise `state` and persist it to the config region.
    ///
    /// Erases the region, then writes the header plus the postcard payload
    /// padded up to `WRITE_ALIGN` with `0xFF`. Clears the dirty flag on
    /// success. The `I: DeviceIdentity` bound mirrors the prior per-crate
    /// stores (identity participates in the save contract even though the
    /// payload itself is config-only).
    pub fn save(&mut self, state: &S) -> Result<(), ConfigStoreError> {
        let persisted = state.to_config();

        let mut buf = [0xFFu8; REGION_SIZE];
        buf[0..4].copy_from_slice(&CONFIG_MAGIC);

        let payload = postcard::to_slice(&persisted, &mut buf[CONFIG_HEADER_SIZE..])
            .expect("serialized state exceeds the config region — increase REGION_SIZE");
        let len = payload.len();
        buf[4..6].copy_from_slice(&(len as u16).to_le_bytes());

        // Pad up to the medium's write granularity (the trailing bytes are
        // already 0xFF, the erased value). WRITE_ALIGN == 1 leaves it unpadded.
        let used = CONFIG_HEADER_SIZE + len;
        let padded = (used + WRITE_ALIGN - 1) & !(WRITE_ALIGN - 1);

        self.io.erase(REGION_OFFSET, REGION_OFFSET + REGION_SIZE as u32).map_err(|_| ConfigStoreError::EraseFailed)?;
        self.io.write(REGION_OFFSET, &buf[..padded]).map_err(|_| ConfigStoreError::WriteFailed)?;

        self.dirty = false;
        Ok(())
    }
}
