//! Generic device-config store over the [`SectorIo`] seam.
//!
//! ETS-programmed device state is persisted as a single postcard blob in a
//! flash region: a magic + length header followed by the serialised
//! [`HasDeviceConfig::Config`]. The codec is parameterised by the region's
//! flash offset/size and the medium's write granularity, so a target supplies
//! only a [`SectorIo`] adapter plus a type alias fixing those constants.
//!
//! This is a *separate concern* from the wear-levelled / verbatim
//! [`KeyValueStore`](super::KeyValueStore) backends in this module: those hold
//! the hot per-frame security counters; this holds the rarely-written ETS
//! config. They share only the [`SectorIo`] seam.
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

use crate::storage::HasDeviceConfig;

use super::sector_io::SectorIo;
use crate::storage::region::{Chip, Region, RegionKind, RegionPlacement};

/// Header width: 4 bytes magic + 2 bytes little-endian payload length.
const CONFIG_HEADER_SIZE: usize = 6;

/// Failure modes of a config-store flash access.
///
/// Unit variants: the underlying HAL error carries device-specific detail the
/// caller can't act on (a config read/erase/write either lands or the device
/// boots fresh), so it is discarded at the seam.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ConfigStoreError {
    ReadFailed,
    EraseFailed,
    WriteFailed,
    /// The serialised config does not fit the region — `REGION_SIZE` is too
    /// small for the device's `Config`. The save is skipped (the previous
    /// blob stays intact); fix by enlarging the config region.
    ConfigTooLarge,
}

/// Postcard-blob device-config store over a fixed flash region.
///
/// Type parameters:
/// - `F` — the [`SectorIo`] medium adapter (a `Copy` handle over the flash);
///   its [`WRITE_ALIGN`](SectorIo::WRITE_ALIGN) governs the write padding.
/// - `S` — runtime state type; converted to/from its serialisable
///   [`HasDeviceConfig::Config`].
/// - `R` — the bound [`Region`] (a `ConfigRegion<…>`); the single source of
///   the header magic, and its `SIZE` must equal `REGION_SIZE`.
/// - `REGION_SIZE` — region size in bytes; also the stack buffer size and the
///   erase granule (one page/sector). It repeats `R::SIZE` as a plain const
///   generic because the `[u8; REGION_SIZE]` buffers cannot be sized by
///   `R::SIZE as usize` without `generic_const_exprs`; `_VALIDATE` pins the
///   two together at compile time, and the `Stored` impl on `ConfigRegion`
///   passes the marker's size parameter straight through, so devices never
///   write it by hand. The region's *offset* is a runtime constructor
///   argument (the storage layer derives it).
pub struct ConfigStore<F: SectorIo, S, R: Region, const REGION_SIZE: usize> {
    io: F,
    /// Region placement — supplied at `new` time by the storage layer (which
    /// auto-derives the offset from the region sizes), not baked into the type.
    /// Only `REGION_SIZE` (sizing the `[u8; REGION_SIZE]` buffers) must stay a
    /// const generic; the offset is just a scalar flash address, so it lives
    /// here as a runtime field.
    region_offset: u32,
    _phantom: PhantomData<(S, R)>,
}

impl<F: SectorIo, S, R: Region, const REGION_SIZE: usize> ConfigStore<F, S, R, REGION_SIZE> {
    // The bound region must be an erase+rewrite blob whose extent equals the
    // buffer size, the region must hold a header plus at least one aligned
    // write, and the medium's alignment must be a power of two for the
    // round-up mask to be valid.
    // `core::assert!` (not the prelude `assert!`): with the crate's `defmt`
    // feature on, defmt shadows the prelude `assert!` with a version whose
    // failure path calls the non-const `defmt::export::panic`, which a const
    // evaluator rejects. `core::assert!` is always const-capable.
    const _VALIDATE: () = {
        core::assert!(
            R::KIND.eq(RegionKind::EraseRewrite),
            "ConfigStore requires an erase+rewrite region (Region::KIND == EraseRewrite)"
        );
        core::assert!(R::SIZE as usize == REGION_SIZE, "ConfigStore's REGION_SIZE must equal its bound region's SIZE");
        core::assert!(REGION_SIZE > 0, "REGION_SIZE must be non-zero");
        core::assert!(
            F::WRITE_ALIGN > 0 && F::WRITE_ALIGN.is_power_of_two(),
            "the medium's WRITE_ALIGN must be a power of two"
        );
        core::assert!(
            REGION_SIZE >= CONFIG_HEADER_SIZE + F::WRITE_ALIGN,
            "REGION_SIZE too small for the config header"
        );
    };

    /// The 4-byte header magic guarding the config region against uninitialised
    /// (`0xFF`) flash, sourced from the bound region — the single source of
    /// truth, so the store and its region cannot disagree.
    const CONFIG_MAGIC: [u8; 4] = R::MAGIC.to_be_bytes();

    /// Build the store at the bound region's storage-layer-derived
    /// [`RegionPlacement`]. Only `R`'s own placement is accepted — handing it
    /// another region's placement is a type error, and `_VALIDATE` pins the
    /// buffer size and mechanism to `R` at compile time, so nothing is left
    /// for a boot assert. The chip is a free parameter here — the chip↔`io`
    /// pairing is enforced one level up, where `Stored::open` takes `C::Io`.
    pub fn open_at<C: Chip>(io: F, placement: RegionPlacement<R, C>) -> Self {
        Self::new(io, placement.offset)
    }

    /// Build the store over an already-configured [`SectorIo`] adapter and the
    /// region's flash `region_offset` (supplied by the storage layer's
    /// auto-packing).
    ///
    /// Prefer [`open_at`](Self::open_at) with the macro-derived placement; this
    /// is the primitive it unpacks into.
    ///
    /// Dirty tracking deliberately does not live here: the stack signals
    /// unsaved changes through `HasPersistence` on the device state, which the
    /// generic storage task polls.
    pub(crate) fn new(io: F, region_offset: u32) -> Self {
        // Referencing the associated const forces its lazy assertion.
        #[allow(clippy::let_unit_value)]
        let _ = Self::_VALIDATE;

        Self { io, region_offset, _phantom: PhantomData }
    }
}

impl<F: SectorIo, S, R: Region, const REGION_SIZE: usize> ConfigStore<F, S, R, REGION_SIZE>
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
        self.io.read(self.region_offset, &mut region).map_err(|_| ConfigStoreError::ReadFailed)?;

        if region[0..4] != Self::CONFIG_MAGIC {
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
                crate::logging::warn!("ConfigStore: postcard deserialization failed, returning None");
                Ok(None)
            }
        }
    }

    /// Serialise `state` and persist it to the config region.
    ///
    /// Erases the region, then writes the header plus the postcard payload
    /// padded up to `WRITE_ALIGN` with `0xFF`.
    pub fn save(&mut self, state: &S) -> Result<(), ConfigStoreError> {
        let persisted = state.to_config();

        let mut buf = [0xFFu8; REGION_SIZE];
        buf[0..4].copy_from_slice(&Self::CONFIG_MAGIC);

        // An oversized config is an error, not a panic: the erase below has
        // not happened yet, so the previous blob survives and the device keeps
        // running on its last-saved state instead of rebooting in a loop.
        let payload = postcard::to_slice(&persisted, &mut buf[CONFIG_HEADER_SIZE..])
            .map_err(|_| ConfigStoreError::ConfigTooLarge)?;
        let len = payload.len();
        buf[4..6].copy_from_slice(&(len as u16).to_le_bytes());

        // Pad up to the medium's write granularity (the trailing bytes are
        // already 0xFF, the erased value). WRITE_ALIGN == 1 leaves it unpadded.
        let used = CONFIG_HEADER_SIZE + len;
        let padded = (used + F::WRITE_ALIGN - 1) & !(F::WRITE_ALIGN - 1);

        self.io
            .erase(self.region_offset, self.region_offset + REGION_SIZE as u32)
            .map_err(|_| ConfigStoreError::EraseFailed)?;
        self.io.write(self.region_offset, &buf[..padded]).map_err(|_| ConfigStoreError::WriteFailed)?;

        Ok(())
    }
}
