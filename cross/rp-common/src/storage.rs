//! Flash-based persistent storage for RP2040/RP2350.
//!
//! Reserves a region at the end of the chip's 2 MB flash for device state
//! persistence. The region size is configurable via a const generic on
//! [`RpFlashStorage`] (default: 4 KiB = one sector). Serialization is via
//! `postcard` (compact no_std binary format).
//!
//! # Format
//!
//! ```text
//! [magic: 4B][len: 2B little-endian][postcard payload][...]
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

use zweidraehte::storage::DeviceStorage;

// ================================================================================
// Constants
// ================================================================================

const FLASH_SIZE: usize = 2 * 1024 * 1024; // 2MB
const SECTOR_SIZE: usize = 4096;
const MAGIC: [u8; 4] = *b"KNXS";
/// Header: 4 bytes magic + 2 bytes payload length.
const HEADER_SIZE: usize = 6;

// ================================================================================
// RpFlashStorage
// ================================================================================

/// Persistent storage backed by RP2040/RP2350 internal flash.
///
/// `STORAGE_SIZE` controls how many bytes at the end of flash are reserved
/// for device state. It must be a non-zero multiple of the 4 KiB sector
/// size. Increase it if your device's serialized state exceeds the default
/// 4 KiB (minus 6 bytes header).
pub struct RpFlashStorage<S, const STORAGE_SIZE: usize = 4096> {
    flash: Flash<'static, FLASH, flash::Blocking, FLASH_SIZE>,
    dirty: bool,
    _phantom: core::marker::PhantomData<S>,
}

impl<S, const STORAGE_SIZE: usize> RpFlashStorage<S, STORAGE_SIZE> {
    /// Offset of the storage region from the start of flash.
    const STORAGE_OFFSET: u32 = (FLASH_SIZE - STORAGE_SIZE) as u32;

    // Compile-time validation of the storage region size.
    const _VALIDATE: () = {
        assert!(STORAGE_SIZE > 0, "STORAGE_SIZE must be non-zero");
        assert!(STORAGE_SIZE % SECTOR_SIZE == 0, "STORAGE_SIZE must be a multiple of the 4 KiB flash sector size",);
        assert!(STORAGE_SIZE <= FLASH_SIZE, "STORAGE_SIZE exceeds total flash size",);
    };

    /// Create a new flash storage instance.
    pub fn new(flash: Flash<'static, FLASH, flash::Blocking, FLASH_SIZE>) -> Self {
        // Force the compile-time validation constants to be evaluated.
        let _ = Self::_VALIDATE;
        Self { flash, dirty: false, _phantom: core::marker::PhantomData }
    }
}

impl<S, const STORAGE_SIZE: usize> DeviceStorage for RpFlashStorage<S, STORAGE_SIZE>
where
    S: Serialize + for<'de> Deserialize<'de>,
{
    type State = S;
    type Error = FlashError;

    fn load(&mut self) -> Result<Option<S>, Self::Error> {
        let mut region = [0u8; STORAGE_SIZE];
        self.flash.blocking_read(Self::STORAGE_OFFSET, &mut region).map_err(|_| FlashError::ReadFailed)?;

        // Check magic bytes.
        if region[0..4] != MAGIC {
            return Ok(None);
        }

        // Read payload length (little-endian u16).
        let len = u16::from_le_bytes([region[4], region[5]]) as usize;
        if len == 0 || HEADER_SIZE + len > region.len() {
            return Ok(None);
        }

        let payload = &region[HEADER_SIZE..HEADER_SIZE + len];
        match postcard::from_bytes(payload) {
            Ok(state) => Ok(Some(state)),
            Err(_) => {
                defmt::warn!("Flash storage: postcard deserialization failed, returning None");
                Ok(None)
            }
        }
    }

    fn save(&mut self, state: &S) -> Result<(), Self::Error> {
        // Serialize into a stack buffer. Reserve header bytes at the front.
        let mut buf = [0u8; STORAGE_SIZE];
        buf[0..4].copy_from_slice(&MAGIC);

        let payload = postcard::to_slice(state, &mut buf[HEADER_SIZE..])
            .expect("serialized state exceeds flash storage region — increase STORAGE_SIZE");
        let len = payload.len();
        buf[4..6].copy_from_slice(&(len as u16).to_le_bytes());

        // Erase the region, then write.
        self.flash
            .blocking_erase(Self::STORAGE_OFFSET, Self::STORAGE_OFFSET + STORAGE_SIZE as u32)
            .map_err(|_| FlashError::EraseFailed)?;
        self.flash
            .blocking_write(Self::STORAGE_OFFSET, &buf[..HEADER_SIZE + len])
            .map_err(|_| FlashError::WriteFailed)?;

        self.dirty = false;
        Ok(())
    }

    fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        // Flush is a no-op because we don't buffer — save() writes
        // immediately. The dirty flag is only used for external tracking.
        Ok(())
    }

    fn is_dirty(&self) -> bool {
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
