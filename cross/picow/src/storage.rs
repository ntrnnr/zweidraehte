//! Flash-based persistent storage for the Pico W (RP2040).
//!
//! Uses the last 4KB sector of the RP2040's 2MB flash for device state
//! persistence. Serialization is via `postcard` (compact no_std binary
//! format).
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
/// Offset of our storage sector from the start of flash.
const STORAGE_OFFSET: u32 = (FLASH_SIZE - SECTOR_SIZE) as u32;
const MAGIC: [u8; 4] = *b"KNXS";

// ================================================================================
// FlashStorage
// ================================================================================

/// Persistent storage backed by RP2040 internal flash.
pub struct FlashStorage<S> {
    flash: Flash<'static, FLASH, flash::Blocking, FLASH_SIZE>,
    dirty: bool,
    _phantom: core::marker::PhantomData<S>,
}

impl<S> FlashStorage<S> {
    /// Create a new flash storage instance.
    pub fn new(flash: Flash<'static, FLASH, flash::Blocking, FLASH_SIZE>) -> Self {
        Self { flash, dirty: false, _phantom: core::marker::PhantomData }
    }
}

impl<S> DeviceStorage for FlashStorage<S>
where
    S: Serialize + for<'de> Deserialize<'de>,
{
    type State = S;
    type Error = FlashError;

    fn load(&mut self) -> Result<Option<S>, Self::Error> {
        let mut sector = [0u8; SECTOR_SIZE as usize];
        self.flash
            .blocking_read(STORAGE_OFFSET, &mut sector)
            .map_err(|_| FlashError::ReadFailed)?;

        // Check magic bytes.
        if sector[0..4] != MAGIC {
            return Ok(None);
        }

        // Read payload length (little-endian u16).
        let len = u16::from_le_bytes([sector[4], sector[5]]) as usize;
        if len == 0 || 6 + len > sector.len() {
            return Ok(None);
        }

        let payload = &sector[6..6 + len];
        match postcard::from_bytes(payload) {
            Ok(state) => Ok(Some(state)),
            Err(_) => {
                defmt::warn!("Flash storage: postcard deserialization failed, returning None");
                Ok(None)
            }
        }
    }

    fn save(&mut self, state: &S) -> Result<(), Self::Error> {
        // Serialize into a stack buffer. Reserve 6 bytes for header.
        let mut buf = [0u8; SECTOR_SIZE as usize];
        buf[0..4].copy_from_slice(&MAGIC);

        let payload = postcard::to_slice(state, &mut buf[6..]).map_err(|_| FlashError::SerializeFailed)?;
        let len = payload.len();
        buf[4..6].copy_from_slice(&(len as u16).to_le_bytes());

        // Erase the sector, then write.
        self.flash
            .blocking_erase(STORAGE_OFFSET, STORAGE_OFFSET + SECTOR_SIZE as u32)
            .map_err(|_| FlashError::EraseFailed)?;
        self.flash
            .blocking_write(STORAGE_OFFSET, &buf[..6 + len])
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
    SerializeFailed,
}
