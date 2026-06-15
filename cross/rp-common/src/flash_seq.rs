//! RP2040 internal-flash binding for the wear-levelled key-value store.
//!
//! The generic wear-levelled append log lives in
//! [`embedded_common::persist::WearLeveledKv`]; this module provides the
//! [`RpFlashIo`] adapter binding it to the `embassy_rp` blocking flash handle,
//! plus the [`RpWearLeveledKv`] alias fixing the flash region from the layout
//! constants in [`crate::storage`]. A secure device builds its sequence/SIAT
//! store as `SiatStore<RpWearLeveledKv<N>, N, K>`.
//!
//! Each erase/write suspends XIP and stalls all embassy tasks; the
//! `SiatStore` watermark (`K`) keeps the hot sending-counter path off flash for
//! `K` sends at a time. Reads go through the in-RAM mirror — no flash hit.

use core::cell::RefCell;

use embassy_rp::flash::{self, Flash};
use embassy_rp::peripherals::FLASH;

use embedded_common::persist::{FlashIo, WearLeveledKv};

use crate::storage::{FLASH_SIZE, SECTOR_SIZE, SEQ_REGION_OFFSET, SEQ_SECTOR_COUNT};

/// [`FlashIo`] over the shared `embassy_rp` blocking flash handle.
///
/// The handle is shared (`&'static RefCell`) so the config store
/// ([`crate::storage::RpFlashStorage`]) and this sequence store can both reach
/// the single `FLASH` peripheral. The `RefCell` is sound under embassy's
/// single-threaded executor — every flash op is synchronous (`blocking_*`,
/// never held across an `.await`).
pub struct RpFlashIo {
    flash: &'static RefCell<Flash<'static, FLASH, flash::Blocking, FLASH_SIZE>>,
}

impl RpFlashIo {
    pub fn new(flash: &'static RefCell<Flash<'static, FLASH, flash::Blocking, FLASH_SIZE>>) -> Self {
        Self { flash }
    }
}

impl FlashIo for RpFlashIo {
    type Error = embassy_rp::flash::Error;

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.flash.borrow_mut().blocking_read(offset, buf)
    }
    fn erase(&mut self, start: u32, end: u32) -> Result<(), Self::Error> {
        self.flash.borrow_mut().blocking_erase(start, end)
    }
    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), Self::Error> {
        self.flash.borrow_mut().blocking_write(offset, data)
    }
}

/// Wear-levelled key-value store over the RP2040 sequence-number flash region
/// (8 sectors below the config sector — see [`crate::storage`]).
///
/// `ENTRIES` is the live-record capacity (≥ SIAT entries + the two singleton
/// sequence counters).
pub type RpWearLeveledKv<const ENTRIES: usize> =
    WearLeveledKv<RpFlashIo, SEQ_REGION_OFFSET, SECTOR_SIZE, SEQ_SECTOR_COUNT, ENTRIES>;
