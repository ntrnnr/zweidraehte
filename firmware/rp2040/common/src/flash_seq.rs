//! RP2040 internal-flash medium adapter.
//!
//! The generic storage backends live in the core crate; this module provides
//! only the [`RpFlashIo`] adapter binding them to the `embassy_rp` blocking
//! flash handle — the [`RpFlash`](crate::storage::RpFlash) chip's `Io`. A
//! secure device declares its SIAT as a
//! [`FlashSiatRegion`](zweidraehte_device::storage::FlashSiatRegion) on that
//! chip; the wear-levelled store and `SiatStore` view derive from the region.
//!
//! Each erase/write suspends XIP and stalls all embassy tasks; the
//! `SiatStore` watermark (`BATCH`) keeps the hot sending-counter path off
//! flash for `BATCH` sends at a time. Reads go through the in-RAM mirror —
//! no flash hit.

use core::cell::RefCell;

use embassy_rp::flash::{self, Flash};
use embassy_rp::peripherals::FLASH;

use zweidraehte_device::storage::SectorIo;

use crate::storage::FLASH_SIZE;

/// [`SectorIo`] over the shared `embassy_rp` blocking flash handle.
///
/// The handle is shared (`&'static RefCell`) and `Copy` so the config store,
/// the sequence store, and the mc_timer store can all reach the single
/// `FLASH` peripheral — each region opens over its own copy. The `RefCell`
/// is sound under embassy's single-threaded executor — every flash op is
/// synchronous (`blocking_*`, never held across an `.await`).
#[derive(Clone, Copy)]
pub struct RpFlashIo {
    flash: &'static RefCell<Flash<'static, FLASH, flash::Blocking, FLASH_SIZE>>,
}

impl RpFlashIo {
    pub fn new(flash: &'static RefCell<Flash<'static, FLASH, flash::Blocking, FLASH_SIZE>>) -> Self {
        Self { flash }
    }
}

impl SectorIo for RpFlashIo {
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
