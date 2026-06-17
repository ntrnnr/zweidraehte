//! [`FlashIo`] adapter over the STM32 internal-flash peripheral.
//!
//! Binds the generic [`ConfigStore`](embedded_common::persist::ConfigStore) to
//! the embassy `Flash` blocking API. The STM32 config store *owns* the `Flash`
//! handle by value — unlike the RP2040, where the single `FLASH` peripheral is
//! shared between the config store and the wear-levelled sequence store via a
//! `&'static RefCell`. On STM32 the sequence/SIAT store lives on an external
//! FRAM, so internal flash has exactly one consumer and plain ownership
//! suffices.

use embassy_stm32::flash::{Blocking, Flash};

use embedded_common::persist::FlashIo;

/// [`FlashIo`] over an owned STM32 `Flash` peripheral.
pub struct StmFlashIo {
    flash: Flash<'static, Blocking>,
}

impl StmFlashIo {
    pub fn new(flash: Flash<'static, Blocking>) -> Self {
        Self { flash }
    }
}

impl FlashIo for StmFlashIo {
    type Error = embassy_stm32::flash::Error;

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.flash.blocking_read(offset, buf)
    }

    fn erase(&mut self, start: u32, end: u32) -> Result<(), Self::Error> {
        self.flash.blocking_erase(start, end)
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), Self::Error> {
        self.flash.blocking_write(offset, data)
    }
}
