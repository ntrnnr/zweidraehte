//! [`SectorIo`] adapter over the STM32 internal-flash peripheral.
//!
//! Binds the generic storage backends to the embassy `Flash` blocking API.
//! Like the RP2040's `RpFlashIo`, the adapter is a `Copy` *handle* over a
//! `&'static RefCell<Flash>` — the chip's `Io` per the storage layer's
//! multi-region contract, so every region a device places on the internal
//! flash opens over its own copy of the same handle (and the identity loader
//! borrows the same cell at boot).

use core::cell::RefCell;

use embassy_stm32::flash::{Blocking, Flash};

use zweidraehte_device::storage::SectorIo;

/// Emit the shared flash handle every STM32 device builds identically: the
/// blocking `embassy_stm32` flash driver behind a `&'static RefCell`, so the
/// config store and any other flash consumer can alias the single `FLASH`
/// peripheral. Expands to an expression yielding the
/// `&'static RefCell<Flash<…>>`.
///
/// ```ignore
/// let flash = stm32_common::stm32_flash_cell!(p.FLASH);
/// let identity_data = load_identity(&mut flash.borrow_mut());
/// let config = Cfg::open(StmFlashIo::new(flash)).expect("config open is infallible");
/// ```
#[macro_export]
macro_rules! stm32_flash_cell {
    ($flash_peri:expr) => {{
        static __FLASH_CELL: ::static_cell::StaticCell<
            ::core::cell::RefCell<::embassy_stm32::flash::Flash<'static, ::embassy_stm32::flash::Blocking>>,
        > = ::static_cell::StaticCell::new();
        &*__FLASH_CELL.init(::core::cell::RefCell::new(::embassy_stm32::flash::Flash::new_blocking($flash_peri)))
    }};
}

/// [`SectorIo`] over the shared STM32 `Flash` cell — a `Copy` handle;
/// borrows are per-call and never held across an await (single-threaded
/// executor, blocking flash API).
#[derive(Clone, Copy)]
pub struct StmFlashIo {
    flash: &'static RefCell<Flash<'static, Blocking>>,
}

impl StmFlashIo {
    pub fn new(flash: &'static RefCell<Flash<'static, Blocking>>) -> Self {
        Self { flash }
    }
}

impl SectorIo for StmFlashIo {
    type Error = embassy_stm32::flash::Error;

    // STM32 flash writes land as whole 8-byte doublewords.
    const WRITE_ALIGN: usize = 8;

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
