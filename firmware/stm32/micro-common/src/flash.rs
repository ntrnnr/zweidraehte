//! The STM32G0B0RE's internal flash over raw registers, as a [`SectorIo`].
//!
//! Every polling micro target keeps its low-write configuration in a flash
//! page and the secure ones read the `KNXP` factory record from the last
//! page, so the page erase and doubleword programming exist once, here.
//! Offsets are relative to the flash base, as in every `SectorIo`; reads come
//! straight from the memory-mapped flash.
//!
//! The geometry is the one chip this crate pins (`stm32g0b0re` in
//! `stm32-metapac`): 512 KiB in two 256 KiB banks of 2 KiB pages. A page
//! erase names its bank and the page within it, which [`page_erase`] derives
//! from the offset.

use core::sync::atomic::{Ordering, compiler_fence};

use stm32_metapac::FLASH;
use zweidraehte_nv::{Area, SectorIo};

// ================================================================================
// Geometry
// ================================================================================

/// Where the flash appears in the address space.
const FLASH_BASE: u32 = 0x0800_0000;

/// The chip's internal flash size.
pub const FLASH_SIZE: u32 = 512 * 1024;

/// The flash erase page.
pub const PAGE_SIZE: u32 = 2 * 1024;

/// Where bank 2 starts, relative to the flash base.
const BANK2_OFFSET: u32 = 256 * 1024;

/// The doubleword the flash controller programs at once.
const DOUBLEWORD: usize = 8;

/// The `KNXP` factory record: the last page of flash, written once by
/// `knx-provision` (see `zweidraehte_nv::stores::provisioning`). Each target's
/// `memory.x` keeps the image below it.
pub const PROVISIONING_PAGE: Area = Area::new(FLASH_SIZE - PAGE_SIZE, PAGE_SIZE);

// ================================================================================
// The medium
// ================================================================================

/// Why an erase or a write failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlashError {
    /// The range is not whole pages (erase) or whole doublewords (write).
    Misaligned,
    /// The range reaches past the end of flash.
    OutOfRange,
    /// The flash controller reported an error.
    Program,
    /// The programmed bytes read back differently.
    Verify,
}

/// The internal flash. There is one flash controller, and every operation
/// runs to completion before it returns, so the handle carries no state.
#[derive(Clone, Copy)]
pub struct RawFlash;

impl RawFlash {
    /// `len` bytes at `offset`, straight from the memory-mapped flash: the
    /// zero-copy view a page-sized configuration record parses from.
    ///
    /// # Panics
    ///
    /// If the range reaches past the end of flash.
    pub fn slice(offset: u32, len: usize) -> &'static [u8] {
        assert!(offset as usize + len <= FLASH_SIZE as usize, "the range lies inside the flash");

        // SAFETY: the range lies inside the memory-mapped internal flash,
        // which is readable for the whole program.
        unsafe { core::slice::from_raw_parts((FLASH_BASE + offset) as *const u8, len) }
    }
}

impl SectorIo for RawFlash {
    type Error = FlashError;

    const WRITE_ALIGN: usize = DOUBLEWORD;

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), FlashError> {
        if offset as usize + buf.len() > FLASH_SIZE as usize {
            return Err(FlashError::OutOfRange);
        }

        buf.copy_from_slice(Self::slice(offset, buf.len()));
        Ok(())
    }

    fn erase(&mut self, start: u32, end: u32) -> Result<(), FlashError> {
        if !start.is_multiple_of(PAGE_SIZE) || !end.is_multiple_of(PAGE_SIZE) || end < start {
            return Err(FlashError::Misaligned);
        }
        if end > FLASH_SIZE {
            return Err(FlashError::OutOfRange);
        }

        unlock();
        let result = (start..end).step_by(PAGE_SIZE as usize).try_for_each(page_erase);
        lock();

        result
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), FlashError> {
        if !(offset as usize).is_multiple_of(DOUBLEWORD) || !data.len().is_multiple_of(DOUBLEWORD) {
            return Err(FlashError::Misaligned);
        }
        if offset as usize + data.len() > FLASH_SIZE as usize {
            return Err(FlashError::OutOfRange);
        }

        unlock();
        let result = data
            .chunks_exact(DOUBLEWORD)
            .enumerate()
            .try_for_each(|(index, doubleword)| program_doubleword(offset + (index * DOUBLEWORD) as u32, doubleword));
        lock();
        result?;

        // Read back what landed, so a write that went wrong without a status
        // flag still fails here rather than at the next boot's CRC.
        if Self::slice(offset, data.len()) != data {
            return Err(FlashError::Verify);
        }
        Ok(())
    }
}

// ================================================================================
// The controller
// ================================================================================

/// Erase the page at `offset`, naming its bank and the page within the bank.
fn page_erase(offset: u32) -> Result<(), FlashError> {
    let (bank2, page) = match offset.checked_sub(BANK2_OFFSET) {
        Some(in_bank2) => (true, in_bank2 / PAGE_SIZE),
        None => (false, offset / PAGE_SIZE),
    };

    clear_status();
    FLASH.cr().modify(|w| {
        w.set_per(true);
        w.set_bker(bank2);
        w.set_pnb(page as u16);
        w.set_strt(true);
    });
    wait_idle();
    FLASH.cr().modify(|w| w.set_per(false));

    check_status()
}

/// Program one erased doubleword at `offset`.
fn program_doubleword(offset: u32, doubleword: &[u8]) -> Result<(), FlashError> {
    let target = (FLASH_BASE + offset) as *mut u32;
    let low = u32::from_le_bytes(doubleword[..4].try_into().expect("a doubleword has a four-byte low word"));
    let high = u32::from_le_bytes(doubleword[4..].try_into().expect("a doubleword has a four-byte high word"));

    clear_status();
    FLASH.cr().modify(|w| w.set_pg(true));
    cortex_m::interrupt::free(|_| {
        compiler_fence(Ordering::SeqCst);
        // SAFETY: the target is a doubleword-aligned flash address, and G0
        // doubleword programming requires these two adjacent 32-bit writes
        // with interrupts excluded.
        unsafe {
            core::ptr::write_volatile(target, low);
            core::ptr::write_volatile(target.add(1), high);
        }
        compiler_fence(Ordering::SeqCst);
    });
    wait_idle();
    FLASH.cr().modify(|w| w.set_pg(false));

    check_status()
}

// Inlined into its two callers: on the shipped targets that is 20 bytes
// smaller than the outlined function and its calls.
#[inline(always)]
fn unlock() {
    wait_idle();
    if FLASH.cr().read().lock() {
        FLASH.keyr().write_value(0x4567_0123);
        FLASH.keyr().write_value(0xCDEF_89AB);
    }
}

fn lock() {
    FLASH.cr().modify(|w| w.set_lock(true));
}

fn wait_idle() {
    while {
        let status = FLASH.sr().read();
        status.bsy() || status.bsy2() || status.cfgbsy()
    } {}
}

fn clear_status() {
    // Read and write back the status register: every error/EOP flag is
    // write-one-to-clear, matching the STM32 reference driver.
    FLASH.sr().modify(|_| {});
}

fn check_status() -> Result<(), FlashError> {
    let status = FLASH.sr().read();
    let failed = status.operr()
        || status.progerr()
        || status.wrperr()
        || status.pgaerr()
        || status.sizerr()
        || status.pgserr()
        || status.miserr()
        || status.fasterr();

    if failed { Err(FlashError::Program) } else { Ok(()) }
}
