//! A host-side NOR flash model for testing stores over [`SectorIo`].
//!
//! It models the properties that crash-safety arguments rest on:
//!
//! - an erased cell reads `0xFF`, and a write can only clear bits (`&=`), so a
//!   store that re-programs already-written bytes corrupts here as it would on
//!   hardware;
//! - erases must cover whole sectors, and writes must be whole
//!   `WRITE_ALIGN` granules at aligned offsets;
//! - a **write budget** simulates power loss: after the budget of programmed
//!   bytes is spent, every further write and erase silently does nothing,
//!   exactly like a device whose supply has gone.
//!
//! The bytes live in a shared [`Backing`], so a test can drop a store and
//! open a new one over the same bytes to model a reboot.

use std::cell::{Ref, RefCell};
use std::rc::Rc;
use std::vec;
use std::vec::Vec;

use crate::{ByteIo, SectorIo};

/// Flash contents plus the power-cut budget, shared by every [`MockFlash`]
/// opened over it.
#[derive(Clone)]
pub struct Backing {
    bytes: Rc<RefCell<Vec<u8>>>,
    sector_size: usize,
    /// Bytes that may still be programmed before power is lost; `None` means
    /// unlimited.
    budget: Rc<RefCell<Option<usize>>>,
    /// Bytes programmed so far, for sizing power-cut sweeps.
    written: Rc<RefCell<usize>>,
}

impl Backing {
    /// Erased flash of `len` bytes with `sector_size`-byte erase granules.
    pub fn new(len: usize, sector_size: usize) -> Self {
        assert!(len.is_multiple_of(sector_size), "MockFlash length must be whole sectors");
        Self {
            bytes: Rc::new(RefCell::new(vec![0xFF; len])),
            sector_size,
            budget: Rc::new(RefCell::new(None)),
            written: Rc::new(RefCell::new(0)),
        }
    }

    /// A byte-granular flash handle over these bytes (a "boot").
    pub fn open(&self) -> MockFlash<1> {
        self.open_aligned()
    }

    /// A flash handle with the given write granularity over these bytes.
    pub fn open_aligned<const WRITE_ALIGN: usize>(&self) -> MockFlash<WRITE_ALIGN> {
        MockFlash { backing: self.clone() }
    }

    /// A byte-medium handle (FRAM, EEPROM) over these bytes.
    pub fn open_bytes(&self) -> MockBytes {
        MockBytes { backing: self.clone() }
    }

    /// Lose power after `bytes` more programmed bytes.
    pub fn cut_power_after(&self, bytes: usize) {
        *self.budget.borrow_mut() = Some(bytes);
    }

    /// Restore power (unlimited writes).
    pub fn restore_power(&self) {
        *self.budget.borrow_mut() = None;
    }

    /// Whether the power-cut budget has been spent.
    pub fn power_lost(&self) -> bool {
        *self.budget.borrow() == Some(0)
    }

    /// Bytes programmed so far across every handle.
    pub fn bytes_written(&self) -> usize {
        *self.written.borrow()
    }

    /// The raw flash contents.
    pub fn bytes(&self) -> Ref<'_, Vec<u8>> {
        self.bytes.borrow()
    }

    /// Overwrite raw contents directly, bypassing NOR rules — for injecting
    /// corruption.
    pub fn poke(&self, offset: usize, data: &[u8]) {
        self.bytes.borrow_mut()[offset..offset + data.len()].copy_from_slice(data);
    }
}

/// A [`SectorIo`] handle over a [`Backing`] with write granularity
/// `WRITE_ALIGN`.
pub struct MockFlash<const WRITE_ALIGN: usize> {
    backing: Backing,
}

impl<const WRITE_ALIGN: usize> MockFlash<WRITE_ALIGN> {
    /// The shared contents behind this handle.
    pub fn backing(&self) -> Backing {
        self.backing.clone()
    }
}

impl<const WRITE_ALIGN: usize> SectorIo for MockFlash<WRITE_ALIGN> {
    type Error = ();

    const WRITE_ALIGN: usize = WRITE_ALIGN;

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), ()> {
        let start = offset as usize;
        buf.copy_from_slice(&self.backing.bytes.borrow()[start..start + buf.len()]);
        Ok(())
    }

    fn erase(&mut self, start: u32, end: u32) -> Result<(), ()> {
        let sector_size = self.backing.sector_size;
        assert!((start as usize).is_multiple_of(sector_size), "erase start not sector-aligned");
        assert!((end as usize).is_multiple_of(sector_size), "erase end not sector-aligned");
        if self.backing.power_lost() {
            return Ok(());
        }
        self.backing.bytes.borrow_mut()[start as usize..end as usize].fill(0xFF);
        Ok(())
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), ()> {
        assert!((offset as usize).is_multiple_of(WRITE_ALIGN), "write offset not aligned to WRITE_ALIGN");
        assert!(data.len().is_multiple_of(WRITE_ALIGN), "write length not whole WRITE_ALIGN granules");

        let start = offset as usize;
        let mut bytes = self.backing.bytes.borrow_mut();
        let mut budget = self.backing.budget.borrow_mut();
        for (i, &byte) in data.iter().enumerate() {
            if let Some(remaining) = budget.as_mut() {
                if *remaining == 0 {
                    return Ok(()); // power lost mid-write
                }
                *remaining -= 1;
            }
            bytes[start + i] &= byte; // NOR: programming only clears bits
            *self.backing.written.borrow_mut() += 1;
        }
        Ok(())
    }
}

/// A [`ByteIo`] handle over a [`Backing`]: byte-writable memory such as FRAM
/// or EEPROM. Writes overwrite (no NOR bit rule, no alignment), one byte at a
/// time against the same power-cut budget as [`MockFlash`], so a cut can
/// leave any prefix of a write on the medium.
pub struct MockBytes {
    backing: Backing,
}

impl ByteIo for MockBytes {
    type Error = ();

    fn read_at(&self, off: u32, buf: &mut [u8]) -> Result<(), ()> {
        let start = off as usize;
        buf.copy_from_slice(&self.backing.bytes.borrow()[start..start + buf.len()]);
        Ok(())
    }

    fn write_at(&mut self, off: u32, data: &[u8]) -> Result<(), ()> {
        let start = off as usize;
        let mut bytes = self.backing.bytes.borrow_mut();
        let mut budget = self.backing.budget.borrow_mut();
        for (i, &byte) in data.iter().enumerate() {
            if let Some(remaining) = budget.as_mut() {
                if *remaining == 0 {
                    return Ok(()); // power lost mid-write
                }
                *remaining -= 1;
            }
            bytes[start + i] = byte;
            *self.backing.written.borrow_mut() += 1;
        }
        Ok(())
    }
}
