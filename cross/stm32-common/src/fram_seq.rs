//! FRAM-backed [`KeyValueStore`] for KNX Data Secure persistence.
//!
//! Implements [`KeyValueStore`] over an FM25L16B SPI FRAM (see [`super::fram`]).
//! FRAM is byte-addressable with no write-cycle time and unlimited endurance, so
//! every write is a direct write-through — no wear-levelling needed. Wrap this in
//! a typed view (`SiatStore<FramKv<..>, N, K>`) exactly like the flash backends.
//!
//! # Wire layout
//!
//! The three KNX sequence-number kinds map onto a fixed linear layout:
//!
//! ```text
//! Offset 0:   magic[4]            "SEQ\0"   first-boot detection
//! Offset 4:   sending[6]                    NS_SENDING singleton
//! Offset 10:  tool[6]                       NS_TOOL singleton (all-zero = unset)
//! Offset 16:  peer_count[2]       big-endian u16
//! Offset 18:  peer_entries[N]     each 8 bytes: ia[2] + seq[6]   (NS_SIAT)
//! ```
//!
//! On a blank FRAM the magic bytes are random; reads check it first and report a
//! blank store (`get` → `None`, `for_each` → no entries). The first `put` writes
//! the magic, so a `SiatStore` over a fresh FRAM boots to defaults.

use core::cell::RefCell;

use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;

use zweidraehte_device::kvstore::{KeyValueStore, NS_SENDING, NS_SIAT, NS_TOOL};

use crate::fram::{Fm25l16b, FramError};

const MAGIC: [u8; 4] = *b"SEQ\0";

const OFF_MAGIC: u16 = 0;
const OFF_SENDING: u16 = 4;
const OFF_TOOL: u16 = 10;
const OFF_PEER_COUNT: u16 = 16;
const OFF_PEER_ENTRIES: u16 = 18;
const PEER_ENTRY_SIZE: u16 = 8; // ia(2) + seq(6)

/// FRAM-backed key-value store.
///
/// `PEER_SLOTS` caps the per-IA SIAT table size; size it ≥ the device's
/// authorized-sender count (an over-full table silently drops new entries).
/// Default 16 fits the FM25L16B's 2 KiB with room to spare.
pub struct FramKv<BUS, CS, const PEER_SLOTS: usize = 16> {
    // The driver needs `&mut` for an SPI transaction, but `KeyValueStore::get`
    // and `for_each` are `&self`. A `RefCell` bridges this; the embassy executor
    // is single-threaded and every transaction is synchronous, so the inner
    // borrow can only re-enter on a reentrant call path (which would be a bug).
    fram: RefCell<Fm25l16b<BUS, CS>>,
}

impl<BUS, CS, E, const PEER_SLOTS: usize> FramKv<BUS, CS, PEER_SLOTS>
where
    BUS: SpiBus<u8, Error = E>,
    CS: OutputPin,
{
    /// Build over an already-configured FRAM driver.
    pub fn new(fram: Fm25l16b<BUS, CS>) -> Self {
        assert!(
            OFF_PEER_ENTRIES as usize + PEER_SLOTS * PEER_ENTRY_SIZE as usize <= crate::fram::CAPACITY as usize,
            "FramKv peer table overflows the FM25L16B's 2 KiB capacity",
        );
        Self { fram: RefCell::new(fram) }
    }

    fn peer_entry_offset(index: u16) -> u16 {
        OFF_PEER_ENTRIES + index * PEER_ENTRY_SIZE
    }
}

// All FRAM access goes through these free helpers taking `&mut Fm25l16b` so both
// the `&self` (get/for_each) and `&mut self` (put/remove) trait methods share
// one implementation via a `borrow_mut()`.

fn has_magic<BUS, CS, E>(fram: &mut Fm25l16b<BUS, CS>) -> Result<bool, FramError<E>>
where
    BUS: SpiBus<u8, Error = E>,
    CS: OutputPin,
{
    let mut buf = [0u8; 4];
    fram.read(OFF_MAGIC, &mut buf)?;
    Ok(buf == MAGIC)
}

fn peer_count<BUS, CS, E>(fram: &mut Fm25l16b<BUS, CS>) -> Result<u16, FramError<E>>
where
    BUS: SpiBus<u8, Error = E>,
    CS: OutputPin,
{
    let mut buf = [0u8; 2];
    fram.read(OFF_PEER_COUNT, &mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

/// Offset of the entry for `ia`, or `None` if absent.
fn find_peer<BUS, CS, E>(fram: &mut Fm25l16b<BUS, CS>, ia: u16) -> Result<Option<u16>, FramError<E>>
where
    BUS: SpiBus<u8, Error = E>,
    CS: OutputPin,
{
    let count = peer_count(fram)?;
    let target = ia.to_be_bytes();
    for i in 0..count {
        let off = OFF_PEER_ENTRIES + i * PEER_ENTRY_SIZE;
        let mut stored = [0u8; 2];
        fram.read(off, &mut stored)?;
        if stored == target {
            return Ok(Some(off));
        }
    }
    Ok(None)
}

impl<BUS, CS, E, const PEER_SLOTS: usize> KeyValueStore for FramKv<BUS, CS, PEER_SLOTS>
where
    BUS: SpiBus<u8, Error = E>,
    CS: OutputPin,
{
    type Error = FramError<E>;

    fn get(&self, ns: u8, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        let mut fram = self.fram.borrow_mut();
        if !has_magic(&mut fram)? {
            return Ok(None);
        }
        match ns {
            NS_SENDING => {
                fram.read(OFF_SENDING, &mut buf[..6])?;
                Ok(Some(6))
            }
            NS_TOOL => {
                let mut seq = [0u8; 6];
                fram.read(OFF_TOOL, &mut seq)?;
                if seq == [0u8; 6] {
                    Ok(None)
                } else {
                    buf[..6].copy_from_slice(&seq);
                    Ok(Some(6))
                }
            }
            NS_SIAT => {
                let ia = u16::from_be_bytes([key[0], key[1]]);
                match find_peer(&mut fram, ia)? {
                    Some(off) => {
                        fram.read(off + 2, &mut buf[..6])?;
                        Ok(Some(6))
                    }
                    None => Ok(None),
                }
            }
            _ => Ok(None),
        }
    }

    fn put(&mut self, ns: u8, key: &[u8], val: &[u8]) -> Result<(), Self::Error> {
        let mut fram = self.fram.borrow_mut();
        fram.write(OFF_MAGIC, &MAGIC)?;
        match ns {
            NS_SENDING => fram.write(OFF_SENDING, &val[..6]),
            NS_TOOL => fram.write(OFF_TOOL, &val[..6]),
            NS_SIAT => {
                let ia = u16::from_be_bytes([key[0], key[1]]);
                if let Some(off) = find_peer(&mut fram, ia)? {
                    fram.write(off + 2, &val[..6])
                } else {
                    let count = peer_count(&mut fram)?;
                    if (count as usize) < PEER_SLOTS {
                        let off = Self::peer_entry_offset(count);
                        fram.write(off, &ia.to_be_bytes())?;
                        fram.write(off + 2, &val[..6])?;
                        fram.write(OFF_PEER_COUNT, &(count + 1).to_be_bytes())?;
                    }
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }

    fn remove(&mut self, ns: u8, key: &[u8]) -> Result<(), Self::Error> {
        if ns != NS_SIAT {
            return Ok(());
        }
        let mut fram = self.fram.borrow_mut();
        let ia = u16::from_be_bytes([key[0], key[1]]);
        if let Some(off) = find_peer(&mut fram, ia)? {
            let count = peer_count(&mut fram)?;
            let last_off = Self::peer_entry_offset(count - 1);
            if off != last_off {
                let mut last = [0u8; PEER_ENTRY_SIZE as usize];
                fram.read(last_off, &mut last)?;
                fram.write(off, &last)?;
            }
            fram.write(OFF_PEER_COUNT, &(count - 1).to_be_bytes())?;
        }
        Ok(())
    }

    fn for_each(&self, ns: u8, f: &mut dyn FnMut(&[u8], &[u8])) {
        let mut fram = self.fram.borrow_mut();
        if !has_magic(&mut fram).unwrap_or(false) {
            return;
        }
        match ns {
            NS_SENDING => {
                let mut seq = [0u8; 6];
                if fram.read(OFF_SENDING, &mut seq).is_ok() {
                    f(&[0], &seq);
                }
            }
            NS_TOOL => {
                let mut seq = [0u8; 6];
                if fram.read(OFF_TOOL, &mut seq).is_ok() && seq != [0u8; 6] {
                    f(&[0], &seq);
                }
            }
            NS_SIAT => {
                let count = peer_count(&mut fram).unwrap_or(0);
                for i in 0..count {
                    let off = OFF_PEER_ENTRIES + i * PEER_ENTRY_SIZE;
                    let mut entry = [0u8; PEER_ENTRY_SIZE as usize];
                    if fram.read(off, &mut entry).is_ok() {
                        f(&entry[0..2], &entry[2..8]);
                    }
                }
            }
            _ => {}
        }
    }
}
