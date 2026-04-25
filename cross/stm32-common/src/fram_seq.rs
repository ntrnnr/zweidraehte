//! FRAM-backed [`SequenceNumberStorage`] for KNX Data Secure.
//!
//! Persists the regular and tool sending counters, the tool
//! receiving counter, and a linear peer table of last-valid
//! receiving counters on an FM25L16B SPI FRAM (see [`super::fram`]).
//! Every `save_*` write-throughs directly to FRAM — no RAM shadow —
//! so a power loss between `save_*` and the next outbound telegram
//! cannot lose an update. FRAM writes have no cycle time and
//! unlimited endurance, so doing this on every outbound secure
//! frame is fine.
//!
//! # Wire layout
//!
//! Adapted from the conformance harness's `ShmSeqStorage` (battle-
//! tested by the conformance suite). 152 bytes worst-case at 16
//! peer slots, out of 2 KiB available on the chip.
//!
//! ```text
//! Offset 0:   magic[4]            "SEQ\0"     first-boot detection
//! Offset 4:   regular_sending[6]
//! Offset 10:  tool_sending[6]
//! Offset 16:  tool_receiving[6]               (all-zero = unset)
//! Offset 22:  peer_count[2]       big-endian u16
//! Offset 24:  peer_entries[N]     each 8 bytes: peer_ia[2] + seq[6]
//! ```
//!
//! # First-boot behaviour
//!
//! On a fresh FRAM the magic bytes are random. `load_*` checks the
//! magic first: if it's not `SEQ\0`, the loads return the same
//! spec-default sentinels `ShmSeqStorage` uses — `[0,0,0,0,0,1]` for
//! sending counters, `None` for receiving. The first `save_*` writes
//! the magic (last, as a commit marker), and subsequent boots see
//! the full persisted state.
//!
//! # Interior mutability
//!
//! The [`SequenceNumberStorage`] trait spells several loads as
//! `&self` but an SPI transaction is inherently mutating (it drives
//! CS and shifts bytes through the stateful bus). We wrap the FRAM
//! driver in a [`RefCell`] so the `&self` methods can still hit the
//! bus. Outside code already serialises `FramSeqStorage` access
//! through a `RefCell` on the state type, and the embassy executor
//! is single-threaded, so the inner `RefCell::borrow_mut()` can only
//! fail if a future call path becomes reentrant — in which case we
//! want the panic.

use core::cell::RefCell;

use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;

use zweidraehte_device::storage::SequenceNumberStorage;

use crate::fram::{Fm25l16b, FramError};

// ============================================================================
// Layout constants
// ============================================================================

const MAGIC: [u8; 4] = *b"SEQ\0";

const OFFSET_MAGIC: u16 = 0;
const OFFSET_REGULAR_SEND: u16 = 4;
const OFFSET_TOOL_SEND: u16 = 10;
const OFFSET_TOOL_RECV: u16 = 16;
const OFFSET_PEER_COUNT: u16 = 22;
const OFFSET_PEER_ENTRIES: u16 = 24;

const PEER_ENTRY_SIZE: u16 = 8; // 2 bytes IA + 6 bytes seq

/// Spec-default sending sequence number when the FRAM is blank.
///
/// Matches the `ShmSeqStorage` fallback in the conformance harness.
/// The secure application layer treats `[0,0,0,0,0,1]` as "fresh
/// device, no history" — ETS reconciles via `S-A_Sync`.
const DEFAULT_SEND: [u8; 6] = [0, 0, 0, 0, 0, 1];

// ============================================================================
// Storage
// ============================================================================

/// FRAM-backed sequence-number storage.
///
/// `PEER_SLOTS` caps the linear peer table size. A typical field
/// device talks to ETS plus a handful of neighbours, so the default
/// of 16 is generous. Setting this higher only costs FRAM space
/// (8 bytes per slot) and a slightly longer linear scan on every
/// receive.
pub struct FramSeqStorage<BUS, CS, const PEER_SLOTS: usize = 16> {
    fram: RefCell<Fm25l16b<BUS, CS>>,
}

impl<BUS, CS, E, const PEER_SLOTS: usize> FramSeqStorage<BUS, CS, PEER_SLOTS>
where
    BUS: SpiBus<u8, Error = E>,
    CS: OutputPin,
{
    /// Build on top of an already-configured FRAM driver.
    pub const fn new(fram: Fm25l16b<BUS, CS>) -> Self {
        // Static assertion: the full layout must fit into the chip.
        // 24 bytes of header + PEER_SLOTS * 8 bytes of peer table.
        assert!(
            OFFSET_PEER_ENTRIES as usize + PEER_SLOTS * PEER_ENTRY_SIZE as usize <= crate::fram::CAPACITY as usize,
            "FramSeqStorage peer table overflows the FM25L16B's 2 KiB capacity",
        );
        Self { fram: RefCell::new(fram) }
    }

    // --------------------------------------------------------------------
    // Magic-byte helpers
    // --------------------------------------------------------------------

    /// Check whether the FRAM has been initialised by a prior boot.
    fn has_magic(fram: &mut Fm25l16b<BUS, CS>) -> Result<bool, FramError<E>> {
        let mut buf = [0u8; 4];
        fram.read(OFFSET_MAGIC, &mut buf)?;
        Ok(buf == MAGIC)
    }

    /// Initialise a blank FRAM with zero'd defaults, writing magic
    /// *last* as a commit marker.
    ///
    /// If we wrote magic first and crashed before zeroing peer_count,
    /// the next boot would see valid magic and then scan up to 65535
    /// garbage slots looking for peers. Writing magic last means a
    /// half-initialised FRAM reads as "still uninitialised" on the
    /// next boot — safe.
    fn initialise_layout(fram: &mut Fm25l16b<BUS, CS>) -> Result<(), FramError<E>> {
        fram.write(OFFSET_PEER_COUNT, &[0, 0])?;
        fram.write(OFFSET_REGULAR_SEND, &DEFAULT_SEND)?;
        fram.write(OFFSET_TOOL_SEND, &DEFAULT_SEND)?;
        fram.write(OFFSET_TOOL_RECV, &[0u8; 6])?;
        fram.write(OFFSET_MAGIC, &MAGIC)?;
        Ok(())
    }

    /// Ensure the FRAM is initialised before a save; no-op on
    /// subsequent calls. Used by every `save_*`.
    fn ensure_initialised(fram: &mut Fm25l16b<BUS, CS>) -> Result<(), FramError<E>> {
        if !Self::has_magic(fram)? {
            Self::initialise_layout(fram)?;
        }
        Ok(())
    }

    // --------------------------------------------------------------------
    // Peer-table helpers
    // --------------------------------------------------------------------

    fn peer_count(fram: &mut Fm25l16b<BUS, CS>) -> Result<u16, FramError<E>> {
        let mut buf = [0u8; 2];
        fram.read(OFFSET_PEER_COUNT, &mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }

    fn set_peer_count(fram: &mut Fm25l16b<BUS, CS>, count: u16) -> Result<(), FramError<E>> {
        fram.write(OFFSET_PEER_COUNT, &count.to_be_bytes())
    }

    fn peer_entry_offset(index: u16) -> u16 {
        OFFSET_PEER_ENTRIES + index * PEER_ENTRY_SIZE
    }

    /// Linear scan: return the index of the slot holding `peer_ia`,
    /// or `None` if absent.
    fn find_peer(fram: &mut Fm25l16b<BUS, CS>, peer_ia: u16) -> Result<Option<u16>, FramError<E>> {
        let count = Self::peer_count(fram)?;
        let target = peer_ia.to_be_bytes();
        for i in 0..count {
            let mut ia = [0u8; 2];
            fram.read(Self::peer_entry_offset(i), &mut ia)?;
            if ia == target {
                return Ok(Some(i));
            }
        }
        Ok(None)
    }
}

// ============================================================================
// SequenceNumberStorage impl
// ============================================================================

impl<BUS, CS, E, const PEER_SLOTS: usize> SequenceNumberStorage for FramSeqStorage<BUS, CS, PEER_SLOTS>
where
    BUS: SpiBus<u8, Error = E>,
    CS: OutputPin,
{
    type Error = FramError<E>;

    fn load_sending_seqs(&self) -> Result<([u8; 6], [u8; 6]), Self::Error> {
        let mut fram = self.fram.borrow_mut();
        if !Self::has_magic(&mut fram)? {
            return Ok((DEFAULT_SEND, DEFAULT_SEND));
        }
        let mut regular = [0u8; 6];
        let mut tool = [0u8; 6];
        fram.read(OFFSET_REGULAR_SEND, &mut regular)?;
        fram.read(OFFSET_TOOL_SEND, &mut tool)?;
        Ok((regular, tool))
    }

    fn save_sending_seqs(&mut self, regular: &[u8; 6], tool: &[u8; 6]) -> Result<(), Self::Error> {
        let mut fram = self.fram.borrow_mut();
        Self::ensure_initialised(&mut fram)?;
        fram.write(OFFSET_REGULAR_SEND, regular)?;
        fram.write(OFFSET_TOOL_SEND, tool)?;
        Ok(())
    }

    fn load_receiving_seq(&self, peer_ia: u16) -> Result<Option<[u8; 6]>, Self::Error> {
        let mut fram = self.fram.borrow_mut();
        if !Self::has_magic(&mut fram)? {
            return Ok(None);
        }
        match Self::find_peer(&mut fram, peer_ia)? {
            Some(idx) => {
                let mut seq = [0u8; 6];
                fram.read(Self::peer_entry_offset(idx) + 2, &mut seq)?;
                Ok(Some(seq))
            }
            None => Ok(None),
        }
    }

    fn save_receiving_seq(&mut self, peer_ia: u16, seq: &[u8; 6]) -> Result<(), Self::Error> {
        let mut fram = self.fram.borrow_mut();
        Self::ensure_initialised(&mut fram)?;
        match Self::find_peer(&mut fram, peer_ia)? {
            Some(idx) => {
                // Update existing slot — overwrite the 6 seq bytes
                // after the 2-byte IA prefix.
                fram.write(Self::peer_entry_offset(idx) + 2, seq)?;
            }
            None => {
                // Append new slot, silently drop if the table is
                // full. Matches `RamSeqStorage`'s behaviour — a
                // full table means the device is paired with more
                // peers than it has room to remember, which only
                // matters for replay-protection completeness and
                // ETS will re-sync.
                let count = Self::peer_count(&mut fram)?;
                if (count as usize) < PEER_SLOTS {
                    let offset = Self::peer_entry_offset(count);
                    fram.write(offset, &peer_ia.to_be_bytes())?;
                    fram.write(offset + 2, seq)?;
                    Self::set_peer_count(&mut fram, count + 1)?;
                }
            }
        }
        Ok(())
    }

    fn load_tool_receiving_seq(&self) -> Result<Option<[u8; 6]>, Self::Error> {
        let mut fram = self.fram.borrow_mut();
        if !Self::has_magic(&mut fram)? {
            return Ok(None);
        }
        let mut seq = [0u8; 6];
        fram.read(OFFSET_TOOL_RECV, &mut seq)?;
        // All-zero means unset (initial state — matches SHM impl).
        if seq == [0u8; 6] { Ok(None) } else { Ok(Some(seq)) }
    }

    fn save_tool_receiving_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error> {
        let mut fram = self.fram.borrow_mut();
        Self::ensure_initialised(&mut fram)?;
        fram.write(OFFSET_TOOL_RECV, seq)?;
        Ok(())
    }
}
