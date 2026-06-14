//! Wear-levelled internal-flash [`SequenceNumberStorage`] for KNX Data Secure.
//!
//! The RP2040 boards carry no FRAM (SPI0 is taken by the W5500), so the only
//! durable backing for the Data Secure sequence numbers is the chip's internal
//! flash. Flash differs from FRAM in two ways that drive this whole design:
//!
//! 1. **Limited endurance** — ~100K erase cycles per 4 KiB sector. The sending
//!    counter is persisted on *every* outgoing secure frame, so a naive
//!    erase-per-save would wear a sector out in months.
//! 2. **XIP stalls** — `blocking_erase` / `blocking_write` suspend execute-in-
//!    place and freeze every embassy task (incl. the network task) for the
//!    duration. Frequent writes wreck the device's real-time behaviour.
//!
//! Both problems are solved by minimising how often flash is actually touched,
//! using two complementary batching strategies plus a multi-sector append log.
//!
//! # Two write workloads, two policies
//!
//! - **Sending counter** is monotonically increasing and *owned by us*, so we
//!   may skip values ahead freely (we just never reuse one). We persist a
//!   **high watermark** `K` values ahead of the live counter and only write
//!   flash when the live counter crosses it. After power loss we resume from
//!   the watermark — guaranteed higher than anything ever sent, so receivers
//!   accept it. `K` is spec-bounded: 03/03/07 §p157 permits re-initialising the
//!   sending counter "at least 20 and at maximum FFFFh higher" (NOTE 33), so
//!   `K ≤ 0xFFFF`.
//!
//! - **Receiving counters** (per-peer + tool) are *Last Valid SeqNr* values
//!   received from other devices. We cannot invent a higher value or we would
//!   reject a peer's next legitimate frame. The only available batching
//!   direction is the inverse: persist *behind* reality. We keep the live value
//!   in RAM (so in-session replay protection is exact) and write flash only once
//!   it has advanced `≥ T` past the last persisted value.
//!
//!   The cost is a bounded post-reboot replay window: after an uncontrolled
//!   power loss the restored receiving counter lags by up to `T`, so an attacker
//!   could replay recorded frames carrying seqs in `(persisted, persisted + T]`
//!   until `S-A_Sync` re-anchors the counter. `T = 1` is write-through (zero
//!   window). Both knobs are const-generic so each device tunes its own
//!   wear/latency-vs-replay-window trade-off.
//!
//! # On-flash format
//!
//! A circular append log over [`SEQ_SECTOR_COUNT`] sectors. Each sector holds
//! fixed-size 12-byte slots; slot 0 is a sector header, slots 1.. are records:
//!
//! ```text
//! Sector header : [b'K'][b'N'][b'X'][b'Q'][gen:4 BE][crc8][FF FF FF]
//! Sending record: [0x01][s0..s5][crc8][FF FF FF FF]
//! Tool-recv      : [0x02][t0..t5][present:1][crc8][FF FF FF]
//! Peer-recv      : [0x03][ia_hi][ia_lo][r0..r5][crc8][FF FF]
//! Free slot      : all 0xFF
//! ```
//!
//! `crc8` covers the bytes before it and catches torn writes. The sector header
//! is written *last* (after the snapshot) as a commit marker; its `gen` (a
//! monotonically increasing u32) identifies the newest sector after a crash.
//!
//! # Recovery
//!
//! On boot we read each sector's header, pick the valid one with the highest
//! `gen`, and replay its records in order, stopping at the first free/CRC-fail
//! slot. The header is the rotation's **commit marker**: it is written *last*,
//! after the snapshot, so a crash mid-rotation leaves the freshly erased sector
//! header-less (ignored on the next boot) and the previous, still-valid,
//! lower-gen sector is used. The old sector is never erased until the new one
//! is fully committed.
//!
//! # Testability
//!
//! All log logic lives in [`SeqLog`], generic over a tiny [`FlashIo`] trait.
//! [`FlashSeqStorage`] is the thin production wrapper binding `SeqLog` to the
//! real `embassy_rp` flash handle; the host unit tests bind it to an in-memory
//! buffer instead.

use core::cell::RefCell;

use embassy_rp::flash::{self, Flash};
use embassy_rp::peripherals::FLASH;

use zweidraehte_device::storage::SequenceNumberStorage;

use crate::storage::{FLASH_SIZE, SECTOR_SIZE, SEQ_REGION_OFFSET, SEQ_SECTOR_COUNT};

// ============================================================================
// Layout / format constants
// ============================================================================

/// Every slot — header or record — is this many bytes. A fixed slot size turns
/// the per-sector scan into plain index arithmetic with no length parsing.
const SLOT_SIZE: usize = 12;

/// Slots per sector. Slot 0 is the sector header; slots 1.. carry records.
const SLOTS_PER_SECTOR: usize = SECTOR_SIZE / SLOT_SIZE; // 341 for 4 KiB / 12

/// Sector-header magic ("KNXQ" — Q for seQuence, distinct from KNXS/KNXP).
const HEADER_MAGIC: [u8; 4] = *b"KNXQ";

// Record type tags (byte 0 of a record slot).
const REC_SENDING: u8 = 0x01;
const REC_TOOL: u8 = 0x02;
const REC_PEER: u8 = 0x03;

/// Spec-default sending sequence number on a blank device.
///
/// The secure AL treats `[0,0,0,0,0,1]` as "fresh device, no history"; ETS
/// reconciles via `S-A_Sync`. Seq 0 is never used (remotes reject it).
const DEFAULT_SEND: u64 = 1;

// ============================================================================
// FlashIo — the minimal flash interface SeqLog needs
// ============================================================================

/// The slice of flash behaviour [`SeqLog`] depends on, so the log logic can be
/// unit-tested against an in-memory buffer without the RP2040 HAL.
///
/// Offsets are absolute from the start of flash, matching `embassy_rp`'s
/// `blocking_*` API. `erase` must accept a `[start, end)` byte range aligned to
/// the sector size.
pub trait FlashIo {
    type Error;

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), Self::Error>;
    fn erase(&mut self, start: u32, end: u32) -> Result<(), Self::Error>;
    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), Self::Error>;
}

// ============================================================================
// CRC-8 (poly 0x07, init 0x00) — small, table-free, enough to spot torn writes
// ============================================================================

fn crc8(data: &[u8]) -> u8 {
    let mut crc: u8 = 0;
    for &b in data {
        crc ^= b;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 { (crc << 1) ^ 0x07 } else { crc << 1 };
        }
    }
    crc
}

// ============================================================================
// Seq <-> u64 helpers (6-octet big-endian, the wire format)
// ============================================================================

fn seq6_to_u64(seq: &[u8; 6]) -> u64 {
    let mut v = 0u64;
    for &b in seq {
        v = (v << 8) | b as u64;
    }
    v
}

fn u64_to_seq6(val: u64) -> [u8; 6] {
    let b = val.to_be_bytes();
    [b[2], b[3], b[4], b[5], b[6], b[7]]
}

// ============================================================================
// Decoded record
// ============================================================================

#[derive(Clone, Copy)]
enum Record {
    Sending(u64),
    Tool(Option<u64>),
    Peer { ia: u16, seq: u64 },
}

impl Record {
    /// Encode into a 12-byte slot (free tail bytes left 0xFF, matching erased
    /// flash so they never need clearing).
    fn encode(&self) -> [u8; SLOT_SIZE] {
        let mut slot = [0xFFu8; SLOT_SIZE];
        match *self {
            Record::Sending(v) => {
                slot[0] = REC_SENDING;
                slot[1..7].copy_from_slice(&u64_to_seq6(v));
                slot[7] = crc8(&slot[0..7]);
            }
            Record::Tool(opt) => {
                slot[0] = REC_TOOL;
                slot[1..7].copy_from_slice(&u64_to_seq6(opt.unwrap_or(0)));
                slot[7] = opt.is_some() as u8;
                slot[8] = crc8(&slot[0..8]);
            }
            Record::Peer { ia, seq } => {
                slot[0] = REC_PEER;
                slot[1..3].copy_from_slice(&ia.to_be_bytes());
                slot[3..9].copy_from_slice(&u64_to_seq6(seq));
                slot[9] = crc8(&slot[0..9]);
            }
        }
        slot
    }

    /// Decode a 12-byte slot. `None` for a free slot (all-0xFF) or a slot whose
    /// CRC does not check out (a torn write — replay must stop here).
    fn decode(slot: &[u8; SLOT_SIZE]) -> Option<Record> {
        match slot[0] {
            REC_SENDING => {
                if crc8(&slot[0..7]) != slot[7] {
                    return None;
                }
                let mut s = [0u8; 6];
                s.copy_from_slice(&slot[1..7]);
                Some(Record::Sending(seq6_to_u64(&s)))
            }
            REC_TOOL => {
                if crc8(&slot[0..8]) != slot[8] {
                    return None;
                }
                let mut s = [0u8; 6];
                s.copy_from_slice(&slot[1..7]);
                let present = slot[7] != 0;
                Some(Record::Tool(present.then(|| seq6_to_u64(&s))))
            }
            REC_PEER => {
                if crc8(&slot[0..9]) != slot[9] {
                    return None;
                }
                let ia = u16::from_be_bytes([slot[1], slot[2]]);
                let mut s = [0u8; 6];
                s.copy_from_slice(&slot[3..9]);
                Some(Record::Peer { ia, seq: seq6_to_u64(&s) })
            }
            // 0xFF (free) or any unknown tag: stop the scan.
            _ => None,
        }
    }
}

// ============================================================================
// SeqLog — the wear-levelled append log (HAL-agnostic, host-testable)
// ============================================================================

/// In-RAM mirror of one peer's last-valid receiving counter plus the value
/// last durably written, so we can apply the lag threshold per peer.
#[derive(Clone, Copy)]
struct PeerSlot {
    ia: u16,
    live: u64,
    persisted: u64,
}

/// The wear-levelled sequence-number log.
///
/// Holds the authoritative runtime state in RAM and lazily persists it to a
/// circular append log over [`FlashIo`]. See the module docs for the format and
/// the `K` / `T` batching rationale.
///
/// * `PEER_SLOTS` — capacity of the per-peer receiving table. This holds the
///   running `LastValidSeqNr` for every secure sender the device accepts, so it
///   **must be sized ≥ the device's authorized-sender table** (the Security
///   extension's SIAT, which seeds this store via `seed_receiving_seqs`). At
///   that size the overflow path below is unreachable. If a caller under-sizes
///   it, a sender beyond capacity is silently dropped — its counter is then
///   never remembered, degrading its replay protection to "reject only SeqNr 0"
///   (an attacker could replay any recorded frame from it). This mirrors the
///   `RamSeqStorage` / `FramSeqStorage` policy, but those are bring-up stores;
///   here the contract is to size the table to the SIAT and never hit it.
/// * `K` — sending-seq skip-ahead watermark (`≤ 0xFFFF`; `1` persists every send).
/// * `T` — receiving-seq lag threshold (`≥ 1`; `1` is write-through).
pub struct SeqLog<F: FlashIo, const PEER_SLOTS: usize = 8, const K: u64 = 256, const T: u64 = 16> {
    io: F,

    // --- Sending counter ---
    /// Live counter: the next value to embed in an outgoing frame.
    sending_live: u64,
    /// Highest value durably persisted (always ≥ `sending_live`).
    sending_watermark: u64,

    // --- Tool receiving counter ---
    tool_live: Option<u64>,
    tool_persisted: Option<u64>,

    // --- Per-peer receiving counters ---
    peers: heapless::Vec<PeerSlot, PEER_SLOTS>,

    // --- Log write position ---
    /// Index (0..SEQ_SECTOR_COUNT) of the sector currently being appended to.
    active_sector: usize,
    /// Next free slot within the active sector (1..=SLOTS_PER_SECTOR).
    next_slot: usize,
    /// Generation counter of the active sector (monotonic across rotations).
    generation: u32,
}

impl<F: FlashIo, const PEER_SLOTS: usize, const K: u64, const T: u64> SeqLog<F, PEER_SLOTS, K, T> {
    // Compile-time guards on the const-generic knobs.
    const _GUARD_K: () = assert!(K <= 0xFFFF, "watermark K exceeds the spec re-init ceiling (FFFFh)");
    const _GUARD_T: () = assert!(T >= 1, "receiving lag threshold T must be at least 1");

    /// Open the log: scan flash, reconstruct RAM state, and locate the append
    /// position. A blank region (no valid header anywhere) yields defaults.
    pub fn new(io: F) -> Result<Self, F::Error> {
        let _ = Self::_GUARD_K;
        let _ = Self::_GUARD_T;

        let mut log = Self {
            io,
            sending_live: DEFAULT_SEND,
            sending_watermark: DEFAULT_SEND,
            tool_live: None,
            tool_persisted: None,
            peers: heapless::Vec::new(),
            active_sector: 0,
            next_slot: 1,
            generation: 0,
        };
        log.recover()?;
        Ok(log)
    }

    // ------------------------------------------------------------------------
    // Offset helpers
    // ------------------------------------------------------------------------

    fn sector_offset(sector: usize) -> u32 {
        SEQ_REGION_OFFSET + (sector * SECTOR_SIZE) as u32
    }

    fn slot_offset(sector: usize, slot: usize) -> u32 {
        Self::sector_offset(sector) + (slot * SLOT_SIZE) as u32
    }

    // ------------------------------------------------------------------------
    // Boot recovery
    // ------------------------------------------------------------------------

    /// Read every sector header and, among the valid ones, return
    /// `(sector_index, generation)` of the highest-generation sector.
    fn newest_sector(&mut self) -> Result<Option<(usize, u32)>, F::Error> {
        let mut best: Option<(usize, u32)> = None;
        for sector in 0..SEQ_SECTOR_COUNT {
            let mut hdr = [0u8; SLOT_SIZE];
            self.io.read(Self::slot_offset(sector, 0), &mut hdr)?;
            if hdr[0..4] != HEADER_MAGIC {
                continue;
            }
            if crc8(&hdr[0..8]) != hdr[8] {
                continue;
            }
            let generation = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
            if best.is_none_or(|(_, g)| generation > g) {
                best = Some((sector, generation));
            }
        }
        Ok(best)
    }

    /// Reconstruct RAM state from flash. On first boot (no valid header) the
    /// caller-set defaults stand and the first save initialises a sector.
    fn recover(&mut self) -> Result<(), F::Error> {
        let Some((sector, generation)) = self.newest_sector()? else {
            // Blank region — defaults already in place, no active sector yet.
            // Park the cursor on the last sector with a full slot count so the
            // first append rotates into sector 0 (gen 1), and start gen at 0 so
            // that first rotation lands at gen 1.
            self.active_sector = SEQ_SECTOR_COUNT - 1;
            self.next_slot = SLOTS_PER_SECTOR; // forces a rotation on first append
            self.generation = 0;
            return Ok(());
        };

        // Replay the active sector's records, stopping at the first free /
        // torn slot. Whatever slot we stop at is where appends resume.
        let mut slot = 1;
        while slot < SLOTS_PER_SECTOR {
            let mut buf = [0u8; SLOT_SIZE];
            self.io.read(Self::slot_offset(sector, slot), &mut buf)?;
            match Record::decode(&buf) {
                Some(rec) => {
                    self.apply_recovered(rec);
                    slot += 1;
                }
                None => break,
            }
        }

        self.active_sector = sector;
        self.next_slot = slot;
        self.generation = generation;
        Ok(())
    }

    /// Fold one replayed record into RAM state. Sending and receiving values
    /// recover to the persisted value; `live == persisted` after boot (the live
    /// counter cannot have advanced past what flash recorded across a reboot).
    fn apply_recovered(&mut self, rec: Record) {
        match rec {
            Record::Sending(v) => {
                self.sending_live = v;
                self.sending_watermark = v;
            }
            Record::Tool(opt) => {
                self.tool_live = opt;
                self.tool_persisted = opt;
            }
            Record::Peer { ia, seq } => match self.peers.iter_mut().find(|p| p.ia == ia) {
                Some(p) => {
                    p.live = seq;
                    p.persisted = seq;
                }
                None => {
                    // Silently drop if the cache is full (same policy as
                    // RamSeqStorage/FramSeqStorage — ETS re-syncs).
                    let _ = self.peers.push(PeerSlot { ia, live: seq, persisted: seq });
                }
            },
        }
    }

    // ------------------------------------------------------------------------
    // Append / rotation
    // ------------------------------------------------------------------------

    /// Append one record, rotating to a fresh sector (with a compacted
    /// snapshot) if the active sector is full or none exists yet.
    fn append(&mut self, rec: Record) -> Result<(), F::Error> {
        if self.next_slot >= SLOTS_PER_SECTOR {
            self.rotate()?;
        }
        let offset = Self::slot_offset(self.active_sector, self.next_slot);
        self.io.write(offset, &rec.encode())?;
        self.next_slot += 1;
        Ok(())
    }

    /// Migrate to a fresh sector carrying a compacted snapshot of all durable
    /// state, committing the new sector's header **last**.
    ///
    /// Ordering is the crux of crash safety. We erase the target sector, write
    /// the snapshot records into slots 1.., and only then write the header
    /// (magic + generation) into slot 0. Because [`newest_sector`] treats a
    /// sector as a rotation candidate *only if its header is valid*, a crash at
    /// any point before the header write leaves the half-written sector
    /// invisible — recovery falls back to the previous (intact, lower-gen)
    /// sector, which is never erased. Once the header lands, the whole snapshot
    /// is already durable, so the commit is atomic from recovery's point of
    /// view.
    ///
    /// We snapshot the *persisted* receiving values (not the live ones) so a
    /// rotation never silently tightens the post-reboot replay window the
    /// device was configured for via `T`.
    fn rotate(&mut self) -> Result<(), F::Error> {
        let next_sector = (self.active_sector + 1) % SEQ_SECTOR_COUNT;
        let next_gen = self.generation.wrapping_add(1);
        let base = Self::sector_offset(next_sector);

        self.io.erase(base, base + SECTOR_SIZE as u32)?;

        // Stream the snapshot into slots 1.. directly — not via `append`, which
        // keys off the still-old active cursor and could re-enter `rotate`.
        // Peers are copied into a temporary first so we don't hold a borrow of
        // `self.peers` while writing through `self.io`.
        let peers: heapless::Vec<(u16, u64), PEER_SLOTS> = self.peers.iter().map(|p| (p.ia, p.persisted)).collect();

        let mut slot = 1usize;
        let write_rec = |io: &mut F, rec: Record, slot: &mut usize| -> Result<(), F::Error> {
            io.write(base + (*slot * SLOT_SIZE) as u32, &rec.encode())?;
            *slot += 1;
            Ok(())
        };
        write_rec(&mut self.io, Record::Sending(self.sending_watermark), &mut slot)?;
        if let Some(v) = self.tool_persisted {
            write_rec(&mut self.io, Record::Tool(Some(v)), &mut slot)?;
        }
        for (ia, seq) in peers {
            write_rec(&mut self.io, Record::Peer { ia, seq }, &mut slot)?;
        }

        // Header last — the commit marker.
        let mut hdr = [0xFFu8; SLOT_SIZE];
        hdr[0..4].copy_from_slice(&HEADER_MAGIC);
        hdr[4..8].copy_from_slice(&next_gen.to_be_bytes());
        hdr[8] = crc8(&hdr[0..8]);
        self.io.write(base, &hdr)?;

        self.active_sector = next_sector;
        self.generation = next_gen;
        self.next_slot = slot;
        Ok(())
    }

    // ------------------------------------------------------------------------
    // SequenceNumberStorage operations (called by the wrapper)
    // ------------------------------------------------------------------------

    fn load_sending(&self) -> u64 {
        self.sending_live
    }

    /// Advance the live sending counter to `next`. Persist a fresh watermark
    /// `next + K` only when `next` reaches the current watermark — so flash is
    /// touched at most once every `K` sends.
    fn save_sending(&mut self, next: u64) -> Result<(), F::Error> {
        self.sending_live = next;
        if next >= self.sending_watermark {
            let new_watermark = next.saturating_add(K);
            self.append(Record::Sending(new_watermark))?;
            self.sending_watermark = new_watermark;
        }
        Ok(())
    }

    fn load_tool(&self) -> Option<u64> {
        self.tool_live
    }

    /// Update the tool receiving counter. Persist only once it has advanced
    /// `≥ T` past the last durably written value (or on first set).
    fn save_tool(&mut self, val: u64) -> Result<(), F::Error> {
        self.tool_live = Some(val);
        let due = match self.tool_persisted {
            None => true,
            Some(p) => val >= p.saturating_add(T),
        };
        if due {
            self.append(Record::Tool(Some(val)))?;
            self.tool_persisted = Some(val);
        }
        Ok(())
    }

    fn load_peer(&self, ia: u16) -> Option<u64> {
        self.peers.iter().find(|p| p.ia == ia).map(|p| p.live)
    }

    /// Update a peer's receiving counter, applying the same `≥ T` lag threshold
    /// as the tool counter. A full cache silently drops new peers.
    fn save_peer(&mut self, ia: u16, val: u64) -> Result<(), F::Error> {
        match self.peers.iter_mut().find(|p| p.ia == ia) {
            Some(p) => {
                p.live = val;
                if val >= p.persisted.saturating_add(T) {
                    let persisted = val;
                    // Drop the &mut borrow before appending (append mutates self).
                    self.append(Record::Peer { ia, seq: val })?;
                    if let Some(p) = self.peers.iter_mut().find(|p| p.ia == ia) {
                        p.persisted = persisted;
                    }
                }
            }
            None => {
                if self.peers.push(PeerSlot { ia, live: val, persisted: val }).is_ok() {
                    self.append(Record::Peer { ia, seq: val })?;
                }
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------------
    // Boot-scan summary (for defmt logging in the production wrapper)
    // ------------------------------------------------------------------------

    /// `(active_sector, generation, sending_watermark, peer_count, next_slot)`
    /// as recovered at boot — handy for on-device defmt diagnostics.
    fn boot_summary(&self) -> (usize, u32, u64, usize, usize) {
        (self.active_sector, self.generation, self.sending_watermark, self.peers.len(), self.next_slot)
    }
}

// ============================================================================
// FlashSeqStorage — production wrapper over the real embassy_rp flash handle
// ============================================================================

/// Adapter binding [`SeqLog`] to the shared `embassy_rp` flash handle.
struct RpFlashIo {
    flash: &'static RefCell<Flash<'static, FLASH, flash::Blocking, FLASH_SIZE>>,
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

/// Wear-levelled internal-flash sequence-number store. See the module docs.
///
/// The trait's `load_*` methods take `&self` but our log mutates RAM/flash
/// state on access, so the `SeqLog` lives behind a `RefCell` (sound under
/// embassy's single-threaded executor — see [`crate::storage::RpFlashStorage`]
/// for the same reasoning).
pub struct FlashSeqStorage<const PEER_SLOTS: usize = 8, const K: u64 = 256, const T: u64 = 16> {
    log: RefCell<SeqLog<RpFlashIo, PEER_SLOTS, K, T>>,
}

impl<const PEER_SLOTS: usize, const K: u64, const T: u64> FlashSeqStorage<PEER_SLOTS, K, T> {
    /// Open (or initialise) the flash-backed store over the shared flash handle.
    ///
    /// Performs the boot scan eagerly. Read failures during the scan surface as
    /// an `Err`; the caller (firmware `main`) treats a failed open as fatal.
    pub fn new(
        flash: &'static RefCell<Flash<'static, FLASH, flash::Blocking, FLASH_SIZE>>,
    ) -> Result<Self, embassy_rp::flash::Error> {
        let log = SeqLog::new(RpFlashIo { flash })?;
        let (sector, generation, watermark, peers, slot) = log.boot_summary();
        defmt::info!(
            "FlashSeqStorage: recovered sector {} gen {} sending-watermark {} peers {} next-slot {}",
            sector,
            generation,
            watermark,
            peers,
            slot,
        );
        Ok(Self { log: RefCell::new(log) })
    }
}

impl<const PEER_SLOTS: usize, const K: u64, const T: u64> SequenceNumberStorage for FlashSeqStorage<PEER_SLOTS, K, T> {
    type Error = embassy_rp::flash::Error;

    fn load_sending_seq(&self) -> Result<[u8; 6], Self::Error> {
        Ok(u64_to_seq6(self.log.borrow().load_sending()))
    }

    fn save_sending_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error> {
        self.log.borrow_mut().save_sending(seq6_to_u64(seq))
    }

    fn load_receiving_seq(&self, peer_ia: u16) -> Result<Option<[u8; 6]>, Self::Error> {
        Ok(self.log.borrow().load_peer(peer_ia).map(u64_to_seq6))
    }

    fn save_receiving_seq(&mut self, peer_ia: u16, seq: &[u8; 6]) -> Result<(), Self::Error> {
        self.log.borrow_mut().save_peer(peer_ia, seq6_to_u64(seq))
    }

    fn load_tool_receiving_seq(&self) -> Result<Option<[u8; 6]>, Self::Error> {
        Ok(self.log.borrow().load_tool().map(u64_to_seq6))
    }

    fn save_tool_receiving_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error> {
        self.log.borrow_mut().save_tool(seq6_to_u64(seq))
    }
}

// ============================================================================
// Host tests
// ============================================================================
//
// These exercise the wear-levelled log logic against an in-memory flash that
// faithfully models the two properties of real NOR flash that the design
// depends on: an erased cell is `0xFF`, and a write can only clear bits
// (`new &= data`), never set them. Bugs that rely on rewriting an already-
// written slot would corrupt under these rules, just as on hardware.

#[cfg(test)]
// The mock `FlashIo::Error` is `()`, so `save_*` calls in these tests return
// `Result<(), ()>` we deliberately don't check — silence the must_use lint.
#[allow(unused_must_use)]
mod tests {
    // The test harness links `std`, so we can use the `Vec` from there even
    // though the crate itself is `#![no_std]`.
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    use super::*;
    use crate::storage::SEQ_REGION_SIZE;

    /// In-memory flash covering exactly the sequence-number region. Offsets
    /// passed in are absolute (from flash start); we translate to a local index.
    struct MockFlash {
        bytes: Vec<u8>,
        /// Optional cap on the number of byte-writes before every further write
        /// is dropped — models a power loss mid-operation for crash tests.
        writes_budget: Option<usize>,
    }

    impl MockFlash {
        fn new() -> Self {
            Self { bytes: vec![0xFFu8; SEQ_REGION_SIZE], writes_budget: None }
        }

        fn idx(offset: u32) -> usize {
            (offset - SEQ_REGION_OFFSET) as usize
        }
    }

    impl FlashIo for MockFlash {
        type Error = ();

        fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), ()> {
            let start = Self::idx(offset);
            buf.copy_from_slice(&self.bytes[start..start + buf.len()]);
            Ok(())
        }

        fn erase(&mut self, start: u32, end: u32) -> Result<(), ()> {
            assert_eq!((start as usize) % SECTOR_SIZE, 0, "erase start not sector-aligned");
            assert_eq!((end as usize) % SECTOR_SIZE, 0, "erase end not sector-aligned");
            let (s, e) = (Self::idx(start), Self::idx(end));
            for b in &mut self.bytes[s..e] {
                *b = 0xFF;
            }
            Ok(())
        }

        fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), ()> {
            let start = Self::idx(offset);
            for (i, &d) in data.iter().enumerate() {
                if let Some(budget) = self.writes_budget.as_mut() {
                    if *budget == 0 {
                        // Power lost: stop writing further bytes.
                        return Ok(());
                    }
                    *budget -= 1;
                }
                // NOR flash: writes can only clear bits.
                self.bytes[start + i] &= d;
            }
            Ok(())
        }
    }

    /// Convenience: a default-tuned log (K=256, T=16, 8 peer slots).
    type TestLog = SeqLog<MockFlash, 8, 256, 16>;

    impl<const PEER_SLOTS: usize, const K: u64, const T: u64> SeqLog<MockFlash, PEER_SLOTS, K, T> {
        /// Consume the log and return the underlying flash bytes (for reboot
        /// simulation in tests).
        fn into_bytes(self) -> Vec<u8> {
            self.io.bytes
        }
    }

    /// Re-open a log over an existing buffer (a clean reboot — no write budget).
    fn reboot<const P: usize, const K: u64, const T: u64>(bytes: Vec<u8>) -> SeqLog<MockFlash, P, K, T> {
        SeqLog::new(MockFlash { bytes, writes_budget: None }).expect("recover")
    }

    // -- CRC sanity -----------------------------------------------------------

    #[test]
    fn crc8_detects_single_bit_flip() {
        let a = crc8(&[0x01, 0x02, 0x03, 0x04]);
        let b = crc8(&[0x01, 0x02, 0x03, 0x05]);
        assert_ne!(a, b);
    }

    #[test]
    fn seq6_roundtrip() {
        for v in [0u64, 1, 255, 256, 0xFFFF, 0x01_0000, 0xFFFF_FFFF_FFFF] {
            assert_eq!(seq6_to_u64(&u64_to_seq6(v)), v);
        }
    }

    // -- fresh boot defaults --------------------------------------------------

    #[test]
    fn fresh_boot_defaults() {
        let log = TestLog::new(MockFlash::new()).unwrap();
        assert_eq!(log.load_sending(), DEFAULT_SEND);
        assert_eq!(log.load_tool(), None);
        assert_eq!(log.load_peer(0x1101), None);
    }

    // -- sending watermark ----------------------------------------------------

    #[test]
    fn sending_watermark_batches_writes() {
        // K = 4 so the crossing is easy to observe.
        let mut log = SeqLog::<MockFlash, 8, 4, 16>::new(MockFlash::new()).unwrap();

        // Mirror reserve_next_seq_nr: use value v, then persist v+1.
        for v in 1u64..=10 {
            log.save_sending(v + 1);
            assert_eq!(log.load_sending(), v + 1);
        }
        // Reboot: the restored live counter must be >= the highest value we
        // ever *used* (10) — actually it equals the last persisted watermark,
        // which is strictly ahead.
        let log2: SeqLog<MockFlash, 8, 4, 16> = reboot(log.into_bytes());
        assert!(log2.load_sending() >= 11, "restored {} must exceed last used", log2.load_sending());
    }

    #[test]
    fn sending_never_regresses_across_reboot() {
        let mut log = TestLog::new(MockFlash::new()).unwrap();
        // Send a batch; highest used value is 1000.
        for v in 1u64..=1000 {
            log.save_sending(v + 1);
        }
        let used_max = 1000;
        let log2: TestLog = reboot(log.into_bytes());
        assert!(log2.load_sending() > used_max);
    }

    // -- tool / peer recv lag threshold --------------------------------------

    #[test]
    fn recv_threshold_lags_persistence() {
        // T = 10.
        let mut log = SeqLog::<MockFlash, 8, 256, 10>::new(MockFlash::new()).unwrap();

        // Advance the tool counter one-by-one; live tracks exactly.
        for v in 1u64..=25 {
            log.save_tool(v);
            assert_eq!(log.load_tool(), Some(v));
        }
        // Reboot: persisted value lags by < T behind the last accepted (25).
        let log2: SeqLog<MockFlash, 8, 256, 10> = reboot(log.into_bytes());
        let restored = log2.load_tool().unwrap();
        assert!(restored <= 25, "cannot restore ahead of reality");
        assert!(25 - restored < 10, "restored {} lags more than T", restored);
    }

    #[test]
    fn recv_write_through_when_t_is_one() {
        let mut log = SeqLog::<MockFlash, 8, 256, 1>::new(MockFlash::new()).unwrap();
        for v in 1u64..=20 {
            log.save_peer(0x1101, v);
        }
        let log2: SeqLog<MockFlash, 8, 256, 1> = reboot(log.into_bytes());
        // T = 1: write-through, so the restored value is exactly the last.
        assert_eq!(log2.load_peer(0x1101), Some(20));
    }

    #[test]
    fn multiple_peers_recovered() {
        let mut log = SeqLog::<MockFlash, 8, 256, 1>::new(MockFlash::new()).unwrap();
        log.save_peer(0x1101, 100);
        log.save_peer(0x1102, 200);
        log.save_peer(0x1101, 150);
        let log2: SeqLog<MockFlash, 8, 256, 1> = reboot(log.into_bytes());
        assert_eq!(log2.load_peer(0x1101), Some(150));
        assert_eq!(log2.load_peer(0x1102), Some(200));
    }

    // -- sector rotation / compaction ----------------------------------------

    #[test]
    fn rotation_compacts_and_recovers() {
        // K=1 (write every send), T=1 (write-through) to fill a sector fast.
        let mut log = SeqLog::<MockFlash, 8, 1, 1>::new(MockFlash::new()).unwrap();
        log.save_peer(0x1101, 42);
        log.save_tool(7);

        // Each save_sending writes one record (K=1). Push well past one
        // sector's worth of slots to force at least one rotation.
        let pushes = (SLOTS_PER_SECTOR as u64) + 50;
        for v in 1..=pushes {
            log.save_sending(v + 1);
        }
        assert!(log.generation >= 1, "expected at least one rotation");

        let log2: SeqLog<MockFlash, 8, 1, 1> = reboot(log.into_bytes());
        // Compaction must have carried the peer and tool state into the new
        // sector.
        assert_eq!(log2.load_peer(0x1101), Some(42));
        assert_eq!(log2.load_tool(), Some(7));
        assert!(log2.load_sending() > pushes);
    }

    // -- crash safety ---------------------------------------------------------

    #[test]
    fn torn_record_stops_replay_at_last_valid() {
        // The first save on a blank log rotates into sector 0, writing the
        // header (slot 0) and a compaction snapshot. To get records at known
        // slots, locate the last written slot in sector 0 and trash it.
        let mut log = SeqLog::<MockFlash, 8, 1, 1>::new(MockFlash::new()).unwrap();
        log.save_peer(0x1101, 5);
        log.save_peer(0x1101, 6); // last record written; this is the torn one
        let last_slot = log.next_slot - 1;
        let mut bytes = log.into_bytes();

        // Flip a byte in the last record's slot so its CRC fails.
        let off = (last_slot * SLOT_SIZE) + 5; // a payload byte, not the tag
        bytes[off] ^= 0xFF;

        let log2: SeqLog<MockFlash, 8, 1, 1> = reboot(bytes);
        // Replay stopped at the torn slot, so the prior valid value (5) stands.
        assert_eq!(log2.load_peer(0x1101), Some(5));
    }

    #[test]
    fn crash_during_rotation_falls_back_to_old_sector() {
        // Build a log with one rotation already done, then provoke a second
        // rotation that is cut short by a tiny write budget.
        let mut log = SeqLog::<MockFlash, 8, 1, 1>::new(MockFlash::new()).unwrap();
        log.save_peer(0x1101, 99); // committed into sector 0 (gen 1)

        // Fill sector 0's remaining slots so the next send rotates.
        while log.next_slot < SLOTS_PER_SECTOR {
            let v = log.load_sending();
            log.save_sending(v + 1);
        }

        // Arm the crash: only 3 byte-writes succeed, then power is lost. The
        // next send triggers a rotation (erase sector 1, then write header +
        // snapshot) that cannot complete — sector 1 stays header-less/garbage.
        log.io.writes_budget = Some(3);
        let v = log.load_sending();
        let _ = log.save_sending(v + 1);
        let crashed = log.into_bytes();

        // Clean reboot: the half-written sector 1 must be rejected (no valid
        // header) and sector 0 (gen 1, holding peer 99) wins.
        let log2: SeqLog<MockFlash, 8, 1, 1> = reboot(crashed);
        assert_eq!(log2.load_peer(0x1101), Some(99));
    }
}
