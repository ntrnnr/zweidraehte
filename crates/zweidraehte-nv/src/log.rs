//! A crash-safe append log over erase-block flash.
//!
//! Flash cannot be rewritten in place: a byte can only have bits cleared
//! until its whole sector is erased, and erasing is slow (tens of
//! milliseconds) and wears the cell. The log therefore never rewrites. Each
//! change is appended as a small record behind the previous one, the full
//! state is the replay of all records in order, and only when a bank is full
//! does the owner's live state get rewritten ("compacted") into the next bank.
//!
//! The log is deliberately ignorant of what a payload means. The
//! [`WearLeveledKv`](crate::WearLeveledKv) view stores `(namespace, key,
//! value)` payloads in it; the device configuration view stores
//! `(section, offset, bytes)` payloads.
//!
//! # Layout
//!
//! The region is split into `banks` banks of `sectors_per_bank` contiguous
//! sectors. A bank is erased as a unit and exactly one bank is live. Rotation
//! walks the banks round-robin, so erase cycles spread evenly across the
//! region.
//!
//! ```text
//! Bank header (bank offset 0, padded to WRITE_ALIGN):
//!     [magic:4 BE][generation:4 BE][crc16:2 BE]         — programmed LAST
//! Record (padded to WRITE_ALIGN with 0xFF):
//!     [len:1][!len:1][payload:len][crc16 over len..payload:2 BE]
//! Free space: 0xFF
//! ```
//!
//! # Crash safety
//!
//! Power may fail at any point during a program operation. The format is
//! built so that every possible interrupted state replays to either the state
//! before or the state after the interrupted operation:
//!
//! - **Interrupted compaction.** The new bank's header is programmed after
//!   its snapshot records. A cut before the header leaves the new bank
//!   without a valid header, so the previous bank — untouched until the next
//!   rotation — still has the highest valid generation and wins.
//! - **Interrupted record, torn payload.** The length octet is stored
//!   together with its complement. NOR programming only clears bits, so a
//!   partially programmed pair still has a bit that is 1 in both octets and
//!   can never pass as a complement pair. A *valid* pair is therefore
//!   trustworthy even when the payload CRC fails, and replay skips exactly
//!   that record and continues. Appends after the reboot land behind the torn
//!   record, never on top of it (re-programming could not repair it). This
//!   keeps records written after an earlier crash visible, which matters for
//!   security sequence counters: dropping them would roll a counter back.
//! - **Interrupted record, torn length.** A non-blank, invalid length pair
//!   gives no record extent to skip. Replay stops there and the log demands
//!   compaction before the next append, so no record is ever placed behind
//!   an unparseable one.
//!
//! The record being written at the cut is lost; its append never returned.

use crate::SectorIo;
use crate::crc::crc16;

/// Octets framing every payload: the length pair before it and the CRC after.
const FRAMING: usize = 4;

/// The longest payload the one-octet length can describe.
const LENGTH_LIMIT: usize = u8::MAX as usize;

/// Bank header content before padding: magic, generation, CRC.
const HEADER_CONTENT: usize = 10;

/// The largest write granule supported; sizes the header staging buffer.
const MAX_WRITE_ALIGN: usize = 16;

/// Where the log lives and how it is divided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogGeometry {
    /// Absolute flash offset of the first bank.
    pub offset: u32,
    /// The medium's erase granule in bytes.
    pub sector_size: u32,
    /// Sectors per bank. One for small views such as the KV store; more when
    /// a compacted snapshot needs more than one sector.
    pub sectors_per_bank: u32,
    /// Number of banks; rotation needs at least two.
    pub banks: u32,
}

impl LogGeometry {
    /// Bytes per bank.
    pub const fn bank_size(&self) -> u32 {
        self.sector_size * self.sectors_per_bank
    }
}

/// An append log over `geometry`, whose longest padded record is `REC`
/// octets.
///
/// `REC` sizes the one stack buffer a record is staged in. It is a const
/// generic so a view with tiny records (the KV store, 16 octets) does not pay
/// the stack of a view with long ones (configuration, a few hundred). A
/// record is staged whole so it reaches the medium in one `write` call: on
/// RP2040 every program call holds interrupts off, so fewer calls mean fewer
/// windows in which the UART can overrun.
pub struct AppendLog<F: SectorIo, const REC: usize> {
    io: F,
    geometry: LogGeometry,
    magic: u32,
    /// The live bank. On a blank region this is the last bank, so the first
    /// compaction lands in bank 0.
    active: u32,
    /// Offset of the next append within the active bank.
    cursor: u32,
    /// Generation of the active bank's header.
    generation: u32,
    /// The next append must compact first: the region is blank, replay hit a
    /// torn length, a compaction failed midway, or a record write failed and
    /// left the bytes at `cursor` in an unknown state.
    compaction_pending: bool,
}

impl<F: SectorIo, const REC: usize> AppendLog<F, REC> {
    /// Checks of the medium/record combination, forced by [`open`](Self::open).
    const CHECKS: () = {
        assert!(
            F::WRITE_ALIGN.is_power_of_two() && F::WRITE_ALIGN <= MAX_WRITE_ALIGN,
            "AppendLog: the medium's WRITE_ALIGN must be a power of two of at most 16"
        );
        assert!(REC.is_multiple_of(F::WRITE_ALIGN), "AppendLog: REC must be whole write granules of the medium");
        assert!(REC >= FRAMING, "AppendLog: REC must at least hold the record framing");
        assert!(
            REC <= (FRAMING + LENGTH_LIMIT).next_multiple_of(F::WRITE_ALIGN),
            "AppendLog: REC exceeds the longest record a one-octet length can describe"
        );
    };

    /// The padded length of the bank header on this medium.
    const HEADER_LEN: u32 = HEADER_CONTENT.next_multiple_of(F::WRITE_ALIGN) as u32;

    /// The longest payload one record can carry.
    pub const MAX_PAYLOAD: usize = if REC - FRAMING < LENGTH_LIMIT { REC - FRAMING } else { LENGTH_LIMIT };

    /// The padded on-flash length of a record carrying `payload_len` octets.
    pub const fn record_len(payload_len: usize) -> u32 {
        (FRAMING + payload_len).next_multiple_of(F::WRITE_ALIGN) as u32
    }

    /// The padded length of the bank header; the smallest `fill()` a bank
    /// reports.
    pub const fn header_len() -> u32 {
        Self::HEADER_LEN
    }

    /// Open the log tagged `magic` over `geometry`: find the live bank and
    /// hand every intact payload to `replay`, in write order, with the
    /// record's offset in the active bank (see [`read_payload`](Self::read_payload)).
    /// A blank region, or one written under another magic, replays nothing.
    ///
    /// # Panics
    ///
    /// On a geometry that cannot work at all: fewer than two banks (no room
    /// to rotate), or a bank too small for its header plus one full-size
    /// record. Both are static sizing mistakes of the caller.
    pub fn open(
        io: F,
        geometry: LogGeometry,
        magic: u32,
        mut replay: impl FnMut(u32, &[u8]),
    ) -> Result<Self, F::Error> {
        #[allow(clippy::let_unit_value)]
        let () = Self::CHECKS;

        assert!(geometry.banks >= 2, "AppendLog: rotation needs at least two banks");
        assert!(
            geometry.sectors_per_bank >= 1 && Self::HEADER_LEN + REC as u32 <= geometry.bank_size(),
            "AppendLog: a bank must hold its header and one full-size record"
        );

        let mut log = Self {
            io,
            geometry,
            magic,
            active: geometry.banks - 1,
            cursor: Self::HEADER_LEN,
            generation: 0,
            compaction_pending: true,
        };

        if let Some((bank, generation)) = log.newest_bank()? {
            log.active = bank;
            log.generation = generation;
            log.compaction_pending = false;
            log.replay(&mut replay)?;
        }
        Ok(log)
    }

    // ------------------------------------------------------------------------
    // Recovery
    // ------------------------------------------------------------------------

    fn bank_offset(&self, bank: u32) -> u32 {
        self.geometry.offset + bank * self.geometry.bank_size()
    }

    /// Among banks with a valid header under our magic, the one with the
    /// highest generation. After an interrupted compaction that is still the
    /// previous bank, because the new one never got its header.
    fn newest_bank(&mut self) -> Result<Option<(u32, u32)>, F::Error> {
        let mut newest: Option<(u32, u32)> = None;
        for bank in 0..self.geometry.banks {
            let mut header = [0u8; HEADER_CONTENT];
            self.io.read(self.bank_offset(bank), &mut header)?;

            let magic = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
            let stored_crc = u16::from_be_bytes([header[8], header[9]]);
            if magic != self.magic || crc16(&header[..8]) != stored_crc {
                continue;
            }

            let generation = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
            if newest.is_none_or(|(_, newest_generation)| generation > newest_generation) {
                newest = Some((bank, generation));
            }
        }
        Ok(newest)
    }

    /// Walk the active bank's records, hand intact payloads to `replay`, and
    /// leave the cursor behind the last record (torn ones included).
    fn replay(&mut self, replay: &mut impl FnMut(u32, &[u8])) -> Result<(), F::Error> {
        let base = self.bank_offset(self.active);
        let bank_size = self.geometry.bank_size();
        let mut buf = [0u8; REC];
        let mut pos = Self::HEADER_LEN;

        while pos + FRAMING as u32 <= bank_size {
            // The length pair decides everything else: free space, a torn
            // header, or a record with a known extent.
            self.io.read(base + pos, &mut buf[..2])?;
            let (len, check) = (buf[0], buf[1]);
            if len == 0xFF && check == 0xFF {
                break;
            }
            if check != !len {
                self.compaction_pending = true;
                break;
            }

            // A record this log could not have written (longer than REC or
            // past the bank end) means corruption, not a tear. Treat it like
            // a torn length: stop and compact before appending.
            let len = usize::from(len);
            let record_len = Self::record_len(len);
            if record_len as usize > REC || pos + record_len > bank_size {
                self.compaction_pending = true;
                break;
            }

            self.io.read(base + pos, &mut buf[..record_len as usize])?;
            let payload_end = 2 + len;
            let stored_crc = u16::from_be_bytes([buf[payload_end], buf[payload_end + 1]]);
            if crc16(&buf[..payload_end]) == stored_crc {
                replay(pos, &buf[2..payload_end]);
            }
            // A failed CRC under a valid length pair is a torn or rotten
            // payload: skip exactly this record (see module docs).
            pos += record_len;
        }

        self.cursor = pos;
        Ok(())
    }

    // ------------------------------------------------------------------------
    // Append and compaction
    // ------------------------------------------------------------------------

    /// Durably append one record whose payload is the concatenation of
    /// `parts`.
    ///
    /// If the record does not fit the active bank, or compaction is pending,
    /// this compacts first: `snapshot` is called to re-emit the owner's live
    /// state *as it was before this record*, then the record follows it.
    ///
    /// # Panics
    ///
    /// If the payload exceeds [`MAX_PAYLOAD`](Self::MAX_PAYLOAD), or if the
    /// record does not fit even a freshly compacted bank. Both are sizing
    /// mistakes of the view, which should assert its worst case at open.
    ///
    /// Returns the record's offset in the active bank, for
    /// [`read_payload`](Self::read_payload).
    pub fn append(
        &mut self,
        parts: &[&[u8]],
        snapshot: impl FnOnce(&mut Compactor<'_, F, REC>) -> Result<(), F::Error>,
    ) -> Result<u32, F::Error> {
        let payload_len = parts.iter().map(|part| part.len()).sum();
        assert!(payload_len <= Self::MAX_PAYLOAD, "AppendLog: payload exceeds the log's record size");
        let record_len = Self::record_len(payload_len);

        let bank_size = self.geometry.bank_size();
        if self.compaction_pending || self.cursor + record_len > bank_size {
            self.compact(snapshot)?;
        }
        assert!(self.cursor + record_len <= bank_size, "AppendLog: record does not fit a freshly compacted bank");

        let offset = self.cursor;
        let at = self.bank_offset(self.active) + offset;
        if let Err(error) = write_record::<F, REC>(&mut self.io, at, parts, payload_len) {
            // The bytes at the cursor may be partly programmed now, and
            // programming them again could not produce a valid record.
            self.compaction_pending = true;
            return Err(error);
        }
        self.cursor += record_len;
        Ok(offset)
    }

    /// Copy the payload of the record at `offset` in the active bank into
    /// `buf` and return its length, or `None` if no intact record starts
    /// there. The offset comes from [`open`](Self::open)'s replay,
    /// [`append`](Self::append) or [`Compactor::push`], and stays valid until
    /// the next compaction.
    pub fn read_payload(&mut self, offset: u32, buf: &mut [u8]) -> Result<Option<usize>, F::Error> {
        let base = self.bank_offset(self.active);
        let mut record = [0u8; REC];
        if offset + FRAMING as u32 > self.cursor {
            return Ok(None);
        }
        self.io.read(base + offset, &mut record[..2])?;
        let (len, check) = (record[0], record[1]);
        let len = usize::from(len);
        let record_len = Self::record_len(len);
        if check != !(len as u8) || record_len as usize > REC || offset + record_len > self.cursor || len > buf.len() {
            return Ok(None);
        }

        self.io.read(base + offset, &mut record[..record_len as usize])?;
        let payload_end = 2 + len;
        let stored_crc = u16::from_be_bytes([record[payload_end], record[payload_end + 1]]);
        if crc16(&record[..payload_end]) != stored_crc {
            return Ok(None);
        }
        buf[..len].copy_from_slice(&record[2..payload_end]);
        Ok(Some(len))
    }

    /// Rewrite the owner's live state into the next bank now and make that
    /// bank live. `snapshot` emits the state through [`Compactor::push`].
    ///
    /// Callers use this to compact at a moment of their choosing (at boot, or
    /// while the bus is held busy) instead of inside an append.
    pub fn compact(
        &mut self,
        snapshot: impl FnOnce(&mut Compactor<'_, F, REC>) -> Result<(), F::Error>,
    ) -> Result<(), F::Error> {
        let next = (self.active + 1) % self.geometry.banks;
        let base = self.bank_offset(next);
        let bank_size = self.geometry.bank_size();

        // Until the new header is programmed, a retry must erase again.
        self.compaction_pending = true;
        self.io.erase(base, base + bank_size)?;

        let mut compactor = Compactor { io: &mut self.io, base, cursor: Self::HEADER_LEN, end: bank_size };
        snapshot(&mut compactor)?;
        let cursor = compactor.cursor;

        // The header goes last: it is the commit marker of the whole bank.
        let generation = self.generation.wrapping_add(1);
        let mut header = [0xFFu8; MAX_WRITE_ALIGN];
        header[0..4].copy_from_slice(&self.magic.to_be_bytes());
        header[4..8].copy_from_slice(&generation.to_be_bytes());
        let crc = crc16(&header[..8]);
        header[8..10].copy_from_slice(&crc.to_be_bytes());
        self.io.write(base, &header[..Self::HEADER_LEN as usize])?;

        self.active = next;
        self.generation = generation;
        self.cursor = cursor;
        self.compaction_pending = false;
        Ok(())
    }

    /// `(used, capacity)` of the active bank in bytes, header included. The
    /// input for a view's "compact early" threshold.
    pub fn fill(&self) -> (u32, u32) {
        (self.cursor, self.geometry.bank_size())
    }

    /// Whether the next append will compact first regardless of fill.
    pub fn compaction_pending(&self) -> bool {
        self.compaction_pending
    }
}

/// The write side of a compaction, handed to the owner's snapshot closure.
pub struct Compactor<'a, F: SectorIo, const REC: usize> {
    io: &'a mut F,
    base: u32,
    cursor: u32,
    end: u32,
}

impl<F: SectorIo, const REC: usize> Compactor<'_, F, REC> {
    /// Write one snapshot record, the concatenation of `parts`.
    ///
    /// # Panics
    ///
    /// If the snapshot outgrows the bank — a sizing mistake of the view.
    ///
    /// Returns the record's offset in the compacting bank, which becomes the
    /// active bank once the compaction commits.
    pub fn push(&mut self, parts: &[&[u8]]) -> Result<u32, F::Error> {
        let payload_len = parts.iter().map(|part| part.len()).sum();
        assert!(payload_len <= AppendLog::<F, REC>::MAX_PAYLOAD, "AppendLog: payload exceeds the log's record size");
        let record_len = AppendLog::<F, REC>::record_len(payload_len);
        assert!(self.cursor + record_len <= self.end, "AppendLog: compaction snapshot overflows the bank");

        let offset = self.cursor;
        write_record::<F, REC>(self.io, self.base + offset, parts, payload_len)?;
        self.cursor += record_len;
        Ok(offset)
    }
}

/// Frame `parts` as one record and program it with a single `write`.
fn write_record<F: SectorIo, const REC: usize>(
    io: &mut F,
    at: u32,
    parts: &[&[u8]],
    payload_len: usize,
) -> Result<(), F::Error> {
    let mut buf = [0xFFu8; REC];
    buf[0] = payload_len as u8;
    buf[1] = !(payload_len as u8);

    let mut end = 2;
    for part in parts {
        buf[end..end + part.len()].copy_from_slice(part);
        end += part.len();
    }
    let crc = crc16(&buf[..end]);
    buf[end..end + 2].copy_from_slice(&crc.to_be_bytes());

    // Padding stays 0xFF, the erased value, so it programs nothing.
    let record_len = AppendLog::<F, REC>::record_len(payload_len) as usize;
    io.write(at, &buf[..record_len])
}
