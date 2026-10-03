//! [`NvStore`] on erase-block flash, as records in the [`AppendLog`].
//!
//! Flash cannot rewrite a section in place, so every change is appended as
//! a record `[section][offset, BE × 2][bytes]`, and boot replays the records
//! into the state in write order. When a bank fills, the log compacts: the
//! whole current state is written into the next bank as one snapshot, and
//! older records are dropped with the bank they lived in.
//!
//! # Guarantees
//!
//! - A Record section always travels in a single log record, so it is
//!   atomic: after a power cut it holds its old or its new content.
//! - An Image range longer than one log record is split into records of
//!   consecutive chunks. After a cut the image holds its old content with a
//!   prefix of those chunks applied. A record carries up to
//!   `MAX_PAYLOAD - 3` section bytes (249 at `REC = 256`), so a single
//!   A_Memory_Write (at most 63 bytes) always fits one record and is atomic
//!   too.
//!
//! # Layout changes
//!
//! The log's magic is the state's layout fingerprint mixed with `"KNXC"`.
//! A firmware whose section layout differs therefore sees the previous log
//! as foreign and boots factory-fresh, without any migration code.

use crate::SectorIo;
use crate::log::{AppendLog, Compactor, LogGeometry};
use crate::nv_store::{Loaded, NvError, NvStore, find_section};
use crate::sections::{PersistentSections, Section, SectionId, SectionKind};

/// Mixed into the layout fingerprint to form the log magic.
const MAGIC_SALT: u32 = u32::from_be_bytes(*b"KNXC");

/// `[section][offset, BE × 2]` ahead of the bytes in every record.
const RECORD_HEADER: usize = 3;

/// A configuration store in a flash region described by `geometry`, whose
/// log records are at most `REC` bytes (see [`AppendLog`]).
pub struct FlashLog<F: SectorIo, const REC: usize> {
    /// The medium until [`load`](NvStore::load) opens the log over it.
    io: Option<F>,
    log: Option<AppendLog<F, REC>>,
    geometry: LogGeometry,

    /// Bytes occupied by a compacted snapshot, including the bank header.
    /// Assumes the section layout stays unchanged after the store is loaded.
    snapshot_bytes: u32,

    /// Where each Record section's latest copy sits in the active bank, so
    /// [`record_matches`](NvStore::record_matches) can read it back instead
    /// of keeping a RAM copy. Rebuilt by every compaction.
    index: RecordIndex,
}

/// Active-bank offsets of the latest copy of each Record section.
type RecordIndex = heapless::Vec<(SectionId, u32), MAX_RECORDS>;

/// The most Record sections a layout may have: the index is fixed-size.
const MAX_RECORDS: usize = 32;

/// Point `id` at `offset` in `index`.
fn index_set(index: &mut RecordIndex, id: SectionId, offset: u32) {
    match index.iter_mut().find(|(entry, _)| *entry == id) {
        Some(entry) => entry.1 = offset,
        None => {
            // Capacity is checked against the layout at load.
            let _ = index.push((id, offset));
        }
    }
}

impl<F: SectorIo, const REC: usize> FlashLog<F, REC> {
    /// The most section bytes one record carries.
    const CHUNK: usize = AppendLog::<F, REC>::MAX_PAYLOAD - RECORD_HEADER;

    /// A store over `geometry` on `io`, opened by [`load`](NvStore::load).
    pub fn new(io: F, geometry: LogGeometry) -> Self {
        Self { io: Some(io), log: None, geometry, snapshot_bytes: 0, index: heapless::Vec::new() }
    }

    /// The log magic for a layout. Blank flash reads as all-ones and the
    /// log rejects all-zero, so the two values that could collide with them
    /// are nudged.
    fn magic(fingerprint: u32) -> u32 {
        match fingerprint ^ MAGIC_SALT {
            0 => 1,
            u32::MAX => u32::MAX - 1,
            magic => magic,
        }
    }

    /// Bytes a full snapshot of one section takes in the log.
    fn snapshot_len(section: &Section) -> u32 {
        let len = usize::from(section.len);
        let (full, rest) = (len / Self::CHUNK, len % Self::CHUNK);
        let mut total = full as u32 * AppendLog::<F, REC>::record_len(RECORD_HEADER + Self::CHUNK);
        if rest > 0 {
            total += AppendLog::<F, REC>::record_len(RECORD_HEADER + rest);
        }

        total
    }

    /// Every Record must fit one log record (its atomicity depends on it),
    /// and a snapshot plus the append that triggered it must fit a bank.
    /// Return the snapshot size so maintenance measures reclaimable history.
    fn check_layout<S: PersistentSections>(&self, state: &S) -> Result<u32, NvError<F::Error>> {
        let mut snapshot = AppendLog::<F, REC>::header_len();
        let mut records_fit = true;
        let mut records = 0;

        state.for_each_section(&mut |section| {
            snapshot += Self::snapshot_len(&section);

            if section.kind == SectionKind::Record {
                records += 1;
                records_fit &= usize::from(section.len) <= Self::CHUNK;
            }
        });

        if !records_fit || records > MAX_RECORDS || snapshot + REC as u32 > self.geometry.bank_size() {
            return Err(NvError::LayoutTooLarge);
        }

        Ok(snapshot)
    }

    /// Write every section of `state` into a compacting bank, recording
    /// where each Record lands in `index`.
    fn snapshot<S: PersistentSections>(
        state: &S,
        compactor: &mut Compactor<'_, F, REC>,
        index: &mut RecordIndex,
    ) -> Result<(), F::Error> {
        index.clear();
        let mut result = Ok(());
        let mut buf = [0u8; REC];

        state.for_each_section(&mut |section| {
            let mut offset = 0usize;

            while result.is_ok() && offset < usize::from(section.len) {
                let n = (usize::from(section.len) - offset).min(Self::CHUNK);
                let chunk = &mut buf[..n];
                state.read_section(section.id, offset as u16, chunk);

                match compactor.push(&[&[section.id], &(offset as u16).to_be_bytes(), chunk]) {
                    Ok(at) if section.kind == SectionKind::Record => index_set(index, section.id, at),
                    Ok(_) => {}
                    Err(error) => result = Err(error),
                }

                offset += n;
            }
        });

        result
    }

    /// Append one record carrying `len` bytes of section `id` from `offset`.
    /// Returns where it landed. If the append compacted first, `index` is
    /// replaced by the one the snapshot built.
    fn append<S: PersistentSections>(
        log: &mut AppendLog<F, REC>,
        index: &mut RecordIndex,
        state: &S,
        id: SectionId,
        offset: u16,
        len: usize,
    ) -> Result<u32, NvError<F::Error>> {
        let mut buf = [0u8; REC];
        let chunk = &mut buf[..len];
        state.read_section(id, offset, chunk);

        // A compaction inside the append builds its index aside; the old one
        // stays valid until the new bank has committed.
        let mut rebuilt: Option<RecordIndex> = None;
        let at = log
            .append(&[&[id], &offset.to_be_bytes(), chunk], |compactor| {
                let fresh = rebuilt.insert(heapless::Vec::new());
                Self::snapshot(state, compactor, fresh)
            })
            .map_err(NvError::Io)?;

        if let Some(fresh) = rebuilt {
            *index = fresh;
        }

        Ok(at)
    }

    fn open_log(&mut self) -> (&mut AppendLog<F, REC>, &mut RecordIndex) {
        (self.log.as_mut().expect("FlashLog used before load"), &mut self.index)
    }
}

impl<F: SectorIo, const REC: usize> NvStore for FlashLog<F, REC> {
    type Error = F::Error;

    fn load<S: PersistentSections>(&mut self, state: &S) -> Result<Loaded, NvError<F::Error>> {
        self.snapshot_bytes = self.check_layout(state)?;

        let io = self.io.take().expect("FlashLog loaded twice");
        let mut replayed = false;
        let index = &mut self.index;

        let log = AppendLog::open(io, self.geometry, Self::magic(state.layout_fingerprint()), |at, payload| {
            let [id, offset_hi, offset_lo, bytes @ ..] = payload else {
                return;
            };

            replayed = true;
            if state.apply_section(*id, u16::from_be_bytes([*offset_hi, *offset_lo]), bytes).is_err() {
                state.reset_section(*id);
            }

            if find_section(state, *id).is_some_and(|section| section.kind == SectionKind::Record) {
                index_set(index, *id, at);
            }
        })
        .map_err(NvError::Io)?;

        self.log = Some(log);

        // A fresh medium gets the factory state as its first snapshot now,
        // at boot where nothing is time-critical; a log replayed above the
        // threshold is compacted for the same reason.
        if !replayed || self.needs_compaction() {
            self.compact(state)?;
        }

        Ok(if replayed { Loaded::Restored } else { Loaded::Fresh })
    }

    fn persist<S: PersistentSections>(
        &mut self,
        state: &S,
        id: SectionId,
        offset: u16,
        len: u16,
    ) -> Result<(), NvError<F::Error>> {
        let section = find_section(state, id).expect("persist of a section the state does not have");
        let (log, index) = self.open_log();

        match section.kind {
            SectionKind::Record => {
                let at = Self::append(log, index, state, id, 0, usize::from(section.len))?;

                index_set(index, id, at);

                Ok(())
            }
            SectionKind::Image => {
                assert!(offset + len <= section.len, "persist range outside the section");

                let mut done = 0usize;
                while done < usize::from(len) {
                    let n = (usize::from(len) - done).min(Self::CHUNK);
                    Self::append(log, index, state, id, offset + done as u16, n)?;

                    done += n;
                }

                Ok(())
            }
        }
    }

    /// True when appends have used three quarters of the space available
    /// beyond a compacted snapshot. The snapshot itself cannot be reclaimed.
    fn needs_compaction(&self) -> bool {
        // TODO: A failed append can also leave compaction pending. Reporting
        // that here alone does not stop foreground appends from erasing; the
        // guarded-maintenance path needs append admission first.
        self.log.as_ref().is_some_and(|log| {
            let (used, capacity) = log.fill();
            let append_capacity = capacity - self.snapshot_bytes;
            let appended = used.saturating_sub(self.snapshot_bytes);

            appended > append_capacity / 4 * 3
        })
    }

    fn compact<S: PersistentSections>(&mut self, state: &S) -> Result<(), NvError<F::Error>> {
        let (log, index) = self.open_log();
        let mut fresh = heapless::Vec::new();

        log.compact(|compactor| Self::snapshot(state, compactor, &mut fresh)).map_err(NvError::Io)?;

        *index = fresh;

        Ok(())
    }

    /// Read the Record's latest log record back and compare its bytes.
    fn record_matches<S: PersistentSections>(&mut self, state: &S, id: SectionId) -> Result<bool, NvError<F::Error>> {
        let Some(section) = find_section(state, id) else {
            return Ok(false);
        };

        let Some(&(_, at)) = self.index.iter().find(|(entry, _)| *entry == id) else {
            return Ok(false);
        };

        let log = self.log.as_mut().expect("FlashLog used before load");

        let mut durable = [0u8; REC];
        let Some(len) = log.read_payload(at, &mut durable).map_err(NvError::Io)? else {
            return Ok(false);
        };

        let record_len = usize::from(section.len);
        if len != RECORD_HEADER + record_len || durable[0] != id {
            return Ok(false);
        }

        let mut current = [0u8; REC];
        state.read_section(id, 0, &mut current[..record_len]);

        Ok(durable[RECORD_HEADER..len] == current[..record_len])
    }
}
