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
//!   prefix of those chunks applied. A single ETS memory write fits one
//!   record when `REC` is at least 264, so it is atomic too.
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
}

impl<F: SectorIo, const REC: usize> FlashLog<F, REC> {
    /// The most section bytes one record carries.
    const CHUNK: usize = AppendLog::<F, REC>::MAX_PAYLOAD - RECORD_HEADER;

    /// A store over `geometry` on `io`, opened by [`load`](NvStore::load).
    pub fn new(io: F, geometry: LogGeometry) -> Self {
        Self { io: Some(io), log: None, geometry }
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
    fn check_layout<S: PersistentSections>(&self, state: &S) -> Result<(), NvError<F::Error>> {
        let mut snapshot = AppendLog::<F, REC>::header_len() + REC as u32;
        let mut records_fit = true;
        state.for_each_section(&mut |section| {
            snapshot += Self::snapshot_len(&section);
            records_fit &= section.kind == SectionKind::Image || usize::from(section.len) <= Self::CHUNK;
        });
        if !records_fit || snapshot > self.geometry.bank_size() {
            return Err(NvError::LayoutTooLarge);
        }
        Ok(())
    }

    /// Write every section of `state` into a compacting bank.
    fn snapshot<S: PersistentSections>(state: &S, compactor: &mut Compactor<'_, F, REC>) -> Result<(), F::Error> {
        let mut result = Ok(());
        let mut buf = [0u8; REC];
        state.for_each_section(&mut |section| {
            let mut offset = 0usize;
            while result.is_ok() && offset < usize::from(section.len) {
                let n = (usize::from(section.len) - offset).min(Self::CHUNK);
                let chunk = &mut buf[..n];
                state.read_section(section.id, offset as u16, chunk);
                result = compactor.push(&[&[section.id], &(offset as u16).to_be_bytes(), chunk]);
                offset += n;
            }
        });
        result
    }

    /// Append one record carrying `len` bytes of section `id` from `offset`.
    fn append<S: PersistentSections>(
        log: &mut AppendLog<F, REC>,
        state: &S,
        id: SectionId,
        offset: u16,
        len: usize,
    ) -> Result<(), NvError<F::Error>> {
        let mut buf = [0u8; REC];
        let chunk = &mut buf[..len];
        state.read_section(id, offset, chunk);
        log.append(&[&[id], &offset.to_be_bytes(), chunk], |compactor| Self::snapshot(state, compactor))
            .map_err(NvError::Io)
    }

    fn log(&mut self) -> &mut AppendLog<F, REC> {
        self.log.as_mut().expect("FlashLog used before load")
    }
}

impl<F: SectorIo, const REC: usize> NvStore for FlashLog<F, REC> {
    type Error = F::Error;

    fn load<S: PersistentSections>(&mut self, state: &S) -> Result<Loaded, NvError<F::Error>> {
        self.check_layout(state)?;

        let io = self.io.take().expect("FlashLog loaded twice");
        let mut replayed = false;
        let log = AppendLog::open(io, self.geometry, Self::magic(state.layout_fingerprint()), |payload| {
            let [id, offset_hi, offset_lo, bytes @ ..] = payload else {
                return;
            };
            replayed = true;
            if state.apply_section(*id, u16::from_be_bytes([*offset_hi, *offset_lo]), bytes).is_err() {
                state.reset_section(*id);
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
        let log = self.log();
        match section.kind {
            SectionKind::Record => Self::append(log, state, id, 0, usize::from(section.len)),
            SectionKind::Image => {
                assert!(offset + len <= section.len, "persist range outside the section");
                let mut done = 0usize;
                while done < usize::from(len) {
                    let n = (usize::from(len) - done).min(Self::CHUNK);
                    Self::append(log, state, id, offset + done as u16, n)?;
                    done += n;
                }
                Ok(())
            }
        }
    }

    /// True above three quarters of the active bank, leaving room for a
    /// download's worth of appends before a forced compaction.
    fn needs_compaction(&self) -> bool {
        self.log.as_ref().is_some_and(|log| {
            let (used, capacity) = log.fill();
            used > capacity / 4 * 3
        })
    }

    fn compact<S: PersistentSections>(&mut self, state: &S) -> Result<(), NvError<F::Error>> {
        self.log().compact(|compactor| Self::snapshot(state, compactor)).map_err(NvError::Io)
    }
}
