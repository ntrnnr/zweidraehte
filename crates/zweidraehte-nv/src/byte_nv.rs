//! [`NvStore`] on byte-writable media: FRAM, EEPROM, shared memory, a file.
//!
//! Byte media overwrite in place and do not wear, so every section lives at
//! a fixed offset and is written straight through. What needs care is power
//! loss during a write: FRAM and EEPROM program byte by byte, so a cut can
//! leave any prefix of a write behind.
//!
//! # Layout
//!
//! ```text
//! base + 0:  header [magic "KNXC" 4][layout fingerprint 4][crc16 2]
//! then, in section-list order:
//!   Record:  two slots, each [generation 1][record][crc16 2]
//!   Image:   [bytes][crc16 2]
//! ```
//!
//! # Crash safety
//!
//! - **Records** (the device core, keys, load controls) must never tear. A
//!   write goes to the slot that does not hold the newest valid copy, with
//!   the CRC last, so a cut leaves that slot invalid and the previous copy in
//!   the other slot wins at boot.
//! - **Images** (tables, parameters) are written in place for the changed
//!   range. A cut can leave a partial image. The owner uses its durable load
//!   state to decide validity; a CRC mismatch on an already Loaded table
//!   changes its control Record to Error without discarding its bytes.
//! - **The header** is written last when formatting, so a cut while
//!   formatting leaves no valid header and the next boot formats again.

use crate::ByteIo;
use crate::crc::{Crc16, crc16};
use crate::nv_store::{Loaded, NvError, NvStore, sections_in_order};
use crate::sections::{PersistentSections, Section, SectionId, SectionKind};

const MAGIC: [u8; 4] = *b"KNXC";
const HEADER_LEN: u32 = 10;
/// The longest Record a slot can stage; longer ones are a layout error.
const MAX_RECORD: usize = 256;
/// Chunk size for streaming Images between state and medium.
const CHUNK: usize = 32;

/// Medium bytes one section occupies.
fn extent(section: &Section) -> u32 {
    let len = u32::from(section.len);
    match section.kind {
        SectionKind::Record => 2 * (1 + len + 2),
        SectionKind::Image => len + 2,
    }
}

/// Visit every section with its medium offset, stopping at the first error.
///
/// The visitor may change the state (load applies sections), so it must not
/// run inside the state's own `for_each_section`: each section is looked up
/// by position instead. That is quadratic in the section count, a few
/// hundred steps for a real device, and only at boot and format.
fn walk<S: PersistentSections, E>(state: &S, mut f: impl FnMut(Section, u32) -> Result<(), E>) -> Result<(), E> {
    let mut position = 0;

    while let Some((section, at)) = nth_section(state, position) {
        f(section, at)?;
        position += 1;
    }

    Ok(())
}

/// The section at `position` in the state's list, with its medium offset.
fn nth_section<S: PersistentSections>(state: &S, position: usize) -> Option<(Section, u32)> {
    let mut at = HEADER_LEN;
    let mut index = 0;
    let mut found = None;

    state.for_each_section(&mut |section| {
        if index == position {
            found = Some((section, at));
        }

        at += extent(&section);
        index += 1;
    });

    found
}

/// A store over `capacity` bytes of `medium` starting at `base`.
pub struct ByteNv<M: ByteIo> {
    medium: M,
    base: u32,
    capacity: u32,
}

impl<M: ByteIo> ByteNv<M> {
    /// The store occupies `capacity` bytes of `medium` from `base`.
    pub fn new(medium: M, base: u32, capacity: u32) -> Self {
        Self { medium, base, capacity }
    }

    /// The medium behind the store.
    pub fn medium(&self) -> &M {
        &self.medium
    }

    fn read(&self, at: u32, buf: &mut [u8]) -> Result<(), NvError<M::Error>> {
        self.medium.read_at(self.base + at, buf).map_err(NvError::Io)
    }

    fn write(&mut self, at: u32, data: &[u8]) -> Result<(), NvError<M::Error>> {
        self.medium.write_at(self.base + at, data).map_err(NvError::Io)
    }

    /// The section entry and medium offset of section `id`.
    fn locate<S: PersistentSections>(state: &S, id: SectionId) -> Option<(Section, u32)> {
        let mut at = HEADER_LEN;
        let mut found = None;

        state.for_each_section(&mut |section| {
            if section.id == id {
                found = Some((section, at));
            }

            at += extent(&section);
        });

        found
    }

    /// Total medium bytes the layout needs, and whether every Record fits a
    /// slot buffer.
    fn check_layout<S: PersistentSections>(&self, state: &S) -> Result<(), NvError<M::Error>> {
        if !sections_in_order(state) {
            return Err(NvError::InvalidLayout);
        }

        let mut total = HEADER_LEN;
        let mut records_fit = true;

        state.for_each_section(&mut |section| {
            total += extent(&section);
            records_fit &= section.kind == SectionKind::Image || usize::from(section.len) <= MAX_RECORD;
        });

        if total > self.capacity || !records_fit {
            return Err(NvError::LayoutTooLarge);
        }

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Records
    // ------------------------------------------------------------------------

    /// The generation of a valid slot at `at` for a record of `len` bytes,
    /// with its content copied into `record`.
    fn read_slot(&self, at: u32, len: usize, record: &mut [u8]) -> Result<Option<u8>, NvError<M::Error>> {
        let mut slot = [0u8; 1 + MAX_RECORD + 2];

        let slot = &mut slot[..1 + len + 2];
        self.read(at, slot)?;

        let stored = u16::from_be_bytes([slot[1 + len], slot[2 + len]]);

        if crc16(&slot[..1 + len]) != stored {
            return Ok(None);
        }
        record[..len].copy_from_slice(&slot[1..1 + len]);

        Ok(Some(slot[0]))
    }

    /// The newest valid slot: `(index, generation)`. Generations compare
    /// modulo 256, so the counter may wrap.
    fn newest_slot(&self, at: u32, len: usize) -> Result<Option<(u32, u8)>, NvError<M::Error>> {
        let mut scratch = [0u8; MAX_RECORD];
        let slot_len = 1 + len as u32 + 2;

        let first = self.read_slot(at, len, &mut scratch)?;
        let second = self.read_slot(at + slot_len, len, &mut scratch)?;

        Ok(match (first, second) {
            (Some(a), Some(b)) => Some(if (b.wrapping_sub(a) as i8) > 0 { (1, b) } else { (0, a) }),
            (Some(a), None) => Some((0, a)),
            (None, Some(b)) => Some((1, b)),
            (None, None) => None,
        })
    }

    /// Write `record` into the slot that does not hold the newest copy,
    /// CRC last.
    fn write_record(&mut self, at: u32, record: &[u8]) -> Result<(), NvError<M::Error>> {
        let len = record.len();
        let slot_len = 1 + len as u32 + 2;
        let (target, generation) = match self.newest_slot(at, len)? {
            Some((newest, generation)) => (1 - newest, generation.wrapping_add(1)),
            None => (0, 0),
        };

        let mut head = [0u8; 1 + MAX_RECORD];
        head[0] = generation;
        head[1..1 + len].copy_from_slice(record);
        let crc = crc16(&head[..1 + len]);

        let slot_at = at + target * slot_len;
        self.write(slot_at, &head[..1 + len])?;
        self.write(slot_at + 1 + len as u32, &crc.to_be_bytes())
    }

    /// Make both slots of a record invalid, so a stale copy from another
    /// layout can never outrank the one written next.
    fn invalidate_record(&mut self, at: u32, len: usize) -> Result<(), NvError<M::Error>> {
        let slot_len = 1 + len as u32 + 2;
        let zeros = [0u8; 1 + MAX_RECORD];
        let bad_crc = !crc16(&zeros[..1 + len]);

        for slot in 0..2 {
            let slot_at = at + slot * slot_len;
            self.write(slot_at, &zeros[..1 + len])?;
            self.write(slot_at + 1 + len as u32, &bad_crc.to_be_bytes())?;
        }

        Ok(())
    }

    /// Apply the newest valid copy of a record; with none, or one the state
    /// rejects, reset the section.
    fn load_record<S: PersistentSections>(
        &self,
        state: &S,
        section: Section,
        at: u32,
    ) -> Result<(), NvError<M::Error>> {
        let len = usize::from(section.len);
        let mut record = [0u8; MAX_RECORD];

        let Some((slot, _)) = self.newest_slot(at, len)? else {
            state.reset_section(section.id);
            return Ok(());
        };

        self.read_slot(at + slot * (1 + len as u32 + 2), len, &mut record)?;

        if state.apply_section(section.id, 0, &record[..len]).is_err() {
            state.reset_section(section.id);
        }

        Ok(())
    }

    fn persist_record<S: PersistentSections>(
        &mut self,
        state: &S,
        section: Section,
        at: u32,
    ) -> Result<(), NvError<M::Error>> {
        let mut record = [0u8; MAX_RECORD];
        let record = &mut record[..usize::from(section.len)];
        state.read_section(section.id, 0, record);
        self.write_record(at, record)
    }

    // ------------------------------------------------------------------------
    // Images
    // ------------------------------------------------------------------------

    /// Stream `len` bytes of an image from the state to the medium.
    fn write_image_range<S: PersistentSections>(
        &mut self,
        state: &S,
        section: Section,
        at: u32,
        offset: u16,
        len: u16,
    ) -> Result<(), NvError<M::Error>> {
        let mut buf = [0u8; CHUNK];
        let mut done = 0u16;

        while done < len {
            let n = (len - done).min(CHUNK as u16);
            let chunk = &mut buf[..usize::from(n)];
            state.read_section(section.id, offset + done, chunk);
            self.write(at + u32::from(offset + done), chunk)?;
            done += n;
        }

        Ok(())
    }

    /// Recompute an image's CRC from the state and store it.
    fn write_image_crc<S: PersistentSections>(
        &mut self,
        state: &S,
        section: Section,
        at: u32,
    ) -> Result<(), NvError<M::Error>> {
        let mut crc = Crc16::new();
        let mut buf = [0u8; CHUNK];
        let mut done = 0u16;

        while done < section.len {
            let n = (section.len - done).min(CHUNK as u16);
            let chunk = &mut buf[..usize::from(n)];
            state.read_section(section.id, done, chunk);
            crc.update(chunk);
            done += n;
        }

        self.write(at + u32::from(section.len), &crc.finish().to_be_bytes())
    }

    /// Restore the stored bytes and report whether their CRC differs.
    /// A partial download can legitimately have a stale image CRC; its owner
    /// decides whether the mismatch changes the load state.
    fn load_image<S: PersistentSections>(
        &self,
        state: &S,
        section: Section,
        at: u32,
    ) -> Result<bool, NvError<M::Error>> {
        let mut crc = Crc16::new();
        let mut buf = [0u8; CHUNK];
        let mut done = 0u16;

        while done < section.len {
            let n = (section.len - done).min(CHUNK as u16);

            let chunk = &mut buf[..usize::from(n)];
            self.read(at + u32::from(done), chunk)?;

            crc.update(chunk);

            if state.apply_section(section.id, done, chunk).is_err() {
                state.reset_section(section.id);
                return Ok(false);
            }

            done += n;
        }

        let mut stored = [0u8; 2];
        self.read(at + u32::from(section.len), &mut stored)?;
        Ok(crc.finish() != u16::from_be_bytes(stored))
    }

    // ------------------------------------------------------------------------
    // Format
    // ------------------------------------------------------------------------

    /// Write every section from `state`, then the header.
    fn format<S: PersistentSections>(&mut self, state: &S) -> Result<(), NvError<M::Error>> {
        walk(state, |section, at| match section.kind {
            SectionKind::Record => {
                self.invalidate_record(at, usize::from(section.len))?;
                self.persist_record(state, section, at)
            }
            SectionKind::Image => {
                self.write_image_range(state, section, at, 0, section.len)?;
                self.write_image_crc(state, section, at)
            }
        })?;

        let mut header = [0u8; HEADER_LEN as usize];
        header[..4].copy_from_slice(&MAGIC);
        header[4..8].copy_from_slice(&state.layout_fingerprint().to_be_bytes());

        let crc = crc16(&header[..8]);
        header[8..].copy_from_slice(&crc.to_be_bytes());

        self.write(0, &header)
    }

    fn header_matches<S: PersistentSections>(&self, state: &S) -> Result<bool, NvError<M::Error>> {
        let mut header = [0u8; HEADER_LEN as usize];
        self.read(0, &mut header)?;

        let crc_ok = crc16(&header[..8]) == u16::from_be_bytes([header[8], header[9]]);
        let fingerprint = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);

        Ok(crc_ok && header[..4] == MAGIC && fingerprint == state.layout_fingerprint())
    }
}

impl<M: ByteIo> NvStore for ByteNv<M> {
    type Error = M::Error;

    fn load<S: PersistentSections>(&mut self, state: &S) -> Result<Loaded, NvError<M::Error>> {
        self.check_layout(state)?;
        if !self.header_matches(state)? {
            self.format(state)?;
            return Ok(Loaded::Fresh);
        }

        // Restore every control Record before checking Images, regardless
        // of the firmware's section order.
        walk(state, |section, at| {
            if section.kind == SectionKind::Record {
                self.load_record(state, section, at)?;
            }
            Ok(())
        })?;

        walk(state, |section, at| {
            if section.kind == SectionKind::Image && self.load_image(state, section, at)? {
                if let Some(control_id) = state.image_crc_mismatch(section.id) {
                    let (control, control_at) =
                        Self::locate(state, control_id).expect("image owner named its control Record");
                    assert_eq!(control.kind, SectionKind::Record, "image owner named a non-Record control");
                    self.persist_record(state, control, control_at)?;
                }
            }
            Ok(())
        })?;

        Ok(Loaded::Restored)
    }

    /// Compare the newest valid slot with the state's record.
    fn record_matches<S: PersistentSections>(&mut self, state: &S, id: SectionId) -> Result<bool, NvError<M::Error>> {
        let Some((section, at)) = Self::locate(state, id) else {
            return Ok(false);
        };

        let len = usize::from(section.len);
        let Some((slot, _)) = self.newest_slot(at, len)? else {
            return Ok(false);
        };

        let mut durable = [0u8; MAX_RECORD];
        self.read_slot(at + slot * (1 + len as u32 + 2), len, &mut durable)?;

        let mut current = [0u8; MAX_RECORD];
        state.read_section(id, 0, &mut current[..len]);

        Ok(durable[..len] == current[..len])
    }

    fn persist<S: PersistentSections>(
        &mut self,
        state: &S,
        id: SectionId,
        offset: u16,
        len: u16,
    ) -> Result<(), NvError<M::Error>> {
        let (section, at) = Self::locate(state, id).expect("persist of a section the state does not have");
        match section.kind {
            SectionKind::Record => self.persist_record(state, section, at),
            SectionKind::Image => {
                assert!(offset <= section.len && len <= section.len - offset, "persist range outside the section");
                self.write_image_range(state, section, at, offset, len)?;
                self.write_image_crc(state, section, at)
            }
        }
    }
}
