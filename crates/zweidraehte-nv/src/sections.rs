//! Persistent sections: the durable units a device's state is stored in.
//!
//! Instead of serialising its whole configuration as one blob, a device state
//! declares its persistent data as numbered **sections**, each with a fixed
//! length and a fixed byte encoding. A change persists only the section, or
//! the byte range of it, that changed; at boot the durable bytes are applied
//! back section by section. The stores in this crate move bytes and know
//! nothing about what a section means; the state that owns the sections does.
//!
//! Section ids are part of the on-media format. [`layout_fingerprint`]
//! summarises the whole list together with the state's declared
//! [`SCHEMA_REVISION`], so a store can tell at boot that a firmware update
//! changed the layout and start factory-fresh rather than misread bytes
//! written under another layout. The list alone shows only a change of
//! shape; an encoding that changes what its bytes mean at the same length
//! is visible only through the revision, which its owner bumps.
//!
//! [`layout_fingerprint`]: PersistentSections::layout_fingerprint
//! [`SCHEMA_REVISION`]: PersistentSections::SCHEMA_REVISION

/// Identifies one section of a device's persistent state.
pub type SectionId = u8;

/// How a section is written and applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionKind {
    /// A byte image addressable by range: tables, application parameters,
    /// key tables. A write persists just the bytes it changed, and any
    /// range of valid bytes is a valid apply.
    Image,
    /// A small structured record, written and applied whole. Applying
    /// validates the encoding, so a torn or foreign record is rejected
    /// rather than decoded into nonsense.
    Record,
}

/// One entry of a state's section list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Section {
    pub id: SectionId,
    /// The section's full length in bytes.
    pub len: u16,
    pub kind: SectionKind,
}

/// Why durable bytes could not be applied. The caller resets the section
/// to its factory default and carries on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionError {
    /// No section with that id exists in this layout.
    UnknownSection,
    /// The bytes do not decode: out of range for the section, or a Record
    /// that is partial or fails validation.
    Malformed,
}

/// A device state whose persistent data is split into sections.
///
/// Methods take `&self`: device states hold their data behind `Cell` /
/// `RefCell`, and boot-time replay applies bytes into an already
/// constructed state.
pub trait PersistentSections {
    /// The revision of the section encodings. Bump it when stored bytes
    /// change meaning without changing length: the fingerprint moves and
    /// the device boots factory-fresh instead of misreading them.
    const SCHEMA_REVISION: u32 = 0;

    /// Visit every section in ascending id order.
    ///
    /// The callback may read sections ([`read_section`](Self::read_section))
    /// but must not apply or reset them: an implementation may hold a borrow
    /// of its state while it reports a section.
    fn for_each_section(&self, f: &mut impl FnMut(Section));

    /// Copy the current bytes of `id` starting at `offset` into `buf`.
    ///
    /// # Panics
    ///
    /// If `id` is unknown or the range lies outside the section; callers
    /// take both from [`for_each_section`](Self::for_each_section).
    fn read_section(&self, id: SectionId, offset: u16, buf: &mut [u8]);

    /// Make `bytes` the content of `id` at `offset`.
    fn apply_section(&self, id: SectionId, offset: u16, bytes: &[u8]) -> Result<(), SectionError>;

    /// Return `id` to its factory default.
    fn reset_section(&self, id: SectionId);

    /// An Image's stored CRC did not match its restored bytes.
    ///
    /// The state owns validity policy: an interrupted download may already be
    /// invalid, while a previously valid table can enter its Error state.
    /// Return the Record section whose control fields changed so the store
    /// makes that decision durable before boot continues. An Image without
    /// a load state returns `None` and keeps its bytes as restored.
    fn image_crc_mismatch(&self, _id: SectionId) -> Option<SectionId> {
        None
    }

    /// Report, and forget, the byte ranges of Image sections changed since
    /// the last call. Records need no tracking: a store compares them with
    /// its durable copy. Implementations must not hold a borrow of their
    /// state while calling `f`.
    fn take_dirty_images(&self, _f: &mut impl FnMut(SectionId, u16, u16)) {}

    /// A fingerprint of the schema revision and the section list (ids,
    /// lengths, kinds): equal layouts give equal fingerprints. FNV-1a, which
    /// is small and stable; it guards against accidental layout changes, not
    /// adversaries.
    fn layout_fingerprint(&self) -> u32 {
        let mut hash: u32 = 0x811C_9DC5;
        for byte in Self::SCHEMA_REVISION.to_be_bytes() {
            hash = (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193);
        }

        self.for_each_section(&mut |section| {
            let kind = match section.kind {
                SectionKind::Image => 0,
                SectionKind::Record => 1,
            };
            let [len_hi, len_lo] = section.len.to_be_bytes();
            for byte in [section.id, len_hi, len_lo, kind] {
                hash = (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193);
            }
        });
        hash
    }
}

/// Copy `buf.len()` bytes of `image` from `offset`, the common body of an
/// Image section's `read_section`.
///
/// # Panics
///
/// If the range lies outside `image`.
pub fn read_image(image: &[u8], offset: u16, buf: &mut [u8]) {
    let start = usize::from(offset);
    buf.copy_from_slice(&image[start..start + buf.len()]);
}

/// Write `bytes` into `image` at `offset`, the common body of an Image
/// section's `apply_section`.
pub fn apply_image(image: &mut [u8], offset: u16, bytes: &[u8]) -> Result<(), SectionError> {
    let start = usize::from(offset);
    let target = image.get_mut(start..start + bytes.len()).ok_or(SectionError::Malformed)?;
    target.copy_from_slice(bytes);
    Ok(())
}

/// The whole-record guard of a Record section's `apply_section`: `bytes`
/// must be the complete record, starting at offset 0.
pub fn whole_record<const LEN: usize>(offset: u16, bytes: &[u8]) -> Result<&[u8; LEN], SectionError> {
    if offset != 0 {
        return Err(SectionError::Malformed);
    }
    bytes.try_into().map_err(|_| SectionError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A state with a configurable section list, for fingerprint tests.
    struct Layout(&'static [Section]);

    impl PersistentSections for Layout {
        fn for_each_section(&self, f: &mut impl FnMut(Section)) {
            self.0.iter().copied().for_each(f);
        }
        fn read_section(&self, _id: SectionId, _offset: u16, _buf: &mut [u8]) {}
        fn apply_section(&self, _id: SectionId, _offset: u16, _bytes: &[u8]) -> Result<(), SectionError> {
            Ok(())
        }
        fn reset_section(&self, _id: SectionId) {}
    }

    const A: Section = Section { id: 1, len: 15, kind: SectionKind::Record };
    const B: Section = Section { id: 8, len: 64, kind: SectionKind::Image };

    #[test]
    fn fingerprint_changes_with_any_layout_fact() {
        let base = Layout(&[A, B]).layout_fingerprint();
        assert_eq!(base, Layout(&[A, B]).layout_fingerprint());
        assert_ne!(base, Layout(&[A]).layout_fingerprint(), "a removed section");
        assert_ne!(base, Layout(&[A, Section { len: 65, ..B }]).layout_fingerprint(), "a longer section");
        assert_ne!(base, Layout(&[A, Section { id: 9, ..B }]).layout_fingerprint(), "a renumbered section");
        assert_ne!(base, Layout(&[A, Section { kind: SectionKind::Record, ..B }]).layout_fingerprint(), "a new kind");
        assert_ne!(base, Revised(Layout(&[A, B])).layout_fingerprint(), "a new schema revision");
    }

    /// The same section list under the next schema revision.
    struct Revised(Layout);

    impl PersistentSections for Revised {
        const SCHEMA_REVISION: u32 = 1;

        fn for_each_section(&self, f: &mut impl FnMut(Section)) {
            self.0.for_each_section(f);
        }
        fn read_section(&self, _id: SectionId, _offset: u16, _buf: &mut [u8]) {}
        fn apply_section(&self, _id: SectionId, _offset: u16, _bytes: &[u8]) -> Result<(), SectionError> {
            Ok(())
        }
        fn reset_section(&self, _id: SectionId) {}
    }

    #[test]
    fn image_ranges_are_bounds_checked() {
        let mut image = [0u8; 4];
        apply_image(&mut image, 1, &[7, 8]).expect("in range");
        assert_eq!(image, [0, 7, 8, 0]);
        assert_eq!(apply_image(&mut image, 3, &[1, 2]), Err(SectionError::Malformed));

        let mut buf = [0u8; 2];
        read_image(&image, 1, &mut buf);
        assert_eq!(buf, [7, 8]);
    }

    #[test]
    fn records_apply_only_whole() {
        assert!(whole_record::<3>(0, &[1, 2, 3]).is_ok());
        assert_eq!(whole_record::<3>(0, &[1, 2]), Err(SectionError::Malformed));
        assert_eq!(whole_record::<3>(1, &[1, 2, 3]), Err(SectionError::Malformed));
    }
}
