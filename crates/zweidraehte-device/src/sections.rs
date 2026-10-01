//! Persistent sections of extension state.
//!
//! A device state persists itself as numbered sections
//! ([`PersistentSections`], from `zweidraehte-nv`). The core state owns the
//! low ids; the extension state it carries contributes the rest through
//! [`ExtensionSections`]. An extension numbers its sections from 0 and
//! declares how many ids it spans, and every composition (a secure wrapper
//! around a medium extension, a tuple of two extensions) shifts the inner
//! extension past the outer one's span. Ids therefore never collide, and
//! they are fixed by the composition the firmware was built with.
//!
//! Small structured records are encoded field by field through
//! [`SectionBytes`], a fixed big-endian encoding, written and read in order
//! by [`RecordWriter`] and [`RecordReader`]. `#[derive(ExtensionState)]`
//! generates both for leaf extensions.

pub use zweidraehte_nv::sections::{
    PersistentSections, Section, SectionError, SectionId, SectionKind, apply_image, read_image, whole_record,
};

use zweidraehte_proto::address::IndividualAddress;

use crate::extension::ExtensionState;
use crate::objects::tables::LoadState;

// ============================================================================
// SectionBytes — fixed encodings of record fields
// ============================================================================

/// A value with a fixed-length byte encoding, for Record sections.
///
/// Integers are big-endian, the KNX convention. `read` rejects values the
/// type cannot hold, which is how a Record detects a torn or foreign
/// encoding.
pub trait SectionBytes: Sized {
    /// Encoded length in bytes.
    const LEN: usize;
    /// Encode into `out`, which is exactly `LEN` bytes long.
    fn write(&self, out: &mut [u8]);
    /// Decode from `bytes`, which is exactly `LEN` bytes long.
    fn read(bytes: &[u8]) -> Option<Self>;
}

impl SectionBytes for u8 {
    const LEN: usize = 1;
    #[inline]
    fn write(&self, out: &mut [u8]) {
        out[0] = *self;
    }
    #[inline]
    fn read(bytes: &[u8]) -> Option<Self> {
        Some(bytes[0])
    }
}

impl SectionBytes for bool {
    const LEN: usize = 1;
    #[inline]
    fn write(&self, out: &mut [u8]) {
        out[0] = u8::from(*self);
    }
    #[inline]
    fn read(bytes: &[u8]) -> Option<Self> {
        match bytes[0] {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }
}

impl SectionBytes for u16 {
    const LEN: usize = 2;
    #[inline]
    fn write(&self, out: &mut [u8]) {
        out.copy_from_slice(&self.to_be_bytes());
    }
    #[inline]
    fn read(bytes: &[u8]) -> Option<Self> {
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

impl SectionBytes for u32 {
    const LEN: usize = 4;
    #[inline]
    fn write(&self, out: &mut [u8]) {
        out.copy_from_slice(&self.to_be_bytes());
    }
    #[inline]
    fn read(bytes: &[u8]) -> Option<Self> {
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

impl<const N: usize> SectionBytes for [u8; N] {
    const LEN: usize = N;
    #[inline]
    fn write(&self, out: &mut [u8]) {
        out.copy_from_slice(self);
    }
    #[inline]
    fn read(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok()
    }
}

/// The two address octets as they appear on the bus.
impl SectionBytes for IndividualAddress {
    const LEN: usize = 2;
    #[inline]
    fn write(&self, out: &mut [u8]) {
        out.copy_from_slice(self.as_bytes());
    }
    #[inline]
    fn read(bytes: &[u8]) -> Option<Self> {
        Some(IndividualAddress::from_bytes(bytes))
    }
}

/// The `PID_LOAD_STATE_CONTROL` code (03/05/01 Table 92); any other value
/// is rejected.
impl SectionBytes for LoadState {
    const LEN: usize = 1;
    #[inline]
    fn write(&self, out: &mut [u8]) {
        out[0] = (*self).into();
    }
    #[inline]
    fn read(bytes: &[u8]) -> Option<Self> {
        LoadState::try_from(bytes[0]).ok()
    }
}

// ============================================================================
// Record cursors
// ============================================================================
//
// A Record is its fields' `SectionBytes` encodings back to back. The cursors
// keep the position, so an encoder lists the fields once in order, and the
// matching decoder lists them in the same order, instead of both spelling
// out byte ranges that have to agree.

/// Encodes fields one after another into a record buffer.
pub struct RecordWriter<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl<'a> RecordWriter<'a> {
    #[inline(always)]
    pub fn new(out: &'a mut [u8]) -> Self {
        Self { out, at: 0 }
    }

    /// Append `value`'s encoding. Panics if it does not fit, which is a
    /// record length that disagrees with its fields.
    #[inline(always)]
    pub fn put<T: SectionBytes>(&mut self, value: &T) -> &mut Self {
        value.write(&mut self.out[self.at..self.at + T::LEN]);
        self.at += T::LEN;
        self
    }

    /// End the record; in debug builds, check that every byte was written.
    #[inline(always)]
    pub fn finish(self) {
        debug_assert_eq!(self.at, self.out.len(), "a record's length disagrees with its fields");
    }
}

/// Decodes fields one after another from a record.
pub struct RecordReader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> RecordReader<'a> {
    #[inline(always)]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// Decode the next field; `None` if its bytes are not a value of `T`.
    /// Panics if the record is too short, which is a record length that
    /// disagrees with its fields.
    #[inline(always)]
    pub fn take<T: SectionBytes>(&mut self) -> Option<T> {
        let field = &self.bytes[self.at..self.at + T::LEN];
        self.at += T::LEN;
        T::read(field)
    }

    /// End the record; in debug builds, check that every byte was read.
    #[inline(always)]
    pub fn finish(self) {
        debug_assert_eq!(self.at, self.bytes.len(), "a record's length disagrees with its fields");
    }
}

// ============================================================================
// ExtensionSections — an extension's share of the section list
// ============================================================================

/// The persistent sections an extension state contributes, numbered from 0.
///
/// The device state maps its extension range onto these relative ids; a
/// composing extension forwards ids past its own [`SPAN`](Self::SPAN) to the
/// extension it wraps.
pub trait ExtensionSections: ExtensionState {
    /// How many consecutive ids this extension occupies.
    const SPAN: u8;

    /// Visit this extension's sections, with ids offset by `base`.
    fn for_each_section(&self, base: SectionId, f: &mut impl FnMut(Section));

    /// See [`PersistentSections::read_section`]; `rel` is relative.
    fn read_section(&self, rel: SectionId, offset: u16, buf: &mut [u8]);

    /// See [`PersistentSections::apply_section`]; `rel` is relative.
    fn apply_section(&self, rel: SectionId, offset: u16, bytes: &[u8]) -> Result<(), SectionError>;

    /// See [`PersistentSections::reset_section`]; `rel` is relative.
    fn reset_section(&self, rel: SectionId);

    /// See [`PersistentSections::take_dirty_images`]; report absolute ids,
    /// offset by `base`. Extensions without Image sections keep the default.
    fn take_dirty_images(&self, _base: SectionId, _f: &mut impl FnMut(SectionId, u16, u16)) {}
}

impl ExtensionSections for () {
    const SPAN: u8 = 0;

    fn for_each_section(&self, _base: SectionId, _f: &mut impl FnMut(Section)) {}

    fn read_section(&self, _rel: SectionId, _offset: u16, _buf: &mut [u8]) {
        panic!("the empty extension has no sections");
    }

    fn apply_section(&self, _rel: SectionId, _offset: u16, _bytes: &[u8]) -> Result<(), SectionError> {
        Err(SectionError::UnknownSection)
    }

    fn reset_section(&self, _rel: SectionId) {}
}

// ============================================================================
// Record helpers
// ============================================================================

/// The one Record section of an extension whose persisted form is a single
/// `SectionBytes` config: the common body of a leaf extension's
/// `ExtensionSections`. `encode` produces the current config, `apply`
/// installs a decoded one.
pub struct ConfigRecord;

impl ConfigRecord {
    /// The section entry for a config record at `base`.
    pub fn section<C: SectionBytes>(base: SectionId) -> Section {
        Section { id: base, len: C::LEN as u16, kind: SectionKind::Record }
    }

    /// Read `buf.len()` bytes of the encoded `config` from `offset`.
    pub fn read<C: SectionBytes, const LEN: usize>(config: &C, offset: u16, buf: &mut [u8]) {
        let mut record = [0u8; LEN];
        config.write(&mut record);
        read_image(&record, offset, buf);
    }

    /// Decode a complete record.
    pub fn decode<C: SectionBytes, const LEN: usize>(offset: u16, bytes: &[u8]) -> Result<C, SectionError> {
        let record = whole_record::<LEN>(offset, bytes)?;
        C::read(record).ok_or(SectionError::Malformed)
    }
}

// ============================================================================
// SectionPair — composing two extensions
// ============================================================================

/// Two extensions side by side: `first` takes ids from 0, `second` follows
/// past `first`'s span. Composite extensions (IP + tunnelling, IP interface
/// + IP Secure) implement [`ExtensionSections`] by forwarding to this.
pub struct SectionPair<'a, A, B> {
    pub first: &'a A,
    pub second: &'a B,
}

impl<A: ExtensionSections, B: ExtensionSections> SectionPair<'_, A, B> {
    /// The pair's combined span.
    pub const SPAN: u8 = A::SPAN + B::SPAN;

    pub fn for_each_section(&self, base: SectionId, f: &mut impl FnMut(Section)) {
        self.first.for_each_section(base, f);
        self.second.for_each_section(base + A::SPAN, f);
    }

    pub fn read_section(&self, rel: SectionId, offset: u16, buf: &mut [u8]) {
        if rel < A::SPAN {
            self.first.read_section(rel, offset, buf)
        } else {
            self.second.read_section(rel - A::SPAN, offset, buf)
        }
    }

    pub fn apply_section(&self, rel: SectionId, offset: u16, bytes: &[u8]) -> Result<(), SectionError> {
        if rel < A::SPAN {
            self.first.apply_section(rel, offset, bytes)
        } else if rel - A::SPAN < B::SPAN {
            self.second.apply_section(rel - A::SPAN, offset, bytes)
        } else {
            Err(SectionError::UnknownSection)
        }
    }

    pub fn reset_section(&self, rel: SectionId) {
        if rel < A::SPAN { self.first.reset_section(rel) } else { self.second.reset_section(rel - A::SPAN) }
    }

    pub fn take_dirty_images(&self, base: SectionId, f: &mut impl FnMut(SectionId, u16, u16)) {
        self.first.take_dirty_images(base, f);
        self.second.take_dirty_images(base + A::SPAN, f);
    }
}

/// Implement [`ExtensionSections`] for a composite extension by forwarding
/// to a [`SectionPair`] of two of its fields. Only the KNX/IP compositions
/// use it.
#[cfg(feature = "knxip")]
macro_rules! extension_sections_pair {
    (impl<[$($generics:tt)*]> for $ty:ty { $first:ident: $first_ty:ty, $second:ident: $second_ty:ty $(,)? }) => {
        impl<$($generics)*> $crate::sections::ExtensionSections for $ty {
            const SPAN: u8 =
                <$first_ty as $crate::sections::ExtensionSections>::SPAN
                    + <$second_ty as $crate::sections::ExtensionSections>::SPAN;

            fn for_each_section(
                &self,
                base: $crate::sections::SectionId,
                f: &mut impl FnMut($crate::sections::Section),
            ) {
                $crate::sections::SectionPair { first: &self.$first, second: &self.$second }.for_each_section(base, f)
            }

            fn read_section(&self, rel: $crate::sections::SectionId, offset: u16, buf: &mut [u8]) {
                $crate::sections::SectionPair { first: &self.$first, second: &self.$second }
                    .read_section(rel, offset, buf)
            }

            fn apply_section(
                &self,
                rel: $crate::sections::SectionId,
                offset: u16,
                bytes: &[u8],
            ) -> Result<(), $crate::sections::SectionError> {
                $crate::sections::SectionPair { first: &self.$first, second: &self.$second }
                    .apply_section(rel, offset, bytes)
            }

            fn reset_section(&self, rel: $crate::sections::SectionId) {
                $crate::sections::SectionPair { first: &self.$first, second: &self.$second }.reset_section(rel)
            }

            fn take_dirty_images(
                &self,
                base: $crate::sections::SectionId,
                f: &mut impl FnMut($crate::sections::SectionId, u16, u16),
            ) {
                $crate::sections::SectionPair { first: &self.$first, second: &self.$second }
                    .take_dirty_images(base, f)
            }
        }
    };
}

#[cfg(feature = "knxip")]
pub(crate) use extension_sections_pair;

#[cfg(test)]
mod tests {
    use super::*;

    const LEN: usize = bool::LEN + IndividualAddress::LEN + u16::LEN + LoadState::LEN + <[u8; 3]>::LEN;

    #[test]
    fn a_record_round_trips_in_field_order() {
        let mut out = [0u8; LEN];
        let mut writer = RecordWriter::new(&mut out);
        writer
            .put(&true)
            .put(&IndividualAddress::new(1, 2, 3))
            .put(&0x1234u16)
            .put(&LoadState::Loaded)
            .put(&[7u8, 8, 9]);
        writer.finish();
        assert_eq!(out, [1, 0x12, 3, 0x12, 0x34, 1, 7, 8, 9]);

        let mut reader = RecordReader::new(&out);
        assert_eq!(reader.take::<bool>(), Some(true));
        assert_eq!(reader.take::<IndividualAddress>(), Some(IndividualAddress::new(1, 2, 3)));
        assert_eq!(reader.take::<u16>(), Some(0x1234));
        assert_eq!(reader.take::<LoadState>(), Some(LoadState::Loaded));
        assert_eq!(reader.take::<[u8; 3]>(), Some([7, 8, 9]));
        reader.finish();
    }

    #[test]
    fn values_a_type_cannot_hold_are_rejected() {
        assert_eq!(RecordReader::new(&[2]).take::<bool>(), None);
        assert_eq!(RecordReader::new(&[0x06]).take::<LoadState>(), None);
    }

    #[test]
    #[should_panic]
    fn writing_past_the_record_panics() {
        let mut out = [0u8; 1];
        RecordWriter::new(&mut out).put(&0u16);
    }

    #[test]
    #[should_panic]
    fn reading_past_the_record_panics() {
        RecordReader::new(&[0]).take::<u16>();
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "disagrees with its fields")]
    fn an_unfilled_record_is_caught_in_debug_builds() {
        let mut out = [0u8; 2];
        let mut writer = RecordWriter::new(&mut out);
        writer.put(&0u8);
        writer.finish();
    }
}
