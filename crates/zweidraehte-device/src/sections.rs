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
//! [`SectionBytes`], a fixed big-endian encoding. `#[derive(ExtensionState)]`
//! generates both for leaf extensions.

pub use zweidraehte_nv::sections::{
    PersistentSections, Section, SectionError, SectionId, SectionKind, apply_image, read_image, whole_record,
};

use crate::extension::ExtensionState;

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
    fn write(&self, out: &mut [u8]) {
        out[0] = *self;
    }
    fn read(bytes: &[u8]) -> Option<Self> {
        Some(bytes[0])
    }
}

impl SectionBytes for bool {
    const LEN: usize = 1;
    fn write(&self, out: &mut [u8]) {
        out[0] = u8::from(*self);
    }
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
    fn write(&self, out: &mut [u8]) {
        out.copy_from_slice(&self.to_be_bytes());
    }
    fn read(bytes: &[u8]) -> Option<Self> {
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

impl SectionBytes for u32 {
    const LEN: usize = 4;
    fn write(&self, out: &mut [u8]) {
        out.copy_from_slice(&self.to_be_bytes());
    }
    fn read(bytes: &[u8]) -> Option<Self> {
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

impl<const N: usize> SectionBytes for [u8; N] {
    const LEN: usize = N;
    fn write(&self, out: &mut [u8]) {
        out.copy_from_slice(self);
    }
    fn read(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok()
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
        }
    };
}

#[cfg(feature = "knxip")]
pub(crate) use extension_sections_pair;
