//! Persistent sections of extension state.
//!
//! A device state persists itself as numbered sections
//! ([`PersistentSections`], from `zweidraehte-nv`). The core state owns the
//! low ids; the extension state it carries contributes the rest through
//! [`ExtensionSections`]. Every section of the stack has one fixed id from
//! the registry in [`ids`], whichever composition it appears in: a secure
//! wrapper or a pair of extensions forwards each id to the extension that
//! owns it, without arithmetic. The application's own sections take ids from
//! [`ids::APPLICATION_FIRST`] up.
//!
//! Small structured records are encoded field by field through
//! [`SectionBytes`], a fixed big-endian encoding, written and read in order
//! by [`RecordWriter`] and [`RecordReader`].

pub use zweidraehte_nv::stores::config::sections::{
    PersistentSections, Section, SectionError, SectionId, SectionKind, apply_image, read_image, whole_record,
};

use zweidraehte_proto::address::IndividualAddress;

use crate::extension::ExtensionState;
use crate::objects::tables::LoadState;

// ============================================================================
// Schema revision
// ============================================================================

/// The revision of the stack's own section encodings: the device and
/// version records, the table controls and every extension's records.
///
/// The layout fingerprint sees lengths, not meanings. Bump this when one of
/// those encodings changes what its bytes mean at the same length; every
/// device then boots factory-fresh, as after any layout change (there is no
/// migration).
pub const STACK_REVISION: u16 = 0;

/// The [`PersistentSections::SCHEMA_REVISION`] of a device state: the
/// stack's [`STACK_REVISION`] in the high half and the product's
/// [`StackDefinition::CONFIG_REVISION`](crate::StackDefinition::CONFIG_REVISION)
/// in the low half, so a bump on either side moves the fingerprint.
pub const fn schema_revision(product: u16) -> u32 {
    (STACK_REVISION as u32) << 16 | product as u32
}

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
// The section id registry
// ============================================================================

/// Every persistent section id of the stack, in one place.
///
/// An id is part of the on-media format: it names the same section in every
/// device and every composition, so moving a section between extensions or
/// wrapping an extension never renumbers it. Changing an id is a format
/// change, and a device then boots factory-fresh (there is no migration).
///
/// | Id | Owner |
/// | --- | --- |
/// | 01–0B | the family's device state: device record, versions, tables |
/// | 20 | TP1 |
/// | 21 | RF |
/// | 22 | RF retransmitter |
/// | 23 | KNX/IP |
/// | 24 | KNX/IP tunnelling addresses |
/// | 25–27 | KNX IP Secure |
/// | 28–2C | KNX Data Secure |
/// | 2D–7F | reserved for the stack |
/// | 80–FF | the application |
///
/// Sections are listed in ascending id order, so a composition lists the
/// extension it wraps before its own, higher ids. The store rejects
/// duplicate or descending ids at boot.
pub mod ids {
    use super::SectionId;

    pub const TP1: SectionId = 0x20;
    pub const RF: SectionId = 0x21;
    pub const RF_RETRANSMITTER: SectionId = 0x22;
    pub const IP: SectionId = 0x23;
    pub const IP_TUNNELLING: SectionId = 0x24;
    pub const IP_SECURE_CORE: SectionId = 0x25;
    pub const IP_SECURE_PASSWORD_HASHES: SectionId = 0x26;
    pub const IP_SECURE_TUNNELLING_USERS: SectionId = 0x27;
    pub const DATA_SECURE_CORE: SectionId = 0x28;
    pub const DATA_SECURE_FAILURES_LOG: SectionId = 0x29;
    pub const DATA_SECURE_GROUP_KEYS: SectionId = 0x2A;
    pub const DATA_SECURE_P2P_KEYS: SectionId = 0x2B;
    pub const DATA_SECURE_GO_FLAGS: SectionId = 0x2C;

    /// The first id an application may use for its own sections.
    pub const APPLICATION_FIRST: SectionId = 0x80;
}

// ============================================================================
// ExtensionSections — an extension's share of the section list
// ============================================================================

/// The persistent sections an extension state contributes, under their
/// fixed ids from [`ids`].
///
/// A composing extension lists the extension it wraps and forwards each id
/// to whichever of them [`owns`](Self::owns) it. Implementations must list
/// their ids in ascending order; the store checks the order at boot.
pub trait ExtensionSections: ExtensionState {
    /// Whether `id` is one of this extension's sections.
    fn owns(id: SectionId) -> bool;

    /// Visit this extension's sections.
    fn for_each_section(&self, f: &mut impl FnMut(Section));

    /// See [`PersistentSections::read_section`].
    fn read_section(&self, id: SectionId, offset: u16, buf: &mut [u8]);

    /// See [`PersistentSections::apply_section`].
    fn apply_section(&self, id: SectionId, offset: u16, bytes: &[u8]) -> Result<(), SectionError>;

    /// See [`PersistentSections::reset_section`].
    fn reset_section(&self, id: SectionId);

    /// See [`PersistentSections::take_dirty_images`]. Extensions without
    /// Image sections keep the default.
    fn take_dirty_images(&self, _f: &mut impl FnMut(SectionId, u16, u16)) {}

    /// See [`PersistentSections::image_crc_mismatch`]. Extensions whose
    /// Images have no load state keep the default and their restored bytes.
    fn image_crc_mismatch(&self, _id: SectionId) -> Option<SectionId> {
        None
    }
}

impl ExtensionSections for () {
    fn owns(_id: SectionId) -> bool {
        false
    }

    fn for_each_section(&self, _f: &mut impl FnMut(Section)) {}

    fn read_section(&self, _id: SectionId, _offset: u16, _buf: &mut [u8]) {
        panic!("the empty extension has no sections");
    }

    fn apply_section(&self, _id: SectionId, _offset: u16, _bytes: &[u8]) -> Result<(), SectionError> {
        Err(SectionError::UnknownSection)
    }

    fn reset_section(&self, _id: SectionId) {}
}

// ============================================================================
// Record helpers
// ============================================================================

/// Narrow a firmware-fixed section length at compile time, not at runtime.
pub(crate) const fn checked_section_len(len: usize) -> u16 {
    core::assert!(len <= u16::MAX as usize, "persistent section length exceeds u16");
    len as u16
}

/// A Record section holding one `SectionBytes` value: the common body of an
/// extension's or device state's record sections. `read` serves the encoded
/// current value, `decode` checks and decodes a complete one.
pub struct ConfigRecord;

impl ConfigRecord {
    /// The section entry for a config record at `base`.
    ///
    /// The encoded length must fit the section format's `u16` length.
    /// An oversized record is rejected when the firmware is compiled:
    ///
    /// ```compile_fail
    /// use zweidraehte_device::sections::ConfigRecord;
    ///
    /// // 65,536 bytes would wrap the stored length to zero.
    /// let _ = ConfigRecord::section::<[u8; 65_536]>(0);
    /// ```
    pub fn section<C: SectionBytes>(base: SectionId) -> Section {
        let len = const { checked_section_len(C::LEN) };

        Section { id: base, len, kind: SectionKind::Record }
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

/// Two extensions side by side, `first` with the lower ids. Composite
/// extensions (IP + tunnelling, IP interface + IP Secure) implement
/// [`ExtensionSections`] by forwarding to this.
pub struct SectionPair<'a, A, B> {
    pub first: &'a A,
    pub second: &'a B,
}

impl<A: ExtensionSections, B: ExtensionSections> SectionPair<'_, A, B> {
    pub fn owns(id: SectionId) -> bool {
        A::owns(id) || B::owns(id)
    }

    pub fn for_each_section(&self, f: &mut impl FnMut(Section)) {
        self.first.for_each_section(f);
        self.second.for_each_section(f);
    }

    pub fn read_section(&self, id: SectionId, offset: u16, buf: &mut [u8]) {
        if A::owns(id) { self.first.read_section(id, offset, buf) } else { self.second.read_section(id, offset, buf) }
    }

    pub fn apply_section(&self, id: SectionId, offset: u16, bytes: &[u8]) -> Result<(), SectionError> {
        if A::owns(id) {
            self.first.apply_section(id, offset, bytes)
        } else {
            self.second.apply_section(id, offset, bytes)
        }
    }

    pub fn reset_section(&self, id: SectionId) {
        if A::owns(id) { self.first.reset_section(id) } else { self.second.reset_section(id) }
    }

    pub fn take_dirty_images(&self, f: &mut impl FnMut(SectionId, u16, u16)) {
        self.first.take_dirty_images(f);
        self.second.take_dirty_images(f);
    }
}

/// Implement [`ExtensionSections`] for a composite extension by forwarding
/// to a [`SectionPair`] of two of its fields. Only the KNX/IP compositions
/// use it.
#[cfg(feature = "knxip")]
macro_rules! extension_sections_pair {
    (impl<[$($generics:tt)*]> for $ty:ty { $first:ident: $first_ty:ty, $second:ident: $second_ty:ty $(,)? }) => {
        impl<$($generics)*> $crate::sections::ExtensionSections for $ty {
            fn owns(id: $crate::sections::SectionId) -> bool {
                $crate::sections::SectionPair::<$first_ty, $second_ty>::owns(id)
            }

            fn for_each_section(&self, f: &mut impl FnMut($crate::sections::Section)) {
                $crate::sections::SectionPair { first: &self.$first, second: &self.$second }.for_each_section(f)
            }

            fn read_section(&self, id: $crate::sections::SectionId, offset: u16, buf: &mut [u8]) {
                $crate::sections::SectionPair { first: &self.$first, second: &self.$second }
                    .read_section(id, offset, buf)
            }

            fn apply_section(
                &self,
                id: $crate::sections::SectionId,
                offset: u16,
                bytes: &[u8],
            ) -> Result<(), $crate::sections::SectionError> {
                $crate::sections::SectionPair { first: &self.$first, second: &self.$second }
                    .apply_section(id, offset, bytes)
            }

            fn reset_section(&self, id: $crate::sections::SectionId) {
                $crate::sections::SectionPair { first: &self.$first, second: &self.$second }.reset_section(id)
            }

            fn take_dirty_images(&self, f: &mut impl FnMut($crate::sections::SectionId, u16, u16)) {
                $crate::sections::SectionPair { first: &self.$first, second: &self.$second }.take_dirty_images(f)
            }
        }
    };
}

#[cfg(feature = "knxip")]
pub(crate) use extension_sections_pair;

// ============================================================================
// Test support: one extension's fields through a real store
// ============================================================================

/// Round trips of a single extension's sections through both store kinds,
/// for the per-field persistence tests next to each extension.
///
/// The extension stands in for a whole device state, under its registry
/// ids. Records are found by the store comparing
/// them with its durable copy and Images by their own dirty ranges, exactly
/// as for a device, so a field that has no section, or an Image write that
/// does not mark its range, fails here.
#[cfg(test)]
pub(crate) mod test_support {
    use core::fmt::Debug;

    use zweidraehte_nv::mock::Backing;
    use zweidraehte_nv::{ByteNv, FlashLog, Flusher, LogGeometry, NvStore};

    use super::{ExtensionSections, PersistentSections, Section, SectionError, SectionId};

    struct Only<'a, E>(&'a E);

    impl<E: ExtensionSections> PersistentSections for Only<'_, E> {
        fn for_each_section(&self, f: &mut impl FnMut(Section)) {
            self.0.for_each_section(f);
        }
        fn read_section(&self, id: SectionId, offset: u16, buf: &mut [u8]) {
            self.0.read_section(id, offset, buf);
        }
        fn apply_section(&self, id: SectionId, offset: u16, bytes: &[u8]) -> Result<(), SectionError> {
            self.0.apply_section(id, offset, bytes)
        }
        fn reset_section(&self, id: SectionId) {
            self.0.reset_section(id);
        }
        fn take_dirty_images(&self, f: &mut impl FnMut(SectionId, u16, u16)) {
            self.0.take_dirty_images(f);
        }
    }

    fn round_trip<E: ExtensionSections, N: NvStore<Error = ()>, T: PartialEq + Debug>(
        open: impl Fn() -> N,
        fresh: &impl Fn() -> E,
        mutate: &impl Fn(&E),
        read: &impl Fn(&E) -> T,
    ) {
        let state = fresh();
        let mut store = open();
        store.load(&Only(&state)).expect("format with the factory state");
        let factory = read(&state);

        mutate(&state);
        let changed = read(&state);
        assert_ne!(changed, factory, "the mutation must change the field away from its factory value");
        Flusher::new().flush(&Only(&state), &mut store).expect("flush");
        drop(store);

        let rebooted = fresh();
        open().load(&Only(&rebooted)).expect("reboot");
        assert_eq!(read(&rebooted), changed, "the field did not survive a reboot");
    }

    /// Change one field of a factory extension with `mutate`, flush, boot a
    /// factory extension from the same medium and require `read` to see the
    /// change. Runs on a byte medium and on flash.
    pub(crate) fn assert_field_persists<E: ExtensionSections, T: PartialEq + Debug>(
        fresh: impl Fn() -> E,
        mutate: impl Fn(&E),
        read: impl Fn(&E) -> T,
    ) {
        let bytes = Backing::new(4096, 1);
        round_trip(|| ByteNv::new(bytes.open_bytes(), 0, 4096), &fresh, &mutate, &read);

        let flash = Backing::new(4096, 2048);
        let geometry = LogGeometry { offset: 0, sector_size: 2048, sectors_per_bank: 1, banks: 2 };
        round_trip(|| FlashLog::<_, 264>::new(flash.open_aligned::<8>(), geometry), &fresh, &mutate, &read);
    }
}

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

    /// The registry gives every stack section its own id, above the family
    /// state's core ids and below the application's range.
    #[test]
    fn registry_ids_are_unique_and_in_the_stack_range() {
        let registry = [
            ids::TP1,
            ids::RF,
            ids::RF_RETRANSMITTER,
            ids::IP,
            ids::IP_TUNNELLING,
            ids::IP_SECURE_CORE,
            ids::IP_SECURE_PASSWORD_HASHES,
            ids::IP_SECURE_TUNNELLING_USERS,
            ids::DATA_SECURE_CORE,
            ids::DATA_SECURE_FAILURES_LOG,
            ids::DATA_SECURE_GROUP_KEYS,
            ids::DATA_SECURE_P2P_KEYS,
            ids::DATA_SECURE_GO_FLAGS,
        ];

        for (i, id) in registry.iter().enumerate() {
            assert!(*id > 0x0B && *id < ids::APPLICATION_FIRST, "id {id:#04x} outside the stack's extension range");
            assert!(!registry[..i].contains(id), "id {id:#04x} assigned twice");
        }
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
