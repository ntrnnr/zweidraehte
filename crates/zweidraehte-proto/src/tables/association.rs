//! Ownership-free association-table coding shared by clients and devices.
//!
//! RT1/RT2 and compact System 7 use a byte count and byte TSAP/ASAPs.
//! System B uses a word count with either byte or word TSAP/ASAPs.
//! All words are big-endian. Row ordering and empty-table fallback belong
//! to the realization, not the codec. Sending lookup therefore takes an
//! explicit policy; RT6's empty identity mapping stays with its device adapter.
//!
//! Resources §4.17.3.1 defines RT1's layout, §4.17.4.1 reuses it for RT2,
//! and §4.17.6.1 repeats it for RT8. Mask 0705 uses the same bytes under
//! ETS's `AssociationTable_M112` formatter, without being assigned to RT8
//! by Profiles §4.5.2.

use core::marker::PhantomData;

/// TSAP used by RT1/RT2 management clients for an unused sending-association
/// slot (Resources §4.17.3.4.1).
pub const UNUSED_SENDING_TSAP: u8 = 0xFE;

/// One decoded association; byte-coded identifiers are zero-extended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Association {
    pub tsap: u16,
    pub asap: u16,
}

/// RT1, RT2 and compact System 7: one-byte count, two-byte rows.
#[derive(Debug, Clone, Copy)]
pub struct Bcu;

/// System B with a two-byte count and two-byte rows.
#[derive(Debug, Clone, Copy)]
pub struct SystemBSmall;

/// System B with a two-byte count and four-byte rows.
#[derive(Debug, Clone, Copy)]
pub struct SystemBBig;

mod private {
    pub trait Sealed {}
    impl Sealed for super::Bcu {}
    impl Sealed for super::SystemBSmall {}
    impl Sealed for super::SystemBBig {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssociationTableError {
    CountOverflow,
    IdentifierOverflow,
    BufferTooShort,
}

impl core::fmt::Display for AssociationTableError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::CountOverflow => "association table exceeds its declared table capacity",
            Self::IdentifierOverflow => "association identifier exceeds its declared table capacity",
            Self::BufferTooShort => "association table output buffer is too short",
        })
    }
}

impl core::error::Error for AssociationTableError {}

/// Compile-time byte layout; ordering and sending lookup remain separate.
///
/// Sealed to the standardized layouts so count and row widths cannot disagree.
/// A device selects one marker type, and all codec operations specialize for it.
pub trait AssociationTableFormat: private::Sealed + core::fmt::Debug + Copy {
    const HEADER_LEN: usize;
    const ENTRY_LEN: usize;
    const MAX_COUNT: usize;
    const UNUSED_TSAP: Option<u16>;

    /// Number of complete rows this storage and the encoded count can hold.
    fn capacity(bytes: usize) -> u16 {
        (bytes.saturating_sub(Self::HEADER_LEN) / Self::ENTRY_LEN).min(Self::MAX_COUNT) as u16
    }

    /// Required storage, rejecting a count which the header cannot represent.
    fn encoded_len(count: usize) -> Result<usize, AssociationTableError> {
        if count > Self::MAX_COUNT {
            return Err(AssociationTableError::CountOverflow);
        }
        Ok(Self::HEADER_LEN + count * Self::ENTRY_LEN)
    }

    /// Encode rows in caller-supplied order. Validate count, identifiers and
    /// output capacity before changing any bytes; trailing storage is untouched.
    fn encode(rows: &[Association], output: &mut [u8]) -> Result<usize, AssociationTableError> {
        let length = Self::encoded_len(rows.len())?;
        if Self::ENTRY_LEN == 2 && rows.iter().any(|row| row.tsap > 255 || row.asap > 255) {
            return Err(AssociationTableError::IdentifierOverflow);
        }
        let output = output.get_mut(..length).ok_or(AssociationTableError::BufferTooShort)?;
        let (count, data) = output.split_at_mut(Self::HEADER_LEN);
        if Self::HEADER_LEN == 1 {
            count[0] = rows.len() as u8;
        } else {
            count.copy_from_slice(&(rows.len() as u16).to_be_bytes());
        }
        for (row, bytes) in rows.iter().zip(data.chunks_exact_mut(Self::ENTRY_LEN)) {
            if Self::ENTRY_LEN == 4 {
                bytes[..2].copy_from_slice(&row.tsap.to_be_bytes());
                bytes[2..].copy_from_slice(&row.asap.to_be_bytes());
            } else {
                bytes.copy_from_slice(&[row.tsap as u8, row.asap as u8]);
            }
        }
        Ok(length)
    }
}

impl AssociationTableFormat for Bcu {
    const HEADER_LEN: usize = 1;
    const ENTRY_LEN: usize = 2;
    const MAX_COUNT: usize = u8::MAX as usize;
    const UNUSED_TSAP: Option<u16> = Some(UNUSED_SENDING_TSAP as u16);
}

impl AssociationTableFormat for SystemBSmall {
    const HEADER_LEN: usize = 2;
    const ENTRY_LEN: usize = 2;
    const MAX_COUNT: usize = u16::MAX as usize;
    const UNUSED_TSAP: Option<u16> = None;
}

impl AssociationTableFormat for SystemBBig {
    const HEADER_LEN: usize = 2;
    const ENTRY_LEN: usize = 4;
    const MAX_COUNT: usize = u16::MAX as usize;
    const UNUSED_TSAP: Option<u16> = None;
}

/// Compile-time rule for selecting the association used for transmission.
pub trait SendingAssociation {
    fn select<F: AssociationTableFormat>(table: &AssociationTableView<'_, F>, asap: u16) -> Option<Association>;
}

/// RT1: use the row whose zero-based association number equals the ASAP.
#[derive(Debug, Clone, Copy)]
pub struct Indexed;

/// RT2: use that row only when it also names the requested ASAP.
#[derive(Debug, Clone, Copy)]
pub struct IndexedChecked;

/// Compact System 7 and RT6: use the first row naming the requested ASAP.
#[derive(Debug, Clone, Copy)]
pub struct FirstMatch;

impl SendingAssociation for Indexed {
    fn select<F: AssociationTableFormat>(table: &AssociationTableView<'_, F>, asap: u16) -> Option<Association> {
        table.association(asap)
    }
}

impl SendingAssociation for IndexedChecked {
    fn select<F: AssociationTableFormat>(table: &AssociationTableView<'_, F>, asap: u16) -> Option<Association> {
        table.association(asap).filter(|row| row.asap == asap)
    }
}

impl SendingAssociation for FirstMatch {
    fn select<F: AssociationTableFormat>(table: &AssociationTableView<'_, F>, asap: u16) -> Option<Association> {
        table.associations().find(|row| row.asap == asap)
    }
}

/// Bounds-checked, ownership-free view of an association table.
///
/// Downloaded counts are untrusted while ETS writes the table piecemeal.
/// Accessors clamp to complete rows present in the borrowed storage.
///
/// A device's table format is fixed in its type: a BCU view cannot replace
/// a System B view, even when both borrow the same storage.
///
/// ```compile_fail,E0308
/// use zweidraehte_proto::tables::association::{AssociationTableView, Bcu, SystemBBig};
/// let eeprom = [0; 10];
/// let mut table = AssociationTableView::<SystemBBig>::new(&eeprom);
/// table = AssociationTableView::<Bcu>::new(&eeprom); // different format type
/// ```
#[derive(Debug, Clone, Copy)]
pub struct AssociationTableView<'a, F: AssociationTableFormat> {
    data: &'a [u8],
    _format: PhantomData<F>,
}

impl<'a, F: AssociationTableFormat> AssociationTableView<'a, F> {
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, _format: PhantomData }
    }

    pub const fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// The encoded count, or `None` when the header is incomplete.
    pub fn stored_count(&self) -> Option<u16> {
        let count = self.data.get(..F::HEADER_LEN)?;
        Some(if F::HEADER_LEN == 1 { u16::from(count[0]) } else { u16::from_be_bytes([count[0], count[1]]) })
    }

    pub fn declared_entry_count(&self) -> u16 {
        self.stored_count().unwrap_or(0)
    }

    /// The number of complete, declared rows available through this view.
    pub fn entry_count(&self) -> u16 {
        self.declared_entry_count().min(F::capacity(self.data.len()))
    }

    /// Return a row by its zero-based association number.
    pub fn association(&self, number: u16) -> Option<Association> {
        if number >= self.entry_count() {
            return None;
        }
        let offset = F::HEADER_LEN + usize::from(number) * F::ENTRY_LEN;
        let row = self.data.get(offset..offset + F::ENTRY_LEN)?;
        Some(if F::ENTRY_LEN == 4 {
            Association { tsap: u16::from_be_bytes([row[0], row[1]]), asap: u16::from_be_bytes([row[2], row[3]]) }
        } else {
            Association { tsap: u16::from(row[0]), asap: u16::from(row[1]) }
        })
    }

    /// Iterate complete rows in association-number order.
    pub fn associations(&self) -> AssociationIter<'a, F> {
        AssociationIter { table: *self, next: 0 }
    }

    /// Resolve the sending TSAP using the caller's realization-specific rule.
    /// The unused-slot sentinel is metadata only in the BCU byte-count format;
    /// System B may use the same numeric TSAP as an ordinary association.
    pub fn sending_tsap<S: SendingAssociation>(&self, asap: u16) -> Option<u16> {
        let association = S::select(self, asap)?;
        (F::UNUSED_TSAP != Some(association.tsap)).then_some(association.tsap)
    }
}

/// Iterator over the complete rows of an [`AssociationTableView`].
#[derive(Debug, Clone)]
pub struct AssociationIter<'a, F: AssociationTableFormat> {
    table: AssociationTableView<'a, F>,
    next: u16,
}

impl<F: AssociationTableFormat> Iterator for AssociationIter<'_, F> {
    type Item = Association;

    fn next(&mut self) -> Option<Self::Item> {
        let association = self.table.association(self.next)?;
        self.next += 1;
        Some(association)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codecs_match_independent_wire_examples_without_reordering() {
        fn check<F: AssociationTableFormat>(rows: &[Association], expected: &[u8]) {
            let mut output = [0xa5; 12];
            assert_eq!(F::encode(rows, &mut output), Ok(expected.len()));
            assert_eq!(&output[..expected.len()], expected);
            assert!(output[expected.len()..].iter().all(|byte| *byte == 0xa5));

            // Decode the golden bytes, independently of the encoder output.
            let view = AssociationTableView::<F>::new(expected);
            assert_eq!(view.stored_count(), Some(2));
            assert_eq!(view.associations().collect::<Vec<_>>(), rows);
        }
        let byte_rows = [Association { tsap: 0xfe, asap: 7 }, Association { tsap: 2, asap: 7 }];
        let wide_rows = [Association { tsap: 0x123, asap: 0x456 }, Association { tsap: 0xffff, asap: 0xfe }];
        check::<Bcu>(&byte_rows, &[2, 0xfe, 7, 2, 7]);
        check::<SystemBSmall>(&byte_rows, &[0, 2, 0xfe, 7, 2, 7]);
        check::<SystemBBig>(&wide_rows, &[0, 2, 1, 0x23, 4, 0x56, 0xff, 0xff, 0, 0xfe]);

        let small = AssociationTableView::<SystemBSmall>::new(&[0, 2, 0xfe, 7, 2, 7]);
        assert_eq!(small.sending_tsap::<FirstMatch>(7), Some(0xfe));
    }

    #[test]
    fn every_truncated_layout_exposes_only_complete_rows() {
        fn check<F: AssociationTableFormat>(bytes: &[u8], counts: &[u16]) {
            for (length, &count) in counts.iter().enumerate() {
                let view = AssociationTableView::<F>::new(&bytes[..length]);
                assert_eq!(view.entry_count(), count, "{}: {length} bytes", core::any::type_name::<F>());
                assert_eq!(view.associations().count(), usize::from(count));
                assert_eq!(view.association(count), None);
            }
        }
        check::<Bcu>(&[255, 1, 0, 2, 1], &[0, 0, 0, 1, 1, 2]);
        check::<SystemBSmall>(&[255, 255, 1, 0, 2, 1], &[0, 0, 0, 0, 1, 1, 2]);
        check::<SystemBBig>(&[255, 255, 0, 1, 0, 0, 0, 2, 0, 1], &[0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2]);
        assert_eq!(AssociationTableView::<SystemBSmall>::new(&[0xff]).stored_count(), None);
        assert_eq!(AssociationTableView::<SystemBBig>::new(&[0xff]).stored_count(), None);
    }

    #[test]
    fn encoding_rejects_overflow_before_mutating_output() {
        fn check_byte_ids<F: AssociationTableFormat>(output: &mut [u8]) {
            for row in [Association { tsap: 256, asap: 1 }, Association { tsap: 1, asap: 256 }] {
                assert_eq!(F::encode(&[row], output), Err(AssociationTableError::IdentifierOverflow));
            }
        }
        fn check_word_count<F: AssociationTableFormat>() {
            assert_eq!(F::encoded_len(65536), Err(AssociationTableError::CountOverflow));
            assert_eq!(F::encoded_len(usize::MAX), Err(AssociationTableError::CountOverflow));
        }
        let mut output = [0xa5; 8];
        check_byte_ids::<Bcu>(&mut output);
        check_byte_ids::<SystemBSmall>(&mut output);
        check_word_count::<SystemBSmall>();
        check_word_count::<SystemBBig>();
        let rows = [Association { tsap: 1, asap: 1 }; 256];
        assert_eq!(Bcu::encode(&rows, &mut output), Err(AssociationTableError::CountOverflow));
        assert_eq!(SystemBSmall::encoded_len(256), Ok(514));
        assert_eq!(SystemBBig::encode(&rows[..2], &mut output), Err(AssociationTableError::BufferTooShort));
        assert_eq!(output, [0xa5; 8]);
    }

    #[test]
    fn empty_tables_have_only_a_count_and_no_invented_mapping() {
        fn check<F: AssociationTableFormat>(expected: &[u8]) {
            let mut output = [0xff; 2];
            let length = F::encode(&[], &mut output).expect("empty table fits");
            assert_eq!(&output[..length], expected);
            let view = AssociationTableView::<F>::new(expected);
            assert_eq!(view.entry_count(), 0);
            assert_eq!(view.sending_tsap::<FirstMatch>(7), None);
        }
        check::<Bcu>(&[0]);
        check::<SystemBSmall>(&[0, 0]);
        check::<SystemBBig>(&[0, 0]);
    }

    #[test]
    fn walks_zero_based_association_rows() {
        let table = AssociationTableView::<Bcu>::new(&[3, 1, 0, 2, 1, 2, 3]);

        assert_eq!(table.stored_count(), Some(3));
        assert_eq!(table.entry_count(), 3);
        assert_eq!(table.association(0), Some(Association { tsap: 1, asap: 0 }));
        assert_eq!(table.association(2), Some(Association { tsap: 2, asap: 3 }));
        assert_eq!(table.association(3), None);
        assert_eq!(table.associations().count(), 3);
    }

    #[test]
    fn sending_rules_remain_distinct() {
        // Slot 0 names ASAP 1; ASAP 0 appears later in slot 1.
        let table = AssociationTableView::<Bcu>::new(&[2, 4, 1, 5, 0]);

        assert_eq!(table.sending_tsap::<Indexed>(0), Some(4));
        assert_eq!(table.sending_tsap::<IndexedChecked>(0), None);
        assert_eq!(table.sending_tsap::<FirstMatch>(0), Some(5));
    }

    #[test]
    fn unused_sending_slot_is_not_a_tsap() {
        let table = AssociationTableView::<Bcu>::new(&[1, UNUSED_SENDING_TSAP, 0]);

        assert_eq!(table.sending_tsap::<Indexed>(0), None);
        assert_eq!(table.sending_tsap::<IndexedChecked>(0), None);
        assert_eq!(table.sending_tsap::<FirstMatch>(0), None);
    }

    #[test]
    fn downloaded_count_is_clamped_to_complete_rows() {
        let table = AssociationTableView::<Bcu>::new(&[u8::MAX, 1, 0, 2]);

        assert_eq!(table.declared_entry_count(), u16::from(u8::MAX));
        assert_eq!(table.entry_count(), 1);
        assert_eq!(table.association(0), Some(Association { tsap: 1, asap: 0 }));
        assert_eq!(table.association(1), None);
    }

    #[test]
    fn missing_count_is_an_empty_table() {
        let table = AssociationTableView::<Bcu>::new(&[]);

        assert_eq!(table.stored_count(), None);
        assert_eq!(table.entry_count(), 0);
        assert_eq!(table.sending_tsap::<FirstMatch>(0), None);
    }
}
