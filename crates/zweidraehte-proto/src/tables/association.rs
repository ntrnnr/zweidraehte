//! Borrowed view over the RT1, RT2, and RT8 association-table coding.
//!
//! The coding is:
//!
//! ```text
//! [count:1][(TSAP:1, ASAP:1) × count]
//! ```
//!
//! Resources §4.17.3.1 defines the format for RT1, §4.17.4.1 reuses it
//! unchanged for RT2, and §4.17.6.1 repeats it for RT8. System 7 mask 0705
//! uses the same bytes under ETS's `AssociationTable_M112` formatter, but
//! Profiles §4.5.2 does not assign that mask to RT8.
//!
//! The format must not hide the realizations' different transmission rules.
//! RT1 indexes the row numbered by the ASAP without checking the ASAP stored
//! in that row (§4.17.3.3.1); RT2 indexes the same way but requires the row to
//! name the requested ASAP (§4.17.4.3.1). Compact System 7 tables instead
//! need a first-match lookup. [`SendingAssociation`] makes the caller choose
//! that policy explicitly.

/// TSAP used by RT1/RT2 management clients for an unused sending-association
/// slot (Resources §4.17.3.4.1).
pub const UNUSED_SENDING_TSAP: u8 = 0xFE;

/// One byte-coded association-table row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Association {
    pub tsap: u8,
    pub asap: u8,
}

/// How a profile selects the one association used for transmission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendingAssociation {
    /// RT1: use the row whose zero-based association number equals the ASAP.
    Indexed,
    /// RT2: use that row only when it also names the requested ASAP.
    IndexedChecked,
    /// Use the first row whose ASAP matches the requested object.
    FirstMatch,
}

/// Bounds-checked, ownership-free view of a byte-coded association table.
///
/// A downloaded count is untrusted while ETS writes the table piecemeal. The
/// view therefore clamps it to the number of complete rows present in `data`;
/// no accessor can walk beyond the borrowed slice.
#[derive(Debug, Clone, Copy)]
pub struct BcuAssociationTableView<'a> {
    data: &'a [u8],
}

impl<'a> BcuAssociationTableView<'a> {
    const HEADER_LEN: usize = 1;
    const ENTRY_LEN: usize = 2;

    /// Borrow an encoded table.
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Return the complete encoded bytes supplied to this view.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// Return the leading count octet, or `None` when it is absent.
    pub fn stored_count(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// Return the row count declared by the count octet, before applying the
    /// borrowed slice's physical bound.
    pub fn declared_entry_count(&self) -> u16 {
        u16::from(self.stored_count().unwrap_or(0))
    }

    /// Return the number of complete rows available through this view.
    pub fn entry_count(&self) -> u16 {
        let available = self.data.len().saturating_sub(Self::HEADER_LEN) / Self::ENTRY_LEN;
        self.declared_entry_count().min(available.min(usize::from(u8::MAX)) as u16)
    }

    /// Return a row by its zero-based association number.
    pub fn association(&self, number: u16) -> Option<Association> {
        if number >= self.entry_count() {
            return None;
        }

        let offset = Self::HEADER_LEN + usize::from(number) * Self::ENTRY_LEN;
        Some(Association { tsap: *self.data.get(offset)?, asap: *self.data.get(offset + 1)? })
    }

    /// Iterate the complete rows in association-number order.
    pub fn associations(&self) -> AssociationIter<'a> {
        AssociationIter { table: *self, next: 0 }
    }

    /// Resolve the sending TSAP using the caller's realization-specific rule.
    ///
    /// The RT1/RT2 unused-slot sentinel is rejected under every policy: it is
    /// metadata, not a real TSAP through which an object can transmit.
    pub fn sending_tsap(&self, asap: u8, selection: SendingAssociation) -> Option<u8> {
        let association = match selection {
            SendingAssociation::Indexed => self.association(u16::from(asap)),
            SendingAssociation::IndexedChecked => {
                self.association(u16::from(asap)).filter(|association| association.asap == asap)
            }
            SendingAssociation::FirstMatch => self.associations().find(|association| association.asap == asap),
        }?;

        (association.tsap != UNUSED_SENDING_TSAP).then_some(association.tsap)
    }
}

/// Iterator over the complete rows of a [`BcuAssociationTableView`].
pub struct AssociationIter<'a> {
    table: BcuAssociationTableView<'a>,
    next: u16,
}

impl Iterator for AssociationIter<'_> {
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
    fn walks_zero_based_association_rows() {
        let table = BcuAssociationTableView::new(&[3, 1, 0, 2, 1, 2, 3]);

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
        let table = BcuAssociationTableView::new(&[2, 4, 1, 5, 0]);

        assert_eq!(table.sending_tsap(0, SendingAssociation::Indexed), Some(4));
        assert_eq!(table.sending_tsap(0, SendingAssociation::IndexedChecked), None);
        assert_eq!(table.sending_tsap(0, SendingAssociation::FirstMatch), Some(5));
    }

    #[test]
    fn unused_sending_slot_is_not_a_tsap() {
        let table = BcuAssociationTableView::new(&[1, UNUSED_SENDING_TSAP, 0]);

        assert_eq!(table.sending_tsap(0, SendingAssociation::Indexed), None);
        assert_eq!(table.sending_tsap(0, SendingAssociation::IndexedChecked), None);
        assert_eq!(table.sending_tsap(0, SendingAssociation::FirstMatch), None);
    }

    #[test]
    fn downloaded_count_is_clamped_to_complete_rows() {
        let table = BcuAssociationTableView::new(&[u8::MAX, 1, 0, 2]);

        assert_eq!(table.declared_entry_count(), u16::from(u8::MAX));
        assert_eq!(table.entry_count(), 1);
        assert_eq!(table.association(0), Some(Association { tsap: 1, asap: 0 }));
        assert_eq!(table.association(1), None);
    }

    #[test]
    fn missing_count_is_an_empty_table() {
        let table = BcuAssociationTableView::new(&[]);

        assert_eq!(table.stored_count(), None);
        assert_eq!(table.entry_count(), 0);
        assert_eq!(table.sending_tsap(0, SendingAssociation::FirstMatch), None);
    }
}
