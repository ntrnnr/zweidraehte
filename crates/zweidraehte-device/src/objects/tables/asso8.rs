//! Group Object Association Table — Realisation Type 8
//! (03/05/01 Resources §4.17.6).
//!
//! The System 7 association table. Unlike the group address table it has
//! no fixed location: the management client reads the base address from
//! `PID_TABLE_REFERENCE` (PID 7) of the Association Table interface
//! object (Resources §4.17.6.2), then writes the data with plain
//! `A_Memory_Write`s after an absolute-segment allocation:
//!
//! ```text
//! offset 0             Current Size (number of associations)
//! offset 1 + 2n        TSAP    (association nr. n)
//! offset 2 + 2n        ASAP
//! ```
//!
//! One octet per TSAP and per ASAP, so either identifier is limited to
//! the range 0..=255 by the association-table format itself.
//! The [`AssociationTable`] trait speaks `u16` IDs, so values are
//! zero-extended on the way out and the write path never has to narrow
//! (ETS cannot express a wider ID in this format to begin with).
//!
//! Resources §4.17.6 specifies RT8's format and location but no sending
//! lookup rule. The System 7 adapter uses the compact table ETS writes for
//! mask 0705 and selects the first row naming the requested ASAP; unlike RT6,
//! a zero count does not invent an identity association.

use const_default::ConstDefault;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zweidraehte_proto::tables::association::{BcuAssociationTableView, SendingAssociation};

use super::{AbsoluteAlloc, AssociationTable, Table, TableMemory};

#[serde_as]
#[derive(Debug, Clone, ConstDefault, Serialize, Deserialize)]
pub struct AssoTab8Impl<const N: usize> {
    #[serde_as(as = "[_; N]")]
    data: [u8; N],
}

impl<const N: usize> Table<AssoTab8Impl<N>, AbsoluteAlloc> {
    fn view(&self) -> BcuAssociationTableView<'_> {
        BcuAssociationTableView::new(&self.table.data)
    }

    /// Get the TSAP at the given **1-based** index.
    ///
    /// Returns `None` for index 0 or beyond [`entry_count`](AssociationTable::entry_count).
    pub fn tsap(&self, idx: u16) -> Option<u16> {
        let number = idx.checked_sub(1)?;
        self.view().association(number).map(|association| u16::from(association.tsap))
    }

    /// Get the ASAP at the given **1-based** index.
    ///
    /// Returns `None` for index 0 or beyond [`entry_count`](AssociationTable::entry_count).
    pub fn asap(&self, idx: u16) -> Option<u16> {
        let number = idx.checked_sub(1)?;
        self.view().association(number).map(|association| u16::from(association.asap))
    }
}

impl<const N: usize> TableMemory for AssoTab8Impl<N> {
    const MAX_SIZE: usize = N;
    fn data_ref(&self) -> &[u8] {
        &self.data
    }
    fn data_ref_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<const N: usize> AssociationTable for Table<AssoTab8Impl<N>, AbsoluteAlloc> {
    fn max_entries(&self) -> usize {
        N.saturating_sub(1) / 2
    }

    fn entry_count(&self) -> u16 {
        self.view().entry_count()
    }

    /// Gets the sending TSAP for a given ASAP
    ///
    /// Returns `Some(tsap)` if a match is found, `None` otherwise.
    fn sending_tsap(&self, asap: u16) -> Option<u16> {
        trace!("Finding sending TSAP for ASAP {}", asap);
        let asap = u8::try_from(asap).ok()?;
        let tsap = self.view().sending_tsap(asap, SendingAssociation::FirstMatch).map(u16::from);
        trace!("Sending TSAP for ASAP {}: {:?}", asap, tsap);
        tsap
    }

    /// Iterator over all TSAPs associated with a given ASAP
    fn tsaps_for_asap(&self, asap: u16) -> impl Iterator<Item = u16> + '_ {
        let asap = u8::try_from(asap).ok();
        self.view()
            .associations()
            .filter(move |association| Some(association.asap) == asap)
            .map(|association| u16::from(association.tsap))
    }

    /// Iterator over all ASAPs associated with a given TSAP
    fn asaps_for_tsap(&self, tsap: u16) -> impl Iterator<Item = u16> + '_ {
        let tsap = u8::try_from(tsap).ok();
        self.view()
            .associations()
            .filter(move |association| Some(association.tsap) == tsap)
            .map(|association| u16::from(association.asap))
    }
}

// GrOAT Type 8: 1-byte count header + MAX_ENTRIES × 2-byte entries (TSAP u8 + ASAP u8)
pub type AssoTab8<const MAX_ENTRIES: usize> = Table<AssoTab8Impl<{ 1 + MAX_ENTRIES * 2 }>, AbsoluteAlloc>;

#[cfg(test)]
mod test {
    use crate::objects::tables::{AssociationTable, HasLoadStateMachine, LoadEvent, LoadState, TableMemory};

    use super::AssoTab8;

    /// Build a loaded table via the System 7 download shape: absolute
    /// allocation at an ETS-chosen address, then memory writes.
    ///
    /// Associations: TSAP 1 → ASAP 1, TSAP 1 → ASAP 3, TSAP 2 → ASAP 2.
    fn loaded_table() -> AssoTab8<10> {
        let mut ast = AssoTab8::<10>::new();

        ast.write_lsm(&[LoadEvent::StartLoading.into()], None);
        // AllocAbsDataSeg at 4100h, 7 bytes.
        ast.write_lsm(
            &[LoadEvent::AdditionalLoadControls.into(), 0x00, 0x41, 0x00, 0x00, 0x07, 0xFF, 0x03, 0x80, 0x00],
            None,
        );

        ast.write(0, &[3]);
        ast.write(1, &[1, 1]);
        ast.write(3, &[1, 3]);
        ast.write(5, &[2, 2]);

        ast.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
        assert_eq!(ast.read_lsm(), [u8::from(LoadState::Loaded)]);
        assert_eq!(ast.table_reference(), 0x4100);
        ast
    }

    #[test]
    fn asso8_sending_tsap() {
        let ast = loaded_table();
        assert_eq!(ast.sending_tsap(1), Some(1));
        assert_eq!(ast.sending_tsap(2), Some(2));
        assert_eq!(ast.sending_tsap(3), Some(1));
        assert_eq!(ast.sending_tsap(4), None);
    }

    #[test]
    fn asso8_multi_asap_per_tsap_iteration() {
        let ast = loaded_table();
        let asaps: heapless::Vec<u16, 4> = ast.asaps_for_tsap(1).collect();
        assert_eq!(&asaps[..], &[1, 3]);

        let tsaps: heapless::Vec<u16, 4> = ast.tsaps_for_asap(2).collect();
        assert_eq!(&tsaps[..], &[2]);

        assert_eq!(ast.asaps_for_tsap(9).count(), 0);
    }

    /// RT6 defines an identity fallback for its property table, but RT8 does
    /// not. A zero-sized byte table therefore contains no association.
    #[test]
    fn asso8_empty_table_has_no_mapping() {
        let ast = AssoTab8::<10>::new();
        assert_eq!(ast.entry_count(), 0);
        assert_eq!(ast.sending_tsap(5), None);
        let tsaps: heapless::Vec<u16, 4> = ast.tsaps_for_asap(7).collect();
        assert!(tsaps.is_empty());
    }

    /// A corrupt count byte larger than the physical capacity must be
    /// clamped, not walk past the buffer.
    #[test]
    fn asso8_count_byte_is_clamped() {
        let mut ast = AssoTab8::<10>::new();
        ast.write(0, &[0xFF]);
        assert_eq!(ast.entry_count(), 10);
        assert_eq!(ast.tsap(10), Some(0));
        assert_eq!(ast.tsap(11), None);
    }
}
