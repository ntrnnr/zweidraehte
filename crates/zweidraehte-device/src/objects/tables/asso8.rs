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
//! One octet per TSAP and per ASAP — an RT8 device is capped at 255
//! group addresses and 255 group objects by the table format itself.
//! The [`AssociationTable`] trait speaks `u16` IDs, so values are
//! zero-extended on the way out and the write path never has to narrow
//! (ETS cannot express a wider ID in this format to begin with).

use const_default::ConstDefault;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::{AbsoluteAlloc, AssociationTable, Table, TableMemory};

#[serde_as]
#[derive(Debug, Clone, ConstDefault, Serialize, Deserialize)]
pub struct AssoTab8Impl<const N: usize> {
    #[serde_as(as = "[_; N]")]
    data: [u8; N],
}

impl<const N: usize> Table<AssoTab8Impl<N>, AbsoluteAlloc> {
    /// Get the TSAP at the given **1-based** index.
    ///
    /// Returns `None` for index 0 or beyond [`entry_count`](AssociationTable::entry_count).
    pub fn tsap(&self, idx: u16) -> Option<u16> {
        if idx == 0 || idx > self.entry_count() {
            return None;
        }
        // Format: [count, tsap1, asap1, tsap2, asap2, ...] — 2 bytes per entry.
        Some(self.table.data[1 + ((idx as usize) - 1) * 2] as u16)
    }

    /// Get the ASAP at the given **1-based** index.
    ///
    /// Returns `None` for index 0 or beyond [`entry_count`](AssociationTable::entry_count).
    pub fn asap(&self, idx: u16) -> Option<u16> {
        if idx == 0 || idx > self.entry_count() {
            return None;
        }
        Some(self.table.data[2 + ((idx as usize) - 1) * 2] as u16)
    }

    /// Find the next ASAP associated with a given TSAP, scanning from
    /// `start_idx`. Empty table assumes the default mapping ASAP = TSAP,
    /// as in [`AssoTab6`](super::asso6::AssoTab6).
    fn find_next_asap(&self, tsap: u16, start_idx: &mut u16) -> Option<(u16, u16)> {
        let count = self.entry_count();

        if count > 0 {
            while *start_idx < count {
                *start_idx += 1;

                if self.tsap(*start_idx) == Some(tsap) {
                    let asap = self.asap(*start_idx).expect("idx stays within entry_count");
                    return Some((asap, *start_idx));
                }
            }

            None
        } else {
            if *start_idx == 0 {
                *start_idx = 1;
                return Some((tsap, 1));
            }

            None
        }
    }

    /// Find the next TSAP associated with a given ASAP, scanning from
    /// `start_idx`. Empty table assumes the default mapping TSAP = ASAP.
    fn find_next_tsap(&self, asap: u16, start_idx: &mut u16) -> Option<(u16, u16)> {
        let count = self.entry_count();

        if count > 0 {
            while *start_idx < count {
                *start_idx += 1;

                if self.asap(*start_idx) == Some(asap) {
                    let tsap = self.tsap(*start_idx).expect("idx stays within entry_count");
                    return Some((tsap, *start_idx));
                }
            }

            None
        } else {
            if *start_idx == 0 {
                *start_idx = 1;
                return Some((asap, 1));
            }

            None
        }
    }
}

/// Iterator for TSAPs associated with a given ASAP
pub struct TsapIterator<'a, const N: usize> {
    table: &'a Table<AssoTab8Impl<N>, AbsoluteAlloc>,
    asap: u16,
    current_idx: u16,
}

impl<'a, const N: usize> Iterator for TsapIterator<'a, N> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        self.table.find_next_tsap(self.asap, &mut self.current_idx).map(|(tsap, _)| tsap)
    }
}

/// Iterator for ASAPs associated with a given TSAP
pub struct AsapIterator<'a, const N: usize> {
    table: &'a Table<AssoTab8Impl<N>, AbsoluteAlloc>,
    tsap: u16,
    current_idx: u16,
}

impl<'a, const N: usize> Iterator for AsapIterator<'a, N> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        self.table.find_next_asap(self.tsap, &mut self.current_idx).map(|(asap, _)| asap)
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
        (N - 1) / 2
    }

    fn entry_count(&self) -> u16 {
        // The count is bus-downloaded data and must not exceed physical capacity.
        (self.table.data[0] as u16).min(self.max_entries() as u16)
    }

    /// Gets the sending TSAP for a given ASAP
    ///
    /// Returns `Some(tsap)` if a match is found, `None` otherwise.
    /// When the table is empty, it assumes a default mapping where TSAP == ASAP.
    fn sending_tsap(&self, asap: u16) -> Option<u16> {
        trace!("Finding sending TSAP for ASAP {}", asap);

        let count = self.entry_count();

        if count == 0 {
            trace!("Table is empty, assuming default TSAP {} for ASAP {}", asap, asap);
            return Some(asap);
        }

        for i in 1..=count {
            if self.asap(i) == Some(asap) {
                let tsap = self.tsap(i).expect("idx stays within entry_count");
                trace!("Found sending TSAP {} for ASAP {}", tsap, asap);
                return Some(tsap);
            }
        }

        trace!("No sending TSAP found for ASAP {}", asap);
        None
    }

    /// Iterator over all TSAPs associated with a given ASAP
    fn tsaps_for_asap(&self, asap: u16) -> impl Iterator<Item = u16> + '_ {
        TsapIterator { table: self, asap, current_idx: 0 }
    }

    /// Iterator over all ASAPs associated with a given TSAP
    fn asaps_for_tsap(&self, tsap: u16) -> impl Iterator<Item = u16> + '_ {
        AsapIterator { table: self, tsap, current_idx: 0 }
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
        assert_eq!(ast.read_lsm(), [LoadState::Loaded.into()]);
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

    /// An empty table falls back to the identity mapping, matching the
    /// RT6 implementation's behaviour.
    #[test]
    fn asso8_empty_table_identity_mapping() {
        let ast = AssoTab8::<10>::new();
        assert_eq!(ast.entry_count(), 0);
        assert_eq!(ast.sending_tsap(5), Some(5));
        let tsaps: heapless::Vec<u16, 4> = ast.tsaps_for_asap(7).collect();
        assert_eq!(&tsaps[..], &[7]);
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
