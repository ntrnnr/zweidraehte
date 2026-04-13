use const_default::ConstDefault;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use zerocopy::big_endian::U16;

use super::{AssociationTable, Table, TableMemory};

#[serde_as]
#[derive(Debug, Clone, ConstDefault, Serialize, Deserialize)]
pub struct AssoTab6Impl<const N: usize> {
    #[serde_as(as = "[_; N]")]
    data: [u8; N],
}

impl<const N: usize> Table<AssoTab6Impl<N>> {
    /// Get the TSAP (Transport Service Access Point) at the given index.
    /// Index is 1-based.
    pub fn tsap(&self, idx: u16) -> u16 {
        // NOTE: idx is 1-indexed!
        // Format: [count_h, count_l, tsap1_h, tsap1_l, asap1_h, asap1_l, tsap2_h, tsap2_l, asap2_h, asap2_l, ...]
        // Each entry is 4 bytes: TSAP (2 bytes) + ASAP (2 bytes)
        let start = 2 + ((idx as usize) - 1) * 4;
        U16::from_bytes(self.table.data[start..start + 2].try_into().unwrap()).get()
    }

    /// Get the ASAP (Application Service Access Point) at the given index.
    /// Index is 1-based.
    pub fn asap(&self, idx: u16) -> u16 {
        // NOTE: idx is 1-indexed!
        // Format: [count_h, count_l, tsap1_h, tsap1_l, asap1_h, asap1_l, tsap2_h, tsap2_l, asap2_h, asap2_l, ...]
        // Each entry is 4 bytes: TSAP (2 bytes) + ASAP (2 bytes)
        let start = 2 + ((idx as usize) - 1) * 4 + 2;
        U16::from_bytes(self.table.data[start..start + 2].try_into().unwrap()).get()
    }

    /// Find the next ASAP number associated with a given TSAP
    ///
    /// This iterates through the association table entries starting from `start_idx`
    /// and finds the next entry where the TSAP matches the given connection number.
    ///
    /// Returns `Some((asap, idx))` with the found ASAP and its index if found,
    /// or `None` if no matching entry is found.
    ///
    /// When the table is empty, it assumes a default mapping where ASAP = TSAP.
    fn find_next_asap(&self, tsap: u16, start_idx: &mut u16) -> Option<(u16, u16)> {
        let count = self.entry_count();

        if count > 0 {
            // Search through the table for entries matching the TSAP
            while *start_idx < count {
                *start_idx += 1;

                if self.tsap(*start_idx) == tsap {
                    // Found a match, return the associated ASAP
                    return Some((self.asap(*start_idx), *start_idx));
                }
            }

            // No match found
            None
        } else {
            // Table is empty, assume default table where ASAP = TSAP
            if *start_idx == 0 {
                *start_idx = 1;
                return Some((tsap, 1));
            }

            None
        }
    }

    /// Find the next TSAP associated with a given ASAP
    ///
    /// Iterates through the association table entries starting from `start_idx`
    /// and finds the next entry where the ASAP matches the given number.
    ///
    /// Returns `Some((tsap, idx))` with the found TSAP and its index if found,
    /// or `None` if no matching entry is found.
    ///
    /// When the table is empty, it assumes a default mapping where TSAP = ASAP.
    fn find_next_tsap(&self, asap: u16, start_idx: &mut u16) -> Option<(u16, u16)> {
        let count = self.entry_count();

        if count > 0 {
            // Search through the table for entries matching the ASAP
            while *start_idx < count {
                *start_idx += 1;

                if self.asap(*start_idx) == asap {
                    // Found a match, return the associated TSAP
                    return Some((self.tsap(*start_idx), *start_idx));
                }
            }

            // No match found
            None
        } else {
            // Table is empty, assume default table where TSAP = ASAP
            if *start_idx == 0 {
                *start_idx = 1;
                return Some((asap, 1));
            }

            None
        }
    }

    // /// Gets the association index for a given ASAP
    // ///
    // /// Returns `Some(index)` with the first association index where ASAP matches,
    // /// or `None` if no match is found.
    // ///
    // /// When the table is empty, it assumes a default mapping and returns index 0.
    // pub fn get_association_index_for_asap(&self, asap: u16) -> Option<usize> {
    //     let count = self.entry_count() as usize;

    //     if count > 0 {
    //         // Search through the table for an entry matching the ASAP
    //         for i in 1..=count {
    //             if self.asap(i) == asap + 1 {
    //                 return Some(i);
    //             }
    //         }

    //         // No match found
    //         None
    //     } else {
    //         // Table is empty, assume default table
    //         Some(0)
    //     }
    // }
}

/// Iterator for TSAPs associated with a given ASAP
pub struct TsapIterator<'a, const N: usize> {
    table: &'a Table<AssoTab6Impl<N>>,
    asap: u16,
    current_idx: u16,
}

impl<'a, const N: usize> Iterator for TsapIterator<'a, N> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some((tsap, _)) = self.table.find_next_tsap(self.asap, &mut self.current_idx) {
            Some(tsap)
        } else {
            None
        }
    }
}

/// Iterator for ASAPs associated with a given TSAP
pub struct AsapIterator<'a, const N: usize> {
    table: &'a Table<AssoTab6Impl<N>>,
    tsap: u16,
    current_idx: u16,
}

impl<'a, const N: usize> Iterator for AsapIterator<'a, N> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some((asap, _)) = self.table.find_next_asap(self.tsap, &mut self.current_idx) {
            Some(asap)
        } else {
            None
        }
    }
}

impl<const N: usize> TableMemory for AssoTab6Impl<N> {
    fn max_size() -> usize {
        N
    }
    fn data_ref(&self) -> &[u8] {
        &self.data
    }
    fn data_ref_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<const N: usize> AssociationTable for Table<AssoTab6Impl<N>> {
    fn max_entries(&self) -> usize {
        (N - 2) / 4
    }

    fn entry_count(&self) -> u16 {
        U16::from_bytes(self.table.data[0..2].try_into().unwrap()).get()
    }

    /// Gets the sending TSAP for a given ASAP
    ///
    /// Returns `Some(tsap)` if a match is found, `None` otherwise.
    /// When the table is empty, it assumes a default mapping where TSAP == ASAP.
    fn get_sending_tsap(&self, asap: u16) -> Option<u16> {
        trace!("Finding sending TSAP for ASAP {}", asap);

        let count = self.entry_count();

        if count == 0 {
            // Table is empty, assume default table where TSAP == ASAP
            trace!("Table is empty, assuming default TSAP {} for ASAP {}", asap, asap);
            return Some(asap);
        }

        // Find the first association where ASAP matches
        for i in 1..=count {
            if self.asap(i) == asap {
                let tsap = self.tsap(i);
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

// GrOAT Type 6 Style 1: 2-byte count header + MAX_ENTRIES × 4-byte entries (TSAP u16 + ASAP u16)
pub type AssoTab6<const MAX_ENTRIES: usize> = Table<AssoTab6Impl<{ 2 + MAX_ENTRIES * 4 }>>;

#[cfg(test)]
mod test {
    use crate::objects::tables::{AssociationTable, HasLoadStateMachine, LoadEvent, LoadState, TableMemory};

    use super::AssoTab6;

    #[test]
    fn asso6_tab_alloc_load() {
        // Test the basic loading process of an association table
        let mut ast = AssoTab6::<10>::new();

        // Should start unloaded
        assert_eq!(ast.read_lsm(), [LoadState::Unloaded.into()]);

        // Begin loading
        ast.write_lsm(&[LoadEvent::StartLoading.into()], None);
        assert_eq!(ast.read_lsm(), [LoadState::Loading.into()]);

        // Allocate a table with space for 2 entries (4 words total including length field)
        ast.write_lsm(
            &[
                LoadEvent::AdditionalLoadControls.into(),
                0x0B,
                0x00,
                0x00,
                0x00,
                0x08, // 8 bytes total
                0x01,
                0xff,
                0x00,
                0x00,
            ],
            None,
        );
        assert_eq!(ast.read_lsm(), [LoadState::Loading.into()]);
        assert_eq!(&ast.data_ref()[0..8], &[0xff; 8]);

        // Write data into the table:
        // - First 2 bytes: count = 2
        // - Entry 1: TSAP = 1, ASAP = 2
        // - Entry 2: TSAP = 3, ASAP = 4
        ast.write(0, &[0x00, 0x02]); // Length: 2 entries
        ast.write(2, &[0x00, 0x01]); // Entry 1: TSAP = 1
        ast.write(4, &[0x00, 0x02]); // Entry 1: ASAP = 2
        ast.write(6, &[0x00, 0x03]); // Entry 2: TSAP = 3
        ast.write(8, &[0x00, 0x04]); // Entry 2: ASAP = 4

        // Verify raw table contents
        assert_eq!(&ast.data_ref()[0..10], &[0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04]);

        // Issue load complete
        ast.write_lsm(&[LoadEvent::LoadCompleted.into()], None);
        assert_eq!(ast.read_lsm(), [LoadState::Loaded.into()]);
    }

    #[test]
    fn asso6_empty_table() {
        // Test behavior with an empty table (default mappings)
        let mut ast = AssoTab6::<10>::new();

        // Setup an empty table (length = 0)
        ast.write_lsm(&[LoadEvent::StartLoading.into()], None);
        ast.write_lsm(
            &[
                LoadEvent::AdditionalLoadControls.into(),
                0x0B,
                0x00,
                0x00,
                0x00,
                0x02, // 2 bytes for the length field only
                0x01,
                0xff,
                0x00,
                0x00,
            ],
            None,
        );
        ast.write(0, &[0x00, 0x00]); // Length: 0 entries
        ast.write_lsm(&[LoadEvent::LoadCompleted.into()], None);

        assert_eq!(ast.entry_count(), 0);
        assert!(ast.is_empty());

        // Test default mappings with empty table

        // Check TSAP → ASAP mapping: ASAP = TSAP
        let mut idx = 0;
        assert_eq!(ast.find_next_asap(5, &mut idx), Some((5, 1)));
        assert_eq!(idx, 1);
        assert_eq!(ast.find_next_asap(5, &mut idx), None);

        // Check ASAP → TSAP mapping
        idx = 0;
        assert_eq!(ast.find_next_tsap(7, &mut idx), Some((7, 1)));
        assert_eq!(idx, 1);
        assert_eq!(ast.find_next_tsap(7, &mut idx), None);

        // Check tsaps_for_asap
        assert_eq!(ast.tsaps_for_asap(10).next(), Some(10));

        // // Check get_association_index_for_asap
        // assert_eq!(ast.get_association_index_for_asap(3), Some(0));

        // Check iterators with empty table
        assert_eq!(ast.tsaps_for_asap(12).collect::<Vec<_>>(), vec![12]);
        assert_eq!(ast.asaps_for_tsap(9).collect::<Vec<_>>(), vec![9]);
    }

    #[test]
    fn asso6_find_next_asap() {
        // Test the find_next_asap function with a non-empty table
        let mut ast = AssoTab6::<20>::new();

        // Setup table with multiple mappings:
        // TSAP 1 → ASAP 2
        // TSAP 3 → ASAP 4
        // TSAP 5 → ASAP 6
        // TSAP 5 → ASAP 7 (multiple ASAPs for same TSAP)
        ast.write_lsm(&[LoadEvent::StartLoading.into()], None);
        ast.write_lsm(
            &[LoadEvent::AdditionalLoadControls.into(), 0x0B, 0x00, 0x00, 0x00, 0x10, 0x01, 0xff, 0x00, 0x00],
            None,
        );
        ast.write(0, &[0x00, 0x04]); // 4 entries
        ast.write(2, &[0x00, 0x01]); // Entry 1: TSAP = 1
        ast.write(4, &[0x00, 0x02]); // Entry 1: ASAP = 2
        ast.write(6, &[0x00, 0x03]); // Entry 2: TSAP = 3
        ast.write(8, &[0x00, 0x04]); // Entry 2: ASAP = 4
        ast.write(10, &[0x00, 0x05]); // Entry 3: TSAP = 5
        ast.write(12, &[0x00, 0x06]); // Entry 3: ASAP = 6
        ast.write(14, &[0x00, 0x05]); // Entry 4: TSAP = 5 (duplicate)
        ast.write(16, &[0x00, 0x07]); // Entry 4: ASAP = 7
        ast.write_lsm(&[LoadEvent::LoadCompleted.into()], None);

        // Test finding ASAPs for TSAP 5 (which has multiple ASAPs)
        let mut idx = 0;
        assert_eq!(ast.find_next_asap(5, &mut idx), Some((6, 3))); // First ASAP (idx=3)
        assert_eq!(ast.find_next_asap(5, &mut idx), Some((7, 4))); // Second ASAP (idx=4)
        assert_eq!(ast.find_next_asap(5, &mut idx), None); // No more ASAPs

        // Test finding ASAP for TSAP 1 (which has one ASAP)
        idx = 0;
        assert_eq!(ast.find_next_asap(1, &mut idx), Some((2, 1))); // First ASAP (idx=1)
        assert_eq!(ast.find_next_asap(1, &mut idx), None); // No more ASAPs

        // Test finding ASAP for TSAP 9 (which doesn't exist in table)
        idx = 0;
        assert_eq!(ast.find_next_asap(9, &mut idx), None); // No ASAPs
    }

    #[test]
    fn asso6_find_next_tsap() {
        // Test the find_next_tsap function with a non-empty table
        let mut ast = AssoTab6::<20>::new();

        // Setup table with multiple mappings:
        // ASAP 1 ← TSAP 2
        // ASAP 3 ← TSAP 4
        // ASAP 5 ← TSAP 6
        // ASAP 5 ← TSAP 7 (multiple TSAPs for same ASAP)
        ast.write_lsm(&[LoadEvent::StartLoading.into()], None);
        ast.write_lsm(
            &[LoadEvent::AdditionalLoadControls.into(), 0x0B, 0x00, 0x00, 0x00, 0x10, 0x01, 0xff, 0x00, 0x00],
            None,
        );
        ast.write(0, &[0x00, 0x04]); // 4 entries
        ast.write(2, &[0x00, 0x02]); // Entry 1: TSAP = 2
        ast.write(4, &[0x00, 0x02]); // Entry 1: ASAP = 2
        ast.write(6, &[0x00, 0x04]); // Entry 2: TSAP = 4
        ast.write(8, &[0x00, 0x04]); // Entry 2: ASAP = 4
        ast.write(10, &[0x00, 0x06]); // Entry 3: TSAP = 6
        ast.write(12, &[0x00, 0x06]); // Entry 3: ASAP = 6
        ast.write(14, &[0x00, 0x07]); // Entry 4: TSAP = 7
        ast.write(16, &[0x00, 0x06]); // Entry 4: ASAP = 6 (duplicate)
        ast.write_lsm(&[LoadEvent::LoadCompleted.into()], None);

        // Test finding TSAPs for ASAP 6 (which has multiple TSAPs)
        let mut idx = 0;
        assert_eq!(ast.find_next_tsap(6, &mut idx), Some((6, 3))); // First TSAP (idx=3)
        assert_eq!(ast.find_next_tsap(6, &mut idx), Some((7, 4))); // Second TSAP (idx=4)
        assert_eq!(ast.find_next_tsap(6, &mut idx), None); // No more TSAPs

        // Test finding TSAP for ASAP 1 (which has one TSAP)
        idx = 0;
        assert_eq!(ast.find_next_tsap(2, &mut idx), Some((2, 1))); // First TSAP (idx=1)
        assert_eq!(ast.find_next_tsap(2, &mut idx), None); // No more TSAPs

        // Test finding TSAP for ASAP 9 (which doesn't exist in table)
        idx = 0;
        assert_eq!(ast.find_next_tsap(9, &mut idx), None); // No TSAPs
    }

    #[test]
    fn asso6_tsaps_for_asap() {
        // Test the tsaps_for_asap function
        let mut ast = AssoTab6::<20>::new();

        // Setup table with multiple mappings:
        // ASAP 1 ← TSAP 2
        // ASAP 3 ← TSAP 4
        // ASAP 5 ← TSAP 6
        // ASAP 5 ← TSAP 7 (multiple TSAPs for same ASAP - should return first match)
        ast.write_lsm(&[LoadEvent::StartLoading.into()], None);
        ast.write_lsm(
            &[LoadEvent::AdditionalLoadControls.into(), 0x0B, 0x00, 0x00, 0x00, 0x10, 0x01, 0xff, 0x00, 0x00],
            None,
        );
        ast.write(0, &[0x00, 0x04]); // 4 entries
        ast.write(2, &[0x00, 0x02]); // Entry 1: TSAP = 2
        ast.write(4, &[0x00, 0x02]); // Entry 1: ASAP = 2
        ast.write(6, &[0x00, 0x04]); // Entry 2: TSAP = 4
        ast.write(8, &[0x00, 0x04]); // Entry 2: ASAP = 3
        ast.write(10, &[0x00, 0x06]); // Entry 3: TSAP = 6
        ast.write(12, &[0x00, 0x06]); // Entry 3: ASAP = 6
        ast.write(14, &[0x00, 0x07]); // Entry 4: TSAP = 7
        ast.write(16, &[0x00, 0x06]); // Entry 4: ASAP = 6 (duplicate)
        ast.write_lsm(&[LoadEvent::LoadCompleted.into()], None);

        // Test finding first TSAP for each ASAP
        assert_eq!(ast.tsaps_for_asap(2).next(), Some(2));
        assert_eq!(ast.tsaps_for_asap(4).next(), Some(4));
        assert_eq!(ast.tsaps_for_asap(6).next(), Some(6)); // Returns first match

        // Test finding TSAP for non-existent ASAP
        assert_eq!(ast.tsaps_for_asap(10).next(), None);
    }

    // #[test]
    // fn asso6_get_association_index() {
    //     // Test the get_association_index_for_asap function
    //     let mut ast = AssoTab6::<20>::new();

    //     // Setup table with multiple mappings:
    //     // ASAP 1 ← TSAP 2
    //     // ASAP 3 ← TSAP 4
    //     // ASAP 5 ← TSAP 6
    //     // ASAP 5 ← TSAP 7 (multiple TSAPs for same ASAP - should return first match)
    //     ast.write_lsm(&[LoadEvent::StartLoading.into()], None);
    //     ast.write_lsm(&[
    //         LoadEvent::AdditionalLoadControls.into(),
    //         0x0B,
    //         0x00,
    //         0x00,
    //         0x00,
    //         0x10,
    //         0x01,
    //         0xff,
    //         0x00,
    //         0x00,
    //     ], None);
    //     ast.write(0, &[0x00, 0x04]); // 4 entries
    //     ast.write(2, &[0x00, 0x02]); // Entry 1: TSAP = 2
    //     ast.write(4, &[0x00, 0x02]); // Entry 1: ASAP = 1+1 (stored as 2)
    //     ast.write(6, &[0x00, 0x04]); // Entry 2: TSAP = 4
    //     ast.write(8, &[0x00, 0x04]); // Entry 2: ASAP = 3+1 (stored as 4)
    //     ast.write(10, &[0x00, 0x06]); // Entry 3: TSAP = 6
    //     ast.write(12, &[0x00, 0x06]); // Entry 3: ASAP = 5+1 (stored as 6)
    //     ast.write(14, &[0x00, 0x07]); // Entry 4: TSAP = 7
    //     ast.write(16, &[0x00, 0x06]); // Entry 4: ASAP = 5+1 (stored as 6) (duplicate)
    //     ast.write_lsm(&[LoadEvent::LoadCompleted.into()], None);

    //     // Test finding association index for each ASAP
    //     assert_eq!(ast.get_association_index_for_asap(1), Some(1)); // Index for ASAP 1
    //     assert_eq!(ast.get_association_index_for_asap(3), Some(2)); // Index for ASAP 3
    //     assert_eq!(ast.get_association_index_for_asap(5), Some(3)); // Index for first ASAP 5

    //     // Test finding association index for non-existent ASAP
    //     assert_eq!(ast.get_association_index_for_asap(10), None);
    // }

    #[test]
    fn asso6_iterators() {
        // Test the iterator functionality
        let mut ast = AssoTab6::<20>::new();

        // Setup table with multiple mappings:
        // TSAP 1 → ASAP 10, ASAP 11
        // TSAP 2 → ASAP 20
        // TSAP 3 → ASAP 30, ASAP 31, ASAP 32
        ast.write_lsm(&[LoadEvent::StartLoading.into()], None);
        ast.write_lsm(
            &[LoadEvent::AdditionalLoadControls.into(), 0x0B, 0x00, 0x00, 0x00, 0x14, 0x01, 0xff, 0x00, 0x00],
            None,
        );
        ast.write(0, &[0x00, 0x06]); // 6 entries
        // TSAP 1 → ASAP 11
        ast.write(2, &[0x00, 0x01]);
        ast.write(4, &[0x00, 0x0B]); // ASAP 11
        // TSAP 1 → ASAP 12
        ast.write(6, &[0x00, 0x01]);
        ast.write(8, &[0x00, 0x0C]); // ASAP 12
        // TSAP 2 → ASAP 21
        ast.write(10, &[0x00, 0x02]);
        ast.write(12, &[0x00, 0x15]); // ASAP 21
        // TSAP 3 → ASAP 31
        ast.write(14, &[0x00, 0x03]);
        ast.write(16, &[0x00, 0x1F]); // ASAP 31
        // TSAP 3 → ASAP 32
        ast.write(18, &[0x00, 0x03]);
        ast.write(20, &[0x00, 0x20]); // ASAP 32
        // TSAP 3 → ASAP 33
        ast.write(22, &[0x00, 0x03]);
        ast.write(24, &[0x00, 0x21]); // ASAP 33
        ast.write_lsm(&[LoadEvent::LoadCompleted.into()], None);

        // Test ASAP iterator for TSAP 1
        let asaps: Vec<u16> = ast.asaps_for_tsap(1).collect();
        assert_eq!(asaps, vec![11, 12]);

        // Test ASAP iterator for TSAP 2
        let asaps: Vec<u16> = ast.asaps_for_tsap(2).collect();
        assert_eq!(asaps, vec![21]);

        // Test ASAP iterator for TSAP 3
        let asaps: Vec<u16> = ast.asaps_for_tsap(3).collect();
        assert_eq!(asaps, vec![31, 32, 33]);

        // Test ASAP iterator for non-existent TSAP
        let asaps: Vec<u16> = ast.asaps_for_tsap(4).collect();
        assert_eq!(asaps, vec![]);

        // Test TSAP iterator for specific ASAPs
        assert_eq!(ast.tsaps_for_asap(11).collect::<Vec<_>>(), vec![1]);
        assert_eq!(ast.tsaps_for_asap(21).collect::<Vec<_>>(), vec![2]);
        assert_eq!(ast.tsaps_for_asap(31).collect::<Vec<_>>(), vec![3]);

        // Test TSAP iterator for non-existent ASAP
        assert_eq!(ast.tsaps_for_asap(40).collect::<Vec<_>>(), vec![]);
    }
}
