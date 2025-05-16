use const_default::ConstDefault;
use zerocopy::big_endian::U16;

use super::{Table, TableMemory};

#[derive(Debug, ConstDefault)]
pub struct AssoTab6Impl<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> Table<AssoTab6Impl<N>> {
    pub fn max_entries(&self) -> usize {
        (N / 2) - 1
    }

    pub fn entry_count(&self) -> u16 {
        U16::from_bytes(self.table.data[0..2].try_into().unwrap()).get()
    }

    pub fn tsap(&self, idx: usize) -> u16 {
        // NOTE: idx is 1-indexed!
        let start = (2 * (idx - 1) + 1) * 2;
        U16::from_bytes(self.table.data[start..start + 2].try_into().unwrap()).get()
    }

    pub fn asap(&self, idx: usize) -> u16 {
        // NOTE: idx is 1-indexed!
        let start = (2 * (idx - 1) + 2) * 2;
        U16::from_bytes(self.table.data[start..start + 2].try_into().unwrap()).get()
    }

    /// Check if the association table is empty
    pub fn is_empty(&self) -> bool {
        self.entry_count() == 0
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
    pub fn find_next_asap(&self, tsap: u16, start_idx: &mut usize) -> Option<(u16, usize)> {
        let count = self.entry_count() as usize;

        if count > 0 {
            // Search through the table for entries matching the TSAP
            while *start_idx < count {
                *start_idx += 1;

                if self.tsap(*start_idx) == tsap {
                    // Found a match, return the associated ASAP
                    // Subtract 1 to match the C implementation's behavior (AST_GetTabVal(...) - 1)
                    return Some((self.asap(*start_idx) - 1, *start_idx));
                }
            }

            // No match found
            None
        } else {
            // Table is empty, assume default table where ASAP = TSAP
            if *start_idx == 0 {
                *start_idx = 1;
                // Subtract 1 to match the C implementation's behavior
                return Some((tsap - 1, 1));
            }

            None
        }
    }

    /// Gets the sending TSAP for a given ASAP
    ///
    /// Returns `Some(tsap)` if a match is found, `None` otherwise.
    /// When the table is empty, it assumes a default mapping where TSAP = ASAP + 1.
    pub fn get_tsap_for_asap(&self, asap: u16) -> Option<u16> {
        let count = self.entry_count() as usize;

        if count == 0 {
            // Table is empty, assume default table where TSAP = ASAP + 1
            return Some(asap + 1);
        }

        // Find the first association where ASAP matches (asap + 1 since table stores 1-indexed values)
        for i in 1..=count {
            if self.asap(i) == asap + 1 {
                return Some(self.tsap(i));
            }
        }

        None
    }

    /// Find the next TSAP associated with a given ASAP
    ///
    /// Iterates through the association table entries starting from `start_idx`
    /// and finds the next entry where the ASAP matches the given number.
    ///
    /// Returns `Some((tsap, idx))` with the found TSAP and its index if found,
    /// or `None` if no matching entry is found.
    ///
    /// When the table is empty, it assumes a default mapping where TSAP = ASAP + 1.
    pub fn find_next_tsap(&self, asap: u16, start_idx: &mut usize) -> Option<(u16, usize)> {
        let count = self.entry_count() as usize;

        if count > 0 {
            // Search through the table for entries matching the ASAP
            while *start_idx < count {
                *start_idx += 1;

                if self.asap(*start_idx) == asap + 1 {
                    // Found a match, return the associated TSAP
                    return Some((self.tsap(*start_idx), *start_idx));
                }
            }

            // No match found
            None
        } else {
            // Table is empty, assume default table where TSAP = ASAP + 1
            if *start_idx == 0 {
                *start_idx = 1;
                return Some((asap + 1, 1));
            }

            None
        }
    }

    /// Gets the association index for a given ASAP
    ///
    /// Returns `Some(index)` with the first association index where ASAP matches,
    /// or `None` if no match is found.
    ///
    /// When the table is empty, it assumes a default mapping and returns index 0.
    pub fn get_association_index_for_asap(&self, asap: u16) -> Option<usize> {
        let count = self.entry_count() as usize;

        if count > 0 {
            // Search through the table for an entry matching the ASAP
            for i in 1..=count {
                if self.asap(i) == asap + 1 {
                    return Some(i);
                }
            }

            // No match found
            None
        } else {
            // Table is empty, assume default table
            Some(0)
        }
    }

    /// Iterator over all TSAPs associated with a given ASAP
    pub fn tsaps_for_asap(&self, asap: u16) -> impl Iterator<Item = u16> + '_ {
        TsapIterator {
            table: self,
            asap,
            current_idx: 0,
        }
    }

    /// Iterator over all ASAPs associated with a given TSAP
    pub fn asaps_for_tsap(&self, tsap: u16) -> impl Iterator<Item = u16> + '_ {
        AsapIterator {
            table: self,
            tsap,
            current_idx: 0,
        }
    }

    // TODO: implement further methods we need like for example an iterator to go from a TSAP to all ASAPs and other things we need
}

/// Iterator for TSAPs associated with a given ASAP
pub struct TsapIterator<'a, const N: usize> {
    table: &'a Table<AssoTab6Impl<N>>,
    asap: u16,
    current_idx: usize,
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
    current_idx: usize,
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

    fn read(&self, offset: usize, data: &mut [u8]) {
        data.copy_from_slice(&self.data[offset..offset + data.len()]);
    }

    fn write(&mut self, offset: usize, data: &[u8]) {
        self.data[offset..offset + data.len()].copy_from_slice(data);
    }
}

pub type AssoTab6<const MAX_ENTRIES: usize> = Table<AssoTab6Impl<{ (MAX_ENTRIES + 1) * 2 }>>;

#[cfg(test)]
mod test {
    use crate::objects::tables::{LoadEvent, LoadState, LoadableTable, TableMemory};

    use super::AssoTab6;

    #[test]
    fn asso6_tab_alloc_load() {
        // Test the basic loading process of an association table
        let mut ast = AssoTab6::<10>::new();

        // Should start unloaded
        assert_eq!(ast.read_lsm(), [LoadState::Unloaded.into()]);

        // Begin loading
        ast.write_lsm(&[LoadEvent::StartLoading.into()]);
        assert_eq!(ast.read_lsm(), [LoadState::Loading.into()]);

        // Allocate a table with space for 2 entries (4 words total including length field)
        ast.write_lsm(&[
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
        ]);
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
        assert_eq!(
            &ast.data_ref()[0..10],
            &[0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04]
        );

        // Issue load complete
        ast.write_lsm(&[LoadEvent::LoadCompleted.into()]);
        assert_eq!(ast.read_lsm(), [LoadState::Loaded.into()]);
    }

    #[test]
    fn asso6_empty_table() {
        // Test behavior with an empty table (default mappings)
        let mut ast = AssoTab6::<10>::new();

        // Setup an empty table (length = 0)
        ast.write_lsm(&[LoadEvent::StartLoading.into()]);
        ast.write_lsm(&[
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
        ]);
        ast.write(0, &[0x00, 0x00]); // Length: 0 entries
        ast.write_lsm(&[LoadEvent::LoadCompleted.into()]);

        assert_eq!(ast.entry_count(), 0);
        assert!(ast.is_empty());

        // Test default mappings with empty table

        // Check TSAP → ASAP mapping: ASAP = TSAP - 1
        let mut idx = 0;
        assert_eq!(ast.find_next_asap(5, &mut idx), Some((4, 1)));
        assert_eq!(idx, 1);
        assert_eq!(ast.find_next_asap(5, &mut idx), None);

        // Check ASAP → TSAP mapping: TSAP = ASAP + 1
        idx = 0;
        assert_eq!(ast.find_next_tsap(7, &mut idx), Some((8, 1)));
        assert_eq!(idx, 1);
        assert_eq!(ast.find_next_tsap(7, &mut idx), None);

        // Check get_tsap_for_asap
        assert_eq!(ast.get_tsap_for_asap(10), Some(11));

        // Check get_association_index_for_asap
        assert_eq!(ast.get_association_index_for_asap(3), Some(0));

        // Check iterators with empty table
        assert_eq!(ast.tsaps_for_asap(12).collect::<Vec<_>>(), vec![13]);
        assert_eq!(ast.asaps_for_tsap(9).collect::<Vec<_>>(), vec![8]);
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
        ast.write_lsm(&[LoadEvent::StartLoading.into()]);
        ast.write_lsm(&[
            LoadEvent::AdditionalLoadControls.into(),
            0x0B,
            0x00,
            0x00,
            0x00,
            0x10,
            0x01,
            0xff,
            0x00,
            0x00,
        ]);
        ast.write(0, &[0x00, 0x04]); // 4 entries
        ast.write(2, &[0x00, 0x01]); // Entry 1: TSAP = 1
        ast.write(4, &[0x00, 0x02]); // Entry 1: ASAP = 2
        ast.write(6, &[0x00, 0x03]); // Entry 2: TSAP = 3
        ast.write(8, &[0x00, 0x04]); // Entry 2: ASAP = 4
        ast.write(10, &[0x00, 0x05]); // Entry 3: TSAP = 5
        ast.write(12, &[0x00, 0x06]); // Entry 3: ASAP = 6
        ast.write(14, &[0x00, 0x05]); // Entry 4: TSAP = 5 (duplicate)
        ast.write(16, &[0x00, 0x07]); // Entry 4: ASAP = 7
        ast.write_lsm(&[LoadEvent::LoadCompleted.into()]);

        // Test finding ASAPs for TSAP 5 (which has multiple ASAPs)
        let mut idx = 0;
        assert_eq!(ast.find_next_asap(5, &mut idx), Some((5, 3))); // First ASAP (idx=3)
        assert_eq!(ast.find_next_asap(5, &mut idx), Some((6, 4))); // Second ASAP (idx=4)
        assert_eq!(ast.find_next_asap(5, &mut idx), None); // No more ASAPs

        // Test finding ASAP for TSAP 1 (which has one ASAP)
        idx = 0;
        assert_eq!(ast.find_next_asap(1, &mut idx), Some((1, 1))); // First ASAP (idx=1)
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
        ast.write_lsm(&[LoadEvent::StartLoading.into()]);
        ast.write_lsm(&[
            LoadEvent::AdditionalLoadControls.into(),
            0x0B,
            0x00,
            0x00,
            0x00,
            0x10,
            0x01,
            0xff,
            0x00,
            0x00,
        ]);
        ast.write(0, &[0x00, 0x04]); // 4 entries
        ast.write(2, &[0x00, 0x02]); // Entry 1: TSAP = 2
        ast.write(4, &[0x00, 0x02]); // Entry 1: ASAP = 1+1 (stored as 2)
        ast.write(6, &[0x00, 0x04]); // Entry 2: TSAP = 4
        ast.write(8, &[0x00, 0x04]); // Entry 2: ASAP = 3+1 (stored as 4)
        ast.write(10, &[0x00, 0x06]); // Entry 3: TSAP = 6
        ast.write(12, &[0x00, 0x06]); // Entry 3: ASAP = 5+1 (stored as 6)
        ast.write(14, &[0x00, 0x07]); // Entry 4: TSAP = 7
        ast.write(16, &[0x00, 0x06]); // Entry 4: ASAP = 5+1 (stored as 6) (duplicate)
        ast.write_lsm(&[LoadEvent::LoadCompleted.into()]);

        // Test finding TSAPs for ASAP 5 (which has multiple TSAPs)
        let mut idx = 0;
        assert_eq!(ast.find_next_tsap(5, &mut idx), Some((6, 3))); // First TSAP (idx=3)
        assert_eq!(ast.find_next_tsap(5, &mut idx), Some((7, 4))); // Second TSAP (idx=4)
        assert_eq!(ast.find_next_tsap(5, &mut idx), None); // No more TSAPs

        // Test finding TSAP for ASAP 1 (which has one TSAP)
        idx = 0;
        assert_eq!(ast.find_next_tsap(1, &mut idx), Some((2, 1))); // First TSAP (idx=1)
        assert_eq!(ast.find_next_tsap(1, &mut idx), None); // No more TSAPs

        // Test finding TSAP for ASAP 9 (which doesn't exist in table)
        idx = 0;
        assert_eq!(ast.find_next_tsap(9, &mut idx), None); // No TSAPs
    }

    #[test]
    fn asso6_get_tsap_for_asap() {
        // Test the get_tsap_for_asap function
        let mut ast = AssoTab6::<20>::new();

        // Setup table with multiple mappings:
        // ASAP 1 ← TSAP 2
        // ASAP 3 ← TSAP 4
        // ASAP 5 ← TSAP 6
        // ASAP 5 ← TSAP 7 (multiple TSAPs for same ASAP - should return first match)
        ast.write_lsm(&[LoadEvent::StartLoading.into()]);
        ast.write_lsm(&[
            LoadEvent::AdditionalLoadControls.into(),
            0x0B,
            0x00,
            0x00,
            0x00,
            0x10,
            0x01,
            0xff,
            0x00,
            0x00,
        ]);
        ast.write(0, &[0x00, 0x04]); // 4 entries
        ast.write(2, &[0x00, 0x02]); // Entry 1: TSAP = 2
        ast.write(4, &[0x00, 0x02]); // Entry 1: ASAP = 1+1 (stored as 2)
        ast.write(6, &[0x00, 0x04]); // Entry 2: TSAP = 4
        ast.write(8, &[0x00, 0x04]); // Entry 2: ASAP = 3+1 (stored as 4)
        ast.write(10, &[0x00, 0x06]); // Entry 3: TSAP = 6
        ast.write(12, &[0x00, 0x06]); // Entry 3: ASAP = 5+1 (stored as 6)
        ast.write(14, &[0x00, 0x07]); // Entry 4: TSAP = 7
        ast.write(16, &[0x00, 0x06]); // Entry 4: ASAP = 5+1 (stored as 6) (duplicate)
        ast.write_lsm(&[LoadEvent::LoadCompleted.into()]);

        // Test finding first TSAP for each ASAP
        assert_eq!(ast.get_tsap_for_asap(1), Some(2));
        assert_eq!(ast.get_tsap_for_asap(3), Some(4));
        assert_eq!(ast.get_tsap_for_asap(5), Some(6)); // Returns first match

        // Test finding TSAP for non-existent ASAP
        assert_eq!(ast.get_tsap_for_asap(10), None);
    }

    #[test]
    fn asso6_get_association_index() {
        // Test the get_association_index_for_asap function
        let mut ast = AssoTab6::<20>::new();

        // Setup table with multiple mappings:
        // ASAP 1 ← TSAP 2
        // ASAP 3 ← TSAP 4
        // ASAP 5 ← TSAP 6
        // ASAP 5 ← TSAP 7 (multiple TSAPs for same ASAP - should return first match)
        ast.write_lsm(&[LoadEvent::StartLoading.into()]);
        ast.write_lsm(&[
            LoadEvent::AdditionalLoadControls.into(),
            0x0B,
            0x00,
            0x00,
            0x00,
            0x10,
            0x01,
            0xff,
            0x00,
            0x00,
        ]);
        ast.write(0, &[0x00, 0x04]); // 4 entries
        ast.write(2, &[0x00, 0x02]); // Entry 1: TSAP = 2
        ast.write(4, &[0x00, 0x02]); // Entry 1: ASAP = 1+1 (stored as 2)
        ast.write(6, &[0x00, 0x04]); // Entry 2: TSAP = 4
        ast.write(8, &[0x00, 0x04]); // Entry 2: ASAP = 3+1 (stored as 4)
        ast.write(10, &[0x00, 0x06]); // Entry 3: TSAP = 6
        ast.write(12, &[0x00, 0x06]); // Entry 3: ASAP = 5+1 (stored as 6)
        ast.write(14, &[0x00, 0x07]); // Entry 4: TSAP = 7
        ast.write(16, &[0x00, 0x06]); // Entry 4: ASAP = 5+1 (stored as 6) (duplicate)
        ast.write_lsm(&[LoadEvent::LoadCompleted.into()]);

        // Test finding association index for each ASAP
        assert_eq!(ast.get_association_index_for_asap(1), Some(1)); // Index for ASAP 1
        assert_eq!(ast.get_association_index_for_asap(3), Some(2)); // Index for ASAP 3
        assert_eq!(ast.get_association_index_for_asap(5), Some(3)); // Index for first ASAP 5

        // Test finding association index for non-existent ASAP
        assert_eq!(ast.get_association_index_for_asap(10), None);
    }

    #[test]
    fn asso6_iterators() {
        // Test the iterator functionality
        let mut ast = AssoTab6::<20>::new();

        // Setup table with multiple mappings:
        // TSAP 1 → ASAP 10, ASAP 11
        // TSAP 2 → ASAP 20
        // TSAP 3 → ASAP 30, ASAP 31, ASAP 32
        ast.write_lsm(&[LoadEvent::StartLoading.into()]);
        ast.write_lsm(&[
            LoadEvent::AdditionalLoadControls.into(),
            0x0B,
            0x00,
            0x00,
            0x00,
            0x14,
            0x01,
            0xff,
            0x00,
            0x00,
        ]);
        ast.write(0, &[0x00, 0x06]); // 6 entries
        // TSAP 1 → ASAP 10
        ast.write(2, &[0x00, 0x01]);
        ast.write(4, &[0x00, 0x0B]); // ASAP 10+1=11
        // TSAP 1 → ASAP 11
        ast.write(6, &[0x00, 0x01]);
        ast.write(8, &[0x00, 0x0C]); // ASAP 11+1=12
        // TSAP 2 → ASAP 20
        ast.write(10, &[0x00, 0x02]);
        ast.write(12, &[0x00, 0x15]); // ASAP 20+1=21
        // TSAP 3 → ASAP 30
        ast.write(14, &[0x00, 0x03]);
        ast.write(16, &[0x00, 0x1F]); // ASAP 30+1=31
        // TSAP 3 → ASAP 31
        ast.write(18, &[0x00, 0x03]);
        ast.write(20, &[0x00, 0x20]); // ASAP 31+1=32
        // TSAP 3 → ASAP 32
        ast.write(22, &[0x00, 0x03]);
        ast.write(24, &[0x00, 0x21]); // ASAP 32+1=33
        ast.write_lsm(&[LoadEvent::LoadCompleted.into()]);

        // Test ASAP iterator for TSAP 1
        let asaps: Vec<u16> = ast.asaps_for_tsap(1).collect();
        assert_eq!(asaps, vec![10, 11]);

        // Test ASAP iterator for TSAP 2
        let asaps: Vec<u16> = ast.asaps_for_tsap(2).collect();
        assert_eq!(asaps, vec![20]);

        // Test ASAP iterator for TSAP 3
        let asaps: Vec<u16> = ast.asaps_for_tsap(3).collect();
        assert_eq!(asaps, vec![30, 31, 32]);

        // Test ASAP iterator for non-existent TSAP
        let asaps: Vec<u16> = ast.asaps_for_tsap(4).collect();
        assert_eq!(asaps, vec![]);

        // Test TSAP iterator for specific ASAPs
        assert_eq!(ast.tsaps_for_asap(10).collect::<Vec<_>>(), vec![1]);
        assert_eq!(ast.tsaps_for_asap(20).collect::<Vec<_>>(), vec![2]);
        assert_eq!(ast.tsaps_for_asap(30).collect::<Vec<_>>(), vec![3]);

        // Test TSAP iterator for non-existent ASAP
        assert_eq!(ast.tsaps_for_asap(40).collect::<Vec<_>>(), vec![]);
    }
}
