use const_default::ConstDefault;
use zerocopy::big_endian::U16;

use super::{MemoryBackedTable, Table};

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

    // TODO: implement further methods we need like for example an iterator to go from a TSAP to all ASAPs and other things we need
}

impl<const N: usize> MemoryBackedTable for AssoTab6Impl<N> {
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
