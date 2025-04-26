use const_default::ConstDefault;
use zerocopy::big_endian::U16;

use super::{MemoryBackedTable, Table};

#[derive(Debug, ConstDefault)]
pub struct CoTab7Impl<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> Table<CoTab7Impl<N>> {
    pub fn max_entries(&self) -> usize {
        (N / 2) - 1
    }

    pub fn entry_count(&self) -> u16 {
        U16::from_bytes(self.table.data[0..2].try_into().unwrap()).get()
    }

    // TODO: implement struct describing flags and type
    // TODO: implement further methods we need
}

impl<const N: usize> MemoryBackedTable for CoTab7Impl<N> {
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

pub type CoTab7<const MAX_ENTRIES: usize> = Table<CoTab7Impl<{ (MAX_ENTRIES + 1) * 2 }>>;
