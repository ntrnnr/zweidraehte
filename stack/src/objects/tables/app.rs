use const_default::ConstDefault;

use super::{MemoryBackedTable, Table};

#[derive(Debug, ConstDefault)]
pub struct ApplicationImpl<D: ConstDefault> {
    data: D,
}

impl<D: ConstDefault> Table<ApplicationImpl<D>> {}

impl<D: ConstDefault> MemoryBackedTable for ApplicationImpl<D> {
    fn data_ref(&self) -> &[u8] {
        &[]
    }

    fn data_ref_mut(&mut self) -> &mut [u8] {
        &mut []
    }

    fn max_size() -> usize {
        core::mem::size_of::<D>()
    }

    fn read(&self, offset: usize, data: &mut [u8]) {}

    fn write(&mut self, offset: usize, data: &[u8]) {}
}

pub type Application<D> = Table<ApplicationImpl<D>>;
