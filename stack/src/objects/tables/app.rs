use const_default::ConstDefault;

use super::{TableMemory, Table};

#[derive(Debug, ConstDefault)]
pub struct ApplicationImpl<D: ConstDefault> {
    _data: D,
}

impl<D: ConstDefault> Table<ApplicationImpl<D>> {}

impl<D: ConstDefault> TableMemory for ApplicationImpl<D> {
    fn data_ref(&self) -> &[u8] {
        &[]
    }

    fn data_ref_mut(&mut self) -> &mut [u8] {
        &mut []
    }

    fn max_size() -> usize {
        core::mem::size_of::<D>()
    }

    fn read(&self, _offset: usize, _data: &mut [u8]) {}

    fn write(&mut self, _offset: usize, _data: &[u8]) {}
}

pub type Application<D> = Table<ApplicationImpl<D>>;
