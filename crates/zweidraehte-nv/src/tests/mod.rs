//! Host tests over the NOR flash model in [`crate::mock`] and a RAM byte
//! medium.

use std::cell::{Ref, RefCell};
use std::rc::Rc;
use std::vec;
use std::vec::Vec;

use crate::ByteIo;

mod kv;
mod log;
mod mc_timer;
mod nv_store;
mod provisioning;
mod siat;
mod split;

/// A byte medium over shared RAM: clones see the same bytes, so dropping a
/// store and opening another over a clone models a reboot.
#[derive(Clone)]
pub(crate) struct RamIo(Rc<RefCell<Vec<u8>>>);

impl RamIo {
    pub(crate) fn zeroed(len: usize) -> Self {
        Self::filled(len, 0)
    }

    /// A medium whose unwritten bytes are `fill` — a factory-fresh FRAM is
    /// not guaranteed to read zero.
    pub(crate) fn filled(len: usize, fill: u8) -> Self {
        Self(Rc::new(RefCell::new(vec![fill; len])))
    }

    pub(crate) fn bytes(&self) -> Ref<'_, Vec<u8>> {
        self.0.borrow()
    }

    pub(crate) fn poke(&self, offset: usize, data: &[u8]) {
        self.0.borrow_mut()[offset..offset + data.len()].copy_from_slice(data);
    }
}

impl ByteIo for RamIo {
    type Error = core::convert::Infallible;

    fn read_at(&self, off: u32, buf: &mut [u8]) -> Result<(), Self::Error> {
        let off = off as usize;
        buf.copy_from_slice(&self.0.borrow()[off..off + buf.len()]);
        Ok(())
    }

    fn write_at(&mut self, off: u32, data: &[u8]) -> Result<(), Self::Error> {
        self.poke(off as usize, data);
        Ok(())
    }
}
