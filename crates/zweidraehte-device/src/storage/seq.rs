//! Security sequence-number storage: the wear-resistant seam and its
//! stores-struct projections.
//!
//! [`SequenceNumberStorage`] is what the secure layers require of a sequence
//! store; [`HasSeqStore`] is how they reach the device's concrete store on
//! the macro-emitted stores struct, carried as
//! [`StackDefinition::Storage`](crate::StackDefinition::Storage) on the
//! `LayerContext`.
//!
//! The seam itself is `zweidraehte_proto::security` — a device stack does not
//! get to define what a KNX sequence number is — and is re-exported here so
//! the storage module stays the one place a backend author has to look.

use core::cell::RefCell;

use super::views::SiatAccess;

pub use zweidraehte_proto::security::{SequenceNumberStorage, erase_seq_on_factory_reset};

/// Typed access to the sequence/SIAT store on a device's stores struct.
/// Implemented by the seq-carrying stores structs
/// ([`SecureStorage`](super::SecureStorage), [`SecureIpStorage`](super::SecureIpStorage));
/// its absence is what gates the secure context/builders at compile time.
pub trait HasSeqStore {
    /// The concrete sequence store type.
    type Seq: SequenceNumberStorage + SiatAccess;
    /// The store's `RefCell`, borrowed per call by the secure layers.
    fn seq_store(&self) -> &RefCell<Self::Seq>;
}

// A device's `StackDefinition::Storage` is the *reference* to its stores
// struct (e.g. `&'static SecureStorage<…>`), so the capability forwards through the
// reference — bounds stay a single line (`D::Storage: HasSeqStore`).
impl<T: HasSeqStore> HasSeqStore for &T {
    type Seq = T::Seq;
    fn seq_store(&self) -> &RefCell<Self::Seq> {
        (*self).seq_store()
    }
}

/// The sequence-store type behind a device's
/// [`Storage`](crate::StackDefinition::Storage) handle — the secure builders'
/// `SEQ` parameter.
pub type SeqStorageFor<D> = <<D as crate::definition::StackDefinition>::Storage as HasSeqStore>::Seq;
