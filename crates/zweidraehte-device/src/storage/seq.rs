//! Security sequence-number storage: the wear-resistant seam and its
//! stores-struct projections.
//!
//! [`SequenceNumberStorage`] is what the secure layers require of a sequence
//! store; [`HasSeqStore`] is how they reach the device's concrete store in
//! its [`Storage`](super::Storage), carried as
//! [`StackDefinition::Storage`](crate::StackDefinition::Storage) on the
//! `LayerContext`.
//!
//! The seam itself is `zweidraehte_proto::security` — a device stack does not
//! get to define what a KNX sequence number is — and is re-exported here so
//! the storage module stays the one place a backend author has to look.

use core::cell::RefCell;

use super::SiatAccess;

pub use zweidraehte_proto::security::{SequenceNumberStorage, erase_seq_on_factory_reset};

/// Typed access to the sequence/SIAT store in a device's storage.
/// Implemented by a [`Storage`](super::Storage) whose sequence slot holds a
/// store ([`SecureStorage`](super::SecureStorage)); its absence is what gates
/// the secure context/builders at compile time.
pub trait HasSeqStore {
    /// The concrete sequence store type.
    type Seq: SequenceNumberStorage + SiatAccess;
    /// The store's `RefCell`, borrowed per call by the secure layers.
    fn seq_store(&self) -> &RefCell<Self::Seq>;
}

/// The sequence-store type behind a device's
/// [`Storage`](crate::StackDefinition::Storage) handle — the secure builders'
/// `SEQ` parameter.
pub type SeqStorageFor<D> = <<D as crate::definition::StackDefinition>::Storage as HasSeqStore>::Seq;
