//! The device's storage: the one capability the router and the storage task
//! drive, and the stores struct devices put behind it.
//!
//! [`DeviceStorage`] is implemented at two levels. A config slot implements
//! the configuration half: [`NvConfig`](super::NvConfig) writes the state's
//! sections through, `()` persists nothing. [`Storage`] composes a config
//! slot with the optional sequence/SIAT slot, and implements the trait by
//! delegating to its config slot and adding the sequence slot's erase work.
//! Test probes implement it directly.
//!
//! A device names one of two aliases of [`Storage`]:
//!
//! - [`ConfigStorage`] — config only (plain devices)
//! - [`SecureStorage`] — config + sequence/SIAT store (KNX Data Secure); an
//!   IP Secure routing device picks a sequence store that also keeps the
//!   multicast-timer watermark ([`McTimerWatermark::KEEPS_MC_TIMER`])
//!
//! An absent sequence slot is the zero-sized [`NoSeq`], and a present one
//! carries its own `RefCell`, so a plain device pays nothing for it. The secure-builder gate is structural:
//! [`HasSeqStore`] is implemented only when the sequence slot holds a store,
//! so composing a secure stack over a [`ConfigStorage`] is a compile error.
//!
//! # Error policy
//!
//! A failed flush leaves the state dirty; the router and the storage task
//! retry it, and a restart waits until it succeeds. Security-counter hooks
//! retain their existing synchronous contracts.

use core::cell::RefCell;
use core::convert::Infallible;
use core::fmt::Debug;

use zweidraehte_nv::Loaded;

use super::seq::{HasSeqStore, SequenceNumberStorage, erase_seq_on_factory_reset};
use super::views::{McTimerWatermark, SiatAccess};
use crate::restart::EraseCode;

// ============================================================================
// DeviceStorage — the one capability the router and the storage task drive
// ============================================================================

/// A device's durable storage of its state `State`, as the router and the
/// storage task drive it.
///
/// Every method has a do-nothing default, which is what `()` uses; a config
/// slot with write-through ([`NvConfig`](super::NvConfig)) overrides the
/// configuration methods, and [`Storage`] forwards all of them.
pub trait DeviceStorage<State> {
    /// Whether [`flush`](Self::flush) persists anything. While false neither
    /// the router nor the storage task calls it, the state's dirty flag is
    /// never cleared, and their flush code compiles away.
    const WRITE_THROUGH: bool = false;

    /// Why [`load`](Self::load) could not use the medium.
    type Error: Debug = Infallible;

    /// Boot: apply the durable configuration to `state`, which must be
    /// factory-fresh, or format the medium with it. Storage that persists
    /// nothing reports [`Loaded::Fresh`].
    fn load(&self, _state: &State) -> Result<Loaded, Self::Error> {
        Ok(Loaded::Fresh)
    }

    /// Make every pending change of `state` durable. `Err` leaves the
    /// changes pending; the router retries on its next pass.
    // The router only needs "not persisted": it counts the failure and
    // retries. The medium's own error stays with the store.
    #[allow(clippy::result_unit_err)]
    fn flush(&self, _state: &State) -> Result<(), ()> {
        Ok(())
    }

    /// Whether the store would like a [`compact`](Self::compact) soon. The
    /// storage task checks it on every tick and compacts under its
    /// `SaveGuard`, so the long flash operation happens with the bus held
    /// busy rather than inside a later flush.
    fn needs_compaction(&self) -> bool {
        false
    }

    /// Rewrite the whole of `state` and drop the store's history.
    #[allow(clippy::result_unit_err)]
    fn compact(&self, _state: &State) -> Result<(), ()> {
        Ok(())
    }

    /// Apply a restart erase code to the durable stores beyond the
    /// configuration. The configuration itself needs nothing here: the
    /// erase resets the runtime state, and the flush that follows persists
    /// that.
    fn erase(&self, _code: EraseCode) {}

    /// The persisted IP Secure multicast-timer watermark (0 if the device
    /// has no sequence store or never wrote one).
    fn load_mc_timer(&self) -> u64 {
        0
    }

    /// Persist a watermark (vanishes without a sequence store; a backend
    /// failure is logged and swallowed — see the module-level error policy).
    fn save_mc_timer(&self, _value: u64) {}
}

// A device with no persistent storage at all (demo stacks, the IP Secure
// conformance DUT): every default stands.
impl<State> DeviceStorage<State> for () {}

// ============================================================================
// Slots
// ============================================================================

/// What a [`Storage`] needs of its sequence slot: its share of an erase and
/// the IP Secure watermark it keeps.
pub trait SeqSlot {
    /// Apply the erase code to the sequence store.
    fn erase(&self, code: EraseCode);
    /// The persisted mc_timer watermark, or 0.
    fn load_mc_timer(&self) -> u64;
    /// Persist `value`, logging a failure.
    fn save_mc_timer(&self, value: u64);
}

/// The sequence slot of a storage without KNX Data Secure. Zero-sized.
pub struct NoSeq;

impl SeqSlot for NoSeq {
    fn erase(&self, _code: EraseCode) {}
    fn load_mc_timer(&self) -> u64 {
        0
    }
    fn save_mc_timer(&self, _value: u64) {}
}

impl<S: SequenceNumberStorage + SiatAccess + McTimerWatermark> SeqSlot for RefCell<S> {
    /// Factory codes apply the near-exhaustion sending-SeqNr re-init and, in
    /// a store that keeps one, forget the watermark, which belongs to the
    /// backbone key the reset wipes (03/08/09 §2.2.4.2). The branch is
    /// constant, so a store without a watermark carries no code for it.
    fn erase(&self, code: EraseCode) {
        let mut seq = self.borrow_mut();
        erase_seq_on_factory_reset(&mut *seq, code);
        if S::KEEPS_MC_TIMER && code.is_factory_reset() && seq.clear_mc_timer().is_err() {
            crate::logging::warn!("mc_timer clear failed");
        }
    }

    fn load_mc_timer(&self) -> u64 {
        match self.borrow().load_mc_timer() {
            Ok(watermark) => watermark.unwrap_or(0),
            Err(_) => {
                crate::logging::warn!("mc_timer load failed — starting from 0");
                0
            }
        }
    }

    fn save_mc_timer(&self, value: u64) {
        if self.borrow_mut().save_mc_timer(value).is_err() {
            crate::logging::warn!("mc_timer save failed — watermark not persisted");
        }
    }
}

// ============================================================================
// Storage
// ============================================================================

/// A device's stores: the configuration slot `C` and the sequence/SIAT slot
/// `S`. Devices name it through [`ConfigStorage`] or [`SecureStorage`].
pub struct Storage<C, S = NoSeq> {
    /// The write-through config store.
    pub config: C,
    /// The sequence/SIAT store, in its `RefCell`, or [`NoSeq`].
    pub seq: S,
}

/// The stores of a **config-only** device: just the ETS configuration.
///
/// No sequence store, and therefore no [`HasSeqStore`] impl, which is what
/// rejects the secure builders for these devices at compile time.
pub type ConfigStorage<C> = Storage<C>;

/// The stores of a **KNX Data Secure** device: the configuration plus the
/// sequence/SIAT store the secure layers replay-protect with. The same
/// store keeps the KNX IP Secure multicast-timer watermark (03/08/09
/// §2.2.4.2) of a secure routing device.
pub type SecureStorage<C, S> = Storage<C, RefCell<S>>;

impl<C> Storage<C> {
    pub const fn new(config: C) -> Self {
        Self { config, seq: NoSeq }
    }
}

impl<C, S: SequenceNumberStorage + SiatAccess + McTimerWatermark> Storage<C, RefCell<S>> {
    pub const fn new(config: C, seq: S) -> Self {
        Self { config, seq: RefCell::new(seq) }
    }
}

impl<C, S: SequenceNumberStorage + SiatAccess + McTimerWatermark> HasSeqStore for Storage<C, RefCell<S>> {
    type Seq = S;
    fn seq_store(&self) -> &RefCell<S> {
        &self.seq
    }
}

impl<State, C, S> DeviceStorage<State> for Storage<C, S>
where
    C: DeviceStorage<State>,
    S: SeqSlot,
{
    const WRITE_THROUGH: bool = C::WRITE_THROUGH;
    type Error = C::Error;

    fn load(&self, state: &State) -> Result<Loaded, Self::Error> {
        self.config.load(state)
    }

    fn flush(&self, state: &State) -> Result<(), ()> {
        self.config.flush(state)
    }

    fn needs_compaction(&self) -> bool {
        self.config.needs_compaction()
    }

    fn compact(&self, state: &State) -> Result<(), ()> {
        self.config.compact(state)
    }

    fn erase(&self, code: EraseCode) {
        self.config.erase(code);
        self.seq.erase(code);
    }

    fn load_mc_timer(&self) -> u64 {
        self.seq.load_mc_timer()
    }

    fn save_mc_timer(&self, value: u64) {
        self.seq.save_mc_timer(value);
    }
}

/// Compile-fail proof of the secure-builder gate: a config-only handle has
/// no [`HasSeqStore`](super::seq::HasSeqStore) impl, so code that needs the
/// sequence store (the secure composition bounds on `D::Storage:
/// HasSeqStore`) cannot be given a [`ConfigStorage`].
///
/// ```compile_fail
/// use zweidraehte_device::storage::{ConfigStorage, HasSeqStore};
///
/// fn needs_seq_store<T: HasSeqStore>(_t: &T) {}
///
/// let storage = ConfigStorage::new(());
/// // ConfigStorage has no seq store — must not compile.
/// needs_seq_store(&storage);
/// ```
#[allow(dead_code)]
struct ConfigOnlyHandleHasNoSeqStore;

#[cfg(test)]
mod tests {
    use super::*;

    /// A device pays nothing for the slot it does not have: the absent
    /// sequence slot adds no bytes to its storage, and reads no watermark.
    #[test]
    fn absent_slots_are_free() {
        assert_eq!(core::mem::size_of::<ConfigStorage<()>>(), 0);

        let storage = ConfigStorage::new(());
        assert!(!<ConfigStorage<()> as DeviceStorage<()>>::WRITE_THROUGH);
        assert_eq!(DeviceStorage::<()>::load_mc_timer(&storage), 0);
        DeviceStorage::<()>::erase(&storage, EraseCode::FactoryReset);
    }

    /// The IP Secure watermark lives in a sequence store that keeps one: the
    /// storage forwards it there, keeps it through ordinary erase codes, and
    /// forgets it on a factory reset, with the backbone key it belongs to.
    #[test]
    fn the_sequence_store_keeps_the_watermark_until_a_factory_reset() {
        use zweidraehte_nv::mock::{Backing, MockBytes};
        use zweidraehte_nv::{PackedSeqStore, SEQUENCE_MAGIC};

        let backing = Backing::new(PackedSeqStore::<MockBytes, 4, true>::REGION_LEN, 1);
        let storage =
            SecureStorage::new((), PackedSeqStore::<_, 4, true>::new(backing.open_bytes(), 0, SEQUENCE_MAGIC));
        let load = || DeviceStorage::<()>::load_mc_timer(&storage);
        assert_eq!(load(), 0, "a fresh store has no watermark");

        DeviceStorage::<()>::save_mc_timer(&storage, 7_200_000);
        assert_eq!(load(), 7_200_000);

        DeviceStorage::<()>::erase(&storage, EraseCode::ResetLinks);
        assert_eq!(load(), 7_200_000, "only a factory reset clears the watermark");

        DeviceStorage::<()>::erase(&storage, EraseCode::FactoryReset);
        assert_eq!(load(), 0);
    }
}
