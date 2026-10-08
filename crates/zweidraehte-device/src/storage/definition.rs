//! The device's storage: the one capability the router and the storage task
//! drive, and the stores struct devices put behind it.
//!
//! [`DeviceStorage`] is implemented at two levels. A config slot implements
//! the configuration half: [`NvConfig`](super::NvConfig) writes the state's
//! sections through, `()` persists nothing. [`Storage`] composes a config
//! slot with optional sequence/SIAT and multicast-timer slots. Each is selected
//! by the firmware and can occupy its own region.
//! Test probes implement it directly.
//!
//! Devices use [`ConfigStorage`], [`SecureStorage`], or
//! [`SecureRoutingStorage`] according to the stores they actually have.
//!
//! An absent sequence slot is the zero-sized [`NoSeq`], and a present one
//! carries its own `RefCell`, so a plain device pays nothing for it. The secure-builder gate is structural:
//! [`HasSeqStore`] is implemented only when the sequence slot holds a store,
//! so composing a secure stack over a [`ConfigStorage`] is a compile error.
//!
//! # Error policy
//!
//! A flush that does not finish leaves the state dirty, and the next flush
//! tries again. A [`FlushError::Deferred`] flush is the normal full-bank
//! path: the storage task compacts under its guard, which completes it. A
//! [`FlushError::Failed`] one means the medium failed; it is logged and
//! counted, and nothing else retries it. Medium failures are rare enough
//! that a broken medium is treated as a broken device. Security-counter
//! hooks retain their existing synchronous contracts.

use core::cell::RefCell;
use core::convert::Infallible;
use core::fmt::Debug;

use zweidraehte_nv::Loaded;

use super::seq::{HasSeqStore, SequenceNumberStorage, erase_seq_on_factory_reset};
use super::{McTimerStore, SiatAccess};
use crate::restart::EraseCode;

// ============================================================================
// DeviceStorage — the one capability the router and the storage task drive
// ============================================================================

/// Why a [`DeviceStorage::flush`] left changes pending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlushError {
    /// The store needs guarded maintenance before it can take the change,
    /// such as a full flash log bank. Compaction completes the write.
    Deferred,
    /// The medium failed.
    Failed,
}

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

    /// Whether this storage has a separate multicast-timer slot.
    const HAS_MC_TIMER: bool = false;

    /// Why [`load`](Self::load) could not use the medium.
    type Error: Debug = Infallible;

    /// Boot: apply the durable configuration to `state`, which must be
    /// factory-fresh, or format the medium with it. Storage that persists
    /// nothing reports [`Loaded::Fresh`].
    fn load(&self, _state: &State) -> Result<Loaded, Self::Error> {
        Ok(Loaded::Fresh)
    }

    /// Make every pending change of `state` durable. `Err` leaves the
    /// changes pending. The medium's own error stays with the store.
    fn flush(&self, _state: &State) -> Result<(), FlushError> {
        Ok(())
    }

    /// Whether the store would like a [`compact`](Self::compact) soon. A
    /// flush that leaves it true wakes the storage task, which compacts
    /// under its `SaveGuard`, so the long flash operation happens with the
    /// bus held busy rather than inside a later flush.
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

    /// The persisted IP Secure multicast-timer watermark (0 if absent).
    fn load_mc_timer(&self) -> u64 {
        0
    }

    /// Persist a watermark. A backend failure is logged and swallowed for now.
    fn save_mc_timer(&self, _value: u64) {}
}

// A device with no persistent storage at all (demo stacks, the IP Secure
// conformance DUT): every default stands.
impl<State> DeviceStorage<State> for () {}

// ============================================================================
// Slots
// ============================================================================

/// The sequence slot's share of a factory reset.
pub trait SeqSlot {
    fn erase(&self, code: EraseCode);
}

/// The sequence slot of a storage without KNX Data Secure. Zero-sized.
pub struct NoSeq;

impl SeqSlot for NoSeq {
    fn erase(&self, _code: EraseCode) {}
}

impl<S: SequenceNumberStorage + SiatAccess> SeqSlot for RefCell<S> {
    fn erase(&self, code: EraseCode) {
        erase_seq_on_factory_reset(&mut *self.borrow_mut(), code);
    }
}

/// A zero-sized watermark slot for devices without IP Secure routing.
pub struct NoMcTimer;

/// The watermark slot's access and factory-reset behavior.
trait McTimerSlot {
    const PRESENT: bool;
    fn load(&self) -> u64;
    fn save(&self, value: u64);
    fn clear(&self);
}

impl McTimerSlot for NoMcTimer {
    const PRESENT: bool = false;

    fn load(&self) -> u64 {
        0
    }
    fn save(&self, _value: u64) {}
    fn clear(&self) {}
}

impl<W: McTimerStore> McTimerSlot for RefCell<W> {
    const PRESENT: bool = true;

    fn load(&self) -> u64 {
        match self.borrow().load() {
            Ok(value) => value.unwrap_or(0),
            Err(_) => {
                crate::logging::warn!("mc_timer load failed — starting from 0");
                0
            }
        }
    }

    fn save(&self, value: u64) {
        if self.borrow_mut().save(value).is_err() {
            crate::logging::warn!("mc_timer save failed — watermark not persisted");
        }
    }

    fn clear(&self) {
        if self.borrow_mut().clear().is_err() {
            crate::logging::warn!("mc_timer clear failed");
        }
    }
}

// ============================================================================
// Storage
// ============================================================================

/// A device's configuration, sequence/SIAT, and multicast-timer slots.
/// A slot is zero-sized when its capability is absent.
pub struct Storage<C, S = NoSeq, W = NoMcTimer> {
    /// The write-through config store.
    pub config: C,
    /// The sequence/SIAT store, in its `RefCell`, or [`NoSeq`].
    pub seq: S,
    /// The independent IP Secure multicast-timer store.
    pub mc_timer: W,
}

/// The stores of a **config-only** device: just the ETS configuration.
///
/// No sequence store, and therefore no [`HasSeqStore`] impl, which is what
/// rejects the secure builders for these devices at compile time.
pub type ConfigStorage<C> = Storage<C>;

/// The stores of a **KNX Data Secure** device: the configuration plus the
/// sequence/SIAT store the secure layers replay-protect with. The watermark
/// slot remains absent; secure routing uses [`SecureRoutingStorage`].
pub type SecureStorage<C, S> = Storage<C, RefCell<S>>;

/// Data Secure plus an independently placed IP Secure routing watermark.
pub type SecureRoutingStorage<C, S, W> = Storage<C, RefCell<S>, RefCell<W>>;

impl<C> Storage<C> {
    pub const fn new(config: C) -> Self {
        Self { config, seq: NoSeq, mc_timer: NoMcTimer }
    }
}

impl<C, S: SequenceNumberStorage + SiatAccess> Storage<C, RefCell<S>> {
    pub const fn new(config: C, seq: S) -> Self {
        Self { config, seq: RefCell::new(seq), mc_timer: NoMcTimer }
    }
}

impl<C, S: SequenceNumberStorage + SiatAccess, W: McTimerStore> Storage<C, RefCell<S>, RefCell<W>> {
    pub const fn new(config: C, seq: S, mc_timer: W) -> Self {
        Self { config, seq: RefCell::new(seq), mc_timer: RefCell::new(mc_timer) }
    }
}

impl<C, W: McTimerStore> Storage<C, NoSeq, RefCell<W>> {
    /// A test or IP-only device with no Data Secure sequence store.
    pub const fn with_watermark(config: C, mc_timer: W) -> Self {
        Self { config, seq: NoSeq, mc_timer: RefCell::new(mc_timer) }
    }
}

impl<C, S: SequenceNumberStorage + SiatAccess, W> HasSeqStore for Storage<C, RefCell<S>, W> {
    type Seq = S;
    fn seq_store(&self) -> &RefCell<S> {
        &self.seq
    }
}

impl<State, C, S, W> DeviceStorage<State> for Storage<C, S, W>
where
    C: DeviceStorage<State>,
    S: SeqSlot,
    W: McTimerSlot,
{
    const WRITE_THROUGH: bool = C::WRITE_THROUGH;
    const HAS_MC_TIMER: bool = W::PRESENT;
    type Error = C::Error;

    fn load(&self, state: &State) -> Result<Loaded, Self::Error> {
        self.config.load(state)
    }

    fn flush(&self, state: &State) -> Result<(), FlushError> {
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
        if W::PRESENT && code.is_factory_reset() {
            self.mc_timer.clear();
        }
    }

    fn load_mc_timer(&self) -> u64 {
        self.mc_timer.load()
    }

    fn save_mc_timer(&self, value: u64) {
        self.mc_timer.save(value);
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

    /// The independent watermark survives ordinary erases and is cleared
    /// with the backbone key on a factory reset.
    #[test]
    fn the_watermark_slot_clears_on_factory_reset() {
        use zweidraehte_nv::mock::{Backing, MockBytes};
        use zweidraehte_nv::stores::sequence;
        use zweidraehte_nv::{ByteMcTimer, PackedSeqStore};

        let seq_len = PackedSeqStore::<MockBytes, 4>::REGION_LEN;
        let backing = Backing::new(seq_len + ByteMcTimer::<MockBytes>::REGION_LEN as usize, 1);
        let storage = SecureRoutingStorage::new(
            (),
            PackedSeqStore::<_, 4>::new(backing.open_bytes(), 0, sequence::MAGIC),
            ByteMcTimer::new(backing.open_bytes(), seq_len as u32),
        );
        assert!(<SecureRoutingStorage<(), PackedSeqStore<MockBytes, 4>, ByteMcTimer<MockBytes>> as DeviceStorage<()>>::HAS_MC_TIMER);

        let load = || DeviceStorage::<()>::load_mc_timer(&storage);
        assert_eq!(load(), 0);
        DeviceStorage::<()>::save_mc_timer(&storage, 7_200_000);
        assert_eq!(load(), 7_200_000);

        DeviceStorage::<()>::erase(&storage, EraseCode::ResetLinks);
        assert_eq!(load(), 7_200_000);

        DeviceStorage::<()>::erase(&storage, EraseCode::FactoryReset);
        assert_eq!(load(), 0);
    }
}
