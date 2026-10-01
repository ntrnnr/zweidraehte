//! The device's storage: the one capability the router and the storage task
//! drive, and the stores struct devices put behind it.
//!
//! [`DeviceStorage`] is implemented at two levels. A config slot implements
//! the configuration half: [`NvConfig`](super::NvConfig) writes the state's
//! sections through, `()` persists nothing. [`Storage`] composes a config
//! slot with the optional sequence/SIAT and mc_timer slots, and implements
//! the trait by delegating to its config slot and adding its slots' erase
//! work. Test probes implement it directly.
//!
//! A device names one of three aliases of [`Storage`]:
//!
//! - [`ConfigStorage`] — config only (plain devices)
//! - [`SecureStorage`] — config + sequence/SIAT store (KNX Data Secure)
//! - [`SecureIpStorage`] — config + seq + mc_timer watermark (KNX IP Secure
//!   routing)
//!
//! An absent slot is a zero-sized marker ([`NoSeq`], [`NoMcTimer`]), and a
//! present one carries its own `RefCell`, so a plain device pays nothing for
//! the slots it does not have. The secure-builder gate is structural:
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
use super::views::SiatAccess;
use crate::restart::EraseCode;

/// The mc_timer watermark store surface: the durable 48-bit counter the
/// IP-Secure routing layer reads at boot and advances under 03/08/09 §2.2.4.2.
pub trait McTimerStoreBackend {
    /// Backend error.
    type Error;
    /// The last persisted watermark, or 0 if never written.
    fn load(&self) -> u64;
    /// Persist `value` (low 48 bits).
    fn save(&mut self, value: u64) -> Result<(), Self::Error>;
    /// Clear the watermark (factory reset).
    fn clear(&mut self) -> Result<(), Self::Error>;
}

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
    /// has no mc_timer store or it was never written).
    fn load_mc_timer(&self) -> u64 {
        0
    }

    /// Persist a watermark (vanishes without an mc_timer store; a backend
    /// failure is logged and swallowed — see the module-level error policy).
    fn save_mc_timer(&self, _value: u64) {}
}

// A device with no persistent storage at all (demo stacks, the IP Secure
// conformance DUT): every default stands.
impl<State> DeviceStorage<State> for () {}

// ============================================================================
// Slots
// ============================================================================

/// What a [`Storage`] needs of its sequence slot: its share of an erase.
pub trait SeqSlot {
    /// Apply the erase code to the sequence store.
    fn erase(&self, code: EraseCode);
}

/// The sequence slot of a storage without KNX Data Secure. Zero-sized.
pub struct NoSeq;

impl SeqSlot for NoSeq {
    fn erase(&self, _code: EraseCode) {}
}

impl<S: SequenceNumberStorage + SiatAccess> SeqSlot for RefCell<S> {
    fn erase(&self, code: EraseCode) {
        // Factory codes apply the near-exhaustion sending-SeqNr re-init.
        erase_seq_on_factory_reset(&mut *self.borrow_mut(), code);
    }
}

/// What a [`Storage`] needs of its mc_timer slot.
pub trait McTimerSlot {
    /// The persisted watermark, or 0.
    fn load(&self) -> u64;
    /// Persist `value`, logging a failure.
    fn save(&self, value: u64);
    /// Apply the erase code to the watermark.
    fn erase(&self, code: EraseCode);
}

/// The mc_timer slot of a storage without KNX IP Secure routing.
/// Zero-sized.
pub struct NoMcTimer;

impl McTimerSlot for NoMcTimer {
    fn load(&self) -> u64 {
        0
    }
    fn save(&self, _value: u64) {}
    fn erase(&self, _code: EraseCode) {}
}

impl<M: McTimerStoreBackend> McTimerSlot for RefCell<M> {
    fn load(&self) -> u64 {
        self.borrow().load()
    }
    fn save(&self, value: u64) {
        if self.borrow_mut().save(value).is_err() {
            crate::logging::warn!("mc_timer save failed — watermark not persisted");
        }
    }
    fn erase(&self, code: EraseCode) {
        if code.is_factory_reset() && self.borrow_mut().clear().is_err() {
            crate::logging::warn!("mc_timer clear failed");
        }
    }
}

// ============================================================================
// Storage
// ============================================================================

/// A device's stores: the configuration slot `C`, the sequence/SIAT slot
/// `S` and the mc_timer slot `M`. Devices name it through [`ConfigStorage`],
/// [`SecureStorage`] or [`SecureIpStorage`].
pub struct Storage<C, S = NoSeq, M = NoMcTimer> {
    /// The write-through config store.
    pub config: C,
    /// The sequence/SIAT store, in its `RefCell`, or [`NoSeq`].
    pub seq: S,
    /// The mc_timer watermark store, in its `RefCell`, or [`NoMcTimer`].
    pub mc_timer: M,
}

/// The stores of a **config-only** device: just the ETS configuration.
///
/// No sequence store, and therefore no [`HasSeqStore`] impl, which is what
/// rejects the secure builders for these devices at compile time.
pub type ConfigStorage<C> = Storage<C>;

/// The stores of a **KNX Data Secure** device: the configuration plus the
/// sequence/SIAT store the secure layers replay-protect with.
pub type SecureStorage<C, S> = Storage<C, RefCell<S>>;

/// The stores of a **KNX IP Secure routing** device: config + seq plus the
/// durable multicast-timer watermark (03/08/09 §2.2.4.2).
pub type SecureIpStorage<C, S, M> = Storage<C, RefCell<S>, RefCell<M>>;

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

impl<C, S: SequenceNumberStorage + SiatAccess, M: McTimerStoreBackend> Storage<C, RefCell<S>, RefCell<M>> {
    pub const fn new(config: C, seq: S, mc_timer: M) -> Self {
        Self { config, seq: RefCell::new(seq), mc_timer: RefCell::new(mc_timer) }
    }
}

impl<C, S: SequenceNumberStorage + SiatAccess, M> HasSeqStore for Storage<C, RefCell<S>, M> {
    type Seq = S;
    fn seq_store(&self) -> &RefCell<S> {
        &self.seq
    }
}

impl<State, C, S, M> DeviceStorage<State> for Storage<C, S, M>
where
    C: DeviceStorage<State>,
    S: SeqSlot,
    M: McTimerSlot,
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
        self.mc_timer.erase(code);
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

    /// A device pays nothing for the slots it does not have: the absent
    /// sequence and mc_timer slots add no bytes to its storage.
    #[test]
    fn absent_slots_are_free() {
        assert_eq!(core::mem::size_of::<ConfigStorage<()>>(), 0);

        let storage = ConfigStorage::new(());
        assert!(!<ConfigStorage<()> as DeviceStorage<()>>::WRITE_THROUGH);
        assert_eq!(DeviceStorage::<()>::load_mc_timer(&storage), 0);
        DeviceStorage::<()>::erase(&storage, EraseCode::FactoryReset);
    }
}
