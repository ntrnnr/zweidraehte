//! The per-device stores structs and their capability traits.
//!
//! A device's live stores are grouped in one of three **handle structs** —
//! one per real-world store combination, each structurally containing only
//! the stores that combination needs:
//!
//! - [`ConfigStorage`] — config blob only (plain devices)
//! - [`SecureStorage`] — config + sequence/SIAT store (KNX Data Secure)
//! - [`SecureIpStorage`] — config + seq + mc_timer watermark (KNX IP Secure
//!   routing)
//!
//! Each struct's type parameters are bounded by the store contracts, and each
//! carries hand-written [`HasConfigStore`] / [`HasSeqStore`]
//! / [`StorageHooks`] impls with exactly its combination's erase behavior.
//! The generic storage task drives any handle through those bounds. The
//! secure-builder gate is structural: [`ConfigStorage`] has no `HasSeqStore`
//! impl, so composing a secure stack over it is a compile error.
//!
//! A device with a different combination hand-writes its own struct plus the
//! same three small impls — the conformance harness's seq-only
//! `ConformanceSecureStorage` is the worked example. A device-custom store
//! needs no framework surface at all: it is simply the device's own field or
//! static.
//!
//! # Error policy
//!
//! Concrete store methods ([`ConfigStore::save`](super::ConfigStore::save),
//! [`McTimerStore::save`](crate::storage::views::McTimerStore::save)) return
//! `Result` — the caller decides. The framework facades ([`HasConfigStore`],
//! [`StorageHooks`]) swallow errors and log a warning instead: the generic
//! storage task loops forever and has nowhere to propagate to, and a device
//! running with stale persisted state beats one that wedges or reboots on
//! every failed save.

use crate::restart::EraseCode;

use super::SectorIo;

// ============================================================================
// NoStore + store behaviour traits (implemented by the concrete stores)
// ============================================================================
//
// Two layers, each with one job — when adding a new framework-blessed store
// kind, touch each once (a device-custom store touches none of them):
//
// 1. `*StoreBackend` (here) — the behavioural surface a *concrete store type*
//    implements (plus the `NoStore` no-op). HAL-free via associated types.
// 2. The stores-struct surface (below) — `HasConfigStore` / `HasSeqStore`
//    capabilities emitted per declared kind, plus the kind's slice of the
//    composed `StorageHooks` impl (its erase statement, its method
//    overrides). The generic storage task bounds on these directly.

/// Trait for converting runtime state into its serializable config.
///
/// Implemented by a BCU's runtime state type (e.g.
/// [`SystemBDeviceState`](crate::bcus::system_b::SystemBDeviceState)) so
/// storage backends can work with the runtime state directly,
/// internalizing the conversion to/from the persisted config form.
///
/// # Contract
///
/// - [`to_config`](Self::to_config) must capture all state that survives a
///   power cycle.
/// - The matching restore path (an inherent `from_config` on the state type)
///   must restore state such that the device behaves identically to before
///   the power cycle (modulo volatile state like programming mode and run
///   state).
pub trait HasDeviceConfig: Sized {
    /// The serializable config type (device-level persisted form).
    type Config: serde::Serialize + for<'de> serde::Deserialize<'de>;

    /// Export current runtime state to a serializable config.
    fn to_config(&self) -> Self::Config;
}

/// The store sentinel for a kind a device does not declare — the no-op impl
/// target the macro's absent-kind emission mirrors.
pub struct NoStore;

/// The config-blob store surface. Behavioural so the generic storage task can
/// `save` the config without naming the concrete `ConfigStore<F, S, …>`; the
/// associated `State` keeps it HAL-free. [`NoStore`] no-ops it.
pub trait ConfigStoreBackend {
    /// The device state type whose `to_config()` blob this store persists.
    type State;
    /// The deserialised config type [`load`](Self::load) yields at boot
    /// (`()` for [`NoStore`]).
    type Config;
    /// Persist `state` to the config region (no-op for [`NoStore`]). Errors are
    /// swallowed with a warning — see the module-level error policy.
    fn save(&mut self, state: &Self::State);
    /// Load the persisted config: `None` for a blank region, an undecodable
    /// blob, or a read failure — in every case the device boots fresh. The
    /// outcome is logged here, uniformly for every device.
    fn load(&mut self) -> Option<Self::Config>;
}

/// The mc_timer watermark store surface: the durable 48-bit counter the
/// IP-Secure routing layer reads at boot and advances under 03/08/09 §2.2.4.2.
pub trait McTimerStoreBackend {
    /// Backend error. [`NoStore`] uses [`core::convert::Infallible`].
    type Error;
    /// The last persisted watermark, or 0 if never written.
    fn load(&self) -> u64;
    /// Persist `value` (low 48 bits).
    fn save(&mut self, value: u64) -> Result<(), Self::Error>;
    /// Clear the watermark (factory reset).
    fn clear(&mut self) -> Result<(), Self::Error>;
}

// NoStore no-op impls — an omitted kind compiles away.
impl ConfigStoreBackend for NoStore {
    type State = ();
    type Config = ();
    fn save(&mut self, _state: &()) {}
    fn load(&mut self) -> Option<()> {
        None
    }
}
impl McTimerStoreBackend for NoStore {
    type Error = core::convert::Infallible;
    fn load(&self) -> u64 {
        0
    }
    fn save(&mut self, _value: u64) -> Result<(), Self::Error> {
        Ok(())
    }
    fn clear(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

// Concrete core-crate store impls. `ConfigStore` lives here; the
// `McTimerStore` view's `McTimerStoreBackend` lives beside it in `views`.
impl<F, S, R, const SZ: usize> ConfigStoreBackend for super::ConfigStore<F, S, R, SZ>
where
    F: SectorIo,
    S: crate::storage::HasDeviceConfig,
    R: crate::storage::region::Region,
{
    type State = S;
    type Config = S::Config;
    fn save(&mut self, state: &S) {
        if super::ConfigStore::save(self, state).is_err() {
            crate::logging::warn!("config save failed");
        }
    }
    fn load(&mut self) -> Option<S::Config> {
        match super::ConfigStore::load_config(self) {
            Ok(Some(config)) => {
                crate::logging::info!("loaded device config from storage");
                Some(config)
            }
            Ok(None) => {
                crate::logging::info!("no stored config, starting fresh");
                None
            }
            Err(_) => {
                crate::logging::warn!("config load failed, starting fresh");
                None
            }
        }
    }
}

// ============================================================================
// Capability traits (implemented by the macro-emitted stores struct)
// ============================================================================

/// Typed access to a device's config store. Implemented (really or as a
/// no-op) by the macro-emitted stores struct; methods take `&self` — the
/// struct wraps each store in its own `RefCell`, borrowed per call and never
/// held across an await.
pub trait HasConfigStore {
    /// The device state the config blob is serialised from.
    type State;
    /// The deserialised config [`load_config`](Self::load_config) yields.
    type Config;
    /// Save the current state to the config region (no-op if absent).
    fn save_config(&self, state: &Self::State);
    /// Load the persisted config (`None` if absent, blank, or undecodable —
    /// the backend logs the outcome). `main` calls this once at boot, after
    /// initialising the stores struct, to feed the device's `StateInit`.
    fn load_config(&self) -> Option<Self::Config>;
}

// A device's `StackDefinition::Storage` is the *reference* to its stores
// struct, so the capabilities forward through the reference — generic code
// bounds directly on `D::Storage: HasConfigStore + …`.
impl<T: HasConfigStore> HasConfigStore for &T {
    type State = T::State;
    type Config = T::Config;
    fn save_config(&self, state: &Self::State) {
        (*self).save_config(state);
    }
    fn load_config(&self) -> Option<Self::Config> {
        (*self).load_config()
    }
}

/// The storage task's per-device hooks — the one impl whose body differs
/// per store combination (see [`ConfigStorage`] / [`SecureStorage`] /
/// [`SecureIpStorage`]).
///
/// - [`erase`](Self::erase): one statement per carried store kind — the
///   mc_timer watermark clears on the factory codes, the sequence store
///   applies the near-exhaustion sending-SeqNr re-init
///   ([`erase_seq_on_factory_reset`](super::seq::erase_seq_on_factory_reset)).
///   A store the handle does not carry contributes nothing.
/// - [`load_mc_timer`](Self::load_mc_timer) / [`save_mc_timer`](Self::save_mc_timer):
///   overridden only by [`SecureIpStorage`]. Everywhere else the no-op
///   defaults stand — and stay dead code, because only the KNX/IP Secure
///   link layer produces mc_timer traffic.
pub trait StorageHooks {
    /// Apply a restart erase code to the durable regions.
    fn erase(&self, code: EraseCode);
    /// The persisted IP-Secure multicast-timer watermark (0 if the device
    /// has no mc_timer store or it was never written).
    fn load_mc_timer(&self) -> u64 {
        0
    }
    /// Persist a watermark (vanishes without an mc_timer store; a backend
    /// failure is logged and swallowed — see the module-level error policy).
    fn save_mc_timer(&self, _value: u64) {}
}

// Forwards every method — including the defaulted ones, which would
// otherwise resurface as no-ops on `&T` even when `T` overrides them.
impl<T: StorageHooks> StorageHooks for &T {
    fn erase(&self, code: EraseCode) {
        (*self).erase(code);
    }
    fn load_mc_timer(&self) -> u64 {
        (*self).load_mc_timer()
    }
    fn save_mc_timer(&self, value: u64) {
        (*self).save_mc_timer(value);
    }
}

// The storage-less sentinel: a `StackDefinition::Storage = ()` stack (demo
// binaries, the shm-persisted conformance DUTs) erases nothing and reads the
// watermark as 0, so storage-consuming context impls hold without a stores
// struct.
impl StorageHooks for () {
    fn erase(&self, _code: EraseCode) {}
}

// ============================================================================
// The three store combinations
// ============================================================================

use core::cell::RefCell;

use super::seq::HasSeqStore;
use super::seq::SequenceNumberStorage;
use super::views::SiatAccess;

/// The stores of a **config-only** device: just the ETS config blob.
///
/// No sequence store — and therefore no
/// [`HasSeqStore`] impl, which is what rejects the
/// secure builders for these devices at compile time.
pub struct ConfigStorage<C: ConfigStoreBackend> {
    /// The config-blob store, opened at the device's `CONFIG` placement.
    pub config: RefCell<C>,
}

impl<C: ConfigStoreBackend> ConfigStorage<C> {
    pub fn new(config: C) -> Self {
        Self { config: RefCell::new(config) }
    }

    /// Load the persisted config (`None` if absent, blank, or undecodable —
    /// the backend logs the outcome). Inherent twin of
    /// [`HasConfigStore::load_config`] so `main` needs no trait import.
    pub fn load_config(&self) -> Option<C::Config> {
        ConfigStoreBackend::load(&mut *self.config.borrow_mut())
    }
}

impl<C: ConfigStoreBackend> HasConfigStore for ConfigStorage<C> {
    type State = C::State;
    type Config = C::Config;
    fn save_config(&self, state: &Self::State) {
        ConfigStoreBackend::save(&mut *self.config.borrow_mut(), state);
    }
    fn load_config(&self) -> Option<Self::Config> {
        ConfigStorage::load_config(self)
    }
}

impl<C: ConfigStoreBackend> StorageHooks for ConfigStorage<C> {
    // Nothing durable to erase: the config blob is not wiped by erase codes
    // (the state-side `apply_erase_code` resets the runtime state, and the
    // follow-up save persists that). The mc_timer no-op defaults stand.
    fn erase(&self, _code: EraseCode) {}
}

/// The stores of a **KNX Data Secure** device: the config blob plus the
/// sequence/SIAT store the secure layers replay-protect with.
pub struct SecureStorage<C, S>
where
    C: ConfigStoreBackend,
    S: SequenceNumberStorage + SiatAccess,
{
    /// The config-blob store, opened at the device's `CONFIG` placement.
    pub config: RefCell<C>,
    /// The sequence/SIAT store (flash `SiatStore` or FRAM-backed).
    pub seq: RefCell<S>,
}

impl<C, S> SecureStorage<C, S>
where
    C: ConfigStoreBackend,
    S: SequenceNumberStorage + SiatAccess,
{
    pub fn new(config: C, seq: S) -> Self {
        Self { config: RefCell::new(config), seq: RefCell::new(seq) }
    }

    /// Load the persisted config — see [`ConfigStorage::load_config`].
    pub fn load_config(&self) -> Option<C::Config> {
        ConfigStoreBackend::load(&mut *self.config.borrow_mut())
    }
}

impl<C, S> HasConfigStore for SecureStorage<C, S>
where
    C: ConfigStoreBackend,
    S: SequenceNumberStorage + SiatAccess,
{
    type State = C::State;
    type Config = C::Config;
    fn save_config(&self, state: &Self::State) {
        ConfigStoreBackend::save(&mut *self.config.borrow_mut(), state);
    }
    fn load_config(&self) -> Option<Self::Config> {
        SecureStorage::load_config(self)
    }
}

impl<C, S> HasSeqStore for SecureStorage<C, S>
where
    C: ConfigStoreBackend,
    S: SequenceNumberStorage + SiatAccess,
{
    type Seq = S;
    fn seq_store(&self) -> &RefCell<S> {
        &self.seq
    }
}

impl<C, S> StorageHooks for SecureStorage<C, S>
where
    C: ConfigStoreBackend,
    S: SequenceNumberStorage + SiatAccess,
{
    fn erase(&self, code: EraseCode) {
        // Factory codes apply the near-exhaustion sending-SeqNr re-init.
        super::seq::erase_seq_on_factory_reset(&mut *self.seq.borrow_mut(), code);
    }
}

/// The stores of a **KNX IP Secure routing** device: config + seq plus the
/// durable multicast-timer watermark (03/08/09 §2.2.4.2).
pub struct SecureIpStorage<C, S, M>
where
    C: ConfigStoreBackend,
    S: SequenceNumberStorage + SiatAccess,
    M: McTimerStoreBackend,
{
    /// The config-blob store, opened at the device's `CONFIG` placement.
    pub config: RefCell<C>,
    /// The sequence/SIAT store.
    pub seq: RefCell<S>,
    /// The mc_timer watermark store.
    pub mc_timer: RefCell<M>,
}

impl<C, S, M> SecureIpStorage<C, S, M>
where
    C: ConfigStoreBackend,
    S: SequenceNumberStorage + SiatAccess,
    M: McTimerStoreBackend,
{
    pub fn new(config: C, seq: S, mc_timer: M) -> Self {
        Self { config: RefCell::new(config), seq: RefCell::new(seq), mc_timer: RefCell::new(mc_timer) }
    }

    /// Load the persisted config — see [`ConfigStorage::load_config`].
    pub fn load_config(&self) -> Option<C::Config> {
        ConfigStoreBackend::load(&mut *self.config.borrow_mut())
    }
}

impl<C, S, M> HasConfigStore for SecureIpStorage<C, S, M>
where
    C: ConfigStoreBackend,
    S: SequenceNumberStorage + SiatAccess,
    M: McTimerStoreBackend,
{
    type State = C::State;
    type Config = C::Config;
    fn save_config(&self, state: &Self::State) {
        ConfigStoreBackend::save(&mut *self.config.borrow_mut(), state);
    }
    fn load_config(&self) -> Option<Self::Config> {
        SecureIpStorage::load_config(self)
    }
}

impl<C, S, M> HasSeqStore for SecureIpStorage<C, S, M>
where
    C: ConfigStoreBackend,
    S: SequenceNumberStorage + SiatAccess,
    M: McTimerStoreBackend,
{
    type Seq = S;
    fn seq_store(&self) -> &RefCell<S> {
        &self.seq
    }
}

impl<C, S, M> StorageHooks for SecureIpStorage<C, S, M>
where
    C: ConfigStoreBackend,
    S: SequenceNumberStorage + SiatAccess,
    M: McTimerStoreBackend,
{
    fn erase(&self, code: EraseCode) {
        super::seq::erase_seq_on_factory_reset(&mut *self.seq.borrow_mut(), code);
        if code.is_factory_reset() && McTimerStoreBackend::clear(&mut *self.mc_timer.borrow_mut()).is_err() {
            crate::logging::warn!("mc_timer clear failed");
        }
    }
    fn load_mc_timer(&self) -> u64 {
        McTimerStoreBackend::load(&*self.mc_timer.borrow())
    }
    fn save_mc_timer(&self, value: u64) {
        if McTimerStoreBackend::save(&mut *self.mc_timer.borrow_mut(), value).is_err() {
            crate::logging::warn!("mc_timer save failed — watermark not persisted");
        }
    }
}

/// Compile-fail proof of the secure-builder gate: a config-only handle has
/// no [`HasSeqStore`](super::seq::HasSeqStore) impl, so code that needs the
/// sequence store (the secure composition bounds on `D::Storage:
/// HasSeqStore`) cannot be given a [`ConfigStorage`].
///
/// ```compile_fail
/// use zweidraehte_device::storage::definition::NoStore;
/// use zweidraehte_device::storage::{ConfigStorage, HasSeqStore};
///
/// fn needs_seq_store<T: HasSeqStore>(_t: &T) {}
///
/// let storage = ConfigStorage::new(NoStore);
/// // ConfigStorage has no seq store — must not compile.
/// needs_seq_store(&storage);
/// ```
#[allow(dead_code)]
struct ConfigOnlyHandleHasNoSeqStore;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::region::{
        Chip, ConfigRegion, FlashSiatRegion, McTimerRegion, RegionPlacement, RegionSpec, region_placement, region_spec,
    };

    // A test chip; the stores are the NoStore sentinel standing in for real
    // backends (its `*StoreBackend` impls are the no-ops above), so the
    // handle structs' capability impls and the layout derivation are all
    // exercised without HAL types.
    struct Flash;
    impl Chip for Flash {
        const TAG: u32 = 0;
        const BASE: u32 = 0x1F6000;
        const CAPACITY: u32 = 0x200000;
        const SECTOR_SIZE: u32 = 0x1000;
        type Io = ();
    }

    // The device-side layout declaration: the SIAT entry needs no named
    // placement here — it still packs and is guarded, shifting the later
    // same-chip offsets.
    const REGIONS: &[RegionSpec] = &[
        region_spec::<Flash, FlashSiatRegion<0x6000, 34, 32>>(),
        region_spec::<Flash, McTimerRegion<0x2000>>(),
        region_spec::<Flash, ConfigRegion<0x1000, ()>>(),
    ];
    const MC_TIMER: RegionPlacement<McTimerRegion<0x2000>, Flash> = region_placement(REGIONS);
    const CONFIG: RegionPlacement<ConfigRegion<0x1000, ()>, Flash> = region_placement(REGIONS);

    /// Each handle struct (and, via the forwarding impls, the `&'static`
    /// handle a device stores in `StackDefinition::Storage`) carries the
    /// storage task's whole bound surface.
    #[test]
    fn handles_carry_the_task_bound_surface() {
        fn takes_task_handle<C: HasConfigStore<State = ()> + StorageHooks>(_c: C) {}

        let storage = ConfigStorage::new(NoStore);
        takes_task_handle(&storage);
        assert_eq!(storage.load_mc_timer(), 0); // no mc_timer store: default stands
        storage.save_config(&());
        storage.erase(EraseCode::FactoryReset);
    }

    /// `SecureIpStorage` overrides the mc_timer hooks (here through the
    /// `NoStore` no-op backend) and composes the factory-erase body; the
    /// `NoStore` seq sentinel is not a valid `S`, so a real store double is
    /// unnecessary — the FRAM/flash-backed structs are covered by the views
    /// tests and the cross builds.
    #[test]
    fn config_storage_has_empty_erase() {
        // Erase on a config-only handle must not touch the config blob: a
        // subsequent load still goes to the backend (NoStore: None).
        let storage = ConfigStorage::new(NoStore);
        storage.erase(EraseCode::FactoryReset);
        assert_eq!(storage.load_config(), None);
    }

    /// The device-side placement derivation reproduces the historical flash
    /// map: entries are found by their region type, offsets by the prefix
    /// sum, and the chip's sector size rides along.
    #[test]
    fn derived_placements_match_historical_map() {
        assert_eq!(MC_TIMER.offset, 0x1FC000); // after the SIAT's 0x6000
        assert_eq!(MC_TIMER.sector_size, 0x1000);

        assert_eq!(CONFIG.offset, 0x1FE000); // after mc_timer's 0x2000
        assert_eq!(CONFIG.sector_size, 0x1000);
    }
}
