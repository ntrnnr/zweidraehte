//! The per-device stores structs and their capability traits.
//!
//! A device's live stores are grouped in one of three **handle structs** —
//! one per real-world store combination, each structurally containing only
//! the stores that combination needs:
//!
//! - [`ConfigStorage`] — config only (plain devices)
//! - [`SecureStorage`] — config + sequence/SIAT store (KNX Data Secure)
//! - [`SecureIpStorage`] — config + seq + mc_timer watermark (KNX IP Secure
//!   routing)
//!
//! The config slot holds the device's write-through store
//! ([`NvConfig`](super::NvConfig)); each struct forwards
//! [`ConfigFlush`](super::ConfigFlush) to it (`flush.rs`). Each also carries
//! hand-written [`HasSeqStore`] / [`StorageHooks`] impls with exactly its
//! combination's bounds and erase behavior.
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
//! A failed flush leaves the state dirty; the router and the storage task
//! retry it, and a restart waits until it succeeds. Security-counter hooks
//! retain their existing synchronous contracts.

use crate::restart::{EraseCode, RestartType};

// ============================================================================
// NoStore + store behaviour traits (implemented by the concrete stores)
// ============================================================================
//
// Two layers, each with one job — when adding a new framework-blessed store
// kind, touch each once (a device-custom store touches none of them):
//
// 1. `*StoreBackend` (here) — the behavioural surface a *concrete store type*
//    implements (plus the `NoStore` no-op). HAL-free via associated types.
// 2. The stores-struct surface (below) — the `HasSeqStore` capability per
//    declared kind, plus the kind's slice of the composed `StorageHooks`
//    impl (its erase statement, its method overrides). The generic storage
//    task bounds on these directly.

/// Projection of a runtime state onto its configuration data model.
///
/// Implemented by a BCU's runtime state type (e.g.
/// [`SystemBDeviceState`](crate::bcus::system_b::SystemBDeviceState)). The
/// device persists its persistent sections, not this; the data model is
/// what conformance fixtures build preconfigured boot images from and what
/// the section tests compare against.
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
    /// The device-level configuration data model.
    type Config;

    /// Project the current runtime state onto the data model.
    fn to_config(&self) -> Self::Config;
}

/// The boot-image type of a device that never boots from one: every real
/// device starts factory-fresh and applies its stored sections afterwards.
///
/// Uninhabited, so a `StateInit` over it can only say "no boot image", and
/// the state's `from_config` path is provably dead and compiles out of the
/// firmware (the `From` impls into the configuration types are `match
/// image {}`). Conformance fixtures and tests use the configuration type
/// itself instead, to boot from a preconfigured image.
#[derive(Debug, Clone, Copy)]
pub enum NoBootImage {}

/// The store sentinel for a kind a device does not declare — the no-op impl
/// target the macro's absent-kind emission mirrors.
pub struct NoStore;

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

// ============================================================================
// Capability traits (implemented by the macro-emitted stores struct)
// ============================================================================

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
/// - [`on_restart`](Self::on_restart): overridden only where a restart is
///   *observed* from outside the device. Everywhere else the no-op default
///   stands.
// `async fn` (not `-> impl Future + Send`) for `on_restart`, for the same
// reason as `SaveGuard`: the storage task runs on a single-threaded embassy
// executor, so the lint's suggested workaround would impose a `Send` bound
// we'd then have to fight.
#[allow(async_fn_in_trait)]
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

    /// Announce an impending restart: called at the top of the storage
    /// task's restart arm, after the outbox has drained and before any
    /// erase touches state.
    ///
    /// A device that simply resets has nothing to announce, so the default
    /// is a no-op. It exists for devices whose restart is *observed* by an
    /// external party that has to be told while the outgoing frames are
    /// still in flight, rather than after the device has stopped serving
    /// the bus. The conformance DUTs are the case in point: their harness
    /// couples the "I am exiting" notification onto the in-flight step
    /// reply, so announcing any later than here is indistinguishable from
    /// the DUT dying unannounced.
    ///
    /// Called before [`erase`](Self::erase) so the announcement carries
    /// pre-erase state; the restart is passed for devices that report
    /// *why* they are restarting.
    async fn on_restart(&self, _restart: RestartType) {}
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
    async fn on_restart(&self, restart: RestartType) {
        (*self).on_restart(restart).await;
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

/// The stores of a **config-only** device: just the ETS configuration.
///
/// No sequence store — and therefore no
/// [`HasSeqStore`] impl, which is what rejects the
/// secure builders for these devices at compile time.
pub struct ConfigStorage<C> {
    /// The write-through config store, opened at the device's `CONFIG`
    /// placement.
    pub config: C,
}

impl<C> ConfigStorage<C> {
    pub fn new(config: C) -> Self {
        Self { config }
    }
}

impl<C> StorageHooks for ConfigStorage<C> {
    // Nothing durable to erase: erase codes reset the runtime state
    // (`apply_erase_code`), and the flush that follows persists that. The
    // mc_timer no-op defaults stand.
    fn erase(&self, _code: EraseCode) {}
}

/// The stores of a **KNX Data Secure** device: the configuration plus the
/// sequence/SIAT store the secure layers replay-protect with.
///
/// The container has no declaration-level bounds; each capability
/// implementation constrains only the field it uses.
pub struct SecureStorage<C, S> {
    /// The write-through config store, opened at the device's `CONFIG`
    /// placement.
    pub config: C,
    /// The sequence/SIAT store (flash `SiatStore` or FRAM-backed).
    pub seq: RefCell<S>,
}

impl<C, S> SecureStorage<C, S>
where
    S: SequenceNumberStorage + SiatAccess,
{
    pub fn new(config: C, seq: S) -> Self {
        Self { config, seq: RefCell::new(seq) }
    }
}
impl<C, S> HasSeqStore for SecureStorage<C, S>
where
    S: SequenceNumberStorage + SiatAccess,
{
    type Seq = S;
    fn seq_store(&self) -> &RefCell<S> {
        &self.seq
    }
}

impl<C, S> StorageHooks for SecureStorage<C, S>
where
    S: SequenceNumberStorage + SiatAccess,
{
    fn erase(&self, code: EraseCode) {
        // Factory codes apply the near-exhaustion sending-SeqNr re-init.
        super::seq::erase_seq_on_factory_reset(&mut *self.seq.borrow_mut(), code);
    }
}

/// The stores of a **KNX IP Secure routing** device: config + seq plus the
/// durable multicast-timer watermark (03/08/09 §2.2.4.2).
///
/// As on [`SecureStorage`], each capability implementation constrains only
/// the field it uses.
pub struct SecureIpStorage<C, S, M> {
    /// The write-through config store, opened at the device's `CONFIG`
    /// placement.
    pub config: C,
    /// The sequence/SIAT store.
    pub seq: RefCell<S>,
    /// The mc_timer watermark store.
    pub mc_timer: RefCell<M>,
}

impl<C, S, M> SecureIpStorage<C, S, M>
where
    S: SequenceNumberStorage + SiatAccess,
    M: McTimerStoreBackend,
{
    pub fn new(config: C, seq: S, mc_timer: M) -> Self {
        Self { config, seq: RefCell::new(seq), mc_timer: RefCell::new(mc_timer) }
    }
}
impl<C, S, M> HasSeqStore for SecureIpStorage<C, S, M>
where
    S: SequenceNumberStorage + SiatAccess,
{
    type Seq = S;
    fn seq_store(&self) -> &RefCell<S> {
        &self.seq
    }
}

impl<C, S, M> StorageHooks for SecureIpStorage<C, S, M>
where
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
    use crate::storage::ConfigFlush;
    use crate::storage::region::{
        Chip, ConfigLogRegion, FlashSiatRegion, McTimerRegion, RegionPlacement, RegionSpec, region_placement,
        region_spec,
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
        region_spec::<Flash, ConfigLogRegion<0x2000>>(),
    ];
    const MC_TIMER: RegionPlacement<McTimerRegion<0x2000>, Flash> = region_placement(REGIONS);
    const CONFIG: RegionPlacement<ConfigLogRegion<0x2000>, Flash> = region_placement(REGIONS);

    /// Each handle struct (and, via the forwarding impls, the `&'static`
    /// handle a device stores in `StackDefinition::Storage`) carries the
    /// storage task's whole bound surface.
    #[test]
    fn handles_carry_the_task_bound_surface() {
        fn takes_task_handle<C: ConfigFlush<()> + StorageHooks>(_c: C) {}

        let storage = ConfigStorage::new(NoStore);
        takes_task_handle(&storage);
        assert_eq!(storage.load_mc_timer(), 0); // no mc_timer store: default stands
        storage.erase(EraseCode::FactoryReset);
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
