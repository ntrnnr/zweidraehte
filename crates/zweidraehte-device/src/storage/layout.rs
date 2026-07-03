//! The device-facing storage surface: regions that open their own stores.
//!
//! [`region`](super::region) proves *where* everything lives; this module
//! couples each region to *what* lives there. The pieces:
//!
//! - [`Stored<C>`] — "this region, stored on chip `C`": maps a region marker
//!   to its concrete store/middleware type and the `open` that builds it.
//!   Implemented here, in core, once per marker × medium contract — platform
//!   crates contribute only `Chip` impls and `Io` adapters.
//! - [`StorageLayout`] — a device's storage map: the ordered region list as
//!   one associated const.
//! - [`Placed<R, C, L>`] — one entry of that map. From its three type
//!   arguments it derives the layout entry ([`SPEC`](Placed::SPEC)), the
//!   proven placement, the store type ([`StoreOf`]), and the
//!   [`open()`](Placed::open) — so a device names each region + chip pair
//!   exactly once:
//!
//! ```ignore
//! struct StorageMap;
//! type Cfg = Placed<ConfigRegion<{ CONFIG_SIZE }, DeviceState>, StmFlash, StorageMap>;
//! type Seq = Placed<FramSiatRegion<{ FRAM_CAPACITY }, SIAT_SIZE>, FramChip, StorageMap>;
//! impl StorageLayout for StorageMap {
//!     const REGIONS: &'static [RegionSpec] = &[Cfg::SPEC, Seq::SPEC];
//! }
//! type DeviceStorage = SecureStorage<StoreOf<Cfg>, StoreOf<Seq>>;
//!
//! // main():
//! let storage = &*STORAGE.init(DeviceStorage::new(
//!     Cfg::open(StmFlashIo::new(flash_cell)).expect("config open is infallible"),
//!     Seq::open(FramRegion::new(fram_cell)).expect("boot FRAM seq store"),
//! ));
//! ```
//!
//! There is no const-evaluation cycle in that shape: `L::REGIONS` lists
//! `Placed::SPEC`s, which read only the chip's and region's consts — never
//! `L` — while `Placed::PLACEMENT` reads `L::REGIONS`. One direction each.
//!
//! The layout proof still fires at compile time: `PLACEMENT` is a generic
//! associated const (the same mechanism as `Region::KIND`), forced when
//! `open()` monomorphizes — a bad layout is a const-panic compile error at
//! the device build. A region that is declared but never opened is still
//! proven, because any *other* entry's `open` runs [`check_layout`] over the
//! whole array.
//!
//! [`Stored::open`] is a convenience, not a boundary: the store primitives
//! (`ConfigStore::open_at`, `WearLeveledKv::open_at`,
//! `PackedSeqStore::new`/`open_at`, `SiatStore::boot`) stay public for
//! hand-assembled setups — the conformance harness's whole-medium
//! shared-memory store is the worked example.
//!
//! [`check_layout`]: super::region::check_layout

use core::convert::Infallible;
use core::marker::PhantomData;

use super::backends::{ByteIo, ConfigStore, PackedSeqStore, PackedWatermark, SectorIo, WearLeveledKv};
use super::region::{
    Chip, ConfigRegion, FlashSiatRegion, FramMcTimerRegion, FramSiatRegion, McTimerRegion, Region, RegionPlacement,
    RegionSpec, region_placement, region_spec,
};
use super::views::{McTimerStore, SiatStore};

// ============================================================================
// Stored — the region ↔ store coupling
// ============================================================================

/// "This region, stored on chip `C`": the coupling between a region marker
/// and the concrete store opened over it. The store type, the payload, and
/// every capacity are facts of the region's type arguments; the medium
/// contract is the bound on `C::Io` (a flash-mechanism region is only
/// `Stored` on chips whose adapter is a [`SectorIo`], a byte-mechanism
/// region only on [`ByteIo`] chips).
///
/// Devices normally reach this through [`Placed`], which supplies the
/// layout-derived placement; hand-assembled setups may call
/// [`open`](Self::open) with a placement from
/// [`region_placement`](super::region::region_placement) directly.
pub trait Stored<C: Chip>: Region + Sized {
    /// The concrete store/middleware `open` yields — e.g. the config blob
    /// codec, or the SIAT view over its medium-appropriate backend.
    type Store;
    /// `open`'s error: the medium's I/O error for stores that scan the
    /// region at boot, [`Infallible`] for stores that only record the
    /// placement.
    type OpenError;
    /// Build the store over `io` at this region's own placement. Another
    /// region's — or another chip's — placement is a type error.
    fn open(io: C::Io, placement: RegionPlacement<Self, C>) -> Result<Self::Store, Self::OpenError>;
}

// ============================================================================
// StorageLayout + Placed — the per-device declaration surface
// ============================================================================

/// A device's storage map: the ordered region list the placements derive
/// from. Implemented by a device-local marker type; the entries are the
/// device's [`Placed`] aliases' [`SPEC`](Placed::SPEC)s, in pack order.
pub trait StorageLayout {
    /// The layout entries, in auto-pack order (same-chip entries pack
    /// upward from the chip's base in array order).
    const REGIONS: &'static [RegionSpec];
}

/// One entry of a device's storage map: region `R` on chip `C` in layout
/// `L`. Everything else derives from those three names — the layout entry
/// ([`SPEC`](Self::SPEC)), the proven placement, the store type
/// ([`StoreOf`]), and [`open`](Self::open).
///
/// Never constructed; used purely through its associated items.
pub struct Placed<R, C: Chip, L>(PhantomData<(R, C, L)>);

impl<R: Region, C: Chip, L> Placed<R, C, L> {
    /// This entry's layout line — what the device's
    /// [`StorageLayout::REGIONS`] array lists. Reads only `C`'s and `R`'s
    /// consts, so listing it inside `L`'s own impl is not a cycle.
    pub const SPEC: RegionSpec = region_spec::<C, R>();
}

impl<R: Stored<C>, C: Chip, L: StorageLayout> Placed<R, C, L> {
    /// The layout-derived placement, proven against the whole `L::REGIONS`
    /// array. A generic associated const: forced at `open`'s
    /// monomorphization, where a bad layout const-panics into a compile
    /// error.
    const PLACEMENT: RegionPlacement<R, C> = region_placement(L::REGIONS);

    /// Open this entry's store over the chip's `io` handle at the derived
    /// placement. The handle is `Copy` — a chip carrying several regions
    /// passes the same handle to each entry's `open`.
    pub fn open(io: C::Io) -> Result<R::Store, R::OpenError> {
        R::open(io, Self::PLACEMENT)
    }
}

/// The store-type projection behind [`StoreOf`] — implemented by [`Placed`]
/// so a device's stores-struct alias can name each slot's store type without
/// re-stating the region or chip.
pub trait Opens {
    /// The store type this entry's [`open`](Placed::open) yields.
    type Store;
}

impl<R: Stored<C>, C: Chip, L> Opens for Placed<R, C, L> {
    type Store = R::Store;
}

/// The store type a [`Placed`] entry opens — for the device's stores-struct
/// alias: `SecureStorage<StoreOf<Cfg>, StoreOf<Seq>>`.
pub type StoreOf<P> = <P as Opens>::Store;

// ============================================================================
// Stored impls — one per marker × medium contract
// ============================================================================

// The `SIZE` marker parameter is passed *bare* into `ConfigStore`'s buffer
// const generic — the whole reason the markers carry `usize` sizes. Any
// arithmetic here (e.g. `{ SIZE / 2 }`) would need `generic_const_exprs`,
// which the pinned nightly cannot handle; keep marker parameters verbatim.
impl<C: Chip, const SIZE: usize, S> Stored<C> for ConfigRegion<SIZE, S>
where
    C::Io: SectorIo,
{
    type Store = ConfigStore<C::Io, S, Self, SIZE>;
    type OpenError = Infallible;

    fn open(io: C::Io, placement: RegionPlacement<Self, C>) -> Result<Self::Store, Self::OpenError> {
        // Recording the placement cannot fail; the region is only read at
        // the boot-time `load_config` call.
        Ok(ConfigStore::open_at(io, placement))
    }
}

impl<C: Chip, const SIZE: usize, const ENTRIES: usize, const CACHE: usize, const BATCH: u64> Stored<C>
    for FlashSiatRegion<SIZE, ENTRIES, CACHE, BATCH>
where
    C::Io: SectorIo,
{
    type Store = SiatStore<WearLeveledKv<C::Io, Self, ENTRIES>, CACHE, BATCH>;
    type OpenError = <C::Io as SectorIo>::Error;

    fn open(io: C::Io, placement: RegionPlacement<Self, C>) -> Result<Self::Store, Self::OpenError> {
        // Scan the append log's sectors, then rebuild the SIAT RAM mirror
        // from the surviving records.
        SiatStore::boot(WearLeveledKv::open_at(io, placement)?)
    }
}

impl<C: Chip, const SIZE: usize, const SLOTS: usize, const BATCH: u64> Stored<C> for FramSiatRegion<SIZE, SLOTS, BATCH>
where
    C::Io: ByteIo,
{
    type Store = SiatStore<PackedSeqStore<C::Io, Self, SLOTS>, SLOTS, BATCH>;
    type OpenError = <C::Io as ByteIo>::Error;

    fn open(io: C::Io, placement: RegionPlacement<Self, C>) -> Result<Self::Store, Self::OpenError> {
        // The packed layout needs no scan (fixed offsets); the boot read
        // rebuilds the SIAT RAM mirror.
        SiatStore::boot(PackedSeqStore::open_at(io, placement))
    }
}

impl<C: Chip, const SIZE: usize> Stored<C> for McTimerRegion<SIZE>
where
    C::Io: SectorIo,
{
    type Store = McTimerStore<WearLeveledKv<C::Io, Self, 1>>;
    type OpenError = <C::Io as SectorIo>::Error;

    fn open(io: C::Io, placement: RegionPlacement<Self, C>) -> Result<Self::Store, Self::OpenError> {
        // One live record (the watermark singleton), so the log needs a
        // single mirror entry.
        Ok(McTimerStore::new(WearLeveledKv::open_at(io, placement)?))
    }
}

impl<C: Chip, const SIZE: usize> Stored<C> for FramMcTimerRegion<SIZE>
where
    C::Io: ByteIo,
{
    type Store = PackedWatermark<C::Io, Self>;
    type OpenError = Infallible;

    fn open(io: C::Io, placement: RegionPlacement<Self, C>) -> Result<Self::Store, Self::OpenError> {
        Ok(PackedWatermark::open_at(io, placement))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::region::RegionKind;

    /// The layout-arithmetic test chip; `Io = ()` gets a no-op `SectorIo`
    /// below so `Placed::open` itself is exercisable.
    struct TestFlash;
    impl Chip for TestFlash {
        const TAG: u32 = 0;
        const BASE: u32 = 0x1F6000;
        const CAPACITY: u32 = 0x200000;
        const SECTOR_SIZE: u32 = 0x1000;
        type Io = ();
    }

    impl SectorIo for () {
        type Error = core::convert::Infallible;
        fn read(&mut self, _offset: u32, buf: &mut [u8]) -> Result<(), Self::Error> {
            buf.fill(0xFF);
            Ok(())
        }
        fn erase(&mut self, _start: u32, _end: u32) -> Result<(), Self::Error> {
            Ok(())
        }
        fn write(&mut self, _offset: u32, _data: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    // The exact circular-looking device shape: the layout lists the Placed
    // aliases' SPECs while the aliases name the layout. No const cycle —
    // SPEC never reads L.
    struct StorageMap;
    type Cfg = Placed<ConfigRegion<0x1000, ()>, TestFlash, StorageMap>;
    type Mct = Placed<McTimerRegion<0x2000>, TestFlash, StorageMap>;
    impl StorageLayout for StorageMap {
        const REGIONS: &'static [RegionSpec] = &[Mct::SPEC, Cfg::SPEC];
    }

    /// `Placed` derives the same placements `region_placement` yields
    /// directly, and its `open` builds the store from just the chip handle.
    #[test]
    fn placed_derives_placements_and_opens() {
        assert_eq!(Mct::PLACEMENT.offset, 0x1F6000);
        assert_eq!(Cfg::PLACEMENT.offset, 0x1F8000); // after mc_timer's 0x2000
        assert_eq!(Cfg::PLACEMENT.sector_size, 0x1000);

        // The stores-struct slot type is nameable without re-stating region
        // or chip, and open() yields exactly that type.
        let store: StoreOf<Cfg> = Cfg::open(()).expect("config open is infallible");
        let _ = store;
    }

    /// The SPEC constants carry the marker facts into the layout array.
    #[test]
    fn spec_carries_region_and_chip_facts() {
        assert_eq!(Cfg::SPEC.magic, u32::from_be_bytes(*b"KNXS"));
        assert_eq!(Cfg::SPEC.size, 0x1000);
        assert!(Cfg::SPEC.kind.eq(RegionKind::EraseRewrite));
        assert_eq!(Mct::SPEC.chip_tag, TestFlash::TAG);
    }
}
