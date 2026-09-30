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
//! type Cfg = Placed<ConfigLogRegion<{ CONFIG_SIZE }, DeviceState>, StmFlash, StorageMap>;
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
//! (`NvConfig::new`, `WearLeveledKv::open`, [`packed_seq_store`],
//! `SiatStore::boot`) stay public for hand-assembled setups — the
//! conformance harness's whole-medium shared-memory store is the worked
//! example.
//!
//! [`check_layout`]: super::region::check_layout

use core::convert::Infallible;
use core::marker::PhantomData;

use zweidraehte_nv::{FlashLog, LogGeometry};

use super::backends::{ByteIo, NvConfig, PackedSeqStore, PackedWatermark, SectorIo, WearLeveledKv, region_len};
use super::region::{
    Chip, ConfigLogRegion, FlashSiatRegion, FramMcTimerRegion, FramSiatRegion, McTimerRegion, Region, RegionKind,
    RegionPlacement, RegionSpec, region_placement, region_spec,
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
/// [`region_placement`] directly.
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

/// The longest padded record of a [`ConfigLogRegion`]'s log.
///
/// A record carries at most 255 payload bytes behind 4 of framing, padded to
/// the medium's write granule, and `REC` must be whole granules: 256 is
/// valid on every medium up to 16-byte granules (the RP2040's 1, the
/// STM32G0's 8). It leaves 249 section bytes per record, so a single
/// A_Memory_Write (at most 63 bytes) fits one record and applies atomically
/// after a power cut (see [`FlashLog`]).
pub const CONFIG_LOG_REC: usize = 256;

impl<C: Chip, const SIZE: usize, S> Stored<C> for ConfigLogRegion<SIZE, S>
where
    C::Io: SectorIo,
{
    type Store = NvConfig<FlashLog<C::Io, CONFIG_LOG_REC>, S>;
    type OpenError = Infallible;

    fn open(io: C::Io, placement: RegionPlacement<Self, C>) -> Result<Self::Store, Self::OpenError> {
        // Recording the geometry cannot fail; the log is scanned by
        // `NvConfig::load` once the state it applies to exists.
        Ok(NvConfig::new(FlashLog::new(io, config_log_geometry(placement))))
    }
}

/// The log geometry of a config-log region: two banks, each half the
/// region's sectors. Few large banks rather than many small ones, because
/// every bank must hold a whole snapshot of the state and what is left of
/// the active bank is the room for appends between compactions.
fn config_log_geometry<R: Region, C: Chip>(placement: RegionPlacement<R, C>) -> LogGeometry {
    #[allow(clippy::let_unit_value)]
    let () = ConfigLogCheck::<R, C>::CHECK;
    let sectors = R::SIZE / C::SECTOR_SIZE;
    LogGeometry { offset: placement.offset, sector_size: C::SECTOR_SIZE, sectors_per_bank: sectors / 2, banks: 2 }
}

/// Carrier of the compile-time checks that region `R` on chip `C` can hold a
/// two-bank config log; see [`AppendLogRegion`] for why this is an
/// associated const.
struct ConfigLogCheck<R, C>(PhantomData<(R, C)>);

impl<R: Region, C: Chip> ConfigLogCheck<R, C> {
    const CHECK: () = {
        core::assert!(
            R::KIND.eq(RegionKind::AppendLog),
            "a config log requires an append-log region (Region::KIND == AppendLog)"
        );
        core::assert!(R::SIZE % (2 * C::SECTOR_SIZE) == 0, "a config log splits into two banks of whole sectors");
    };
}

/// The log geometry of an append-log region: one sector per bank, as many
/// banks as the region has sectors, so every sector takes its turn in the
/// rotation.
///
/// This is also where the region↔magic binding holds: the key/value store
/// takes its magic as a plain argument, and only the `Stored` impl for `R`
/// passes `R::MAGIC` together with `R`'s own placement.
fn append_log_geometry<R: Region, C: Chip>(placement: RegionPlacement<R, C>) -> LogGeometry {
    #[allow(clippy::let_unit_value)]
    let () = AppendLogRegion::<R>::CHECK;
    LogGeometry {
        offset: placement.offset,
        sector_size: placement.sector_size,
        sectors_per_bank: 1,
        banks: R::SIZE / placement.sector_size,
    }
}

/// Carrier of the compile-time check that a region handed to the append log
/// is an append-log region. An associated const rather than an inline
/// `const {}` block, which `generic_const_exprs` rejects over a generic `R`.
struct AppendLogRegion<R>(PhantomData<R>);

impl<R: Region> AppendLogRegion<R> {
    const CHECK: () = core::assert!(
        R::KIND.eq(RegionKind::AppendLog),
        "a wear-levelled log requires an append-log region (Region::KIND == AppendLog)"
    );
}

impl<C: Chip, const SIZE: usize, const ENTRIES: usize, const CACHE: usize, const BATCH: u64> Stored<C>
    for FlashSiatRegion<SIZE, ENTRIES, CACHE, BATCH>
where
    C::Io: SectorIo,
{
    type Store = SiatStore<WearLeveledKv<C::Io, ENTRIES>, CACHE, BATCH>;
    type OpenError = <C::Io as SectorIo>::Error;

    fn open(io: C::Io, placement: RegionPlacement<Self, C>) -> Result<Self::Store, Self::OpenError> {
        // Scan the append log's sectors, then rebuild the SIAT RAM mirror
        // from the surviving records.
        SiatStore::boot(WearLeveledKv::open(io, append_log_geometry(placement), Self::MAGIC)?)
    }
}

/// Open the packed sequence/SIAT layout of write-in-place region `R` at
/// `offset` within `medium`, under `R`'s magic.
///
/// The `Stored` impl of a placed [`FramSiatRegion`] opens through this; a
/// medium the region owns outright (the conformance shared memory, the Linux
/// file) calls it with offset 0. Either way the region's kind and size are
/// checked against the layout at compile time.
pub fn packed_seq_store<R: Region, M: ByteIo, const SLOTS: usize>(medium: M, offset: u32) -> PackedSeqStore<M, SLOTS> {
    #[allow(clippy::let_unit_value)]
    let () = PackedSeqRegion::<R, SLOTS>::CHECK;
    PackedSeqStore::new(medium, offset, R::MAGIC)
}

/// Carrier of the compile-time checks that region `R` can hold the packed
/// layout for `SLOTS` SIAT elements; see [`AppendLogRegion`] for why this is
/// an associated const.
struct PackedSeqRegion<R, const SLOTS: usize>(PhantomData<R>);

impl<R: Region, const SLOTS: usize> PackedSeqRegion<R, SLOTS> {
    const CHECK: () = {
        core::assert!(
            R::KIND.eq(RegionKind::WriteInPlace),
            "the packed sequence layout requires a write-in-place region (Region::KIND == WriteInPlace)"
        );
        core::assert!(
            region_len(SLOTS) <= R::SIZE as usize,
            "the packed sequence layout (region_len(SLOTS)) exceeds the region's SIZE"
        );
    };
}

impl<C: Chip, const SIZE: usize, const SLOTS: usize> Stored<C> for FramSiatRegion<SIZE, SLOTS>
where
    C::Io: ByteIo,
{
    type Store = PackedSeqStore<C::Io, SLOTS>;
    type OpenError = Infallible;

    fn open(io: C::Io, placement: RegionPlacement<Self, C>) -> Result<Self::Store, Self::OpenError> {
        // Fixed offsets and no RAM mirror: nothing to scan at boot.
        Ok(packed_seq_store::<Self, _, SLOTS>(io, placement.offset))
    }
}

impl<C: Chip, const SIZE: usize> Stored<C> for McTimerRegion<SIZE>
where
    C::Io: SectorIo,
{
    type Store = McTimerStore<WearLeveledKv<C::Io, 1>>;
    type OpenError = <C::Io as SectorIo>::Error;

    fn open(io: C::Io, placement: RegionPlacement<Self, C>) -> Result<Self::Store, Self::OpenError> {
        // One live record (the watermark singleton), so the log needs a
        // single mirror entry.
        Ok(McTimerStore::new(WearLeveledKv::open(io, append_log_geometry(placement), Self::MAGIC)?))
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

    /// The layout-arithmetic test chip; `Io = NullFlash` is a no-op
    /// `SectorIo` so `Placed::open` itself is exercisable.
    struct TestFlash;
    impl Chip for TestFlash {
        const TAG: u32 = 0;
        const BASE: u32 = 0x1F6000;
        const CAPACITY: u32 = 0x200000;
        const SECTOR_SIZE: u32 = 0x1000;
        type Io = NullFlash;
    }

    /// Reads as erased flash, accepts every write and erase.
    #[derive(Clone, Copy)]
    struct NullFlash;

    impl SectorIo for NullFlash {
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
    type Cfg = Placed<ConfigLogRegion<0x2000, ()>, TestFlash, StorageMap>;
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
        let store: StoreOf<Cfg> = Cfg::open(NullFlash).expect("config open is infallible");
        let _ = store;
    }

    /// The SPEC constants carry the marker facts into the layout array.
    #[test]
    fn spec_carries_region_and_chip_facts() {
        assert_eq!(Cfg::SPEC.magic, u32::from_be_bytes(*b"KNXC"));
        assert_eq!(Cfg::SPEC.size, 0x2000);
        assert!(Cfg::SPEC.kind.eq(RegionKind::AppendLog));
        assert_eq!(Mct::SPEC.chip_tag, TestFlash::TAG);
    }

    /// Moving a secure device's config from a one-sector blob listed last to
    /// a larger log listed first, with the chip base lowered by the log's
    /// size, leaves the SIAT and mc_timer logs where they were: the device
    /// keeps its sequence counters across the change. The RP2040 layout.
    mod config_first {
        use super::*;
        use crate::storage::region::{ConfigLogRegion, FlashSiatRegion};

        const SECTOR: u32 = 0x1000;
        type Siat = FlashSiatRegion<{ 6 * 0x1000 }, 64, 32>;
        type Timer = McTimerRegion<{ 2 * 0x1000 }>;

        /// The one-sector config blob the RP2040 placed last before the
        /// config log; only its extent matters here.
        struct OldBlob;
        impl Region for OldBlob {
            const SIZE: u32 = 0x1000;
            const MAGIC: u32 = u32::from_be_bytes(*b"KNXS");
            const KIND: RegionKind = RegionKind::AppendLog;
        }

        struct BlobChip;
        impl Chip for BlobChip {
            const TAG: u32 = 0;
            const BASE: u32 = 0x1F6000;
            const CAPACITY: u32 = 0x1FF000;
            const SECTOR_SIZE: u32 = SECTOR;
            type Io = NullFlash;
        }

        struct LogChip;
        impl Chip for LogChip {
            const TAG: u32 = 0;
            const BASE: u32 = 0x1F2000;
            const CAPACITY: u32 = 0x1FF000;
            const SECTOR_SIZE: u32 = SECTOR;
            type Io = NullFlash;
        }

        struct BlobMap;
        type BlobSeq = Placed<Siat, BlobChip, BlobMap>;
        type BlobMct = Placed<Timer, BlobChip, BlobMap>;
        impl StorageLayout for BlobMap {
            const REGIONS: &'static [RegionSpec] = &[BlobSeq::SPEC, BlobMct::SPEC, region_spec::<BlobChip, OldBlob>()];
        }
        const BLOB_CFG: RegionPlacement<OldBlob, BlobChip> = region_placement(BlobMap::REGIONS);

        struct LogMap;
        type LogCfg = Placed<ConfigLogRegion<0x4000, ()>, LogChip, LogMap>;
        type LogSeq = Placed<Siat, LogChip, LogMap>;
        type LogMct = Placed<Timer, LogChip, LogMap>;
        impl StorageLayout for LogMap {
            const REGIONS: &'static [RegionSpec] = &[LogCfg::SPEC, LogSeq::SPEC, LogMct::SPEC];
        }

        #[test]
        fn the_sequence_and_timer_logs_keep_their_offsets() {
            assert_eq!(LogSeq::PLACEMENT.offset, BlobSeq::PLACEMENT.offset);
            assert_eq!(LogMct::PLACEMENT.offset, BlobMct::PLACEMENT.offset);
            assert_eq!(LogCfg::PLACEMENT.offset, 0x1F2000);
            assert!(LogMct::PLACEMENT.offset + Timer::SIZE <= BLOB_CFG.offset);
        }
    }
}
