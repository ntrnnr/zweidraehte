//! The storage memory map: self-describing regions, auto-placed per chip.
//!
//! A device's persistent storage is a list of *placement entries*, declared
//! as a plain `const REGIONS: &[RegionSpec]` array (a device normally lists
//! it through its [`StorageLayout`](super::layout::StorageLayout) impl — see
//! the [`layout`](super::layout) module for the device-facing surface). The
//! split of responsibilities is:
//!
//! - A [`Region`] is the anchor of the coupling: it declares its byte
//!   [`SIZE`](Region::SIZE), its 4-byte header [`MAGIC`](Region::MAGIC), and
//!   its [`KIND`](Region::KIND) — the region *knows* which middleware is
//!   placed in it (wear-levelled append log, erase+rewrite blob, verbatim
//!   packed KV), and through [`Stored`](super::layout::Stored) also *what*
//!   is stored (the payload type and capacities are marker parameters). It
//!   carries **no offset** and no chip. Where the mechanism is a genuine
//!   deployment choice — the SIAT, append-log on flash or write-in-place on
//!   FRAM — the choice is a marker choice: [`FlashSiatRegion`] vs.
//!   [`FramSiatRegion`], same `KNXR` magic, different kind.
//! - A [`Chip`] is a physical memory device: its capacity, its base address
//!   (where this chip's packed regions start), a unique [`TAG`](Chip::TAG),
//!   and its `Copy` [`Io`](Chip::Io) handle type. The medium falls out of
//!   the chip; moving the SIAT to FRAM is swapping the entry's chip and the
//!   marker in the `REGIONS` array.
//!
//! The storage layer **auto-places** the regions over the flattened list
//! (each entry built by [`region_spec`]): [`region_placement`] looks an
//! entry up **by its chip and region type** (tag + magic + size, no index to
//! drift), and derives its offset as its chip's base plus the total
//! [`SIZE`](Region::SIZE) of the earlier same-chip entries — offsets are
//! *derived*, never hand-written. The derived [`RegionPlacement<R, C>`] is
//! tagged at the type level with its *region and chip*, and each store binds
//! the same region type as a generic parameter — handing a store another
//! region's (or another chip's) placement is a type error, which subsumes
//! the weaker wrong-mechanism check (a store's required kind is checked
//! against `R::KIND` when the store type is instantiated).
//!
//! [`check_layout`] is the compile-time layout proof, fired by every
//! [`region_placement`] call (and available standalone): regions fit their
//! chip window, no two same-chip regions share a header magic (region scans
//! never cross-read), two different chips never share a `TAG`, and each
//! placement kind sits on a medium it is valid for. A bad layout
//! const-panics at the placement's const-evaluation site — for a device
//! going through [`Placed`](super::layout::Placed), that is the first
//! `open()` call's monomorphization.
//!
//! Everything here is plain `const fn` arithmetic over an array — no
//! const-generic `where`-clause positions, which overflow
//! `generic_const_exprs` on the pinned nightly.

use core::marker::PhantomData;

// ============================================================================
// Region — self-describing, medium-agnostic
// ============================================================================

/// A logical storage region: what it is, how big, and which middleware is
/// placed in it — with no chip and no offset (those are the device's layout
/// choices in its `REGIONS` array).
///
/// Implemented by the small reusable region marker types ([`ConfigRegion`],
/// [`FlashSiatRegion`] / [`FramSiatRegion`], [`McTimerRegion`]). The region is the single source of
/// truth the rest of the layer hangs off: [`region_spec`] reads all three
/// consts to build a layout entry, [`region_placement`] identifies the entry
/// by `MAGIC`+`SIZE`, and the stores bind a `R: Region` parameter to read
/// their magic and check their mechanism against [`KIND`](Self::KIND).
pub trait Region {
    /// Byte extent of this region. An associated const, or a const expression
    /// over a capacity (e.g. `SECTORS * SECTOR_SIZE`).
    const SIZE: u32;
    /// 4-byte header magic (`KNXS`/`KNXR`/`KNXM` …) as a big-endian `u32` —
    /// what a store's region scan matches on the medium, so it must be unique
    /// among a chip's regions (enforced by [`check_layout`]).
    const MAGIC: u32;
    /// The store middleware placed in this region. For most regions a fixed
    /// fact of the type; the SIAT exposes it as a const parameter
    /// ([`FlashSiatRegion`] / [`FramSiatRegion`]) because flash vs. FRAM is a
    /// per-device deployment choice.
    const KIND: RegionKind;
}

// ============================================================================
// Chip — a physical memory device
// ============================================================================

/// A physical memory device the regions are packed onto — more precisely, the
/// *partition window* the stack owns on that device: `BASE..CAPACITY` describes
/// where regions may pack (e.g. the top of an MCU's flash, stopping short of a
/// write-once provisioning sector), not the part's full address range.
///
/// `TAG` groups entries during auto-placement (regions on the same chip pack
/// together, in different chips' address spaces). `Io` is the medium handle
/// type the stores are built over.
pub trait Chip {
    /// Unique per-chip tag (the auto-pack grouping key). Two *different* chips
    /// declared in one region list must not share a tag — enforced by
    /// [`check_layout`].
    const TAG: u32;
    /// Where this chip's packed regions start (absolute address).
    const BASE: u32;
    /// One-past-the-end of usable space (regions must pack within `BASE..CAPACITY`).
    const CAPACITY: u32;
    /// Erase-granule size in bytes for erase-block media (flash sectors/pages);
    /// `1` for byte-writable media (FRAM, MRAM, shared memory).
    /// [`check_layout`] uses this to enforce that each placement kind sits on
    /// a suitable medium, and the derived [`RegionPlacement`] carries it to
    /// the stores.
    const SECTOR_SIZE: u32;
    /// The medium adapter driving this chip — a `SectorIo` impl for
    /// erase-block media, a `ByteIo` impl for byte media.
    ///
    /// `Copy` is the multi-region guarantee: the adapter is a cheap handle
    /// (typically over a `&'static RefCell<peripheral>`), and every region on
    /// the chip opens over its own copy of the same handle. Test chips that
    /// only exercise the layout arithmetic use `type Io = ()`.
    type Io: Copy;
}

// ============================================================================
// RegionSpec — one placement entry, as plain const data
// ============================================================================

/// The store middleware placed on a region, and with it the medium contract
/// the entry must satisfy (checked by [`check_layout`]).
///
/// Declared per region type as [`Region::KIND`] — a fixed fact of every
/// marker. Where the mechanism is a deployment choice (the SIAT), the choice
/// is between two markers ([`FlashSiatRegion`] vs. [`FramSiatRegion`]), not a
/// parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionKind {
    /// Wear-levelled `WearLeveledKv` append-log middleware.
    ///
    /// Valid only on an erase-block medium, spanning whole sectors — the
    /// append log's crash-safety hinges on sector-header commit markers, which
    /// have no meaning on byte media (use [`WriteInPlace`](Self::WriteInPlace)
    /// there).
    AppendLog,
    /// Erase+rewrite `ConfigStore` middleware. **Not** wear-levelled — every
    /// save erases the region and writes a fresh full copy, so it fits
    /// rarely-written whole-blob state (the ETS config), not per-frame
    /// counters.
    ///
    /// Valid only on an erase-block medium, spanning whole sectors (the erase
    /// granule bounds the rewrite).
    EraseRewrite,
    /// Verbatim write-in-place `PackedSeqStore` middleware. Bytes are
    /// overwritten directly at fixed offsets — no erase, no wear concern.
    ///
    /// Valid only on a byte-writable medium (FRAM, MRAM, shared memory); an
    /// erase-block medium cannot overwrite in place (use
    /// [`AppendLog`](Self::AppendLog) or [`EraseRewrite`](Self::EraseRewrite)).
    WriteInPlace,
}

impl RegionKind {
    /// Const equality over the variants.
    ///
    /// Written as an exhaustive match rather than an `as u32` discriminant
    /// comparison so it stays correct if a variant is ever given an explicit
    /// (non-sequential) discriminant — a numeric cast would silently compare
    /// the wrong values. `PartialEq` isn't usable in `const` context on this
    /// pinned toolchain, so this const method fills the gap.
    pub const fn eq(self, other: RegionKind) -> bool {
        matches!(
            (self, other),
            (RegionKind::AppendLog, RegionKind::AppendLog)
                | (RegionKind::EraseRewrite, RegionKind::EraseRewrite)
                | (RegionKind::WriteInPlace, RegionKind::WriteInPlace)
        )
    }
}

/// One placement entry of a device's region list, flattened to plain const
/// data: the chip's window (from its [`Chip`] impl) and the region's extent,
/// magic, and [`RegionKind`] (from its [`Region`] impl).
///
/// Built by [`region_spec`] into the device's `const REGIONS: &[RegionSpec]`
/// array — the input [`check_layout`] proves and [`region_placement`] packs.
/// Devices never assemble one by hand.
#[derive(Clone, Copy, Debug)]
/// `#[non_exhaustive]`: every construction/match site is inside this crate,
/// where the attribute has no effect — so in-crate exhaustiveness checking
/// is preserved while downstream crates stay insulated from new variants.
#[non_exhaustive]
pub struct RegionSpec {
    /// The chip this entry lives on (its auto-pack group).
    pub chip_tag: u32,
    /// The chip's base address (the start of its packed region span).
    pub chip_base: u32,
    /// The chip's one-past-the-end capacity (the bound the packing must fit in).
    pub chip_capacity: u32,
    /// The chip's erase-granule size (`1` on byte media).
    pub chip_sector_size: u32,
    /// This entry's byte size (from its region).
    pub size: u32,
    /// This entry's header magic (from its region).
    pub magic: u32,
    /// The middleware placed on this entry, carrying its medium contract.
    pub kind: RegionKind,
}

/// One layout entry from a chip + region pair — the entry is described
/// entirely by its type-argument list; the mechanism comes from the region
/// itself ([`Region::KIND`]), so a region↔kind mismatch is unrepresentable:
///
/// ```ignore
/// const REGIONS: &[RegionSpec] = &[
///     region_spec::<RpFlash, FlashSiatRegion<SEQ_SIZE, SEQ_RECORDS, SEQ_CACHE>>(),
///     region_spec::<RpFlash, RpConfigRegion<DeviceState>>(),
/// ];
/// ```
///
/// (Devices going through [`Placed`](super::layout::Placed) list
/// `Placed::SPEC` instead — the same call, made once per layout entry.)
///
/// The returned [`RegionSpec`] still carries the kind as a plain field — the
/// homogeneous `REGIONS` array is what [`check_layout`] walks.
pub const fn region_spec<C: Chip, R: Region>() -> RegionSpec {
    RegionSpec {
        chip_tag: C::TAG,
        chip_base: C::BASE,
        chip_capacity: C::CAPACITY,
        chip_sector_size: C::SECTOR_SIZE,
        size: R::SIZE,
        magic: R::MAGIC,
        kind: R::KIND,
    }
}

// ============================================================================
// Auto-placement: layout proof and derived RegionPlacement
// ============================================================================

/// A region's derived placement, handed to the stores' `open_at`
/// constructors — tagged at the type level with its **region and chip**, so
/// a store bound to `R` can only be opened at `R`'s own placement, and the
/// [`Stored`](super::layout::Stored) open path can only pair it with `C`'s
/// own `Io` handle. Handing it another region's (or chip's) placement is a
/// type error; the mechanism match follows from that (the store checks its
/// required kind against `R::KIND` at instantiation).
///
/// Only what the region type cannot know is carried as data: the derived
/// `offset` and the chip's `sector_size`. Size and magic live on `R`.
///
/// Derived via [`region_placement`] — normally inside
/// [`Placed`](super::layout::Placed), so devices never name one.
pub struct RegionPlacement<R: Region, C: Chip> {
    /// Absolute start address of the region on its chip.
    pub offset: u32,
    /// The chip's erase-granule size (`1` on byte media).
    pub sector_size: u32,
    _marker: PhantomData<(R, C)>,
}

// Manual Clone/Copy/Debug: a derive would demand the bounds on `R`/`C`, but
// the region markers are plain unit structs without derives (and only ever
// appear behind `PhantomData` here).
impl<R: Region, C: Chip> RegionPlacement<R, C> {
    /// Assemble a placement from raw parts — crate-internal, for backend
    /// tests that place a region without a `REGIONS` array. Devices always
    /// derive placements through [`region_placement`].
    #[cfg(test)]
    pub(crate) const fn from_raw(offset: u32, sector_size: u32) -> Self {
        Self { offset, sector_size, _marker: PhantomData }
    }
}

impl<R: Region, C: Chip> Clone for RegionPlacement<R, C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<R: Region, C: Chip> Copy for RegionPlacement<R, C> {}
impl<R: Region, C: Chip> core::fmt::Debug for RegionPlacement<R, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RegionPlacement").field("offset", &self.offset).field("sector_size", &self.sector_size).finish()
    }
}

/// The compile-time layout proof over a device's flattened region array.
/// Fired internally by every [`region_placement`] call, so deriving any
/// named placement re-proves the whole layout — a device cannot forget the
/// guard. A violated invariant const-panics — a compile error at the
/// placement const.
///
/// Four invariants, each checked for every entry:
///
/// 1. **Capacity** — the summed sizes of a chip's entries fit its
///    `BASE..CAPACITY` window (which stops short of e.g. a write-once
///    provisioning sector), so overlap and overrun are impossible by
///    construction.
/// 2. **Magic uniqueness per chip** — region scans identify their data by
///    header magic, so two same-magic regions on one chip would silently read
///    each other's records.
/// 3. **Tag consistency** — entries with equal tags must agree on base,
///    capacity, and sector size (same-chip entries legitimately share their
///    tag). Without this, a two-chip layout with colliding tags would
///    silently pack both chips into one address space.
/// 4. **Medium contract** — each entry's [`RegionKind`] sits on a medium it
///    is valid for: append-log and erase+rewrite need an erase-block medium
///    and must span whole sectors; write-in-place needs a byte medium.
pub const fn check_layout(specs: &[RegionSpec]) {
    let mut i = 0;
    while i < specs.len() {
        let s = &specs[i];

        // 1. Capacity: this chip's total packed usage fits its window. The
        // check re-proves the same chip once per entry, but const-folds away;
        // the redundancy keeps this a simple per-entry walk.
        let mut used: u32 = 0;
        let mut j = 0;
        while j < specs.len() {
            if specs[j].chip_tag == s.chip_tag {
                used += specs[j].size;
            }
            j += 1;
        }
        core::assert!(
            s.chip_base + used <= s.chip_capacity,
            "storage regions overrun a chip's capacity (the declared region sizes don't fit between the chip's BASE and CAPACITY)"
        );

        // 2. Magic uniqueness per chip (each pair checked once, at its first
        // member).
        let mut j = i + 1;
        while j < specs.len() {
            core::assert!(
                !(specs[j].chip_tag == s.chip_tag && specs[j].magic == s.magic),
                "two regions on the same chip share a header MAGIC — their scans would cross-read; every same-chip region needs a distinct magic"
            );
            j += 1;
        }

        // 3. Tag consistency: a TAG identifies exactly one chip window.
        let mut j = i + 1;
        while j < specs.len() {
            core::assert!(
                specs[j].chip_tag != s.chip_tag
                    || (specs[j].chip_base == s.chip_base
                        && specs[j].chip_capacity == s.chip_capacity
                        && specs[j].chip_sector_size == s.chip_sector_size),
                "two different chips in one region list share a TAG — the auto-packer would merge their address spaces; give each chip a distinct TAG"
            );
            j += 1;
        }

        // 4. Medium contract of the entry's placement kind.
        match s.kind {
            RegionKind::AppendLog | RegionKind::EraseRewrite => {
                core::assert!(
                    s.chip_sector_size > 1,
                    "an append-log or erase+rewrite region needs an erase-block medium — use a write-in-place placement on byte media"
                );
                core::assert!(
                    s.size % s.chip_sector_size == 0,
                    "an append-log or erase+rewrite region must span whole sectors of its chip"
                );
            }
            RegionKind::WriteInPlace => {
                core::assert!(
                    s.chip_sector_size == 1,
                    "a write-in-place region needs a byte-writable medium (FRAM/shm) — use an append-log or erase+rewrite placement on flash"
                );
            }
        }

        i += 1;
    }
}

/// Derive region `R`'s [`RegionPlacement`] on chip `C` by looking its entry
/// up **by type** — the unique `specs` entry matching `C::TAG`, `R::MAGIC`,
/// and `R::SIZE`. There is no index to pass, so reordering the `REGIONS`
/// array can never silently hand one region's placement to another region's
/// store; and because the lookup is chip-scoped, the same region type may
/// legitimately appear on two different chips. `R` and `C` are inferred from
/// the placement's declared type — normally
/// [`Placed::PLACEMENT`](super::layout::Placed), so devices never write this
/// call themselves.
///
/// The offset is the auto-pack prefix sum: the chip base plus the summed
/// sizes of *earlier* same-chip entries. An entry that needs no named
/// placement still occupies its slot and shifts later same-chip offsets.
///
/// Fires [`check_layout`] over the whole array first. Const-panics — a
/// compile error at the placement's const-evaluation site — when `R` matches
/// **no** entry on `C` (the region is not part of this chip's layout — e.g.
/// a `Placed` naming the wrong chip), or when the matched entry's window
/// disagrees with `C` (an entry was declared through a *different* chip type
/// that shares `C`'s tag). Two same-chip matches are impossible: they would
/// share a magic, which [`check_layout`] already rejects; the ambiguity
/// assert stays as a defensive backstop.
pub const fn region_placement<R: Region, C: Chip>(specs: &[RegionSpec]) -> RegionPlacement<R, C> {
    check_layout(specs);

    // Locate R's entry on C by tag + magic + size. `usize::MAX` is the "not
    // found" sentinel — plain integer state keeps the whole scan trivially
    // const-evaluable.
    let mut idx = usize::MAX;
    let mut i = 0;
    while i < specs.len() {
        if specs[i].chip_tag == C::TAG && specs[i].magic == R::MAGIC && specs[i].size == R::SIZE {
            core::assert!(
                idx == usize::MAX,
                "region_placement: ambiguous lookup — more than one same-chip REGIONS entry matches this region's magic and size"
            );
            idx = i;
        }
        i += 1;
    }
    core::assert!(
        idx != usize::MAX,
        "region_placement: no REGIONS entry matches this chip + region type — the region is not part of this chip's layout (wrong chip on the placement, or the region was never declared)"
    );

    // The lookup chip must BE the declared chip, not merely share its tag —
    // otherwise the placement would silently carry another window's offsets.
    let s = &specs[idx];
    core::assert!(
        s.chip_base == C::BASE && s.chip_capacity == C::CAPACITY && s.chip_sector_size == C::SECTOR_SIZE,
        "region_placement: the placement's chip type disagrees with the REGIONS entry's chip window (two different chip types share a TAG)"
    );

    let mut used: u32 = 0;
    let mut j = 0;
    while j < idx {
        if specs[j].chip_tag == s.chip_tag {
            used += specs[j].size;
        }
        j += 1;
    }
    RegionPlacement { offset: s.chip_base + used, sector_size: s.chip_sector_size, _marker: PhantomData }
}

// ============================================================================
// Concrete region types
// ============================================================================
//
// Marker `SIZE` parameters are `usize` (cast to the trait's `u32` in the
// initializer — the legal direction on the pinned nightly), so the
// `Stored` impls in `layout.rs` can pass them *bare* into store const
// generics (buffer sizing) without `generic_const_exprs`. Capacities that a
// region's store/view needs (wear-log entries, SIAT slots, cache size,
// write batch) are marker parameters too: the region type is the single
// declaration of what is stored in it and how.

/// The ETS device-config blob region: an erase+rewrite postcard blob of `S`'s
/// [`HasDeviceConfig::Config`](crate::storage::HasDeviceConfig::Config).
/// `SIZE` is its flash extent (whole sectors); magic `KNXS`; always
/// erase+rewrite (the config is rarely-written whole-blob state —
/// wear-levelling it would be pointless).
///
/// `S` is the device's runtime state type — the payload is a fact of the
/// region, so two devices' config regions are different types even at equal
/// sizes.
pub struct ConfigRegion<const SIZE: usize, S>(PhantomData<S>);
impl<const SIZE: usize, S> Region for ConfigRegion<SIZE, S> {
    const SIZE: u32 = SIZE as u32;
    const MAGIC: u32 = u32::from_be_bytes(*b"KNXS");
    const KIND: RegionKind = RegionKind::EraseRewrite;
}

/// The SIAT + sequence-counter region on an **erase-block medium** (flash):
/// a wear-levelled append log compacting into a
/// [`SiatStore`](crate::storage::SiatStore) view. Magic `KNXR`;
/// `SIZE = SECTORS * SECTOR_SIZE` (whole sectors).
///
/// The deployment choice "SIAT on flash vs. FRAM" is the choice between this
/// marker and [`FramSiatRegion`] — same magic, different mechanism and
/// capacities:
///
/// * `ENTRIES` — wear-log record capacity (must hold every live key: the
///   SIAT peers plus the two singleton counters).
/// * `CACHE` — the `SiatStore` RAM mirror's capacity (≥ the authorized-peer
///   count).
/// * `BATCH` — the sending-counter skip-ahead watermark; flash is touched
///   once per `BATCH` sends.
pub struct FlashSiatRegion<const SIZE: usize, const ENTRIES: usize, const CACHE: usize, const BATCH: u64 = 256>;
impl<const SIZE: usize, const ENTRIES: usize, const CACHE: usize, const BATCH: u64> Region
    for FlashSiatRegion<SIZE, ENTRIES, CACHE, BATCH>
{
    const SIZE: u32 = SIZE as u32;
    const MAGIC: u32 = u32::from_be_bytes(*b"KNXR");
    const KIND: RegionKind = RegionKind::AppendLog;
}

/// The SIAT + sequence-counter region on a **byte medium** (FRAM, shared
/// memory): the fixed packed write-in-place layout under a
/// [`SiatStore`](crate::storage::SiatStore) view. Magic `KNXR` — the same
/// data as [`FlashSiatRegion`], stored the byte-medium way.
///
/// * `SLOTS` — the packed layout's peer capacity *and* the RAM mirror's
///   (they hold the same entries, so one number serves both).
/// * `BATCH` — sending-counter watermark; the default 1 writes through on
///   every send (byte media don't wear, and a save is a few byte writes).
pub struct FramSiatRegion<const SIZE: usize, const SLOTS: usize, const BATCH: u64 = 1>;
impl<const SIZE: usize, const SLOTS: usize, const BATCH: u64> Region for FramSiatRegion<SIZE, SLOTS, BATCH> {
    const SIZE: u32 = SIZE as u32;
    const MAGIC: u32 = u32::from_be_bytes(*b"KNXR");
    const KIND: RegionKind = RegionKind::WriteInPlace;
}

/// The IP-Secure mc_timer watermark region on an **erase-block medium**:
/// a single-record wear-levelled append log under an
/// [`McTimerStore`](crate::storage::McTimerStore) view.
/// `SIZE = SECTORS * SECTOR_SIZE`; magic `KNXM` (distinct from the SIAT's
/// `KNXR` so the two never cross-read).
pub struct McTimerRegion<const SIZE: usize>;
impl<const SIZE: usize> Region for McTimerRegion<SIZE> {
    const SIZE: u32 = SIZE as u32;
    const MAGIC: u32 = u32::from_be_bytes(*b"KNXM");
    const KIND: RegionKind = RegionKind::AppendLog;
}

/// The IP-Secure mc_timer watermark region on a **byte medium**: a
/// write-in-place `[magic][value]` record
/// ([`PackedWatermark`](crate::storage::backends::PackedWatermark)) — what a
/// FRAM device declares to persist the watermark next to its SIAT. Magic
/// `KNXM`; 16 bytes is plenty (the record itself is 12).
pub struct FramMcTimerRegion<const SIZE: usize = 16>;
impl<const SIZE: usize> Region for FramMcTimerRegion<SIZE> {
    const SIZE: u32 = SIZE as u32;
    const MAGIC: u32 = u32::from_be_bytes(*b"KNXM");
    const KIND: RegionKind = RegionKind::WriteInPlace;
}

// ============================================================================
// Layout guards — compile-fail proofs
// ============================================================================

// A shared spec literal for the compile-fail examples below would hide the
// violated invariant; each doctest spells out its own minimal bad layout.

/// Compile-fail proof that [`check_layout`] rejects a layout whose regions
/// overrun a chip's capacity — the proof every [`region_placement`] call
/// fires.
///
/// A chip with only 16 KiB between `chip_base` and `chip_capacity` is given a
/// SIAT (24 KiB) + mc_timer (8 KiB) = 32 KiB layout; evaluating
/// `check_layout` const-panics, so this must fail to compile.
///
/// ```compile_fail
/// use zweidraehte_device::storage::region::{RegionKind, RegionSpec, check_layout};
///
/// // 24 KiB + 8 KiB of regions on a 16 KiB chip window — must not compile.
/// const REGIONS: &[RegionSpec] = &[
///     RegionSpec {
///         chip_tag: 0, chip_base: 0x1F6000, chip_capacity: 0x1F6000 + 0x4000,
///         chip_sector_size: 0x1000, size: 0x6000,
///         magic: u32::from_be_bytes(*b"KNXR"), kind: RegionKind::AppendLog,
///     },
///     RegionSpec {
///         chip_tag: 0, chip_base: 0x1F6000, chip_capacity: 0x1F6000 + 0x4000,
///         chip_sector_size: 0x1000, size: 0x2000,
///         magic: u32::from_be_bytes(*b"KNXM"), kind: RegionKind::AppendLog,
///     },
/// ];
///
/// // The same proof every placement derivation fires — must not compile.
/// const _: () = check_layout(REGIONS);
/// ```
#[allow(dead_code)]
struct CapacityGuardIsEnforced;

/// Compile-fail proof that [`check_layout`] rejects two same-chip regions
/// sharing a header magic — here two SIAT regions (both `KNXR`) on one chip,
/// whose flash scans would cross-read each other's records.
///
/// ```compile_fail
/// use zweidraehte_device::storage::region::{RegionKind, RegionSpec, check_layout};
///
/// // Two SIAT regions on the same chip — same `KNXR` magic. Must not compile.
/// const REGIONS: &[RegionSpec] = &[
///     RegionSpec {
///         chip_tag: 0, chip_base: 0x1F0000, chip_capacity: 0x200000,
///         chip_sector_size: 0x1000, size: 0x6000,
///         magic: u32::from_be_bytes(*b"KNXR"), kind: RegionKind::AppendLog,
///     },
///     RegionSpec {
///         chip_tag: 0, chip_base: 0x1F0000, chip_capacity: 0x200000,
///         chip_sector_size: 0x1000, size: 0x2000,
///         magic: u32::from_be_bytes(*b"KNXR"), kind: RegionKind::AppendLog,
///     },
/// ];
///
/// const _: () = check_layout(REGIONS);
/// ```
#[allow(dead_code)]
struct MagicGuardIsEnforced;

/// Compile-fail proof that [`check_layout`] rejects two *different* chips
/// sharing a `TAG` in one layout — the auto-packer would otherwise merge
/// their address spaces silently.
///
/// ```compile_fail
/// use zweidraehte_device::storage::region::{RegionKind, RegionSpec, check_layout};
///
/// // Both entries claim tag 0 but describe different chip windows.
/// const REGIONS: &[RegionSpec] = &[
///     RegionSpec {
///         chip_tag: 0, chip_base: 0x1F0000, chip_capacity: 0x200000,
///         chip_sector_size: 0x1000, size: 0x6000,
///         magic: u32::from_be_bytes(*b"KNXR"), kind: RegionKind::AppendLog,
///     },
///     RegionSpec {
///         chip_tag: 0, chip_base: 0x08000000, chip_capacity: 0x08010000,
///         chip_sector_size: 0x800, size: 0x800,
///         magic: u32::from_be_bytes(*b"KNXS"), kind: RegionKind::EraseRewrite,
///     },
/// ];
///
/// const _: () = check_layout(REGIONS);
/// ```
#[allow(dead_code)]
struct TagGuardIsEnforced;

/// Compile-fail proof that [`check_layout`] rejects a wear-levelled
/// (append-log) placement on a byte medium — the append log's sector-header
/// commit markers are meaningless without erase blocks.
///
/// ```compile_fail
/// use zweidraehte_device::storage::region::{RegionKind, RegionSpec, check_layout};
///
/// // An append log on FRAM (sector size 1) — must not compile.
/// const REGIONS: &[RegionSpec] = &[RegionSpec {
///     chip_tag: 1, chip_base: 0, chip_capacity: 0x800,
///     chip_sector_size: 1, size: 0x200,
///     magic: u32::from_be_bytes(*b"KNXR"), kind: RegionKind::AppendLog,
/// }];
///
/// const _: () = check_layout(REGIONS);
/// ```
#[allow(dead_code)]
struct WearOnByteMediumIsRejected;

/// Compile-fail proof that [`check_layout`] rejects a write-in-place
/// placement on an erase-block medium — flash cannot overwrite bytes in place.
///
/// ```compile_fail
/// use zweidraehte_device::storage::region::{RegionKind, RegionSpec, check_layout};
///
/// // A write-in-place store on sector flash — must not compile.
/// const REGIONS: &[RegionSpec] = &[RegionSpec {
///     chip_tag: 0, chip_base: 0x1F0000, chip_capacity: 0x200000,
///     chip_sector_size: 0x1000, size: 0x1000,
///     magic: u32::from_be_bytes(*b"KNXR"), kind: RegionKind::WriteInPlace,
/// }];
///
/// const _: () = check_layout(REGIONS);
/// ```
#[allow(dead_code)]
struct PackedOnSectorMediumIsRejected;

/// Compile-fail proof that [`check_layout`] rejects a wear-levelled region
/// that does not span whole sectors of its chip.
///
/// ```compile_fail
/// use zweidraehte_device::storage::region::{RegionKind, RegionSpec, check_layout};
///
/// // 0x1800 is one and a half 0x1000 sectors — must not compile.
/// const REGIONS: &[RegionSpec] = &[RegionSpec {
///     chip_tag: 0, chip_base: 0x1F0000, chip_capacity: 0x200000,
///     chip_sector_size: 0x1000, size: 0x1800,
///     magic: u32::from_be_bytes(*b"KNXR"), kind: RegionKind::AppendLog,
/// }];
///
/// const _: () = check_layout(REGIONS);
/// ```
#[allow(dead_code)]
struct UnalignedWearRegionIsRejected;

/// Compile-fail proof of the region-typed-placement linkage: a placement
/// derived for one region cannot be handed to a store bound to another —
/// mirrored here as a function pinning the config region, exactly like a
/// `ConfigStore<_, _, ConfigRegion<0x1000, S>, …>::open_at` does.
///
/// ```compile_fail
/// use zweidraehte_device::storage::region::{
///     Chip, ConfigRegion, FlashSiatRegion, RegionPlacement, RegionSpec,
///     region_placement, region_spec,
/// };
///
/// struct Flash;
/// impl Chip for Flash {
///     const TAG: u32 = 0;
///     const BASE: u32 = 0x1F0000;
///     const CAPACITY: u32 = 0x200000;
///     const SECTOR_SIZE: u32 = 0x1000;
///     type Io = ();
/// }
///
/// type Siat = FlashSiatRegion<0x6000, 16, 16>;
/// const REGIONS: &[RegionSpec] = &[region_spec::<Flash, Siat>()];
/// const SEQ: RegionPlacement<Siat, Flash> = region_placement(REGIONS);
///
/// // The `ConfigStore::open_at` shape — pins the config region.
/// fn open_config_at(_p: RegionPlacement<ConfigRegion<0x1000, ()>, Flash>) {}
///
/// // The SIAT's placement is not the config region's — must not compile.
/// open_config_at(SEQ);
/// ```
#[allow(dead_code)]
struct WrongRegionPlacementIsRejected;

/// Compile-fail proof that [`region_placement`] rejects a region type that
/// has no entry in the `REGIONS` array — a placement cannot claim a region
/// the device never declared.
///
/// ```compile_fail
/// use zweidraehte_device::storage::region::{
///     Chip, FlashSiatRegion, McTimerRegion, RegionPlacement, RegionSpec,
///     region_placement, region_spec,
/// };
///
/// struct Flash;
/// impl Chip for Flash {
///     const TAG: u32 = 0;
///     const BASE: u32 = 0x1F0000;
///     const CAPACITY: u32 = 0x200000;
///     const SECTOR_SIZE: u32 = 0x1000;
///     type Io = ();
/// }
///
/// const REGIONS: &[RegionSpec] =
///     &[region_spec::<Flash, FlashSiatRegion<0x6000, 16, 16>>()];
///
/// // The layout has no mc_timer region — the lookup const-panics. Must not
/// // compile.
/// const MCT: RegionPlacement<McTimerRegion<0x2000>, Flash> = region_placement(REGIONS);
/// const _: u32 = MCT.offset; // force evaluation
/// ```
#[allow(dead_code)]
struct RegionAbsentFromLayoutIsRejected;

/// Compile-fail proof that the chip-scoped lookup rejects a placement naming
/// the **wrong chip**: the region is declared on the flash, so deriving its
/// placement on the FRAM chip finds no entry and const-panics — the guard
/// behind `Placed<R, C, L>` pairing a region with a chip its layout never
/// put it on.
///
/// ```compile_fail
/// use zweidraehte_device::storage::region::{
///     Chip, ConfigRegion, RegionPlacement, RegionSpec, region_placement, region_spec,
/// };
///
/// struct Flash;
/// impl Chip for Flash {
///     const TAG: u32 = 0;
///     const BASE: u32 = 0x1F0000;
///     const CAPACITY: u32 = 0x200000;
///     const SECTOR_SIZE: u32 = 0x1000;
///     type Io = ();
/// }
/// struct Fram;
/// impl Chip for Fram {
///     const TAG: u32 = 1;
///     const BASE: u32 = 0;
///     const CAPACITY: u32 = 0x800;
///     const SECTOR_SIZE: u32 = 1;
///     type Io = ();
/// }
///
/// type Cfg = ConfigRegion<0x1000, ()>;
/// // The config region lives on the flash…
/// const REGIONS: &[RegionSpec] = &[region_spec::<Flash, Cfg>()];
/// // …so a placement claiming it on the FRAM chip must not compile.
/// const CFG: RegionPlacement<Cfg, Fram> = region_placement(REGIONS);
/// const _: u32 = CFG.offset; // force evaluation
/// ```
#[allow(dead_code)]
struct WrongChipPlacementIsRejected;

/// Compile-fail proof that the byte-medium SIAT marker cannot be placed on
/// an erase-block chip: [`FramSiatRegion`]'s fixed `WriteInPlace` kind meets
/// [`check_layout`]'s medium contract and const-panics. (The flash marker on
/// a byte chip fails the same way through the append-log arm — one
/// representative proof per direction keeps the matrix covered together
/// with [`WearOnByteMediumIsRejected`].)
///
/// ```compile_fail
/// use zweidraehte_device::storage::region::{
///     Chip, FramSiatRegion, RegionSpec, check_layout, region_spec,
/// };
///
/// struct Flash;
/// impl Chip for Flash {
///     const TAG: u32 = 0;
///     const BASE: u32 = 0x1F0000;
///     const CAPACITY: u32 = 0x200000;
///     const SECTOR_SIZE: u32 = 0x1000;
///     type Io = ();
/// }
///
/// // A write-in-place SIAT on sector flash — must not compile.
/// const REGIONS: &[RegionSpec] = &[region_spec::<Flash, FramSiatRegion<0x800, 16>>()];
/// const _: () = check_layout(REGIONS);
/// ```
#[allow(dead_code)]
struct FramSiatRegionOnFlashIsRejected;

/// Compile-fail proof that the byte-medium mc_timer marker
/// ([`FramMcTimerRegion`]) is likewise rejected on an erase-block chip.
///
/// ```compile_fail
/// use zweidraehte_device::storage::region::{
///     Chip, FramMcTimerRegion, RegionSpec, check_layout, region_spec,
/// };
///
/// struct Flash;
/// impl Chip for Flash {
///     const TAG: u32 = 0;
///     const BASE: u32 = 0x1F0000;
///     const CAPACITY: u32 = 0x200000;
///     const SECTOR_SIZE: u32 = 0x1000;
///     type Io = ();
/// }
///
/// // A write-in-place watermark on sector flash — must not compile.
/// const REGIONS: &[RegionSpec] = &[region_spec::<Flash, FramMcTimerRegion>()];
/// const _: () = check_layout(REGIONS);
/// ```
#[allow(dead_code)]
struct FramMcTimerRegionOnFlashIsRejected;

#[cfg(test)]
mod tests {
    use super::*;

    /// The test chip mirrors the RP2040 window: BASE 0x1F6000, 4 KiB sectors.
    struct TestFlash;
    impl Chip for TestFlash {
        const TAG: u32 = 0;
        const BASE: u32 = 0x1F6000;
        const CAPACITY: u32 = 0x200000;
        const SECTOR_SIZE: u32 = 0x1000;
        type Io = ();
    }

    /// A byte-medium test chip (the FRAM shape: sector size 1).
    struct TestFram;
    impl Chip for TestFram {
        const TAG: u32 = 1;
        const BASE: u32 = 0;
        const CAPACITY: u32 = 0x800;
        const SECTOR_SIZE: u32 = 1;
        type Io = ();
    }

    const fn spec(size: u32, magic: &[u8; 4], kind: RegionKind) -> RegionSpec {
        RegionSpec {
            chip_tag: TestFlash::TAG,
            chip_base: TestFlash::BASE,
            chip_capacity: TestFlash::CAPACITY,
            chip_sector_size: TestFlash::SECTOR_SIZE,
            size,
            magic: u32::from_be_bytes(*magic),
            kind,
        }
    }

    // Order matches today's physical map: SIAT first (0x1F6000), then mc_timer,
    // then config — packed upward from the chip base.
    const LAYOUT: &[RegionSpec] = &[
        spec(0x6000, b"KNXR", RegionKind::AppendLog),
        spec(0x2000, b"KNXM", RegionKind::AppendLog),
        spec(0x1000, b"KNXS", RegionKind::EraseRewrite),
    ];

    /// The by-type lookup (behind a device's `Placed` entries) reproduces the
    /// historical flash map from sizes + order — entries are found by their
    /// chip's tag plus their region's magic + size, not by index, so
    /// reordering the array can never swap two placements.
    #[test]
    fn prefix_sum_derives_the_physical_map() {
        const SIAT: RegionPlacement<FlashSiatRegion<0x6000, 34, 32>, TestFlash> = region_placement(LAYOUT);
        const MCT: RegionPlacement<McTimerRegion<0x2000>, TestFlash> = region_placement(LAYOUT);
        const CFG: RegionPlacement<ConfigRegion<0x1000, ()>, TestFlash> = region_placement(LAYOUT);
        assert_eq!(SIAT.offset, 0x1F6000);
        assert_eq!(MCT.offset, 0x1FC000); // after SIAT's 0x6000
        assert_eq!(CFG.offset, 0x1FE000); // after mc_timer's 0x2000
        assert_eq!(MCT.sector_size, 0x1000);
    }

    /// Two chips pack independently: each entry's offset counts only earlier
    /// entries on its *own* chip.
    #[test]
    fn chips_pack_independently() {
        const TWO_CHIP: &[RegionSpec] =
            &[spec(0x1000, b"KNXS", RegionKind::EraseRewrite), region_spec::<TestFram, FramSiatRegion<0x800, 16>>()];
        // The FRAM entry starts at its own chip's base, not after the flash entry.
        const SIAT: RegionPlacement<FramSiatRegion<0x800, 16>, TestFram> = region_placement(TWO_CHIP);
        assert_eq!(SIAT.offset, 0);
        assert_eq!(SIAT.sector_size, 1);
    }

    /// The chip-scoped lookup makes the *same region type on two chips* legal
    /// and unambiguous: each placement resolves within its own chip's entries.
    /// (Before the chip-typed lookup this layout const-panicked as ambiguous.)
    #[test]
    fn same_region_on_two_chips_resolves_per_chip() {
        /// A second erase-block chip with its own window.
        struct OtherFlash;
        impl Chip for OtherFlash {
            const TAG: u32 = 2;
            const BASE: u32 = 0x08000000;
            const CAPACITY: u32 = 0x08010000;
            const SECTOR_SIZE: u32 = 0x1000;
            type Io = ();
        }

        type Cfg = ConfigRegion<0x1000, ()>;
        const REGIONS: &[RegionSpec] = &[region_spec::<TestFlash, Cfg>(), region_spec::<OtherFlash, Cfg>()];
        const A: RegionPlacement<Cfg, TestFlash> = region_placement(REGIONS);
        const B: RegionPlacement<Cfg, OtherFlash> = region_placement(REGIONS);
        assert_eq!(A.offset, 0x1F6000);
        assert_eq!(B.offset, 0x08000000);
    }

    /// The layout guard evaluates (at compile time) for a valid layout.
    #[test]
    fn guards_pass_for_a_valid_layout() {
        const _: () = check_layout(LAYOUT);
    }
}
