//! Where a device's stores live, decided by the device, checked and
//! computed at compile time.
//!
//! Which medium holds which store is a fact of the board, not of the chip:
//! one STM32 board keeps its SIAT on an FRAM, another in flash. So the device
//! places every store itself: a [`Medium`] and an [`Area`] on it, as a unit
//! type implementing [`Placement`]. The platform crates provide the media,
//! their geometry as constants (flash size, erase granule, reserved areas
//! such as the provisioning page) and their I/O handles.
//!
//! A firmware declares all of its stores once, with
//! [`storage_layout!`](crate::storage_layout). The macro emits the placement
//! types and a `STORAGE_LAYOUT` list, and checks at compile time that every
//! area suits its medium and that no two areas on one medium overlap. The
//! platform's storage macro takes the same list to reserve the flash areas
//! from the linker and to scope its flash error recovery, so nothing about
//! the layout is stated twice:
//!
//! ```ignore
//! zweidraehte_device::storage_layout! {
//!     ConfigArea: InternalFlash = InternalFlash::below_provisioning(16 * 1024);
//!     SiatArea: Fram = Area::new(0, 512);
//! }
//! stm32_common::storage_platform!(STORAGE_LAYOUT);
//!
//! let storage = SecureStorage::new(
//!     open_config_log::<ConfigArea>(flash_io),
//!     open_packed_seq::<SiatArea, SIAT_SIZE>(fram_io),
//! );
//! ```
//!
//! The `open_*` functions take the placement as a type parameter, so every
//! offset and log geometry they use is a constant, evaluated per device at
//! compile time. A placement that breaks a rule of its medium or of its
//! store is a compile error.
//!
//! Which store implementation a placement gets follows from the medium: the
//! logs need an erase-block medium ([`SectorIo`]), the packed and image
//! stores a byte-writable one ([`ByteIo`]). Each store opens over a
//! [`Region`] of the handle, bounded to its area and addressed from 0, so a
//! store cannot reach into a neighbour's area on a shared chip.

use core::marker::PhantomData;

use zweidraehte_nv::stores::sequence::region_len;
use zweidraehte_nv::stores::{mc_timer, sequence};
use zweidraehte_nv::{
    Area, ByteIo, ByteMcTimer, ByteNv, FlashLog, LogGeometry, PackedSeqStore, Region, Routes, SectorIo, SiatStore,
    SplitNv, WearLeveledKv,
};

use super::nv_config::{CONFIG_LOG_REC, ConfigLog, NvConfig};
use crate::objects::tables::sections::{
    SECTION_ADT_CONTROL, SECTION_ADT_DATA, SECTION_APP_CONTROL, SECTION_APP_DATA, SECTION_AST_CONTROL,
    SECTION_AST_DATA, SECTION_COT_CONTROL, SECTION_COT_DATA,
};
use crate::sections::{SectionId, ids};

// ============================================================================
// Medium and Placement
// ============================================================================

/// A storage medium of a board: its geometry as constants, and the handle
/// its stores open over. Implemented by the platform crates (the internal
/// flash of a chip, an external FRAM, ...).
pub trait Medium {
    /// Which physical medium this is, among those one firmware uses: two
    /// media of the same kind (two FRAM chips) are two types with different
    /// ids. `const` code cannot compare types, so the layout check compares
    /// these to find the stores that share a medium.
    const ID: u32;
    /// The handle a store opens over: a [`SectorIo`] for erase-block media,
    /// a [`ByteIo`] for byte-writable ones.
    type Io;
    /// Addressable bytes.
    const CAPACITY: u32;
    /// The erase granule; `1` on a byte-writable medium.
    const ERASE_SIZE: u32;
    /// Areas no store may use, such as the provisioning page.
    const RESERVED: &'static [Area] = &[];
}

/// Where one store lives: an area of a medium. A device implements it on a
/// unit type per store.
pub trait Placement {
    type Medium: Medium;
    const AREA: Area;
}

/// The area of placement `P`, after checking it against its medium: whole
/// erase granules, inside the medium, clear of every reserved area.
///
/// # Panics
///
/// On an area that breaks a rule; in the `const` blocks of the `open_*`
/// functions that is a compile error.
pub const fn checked_area<P: Placement>() -> Area {
    let area = P::AREA;
    core::assert!(area.len > 0, "a store's area is not empty");
    core::assert!(area.is_aligned(P::Medium::ERASE_SIZE), "a store's area is whole erase granules of its medium");
    core::assert!(area.end() <= P::Medium::CAPACITY, "a store's area lies inside its medium");
    let reserved = P::Medium::RESERVED;
    let mut i = 0;
    while i < reserved.len() {
        core::assert!(!area.overlaps(&reserved[i]), "a store's area stays clear of its medium's reserved areas");
        i += 1;
    }
    area
}

// ============================================================================
// The layout: every store of a firmware, stated once
// ============================================================================

/// One store of a firmware's storage layout: the medium it lives on and its
/// area there. Built from a placement by [`storage_layout!`](crate::storage_layout).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayoutEntry {
    /// The [`Medium::ID`] of the store's medium.
    pub medium: u32,
    /// The store's area on it.
    pub area: Area,
}

impl LayoutEntry {
    /// The entry of placement `P`, its area checked against its medium.
    pub const fn of<P: Placement>() -> Self {
        Self { medium: P::Medium::ID, area: checked_area::<P>() }
    }
}

/// Panics, at compile time in a `const`, if two stores of `layout` on the
/// same medium overlap. [`storage_layout!`](crate::storage_layout) runs it.
pub const fn check_layout(layout: &[LayoutEntry]) {
    let mut i = 0;
    while i < layout.len() {
        let mut j = i + 1;
        while j < layout.len() {
            let (a, b) = (&layout[i], &layout[j]);
            core::assert!(a.medium != b.medium || !a.area.overlaps(&b.area), "two stores on one medium overlap");
            j += 1;
        }
        i += 1;
    }
}

/// Declare every store of a firmware, once.
///
/// Each line names a placement type, its [`Medium`] and its [`Area`]; doc
/// comments on a line go to its type, and an area may be computed from an
/// earlier one (`ConfigArea::AREA.after(len)`). The
/// macro emits the types with their [`Placement`] impls, and a
/// `STORAGE_LAYOUT: &[LayoutEntry]` constant for the platform's storage
/// macro. It checks at compile time that every area suits its medium (whole
/// erase granules, inside the medium, clear of its reserved areas) and that
/// no two areas on one medium overlap:
///
/// ```ignore
/// zweidraehte_device::storage_layout! {
///     ConfigArea: InternalFlash = InternalFlash::below_provisioning(16 * 1024);
///     pub SiatArea: Fram = Area::new(0, 512);
/// }
/// ```
///
/// Two overlapping stores do not compile:
///
/// ```compile_fail
/// use zweidraehte_device::storage::{Area, Medium};
///
/// struct Fram;
/// impl Medium for Fram {
///     const ID: u32 = 1;
///     type Io = ();
///     const CAPACITY: u32 = 2048;
///     const ERASE_SIZE: u32 = 1;
/// }
///
/// // The SIAT's first byte is the parameters' last.
/// zweidraehte_device::storage_layout! {
///     ParamsArea: Fram = Area::new(0, 513);
///     SiatArea: Fram = Area::new(512, 512);
/// }
/// ```
#[macro_export]
macro_rules! storage_layout {
    ($($(#[$attr:meta])* $vis:vis $name:ident : $medium:ty = $area:expr;)+) => {
        $(
            $(#[$attr])*
            $vis struct $name;

            impl $crate::storage::Placement for $name {
                type Medium = $medium;
                const AREA: $crate::storage::Area = $area;
            }
        )+

        /// Every store of this firmware: its medium and area. The
        /// platform's storage macro reserves and recovers the flash areas.
        const STORAGE_LAYOUT: &[$crate::storage::LayoutEntry] = &[$($crate::storage::LayoutEntry::of::<$name>()),+];

        const _: () = $crate::storage::check_layout(STORAGE_LAYOUT);
    };
}

// ============================================================================
// Opening the stores at their placements
// ============================================================================
//
// The constants each store opens with are associated constants of a carrier
// type rather than `const { }` blocks: this crate enables
// `generic_const_exprs`, which rejects blocks over generic parameters. An
// associated constant is just as compile-time, evaluated once per placement
// where it is used, and a failed check in it is a compile error.

/// The compile-time facts of placement `P` the stores open with.
struct Placed<P>(PhantomData<P>);

impl<P: Placement> Placed<P> {
    const AREA: Area = checked_area::<P>();

    // The logs open over a region of their own, so their geometry starts at
    // the region's offset 0. The area's alignment, checked above, keeps the
    // banks on the medium's erase boundaries.
    const TWO_BANKS: LogGeometry = LogGeometry::two_banks(0, Self::AREA.len, P::Medium::ERASE_SIZE);
    const ONE_SECTOR_PER_BANK: LogGeometry = LogGeometry::one_sector_per_bank(0, Self::AREA.len, P::Medium::ERASE_SIZE);

    /// The store's region of the medium behind `io`.
    fn region<Io>(io: Io) -> Region<Io> {
        Region::new(io, Self::AREA)
    }
}

/// The area of placement `P`, checked to hold the packed layout of `SLOTS`
/// SIAT elements.
struct PackedSeqArea<P, const SLOTS: usize>(PhantomData<P>);

impl<P: Placement, const SLOTS: usize> PackedSeqArea<P, SLOTS> {
    const AREA: Area = {
        let area = Placed::<P>::AREA;
        core::assert!(region_len(SLOTS) <= area.len as usize, "the packed SIAT fits its area");
        area
    };
}

/// The configuration as a two-bank log on erase-block flash, at `P`. Each
/// bank must hold a whole snapshot of the state, so the area is an even
/// number of erase granules. The log is scanned when
/// [`new`](crate::new) loads it, so opening cannot fail.
pub fn open_config_log<P>(io: <P::Medium as Medium>::Io) -> ConfigLog<Region<<P::Medium as Medium>::Io>>
where
    P: Placement,
    <P::Medium as Medium>::Io: SectorIo,
{
    NvConfig::new(FlashLog::new(Placed::<P>::region(io), Placed::<P>::TWO_BANKS))
}

/// The configuration as a section image on a byte-writable medium, at `P`.
/// The image is read when [`new`](crate::new) loads it, so opening cannot
/// fail; a layout too large for the area is that load's error.
pub fn open_config_image<P>(io: <P::Medium as Medium>::Io) -> NvConfig<ByteNv<Region<<P::Medium as Medium>::Io>>>
where
    P: Placement,
    <P::Medium as Medium>::Io: ByteIo,
{
    NvConfig::new(ByteNv::new(Placed::<P>::region(io), 0, Placed::<P>::AREA.len))
}

// ============================================================================
// Configuration across two stores
// ============================================================================

/// Sections whose validity depends on another one, as `(control, data)`:
/// an Image and the Record holding its load state. A store that finds an
/// Image's CRC broken persists its control Record, so both must live in the
/// same store.
const DEPENDENT_SECTIONS: &[(SectionId, SectionId)] = &[
    (SECTION_ADT_CONTROL, SECTION_ADT_DATA),
    (SECTION_AST_CONTROL, SECTION_AST_DATA),
    (SECTION_COT_CONTROL, SECTION_COT_DATA),
    (SECTION_APP_CONTROL, SECTION_APP_DATA),
    (ids::DATA_SECURE_CORE, ids::DATA_SECURE_GROUP_KEYS),
    (ids::DATA_SECURE_CORE, ids::DATA_SECURE_P2P_KEYS),
    (ids::DATA_SECURE_CORE, ids::DATA_SECURE_GO_FLAGS),
];

/// Whether `ids` contains `id`, in `const` code.
const fn contains(ids: &[SectionId], id: SectionId) -> bool {
    let mut i = 0;
    while i < ids.len() {
        if ids[i] == id {
            return true;
        }
        i += 1;
    }
    false
}

/// Panics, at compile time in a `const`, if `second` (the sections a
/// [`SplitNv`] routes to its second store) separates a control Record from
/// the Image it governs.
pub const fn check_routes(second: &[SectionId]) {
    let mut i = 0;
    while i < DEPENDENT_SECTIONS.len() {
        let (control, data) = DEPENDENT_SECTIONS[i];
        core::assert!(
            contains(second, control) == contains(second, data),
            "routes put a control Record and its Image in different stores"
        );
        i += 1;
    }
}

/// Routes `R`, checked to keep dependent sections together.
struct CheckedRoutes<R>(PhantomData<R>);

impl<R: Routes> CheckedRoutes<R> {
    const CHECK: () = check_routes(R::SECOND);
}

/// The configuration split across two stores: a log on erase-block flash
/// at `First`, holding every section except those `R` routes to the image
/// on a byte-writable medium at `Second`.
pub type SplitConfig<FirstIo, SecondIo, R> =
    NvConfig<SplitNv<FlashLog<Region<FirstIo>, CONFIG_LOG_REC>, ByteNv<Region<SecondIo>>, R>>;

/// The configuration as a log at `First` and an image at `Second`, with the
/// sections routed by `R` (see [`SplitNv`]). The log needs an erase-block
/// medium, the image a byte-writable one; both open over their own region.
///
/// Routes that separate a table's control Record from its data, or the
/// Security IO's core record from its key tables, do not compile:
///
/// ```compile_fail
/// use zweidraehte_device::storage::check_routes;
/// use zweidraehte_device::objects::tables::sections::SECTION_APP_DATA;
///
/// // The application parameters without their control Record.
/// const _: () = check_routes(&[SECTION_APP_DATA]);
/// ```
pub fn open_split_config<First, Second, R>(
    first_io: <First::Medium as Medium>::Io,
    second_io: <Second::Medium as Medium>::Io,
) -> SplitConfig<<First::Medium as Medium>::Io, <Second::Medium as Medium>::Io, R>
where
    First: Placement,
    Second: Placement,
    R: Routes,
    <First::Medium as Medium>::Io: SectorIo,
    <Second::Medium as Medium>::Io: ByteIo,
{
    #[allow(clippy::let_unit_value)]
    let () = CheckedRoutes::<R>::CHECK;

    let log = FlashLog::new(Placed::<First>::region(first_io), Placed::<First>::TWO_BANKS);
    let image = ByteNv::new(Placed::<Second>::region(second_io), 0, Placed::<Second>::AREA.len);

    NvConfig::new(SplitNv::new(log, image))
}

/// The records a sequence log's mirror must hold: one per SIAT element plus
/// the two singletons, the sending and tool counters.
struct SeqLogEntries<const ENTRIES: usize, const CACHE: usize>;

impl<const ENTRIES: usize, const CACHE: usize> SeqLogEntries<ENTRIES, CACHE> {
    const CHECK: () =
        core::assert!(ENTRIES >= CACHE + 2, "a sequence log needs ENTRIES >= CACHE + 2: the SIAT and the singletons");
}

/// The SIAT and sequence counters as a wear-levelled log on erase-block
/// flash, at `P`, scanned here to rebuild their RAM mirror. The log rotates
/// through one bank per erase granule and needs at least two. `ENTRIES`
/// sizes the log's record mirror (at least `CACHE + 2`, checked at compile
/// time), `CACHE` the SIAT cache, and `BATCH` how many sends the hot sending
/// counter stays off flash.
///
/// # Errors
///
/// The medium's error of a failed scan.
#[allow(clippy::type_complexity)]
pub fn open_seq_log<P, const ENTRIES: usize, const CACHE: usize, const BATCH: u64>(
    io: <P::Medium as Medium>::Io,
) -> Result<
    SiatStore<WearLeveledKv<Region<<P::Medium as Medium>::Io>, ENTRIES>, CACHE, BATCH>,
    <<P::Medium as Medium>::Io as SectorIo>::Error,
>
where
    P: Placement,
    <P::Medium as Medium>::Io: SectorIo,
{
    #[allow(clippy::let_unit_value)]
    let () = SeqLogEntries::<ENTRIES, CACHE>::CHECK;
    SiatStore::boot(WearLeveledKv::open(Placed::<P>::region(io), Placed::<P>::ONE_SECTOR_PER_BANK, sequence::MAGIC)?)
}

/// A one-key multicast-timer log on erase-block flash, in its own area.
/// The device chooses that area independently of the sequence log.
///
/// # Errors
///
/// If opening or scanning the medium fails.
#[allow(clippy::type_complexity)]
pub fn open_mc_timer_log<P>(
    io: <P::Medium as Medium>::Io,
) -> Result<WearLeveledKv<Region<<P::Medium as Medium>::Io>, 1>, <<P::Medium as Medium>::Io as SectorIo>::Error>
where
    P: Placement,
    <P::Medium as Medium>::Io: SectorIo,
{
    WearLeveledKv::open(Placed::<P>::region(io), Placed::<P>::ONE_SECTOR_PER_BANK, mc_timer::MAGIC)
}

/// An independent multicast-timer store on a byte-writable medium.
/// Its placement must hold both CRC-protected slots.
pub fn open_mc_timer_bytes<P>(io: <P::Medium as Medium>::Io) -> ByteMcTimer<Region<<P::Medium as Medium>::Io>>
where
    P: Placement,
    <P::Medium as Medium>::Io: ByteIo,
{
    ByteMcTimer::new(Region::new(io, McTimerByteArea::<P>::AREA), 0)
}

/// Check the independent byte store's size during monomorphization.
struct McTimerByteArea<P>(PhantomData<P>);

impl<P: Placement> McTimerByteArea<P>
where
    <P::Medium as Medium>::Io: ByteIo,
{
    const AREA: Area = {
        let area = Placed::<P>::AREA;
        core::assert!(
            ByteMcTimer::<<P::Medium as Medium>::Io>::REGION_LEN <= area.len,
            "mc_timer slots fit their area"
        );
        area
    };
}

/// The SIAT and sequence counters in the packed layout on a byte-writable
/// medium, at `P`, for `SLOTS` SIAT elements. An area too small for them is
/// a compile error.
pub fn open_packed_seq<P, const SLOTS: usize>(
    io: <P::Medium as Medium>::Io,
) -> PackedSeqStore<Region<<P::Medium as Medium>::Io>, SLOTS>
where
    P: Placement,
    <P::Medium as Medium>::Io: ByteIo,
{
    PackedSeqStore::new(Region::new(io, PackedSeqArea::<P, SLOTS>::AREA), 0, sequence::MAGIC)
}

/// Compile-fail proof that a placement is checked at compile time: opening a
/// config log over a medium's reserved area (here, its provisioning sector)
/// does not compile, because the log's geometry is an associated constant
/// whose check panics during constant evaluation.
///
/// ```compile_fail
/// use zweidraehte_device::storage::{Area, Medium, Placement, SectorIo, open_config_log};
///
/// struct Flash;
/// impl SectorIo for Flash {
///     type Error = ();
///     fn read(&mut self, _: u32, _: &mut [u8]) -> Result<(), ()> { Ok(()) }
///     fn erase(&mut self, _: u32, _: u32) -> Result<(), ()> { Ok(()) }
///     fn write(&mut self, _: u32, _: &[u8]) -> Result<(), ()> { Ok(()) }
/// }
///
/// struct Chip;
/// impl Medium for Chip {
///     const ID: u32 = 1;
///     type Io = Flash;
///     const CAPACITY: u32 = 0x10000;
///     const ERASE_SIZE: u32 = 0x1000;
///     const RESERVED: &'static [Area] = &[Area::new(0xF000, 0x1000)];
/// }
///
/// // Four sectors up to the end of the medium: the last one is reserved.
/// struct ConfigArea;
/// impl Placement for ConfigArea {
///     type Medium = Chip;
///     const AREA: Area = Area::new(0xC000, 0x4000);
/// }
///
/// let _ = open_config_log::<ConfigArea>(Flash);
/// ```
#[allow(dead_code)]
struct PlacementsAreCheckedAtCompileTime;

#[cfg(test)]
mod tests {
    use super::*;

    struct Chip;
    impl Medium for Chip {
        const ID: u32 = 1;
        type Io = ();
        const CAPACITY: u32 = 0x10000;
        const ERASE_SIZE: u32 = 0x1000;
        const RESERVED: &'static [Area] = &[Area::new(0xF000, 0x1000)];
    }

    macro_rules! placement {
        ($name:ident, $offset:expr, $len:expr) => {
            struct $name;
            impl Placement for $name {
                type Medium = Chip;
                const AREA: Area = Area::new($offset, $len);
            }
        };
    }

    placement!(BelowReserved, 0xB000, 0x4000);
    placement!(IntoReserved, 0xC000, 0x4000);
    placement!(Unaligned, 0xB800, 0x4000);
    placement!(PastTheEnd, 0xE000, 0x4000);

    #[test]
    fn an_area_below_the_reserved_one_passes() {
        assert_eq!(checked_area::<BelowReserved>(), Area::new(0xB000, 0x4000));
    }

    #[test]
    #[should_panic(expected = "reserved areas")]
    fn an_area_over_a_reserved_one_fails() {
        let _ = checked_area::<IntoReserved>();
    }

    #[test]
    #[should_panic(expected = "whole erase granules")]
    fn an_unaligned_area_fails() {
        let _ = checked_area::<Unaligned>();
    }

    #[test]
    #[should_panic(expected = "inside its medium")]
    fn an_area_past_the_medium_fails() {
        let _ = checked_area::<PastTheEnd>();
    }

    /// Two stores on one byte chip: each opens over its own area and
    /// writes nothing outside it.
    #[test]
    fn stores_on_one_chip_stay_in_their_areas() {
        use zweidraehte_nv::McTimerStore;
        use zweidraehte_nv::mock::{Backing, MockBytes};
        use zweidraehte_nv::stores::sequence::region_len;
        use zweidraehte_proto::security::SequenceNumberStorage;

        struct Fram;
        impl Medium for Fram {
            const ID: u32 = 2;
            type Io = MockBytes;
            const CAPACITY: u32 = 1024;
            const ERASE_SIZE: u32 = 1;
        }

        struct TimerArea;
        impl Placement for TimerArea {
            type Medium = Fram;
            const AREA: Area = Area::new(0, 64);
        }

        struct SeqArea;
        impl Placement for SeqArea {
            type Medium = Fram;
            const AREA: Area = Area::new(64, region_len(4) as u32);
        }

        let chip = Backing::new(1024, 1);
        let blank = chip.bytes().clone();

        let mut timer = open_mc_timer_bytes::<TimerArea>(chip.open_bytes());
        let mut seq = open_packed_seq::<SeqArea, 4>(chip.open_bytes());
        timer.save(42).expect("save the watermark");
        seq.save_sending_seq(&[0, 0, 0, 0, 1, 0]).expect("save the sending counter");

        let written: std::vec::Vec<usize> = (0..1024).filter(|&at| chip.bytes()[at] != blank[at]).collect();
        let timer_bytes = written.iter().filter(|&&at| TimerArea::AREA.contains(at as u32)).count();
        let seq_bytes = written.iter().filter(|&&at| SeqArea::AREA.contains(at as u32)).count();
        assert!(timer_bytes > 0 && seq_bytes > 0, "each store wrote into its own area");
        assert_eq!(timer_bytes + seq_bytes, written.len(), "a store wrote outside its area");

        let timer = open_mc_timer_bytes::<TimerArea>(chip.open_bytes());
        let seq = open_packed_seq::<SeqArea, 4>(chip.open_bytes());
        assert_eq!(timer.load().expect("load the watermark"), Some(42));
        assert_eq!(seq.load_sending_seq().expect("load the sending counter"), [0, 0, 0, 0, 1, 0]);
    }

    /// A split configuration keeps the routed sections on the byte medium
    /// and the rest in the flash log, and restores both through `NvConfig`.
    #[test]
    fn a_split_config_routes_sections_to_their_store() {
        use core::cell::RefCell;

        use zweidraehte_nv::mock::{Backing, MockBytes, MockFlash};

        use crate::sections::{PersistentSections, Section, SectionError, SectionKind, apply_image, read_image};
        use crate::storage::{DeviceStorage, Loaded};

        struct Flash;
        impl Medium for Flash {
            const ID: u32 = 1;
            type Io = MockFlash<1>;
            const CAPACITY: u32 = 4096;
            const ERASE_SIZE: u32 = 1024;
        }

        struct Fram;
        impl Medium for Fram {
            const ID: u32 = 2;
            type Io = MockBytes;
            const CAPACITY: u32 = 1024;
            const ERASE_SIZE: u32 = 1;
        }

        struct LogArea;
        impl Placement for LogArea {
            type Medium = Flash;
            const AREA: Area = Area::new(2048, 2048);
        }

        struct ParamsArea;
        impl Placement for ParamsArea {
            type Medium = Fram;
            const AREA: Area = Area::new(256, 256);
        }

        struct ParamsOnFram;
        impl Routes for ParamsOnFram {
            const SECOND: &'static [SectionId] = &[SECTION_APP_CONTROL, SECTION_APP_DATA];
        }

        /// The address table's control Record, and the application's control
        /// Record and parameters.
        #[derive(Default)]
        struct State {
            adt_control: RefCell<[u8; 4]>,
            app_control: RefCell<[u8; 4]>,
            params: RefCell<[u8; 16]>,
        }

        impl PersistentSections for State {
            fn for_each_section(&self, f: &mut impl FnMut(Section)) {
                f(Section { id: SECTION_ADT_CONTROL, len: 4, kind: SectionKind::Record });
                f(Section { id: SECTION_APP_CONTROL, len: 4, kind: SectionKind::Record });
                f(Section { id: SECTION_APP_DATA, len: 16, kind: SectionKind::Image });
            }

            fn read_section(&self, id: SectionId, offset: u16, buf: &mut [u8]) {
                match id {
                    SECTION_ADT_CONTROL => read_image(&*self.adt_control.borrow(), offset, buf),
                    SECTION_APP_CONTROL => read_image(&*self.app_control.borrow(), offset, buf),
                    _ => read_image(&*self.params.borrow(), offset, buf),
                }
            }

            fn apply_section(&self, id: SectionId, offset: u16, bytes: &[u8]) -> Result<(), SectionError> {
                match id {
                    SECTION_ADT_CONTROL => apply_image(&mut *self.adt_control.borrow_mut(), offset, bytes),
                    SECTION_APP_CONTROL => apply_image(&mut *self.app_control.borrow_mut(), offset, bytes),
                    _ => apply_image(&mut *self.params.borrow_mut(), offset, bytes),
                }
            }

            fn reset_section(&self, _id: SectionId) {}
        }

        let flash = Backing::new(4096, 1024);
        let fram = Backing::new(1024, 1);
        let open = || open_split_config::<LogArea, ParamsArea, ParamsOnFram>(flash.open(), fram.open_bytes());

        let state = State::default();
        let config = open();
        assert_eq!(config.load(&state).expect("format"), Loaded::Fresh);

        *state.adt_control.borrow_mut() = [1, 1, 1, 1];
        *state.app_control.borrow_mut() = [2, 2, 2, 2];
        config.flush(&state).expect("flush the Records");
        drop(config);

        let rebooted = State::default();
        assert_eq!(open().load(&rebooted).expect("reboot"), Loaded::Restored);
        assert_eq!(*rebooted.adt_control.borrow(), [1, 1, 1, 1]);
        assert_eq!(*rebooted.app_control.borrow(), [2, 2, 2, 2]);

        // The FRAM image holds the application's sections, inside its area.
        let fram_bytes = fram.bytes();
        assert!(fram_bytes[..256].iter().all(|&b| b == 0xFF), "the image wrote below its area");
        assert!(fram_bytes[256..512].windows(4).any(|w| w == [2, 2, 2, 2]), "the routed Record is not on the FRAM");
        assert!(!fram_bytes[256..512].windows(4).any(|w| w == [1, 1, 1, 1]), "an unrouted Record reached the FRAM");
    }

    /// Neighbours on one medium pass; the same span on two media passes;
    /// an overlap on one medium fails.
    #[test]
    fn a_layout_rejects_overlaps_on_one_medium_only() {
        let entry = |medium, offset, len| LayoutEntry { medium, area: Area::new(offset, len) };

        check_layout(&[entry(1, 0, 0x1000), entry(1, 0x1000, 0x1000)]);
        check_layout(&[entry(1, 0, 0x2000), entry(2, 0x1000, 0x1000)]);

        let overlap = std::panic::catch_unwind(|| check_layout(&[entry(1, 0, 0x2000), entry(1, 0x1000, 0x1000)]));
        assert!(overlap.is_err());
    }
}
