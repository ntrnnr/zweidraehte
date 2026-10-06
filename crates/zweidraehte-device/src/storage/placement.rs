//! Where a device's stores live, decided by the device, checked and
//! computed at compile time.
//!
//! Which medium holds which store is a fact of the board, not of the chip:
//! one STM32 board keeps its SIAT on an FRAM, another in flash. So the device
//! places every store itself, as a unit type implementing [`Placement`]: a
//! [`Medium`] and an [`Area`] on it. The platform crates provide the media,
//! their geometry as constants (flash size, erase granule, reserved areas
//! such as the provisioning page) and their I/O handles.
//!
//! The `open_*` functions take the placement as a type parameter, so every
//! offset and log geometry they use is a constant, evaluated per device at
//! compile time. A placement that breaks a rule of its medium or of its
//! store is a compile error:
//!
//! ```ignore
//! struct Config;
//! impl Placement for Config {
//!     type Medium = InternalFlash;
//!     const AREA: Area = Area::new(InternalFlash::PROVISIONING.offset - 16 * 1024, 16 * 1024);
//! }
//! struct Siat;
//! impl Placement for Siat {
//!     type Medium = Fram;
//!     const AREA: Area = Area::new(0, 2048);
//! }
//!
//! let storage = SecureStorage::new(
//!     open_config_log::<Config>(flash_io),
//!     open_packed_seq::<Siat, SIAT_SIZE>(fram_io),
//! );
//! ```
//!
//! Which store implementation a placement gets follows from the medium: the
//! logs need an erase-block medium ([`SectorIo`]), the packed and image
//! stores a byte-writable one ([`ByteIo`]). Each store opens over a
//! [`Region`] of the handle, bounded to its area and addressed from 0, so a
//! store cannot reach into a neighbour's area on a shared chip.
//!
//! Areas of different stores on the same medium must not overlap. The check
//! needs both areas, and a medium's identity is a type, which `const` code
//! cannot compare, so it runs over a list someone states: for the flash,
//! the platform's `reserve_storage!`, which already takes every store on
//! it; for another medium, the device, once, with [`assert_disjoint`].

use core::marker::PhantomData;

use zweidraehte_nv::{
    Area, ByteIo, ByteMcTimer, ByteNv, FlashLog, LogGeometry, PackedSeqStore, Region, SectorIo, SiatStore,
    WearLeveledKv,
};
use zweidraehte_nv::{MC_TIMER_MAGIC, SEQUENCE_MAGIC, region_len};

use super::nv_config::{ConfigLog, NvConfig};

// ============================================================================
// Medium and Placement
// ============================================================================

/// A storage medium of a board: its geometry as constants, and the handle
/// its stores open over. Implemented by the platform crates (the internal
/// flash of a chip, an external FRAM, ...).
pub trait Medium {
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

/// Panics, at compile time in a `const`, if any two of `areas` overlap.
/// For the stores a device puts on the same medium.
pub const fn assert_disjoint(areas: &[Area]) {
    let mut i = 0;
    while i < areas.len() {
        let mut j = i + 1;
        while j < areas.len() {
            core::assert!(!areas[i].overlaps(&areas[j]), "two stores on one medium overlap");
            j += 1;
        }
        i += 1;
    }
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
    SiatStore::boot(WearLeveledKv::open(Placed::<P>::region(io), Placed::<P>::ONE_SECTOR_PER_BANK, SEQUENCE_MAGIC)?)
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
    WearLeveledKv::open(Placed::<P>::region(io), Placed::<P>::ONE_SECTOR_PER_BANK, MC_TIMER_MAGIC)
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
    PackedSeqStore::new(Region::new(io, PackedSeqArea::<P, SLOTS>::AREA), 0, SEQUENCE_MAGIC)
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
        use zweidraehte_nv::mock::{Backing, MockBytes};
        use zweidraehte_nv::{McTimerStore, region_len};
        use zweidraehte_proto::security::SequenceNumberStorage;

        struct Fram;
        impl Medium for Fram {
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

    #[test]
    fn disjoint_areas_pass_and_overlapping_ones_fail() {
        assert_disjoint(&[Area::new(0, 0x1000), Area::new(0x1000, 0x1000)]);
        let overlap = std::panic::catch_unwind(|| assert_disjoint(&[Area::new(0, 0x2000), Area::new(0x1000, 0x1000)]));
        assert!(overlap.is_err());
    }
}
