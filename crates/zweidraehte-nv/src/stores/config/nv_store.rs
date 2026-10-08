//! The configuration store: moves a device state's sections to and from a
//! non-volatile medium.
//!
//! A device state describes its configuration as [`PersistentSections`]. A
//! store makes a section, or a byte range of one, durable when the state
//! changes it ([`persist`](NvStore::persist)), and applies every durable
//! section back into a factory-fresh state at boot ([`load`](NvStore::load)).
//! The store reads the bytes from the state itself, so a caller only names
//! what changed.
//!
//! Two backends implement it:
//! - [`ByteNv`](crate::ByteNv) for byte-writable media (FRAM, EEPROM, shared
//!   memory, a file): every section at a fixed offset, written in place;
//! - [`FlashLog`](crate::FlashLog) for erase-block flash: section records
//!   appended to the [`AppendLog`](crate::AppendLog).

use core::cell::Cell;

use super::sections::{PersistentSections, Section, SectionId, SectionKind};

/// What [`NvStore::load`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Loaded {
    /// The medium held this layout; the state now holds its content.
    Restored,
    /// The medium was blank, foreign, or written under another layout. The
    /// state keeps its factory defaults, and the medium now holds them.
    Fresh,
}

/// Why a store operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvError<E> {
    /// The medium reported an error.
    Io(E),
    /// The state's sections do not fit the medium: a static sizing mistake
    /// of the device, reported rather than panicking so firmware can log it.
    LayoutTooLarge,
    /// Section IDs are duplicated or not in ascending order.
    InvalidLayout,
    /// The next flash record needs compaction. Earlier Image chunks may
    /// already be durable; a guarded snapshot of the current state completes
    /// the pending write.
    NeedsMaintenance,
}

/// A non-volatile home for a device state's sections.
pub trait NvStore {
    /// The medium's error type.
    type Error;

    /// Boot: apply every durable section to `state`, which must be
    /// factory-fresh.
    ///
    /// A section that fails to apply (a torn or foreign Record) is reset to
    /// its factory default; the others load normally.
    fn load<S: PersistentSections>(&mut self, state: &S) -> Result<Loaded, NvError<Self::Error>>;

    /// Make `len` bytes of section `id` from `offset` durable, reading them
    /// from `state`. A Record section is always persisted whole. An Image
    /// may have earlier chunks durable when this returns an error; a full
    /// snapshot of `state` can complete a deferred write.
    ///
    /// # Panics
    ///
    /// If `id` is not one of `state`'s sections, or the range lies outside
    /// it; both are caller bugs.
    fn persist<S: PersistentSections>(
        &mut self,
        state: &S,
        id: SectionId,
        offset: u16,
        len: u16,
    ) -> Result<(), NvError<Self::Error>>;

    /// Whether the durable copy of Record section `id` equals the state's
    /// current bytes. The store's own copy is the comparison baseline, so
    /// finding changed Records needs no RAM shadow; a missing or unreadable
    /// copy counts as different.
    fn record_matches<S: PersistentSections>(&mut self, state: &S, id: SectionId)
    -> Result<bool, NvError<Self::Error>>;

    /// Whether the store needs or would benefit from
    /// [`compact`](Self::compact). A flash store may return
    /// [`NeedsMaintenance`](NvError::NeedsMaintenance) from `persist`
    /// until the caller compacts with the bus held busy.
    fn needs_compaction(&self) -> bool {
        false
    }

    /// Make every current section of `state` durable in one pass and drop
    /// the store's history. Afterwards nothing pending is lost, so the
    /// caller may forget its dirty ranges. A store that writes in place
    /// rewrites its sections; one without sections of its own does nothing.
    fn compact<S: PersistentSections>(&mut self, _state: &S) -> Result<(), NvError<Self::Error>> {
        Ok(())
    }
}

/// Whether a firmware layout gives each section one ID in ascending order.
/// Stores check this before reading or formatting an on-media layout.
pub(crate) fn sections_in_order<S: PersistentSections>(state: &S) -> bool {
    let mut previous = None;
    let mut ordered = true;

    state.for_each_section(&mut |section| {
        if previous.is_some_and(|id| section.id <= id) {
            ordered = false;
        }

        previous = Some(section.id);
    });

    ordered
}

/// The entry of section `id` in `state`'s section list.
pub(crate) fn find_section<S: PersistentSections>(state: &S, id: SectionId) -> Option<Section> {
    let mut found = None;
    state.for_each_section(&mut |section| {
        if section.id == id {
            found = Some(section);
        }
    });
    found
}

// ============================================================================
// Flusher
// ============================================================================

/// How many dirty Image ranges one flush collects before it falls back to
/// persisting every Image whole; a dispatch touches one or two.
const DIRTY_RANGES: usize = 16;

/// Persists what changed in a state since the last flush.
///
/// Images report their own dirty byte ranges
/// ([`take_dirty_images`](PersistentSections::take_dirty_images)); Records
/// are compared with the store's durable copy
/// ([`record_matches`](NvStore::record_matches)). Taking the dirty ranges
/// consumes them, so when a flush fails part-way, or more ranges are pending
/// than it collects, the flusher remembers that a range may be lost and its
/// next flush persists every Image whole.
pub struct Flusher {
    resync: Cell<bool>,
}

impl Default for Flusher {
    fn default() -> Self {
        Self::new()
    }
}

impl Flusher {
    pub const fn new() -> Self {
        Self { resync: Cell::new(false) }
    }

    /// Persist every changed range and Record of `state` into `store`.
    pub fn flush<S: PersistentSections, N: NvStore>(&self, state: &S, store: &mut N) -> Result<(), NvError<N::Error>> {
        // Collect first: the state may hold a borrow while it reports a
        // range, and persisting reads the state again.
        let mut ranges = heapless::Vec::<(SectionId, u16, u16), DIRTY_RANGES>::new();
        state.take_dirty_images(&mut |id, offset, len| {
            if ranges.push((id, offset, len)).is_err() {
                self.resync.set(true);
            }
        });

        let result = self.persist_changes(state, store, &ranges);
        if result.is_err() {
            self.resync.set(true);
        }

        result
    }

    /// A full snapshot of `state` made every current section durable.
    /// Consume stale dirty ranges so a retry does not append them again.
    pub fn snapshot_committed<S: PersistentSections>(&self, state: &S) {
        state.take_dirty_images(&mut |_, _, _| {});
        self.resync.set(false);
    }

    fn persist_changes<S: PersistentSections, N: NvStore>(
        &self,
        state: &S,
        store: &mut N,
        ranges: &[(SectionId, u16, u16)],
    ) -> Result<(), NvError<N::Error>> {
        if self.resync.get() {
            for (id, len) in sections_of_kind(state, SectionKind::Image) {
                store.persist(state, id, 0, len)?;
            }
            self.resync.set(false);
        } else {
            for &(id, offset, len) in ranges {
                store.persist(state, id, offset, len)?;
            }
        }

        for (id, len) in sections_of_kind(state, SectionKind::Record) {
            if !store.record_matches(state, id)? {
                store.persist(state, id, 0, len)?;
            }
        }
        Ok(())
    }
}

/// Scan once per item so the state's section-list borrow ends before
/// the caller reads or persists that section.
fn sections_of_kind<S: PersistentSections>(
    state: &S,
    kind: SectionKind,
) -> impl Iterator<Item = (SectionId, u16)> + '_ {
    let mut after: Option<SectionId> = None;

    core::iter::from_fn(move || {
        let mut next = None;

        state.for_each_section(&mut |section| {
            if next.is_none() && section.kind == kind && after.is_none_or(|id| section.id > id) {
                next = Some((section.id, section.len));
            }
        });

        if let Some((id, _)) = next {
            after = Some(id);
        }

        next
    })
}
