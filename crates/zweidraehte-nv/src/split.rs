//! One device state's configuration across two stores.
//!
//! A board may want its sections on two media: the tables in a flash log,
//! say, and the application parameters on an FRAM next to the SIAT.
//! [`SplitNv`] is an [`NvStore`] over two stores. The firmware names the
//! sections the second store keeps with a zero-sized [`Routes`] type; every
//! other section stays in the first.
//!
//! Each store sees the state through a filtered view that lists only its own
//! sections. So each store checks, loads, snapshots and fingerprints its
//! share alone: a layout change in one group of sections boots that store
//! fresh and leaves the other's data in place.
//!
//! There is still one owner of the dirty ranges: the
//! [`Flusher`](crate::Flusher) that drives this store drives both halves.
//! When either half fails a write, the flush fails as a whole and the next
//! one persists every Image again, on both.
//!
//! A section whose validity depends on another one must live in the same
//! store: a table's data Image and its control Record, for instance. A
//! store that finds a CRC mismatch in an Image persists the control Record
//! the state names for it, and that Record has to be in the same store. The
//! device crate checks the stack's pairs at compile time; `ByteNv` panics at
//! boot if the control Record is not in its view.

use core::marker::PhantomData;

use crate::nv_store::{Loaded, NvError, NvStore};
use crate::sections::{PersistentSections, Section, SectionError, SectionId};

/// Which sections a [`SplitNv`] keeps in its second store. Implemented by
/// the firmware on a unit type.
pub trait Routes {
    /// The ids of the sections the second store holds. Every other section
    /// lives in the first store.
    const SECOND: &'static [SectionId];
}

/// Whether routes `R` keep section `id` in the second store.
fn in_second<R: Routes>(id: SectionId) -> bool {
    R::SECOND.contains(&id)
}

/// A medium error of either half of a [`SplitNv`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SplitError<A, B> {
    /// The first store's medium failed.
    First(A),
    /// The second store's medium failed.
    Second(B),
}

/// The configuration of one state in two stores, `first` and `second`, with
/// the sections routed by `R`.
pub struct SplitNv<A, B, R> {
    first: A,
    second: B,
    routes: PhantomData<R>,
}

impl<A: NvStore, B: NvStore, R: Routes> SplitNv<A, B, R> {
    /// Both stores, opened but not yet loaded.
    pub const fn new(first: A, second: B) -> Self {
        Self { first, second, routes: PhantomData }
    }
}

/// `state` as one store of a [`SplitNv`] sees it: only the sections routed
/// to that store (`SECOND` picks the half).
struct Routed<'s, S, R, const SECOND: bool> {
    state: &'s S,
    routes: PhantomData<R>,
}

impl<'s, S, R, const SECOND: bool> Routed<'s, S, R, SECOND> {
    fn new(state: &'s S) -> Self {
        Self { state, routes: PhantomData }
    }
}

impl<S: PersistentSections, R: Routes, const SECOND: bool> PersistentSections for Routed<'_, S, R, SECOND> {
    fn for_each_section(&self, f: &mut impl FnMut(Section)) {
        self.state.for_each_section(&mut |section| {
            if in_second::<R>(section.id) == SECOND {
                f(section);
            }
        });
    }

    fn read_section(&self, id: SectionId, offset: u16, buf: &mut [u8]) {
        self.state.read_section(id, offset, buf);
    }

    fn apply_section(&self, id: SectionId, offset: u16, bytes: &[u8]) -> Result<(), SectionError> {
        self.state.apply_section(id, offset, bytes)
    }

    fn reset_section(&self, id: SectionId) {
        self.state.reset_section(id);
    }

    fn image_crc_mismatch(&self, id: SectionId) -> Option<SectionId> {
        self.state.image_crc_mismatch(id)
    }

    // The flusher takes the dirty ranges from the whole state, never from a
    // half, so the default of reporting none is never in the way.
}

/// Carry a half's error into the split store's error type.
fn lift<E, F>(error: NvError<E>, wrap: impl FnOnce(E) -> F) -> NvError<F> {
    match error {
        NvError::Io(error) => NvError::Io(wrap(error)),
        NvError::LayoutTooLarge => NvError::LayoutTooLarge,
        NvError::InvalidLayout => NvError::InvalidLayout,
        NvError::NeedsMaintenance => NvError::NeedsMaintenance,
    }
}

impl<A: NvStore, B: NvStore, R: Routes> NvStore for SplitNv<A, B, R> {
    type Error = SplitError<A::Error, B::Error>;

    /// Load both halves. The state is `Fresh` only when both media were.
    fn load<S: PersistentSections>(&mut self, state: &S) -> Result<Loaded, NvError<Self::Error>> {
        let first = self.first.load(&Routed::<S, R, false>::new(state)).map_err(|e| lift(e, SplitError::First))?;
        let second = self.second.load(&Routed::<S, R, true>::new(state)).map_err(|e| lift(e, SplitError::Second))?;

        Ok(if first == Loaded::Fresh && second == Loaded::Fresh { Loaded::Fresh } else { Loaded::Restored })
    }

    fn persist<S: PersistentSections>(
        &mut self,
        state: &S,
        id: SectionId,
        offset: u16,
        len: u16,
    ) -> Result<(), NvError<Self::Error>> {
        if in_second::<R>(id) {
            self.second
                .persist(&Routed::<S, R, true>::new(state), id, offset, len)
                .map_err(|e| lift(e, SplitError::Second))
        } else {
            self.first
                .persist(&Routed::<S, R, false>::new(state), id, offset, len)
                .map_err(|e| lift(e, SplitError::First))
        }
    }

    fn record_matches<S: PersistentSections>(
        &mut self,
        state: &S,
        id: SectionId,
    ) -> Result<bool, NvError<Self::Error>> {
        if in_second::<R>(id) {
            self.second.record_matches(&Routed::<S, R, true>::new(state), id).map_err(|e| lift(e, SplitError::Second))
        } else {
            self.first.record_matches(&Routed::<S, R, false>::new(state), id).map_err(|e| lift(e, SplitError::First))
        }
    }

    fn needs_compaction(&self) -> bool {
        self.first.needs_compaction() || self.second.needs_compaction()
    }

    /// Compact both halves, so that the whole state is durable afterwards
    /// whichever half asked.
    fn compact<S: PersistentSections>(&mut self, state: &S) -> Result<(), NvError<Self::Error>> {
        self.first.compact(&Routed::<S, R, false>::new(state)).map_err(|e| lift(e, SplitError::First))?;
        self.second.compact(&Routed::<S, R, true>::new(state)).map_err(|e| lift(e, SplitError::Second))
    }
}
