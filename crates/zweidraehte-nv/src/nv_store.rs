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

use crate::sections::{PersistentSections, Section, SectionId};

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
    /// from `state`. A Record section is always persisted whole.
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

    /// Whether the store would like a [`compact`](Self::compact) soon: the
    /// caller can then compact at a moment of its choosing (with the bus
    /// held busy) instead of inside a later `persist`.
    fn needs_compaction(&self) -> bool {
        false
    }

    /// Rewrite the whole state and drop history. A no-op on media that
    /// write in place.
    fn compact<S: PersistentSections>(&mut self, _state: &S) -> Result<(), NvError<Self::Error>> {
        Ok(())
    }
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
