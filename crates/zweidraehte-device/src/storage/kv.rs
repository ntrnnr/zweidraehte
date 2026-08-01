//! The [`KeyValueStore`] seam between storage backends and typed views.
//!
//! This module separates *what* to persist from *how* to persist it: a durable
//! map keyed by `(namespace, key)`. Backends implement it
//! ([`WearLeveledKv`](super::WearLeveledKv) over sector flash,
//! [`PackedSeqStore`](super::backends::PackedSeqStore) over byte media); the
//! typed views in [`views`](super::views) consume it, generic over the
//! backend, so the wear-levelled-vs-verbatim choice is a construction-time
//! type decision the view code never branches on. The seam lives in its own
//! module because both sides depend on it and it belongs to neither.
//!
//! # Why key-value rather than a blob region
//!
//! The SIAT's hot path changes one entry's 6-byte sequence number on every
//! accepted frame. A blob interface (`store(&[u8])` of the whole table) would
//! force the wear-levelled backend to re-append the entire table per update,
//! defeating the append-log. A keyed `put` of one entry *is* the delta, so the
//! wear-levelled backend appends a single record and the verbatim backend does
//! a whole-region rewrite — the view is identical either way.

// ============================================================================
// Namespaces
// ============================================================================
//
// One byte distinguishing record kinds within a backend. A device may give each
// view its own backend instance (own flash region) or share one backend across
// views; the namespace keeps records unambiguous in the shared case and is
// harmless in the per-instance case.

/// SIAT entries: key = sender IA (2 bytes big-endian), value = SeqNr (6 bytes).
pub const NS_SIAT: u8 = 0x01;
/// The single Sequence Number Sending: key = `[0]`, value = SeqNr (6 bytes).
pub const NS_SENDING: u8 = 0x02;
/// The Tool Access receiving SeqNr (a singleton, separate from the SIAT per
/// 03/03/07 NOTE 104): key = `[0]`, value = SeqNr (6 bytes).
pub const NS_TOOL: u8 = 0x03;

/// The IP-Secure mc_timer watermark (a singleton): key = `[0]`, value = the
/// low 48 bits of the multicast timer as a 6-byte big-endian counter. Disjoint
/// from the SIAT namespaces above so the mc_timer and the SIAT could share one
/// backend without colliding — though in practice each gets its own region.
pub const NS_MC_TIMER: u8 = 0x10;

/// Fixed key used for singleton namespaces ([`NS_SENDING`], [`NS_TOOL`],
/// [`NS_MC_TIMER`]).
pub(crate) const SINGLETON_KEY: &[u8] = &[0];

// ============================================================================
// KeyValueStore — the one backend trait
// ============================================================================

/// A durable map keyed by `(namespace, key)` with byte-slice values.
///
/// This is the *only* trait a storage backend implements. All table- and
/// counter-specific behaviour lives in views
/// ([`SiatStore`](super::views::SiatStore)) generic over this trait, so
/// wear-levelling is an orthogonal backend choice.
///
/// `get` and `for_each` take `&self`: a backend keeps its current contents
/// readable without a per-call flash read (wear-levelled and verbatim backends
/// both maintain an in-RAM mirror; this matches the existing `load_*(&self)`
/// sequence-number convention). Mutations take `&mut self`.
pub trait KeyValueStore {
    /// Backend error type (e.g. a flash I/O error). RAM backends use
    /// [`core::convert::Infallible`].
    type Error;

    /// Read the current value of `(ns, key)` into `buf`. Returns `Some(len)`
    /// with the value length, or `None` if the key is absent. Returns an error
    /// (not a panic) if `buf` is too small — callers size `buf` to the known
    /// value width.
    fn get(&self, ns: u8, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>, Self::Error>;

    /// Durably set `(ns, key) = val`, replacing any prior value.
    fn put(&mut self, ns: u8, key: &[u8], val: &[u8]) -> Result<(), Self::Error>;

    /// Durably remove `(ns, key)`. A no-op if the key is absent.
    fn remove(&mut self, ns: u8, key: &[u8]) -> Result<(), Self::Error>;

    /// Visit every live `(key, value)` pair in `ns`, in unspecified order.
    ///
    /// Used once at boot by a view to reconstruct its in-RAM mirror. Uses a
    /// `&mut dyn FnMut` rather than a generic to keep this cold-path scan from
    /// monomorphising per closure and to keep the trait object-friendly.
    fn for_each(&self, ns: u8, f: &mut dyn FnMut(&[u8], &[u8]));
}

// ============================================================================
// Seq <-> u64 helpers (6-octet big-endian, the KNX wire format)
// ============================================================================

/// Decode a 6-octet big-endian sequence number to `u64`.
pub fn seq6_to_u64(seq: &[u8; 6]) -> u64 {
    u64::from_be_bytes([0, 0, seq[0], seq[1], seq[2], seq[3], seq[4], seq[5]])
}

/// Encode the low 48 bits of `val` as a 6-octet big-endian sequence number.
pub fn u64_to_seq6(val: u64) -> [u8; 6] {
    let b = val.to_be_bytes();
    [b[2], b[3], b[4], b[5], b[6], b[7]]
}

/// Largest value a 6-octet sequence number can carry (`2^48 - 1`).
pub const SEQ6_MAX: u64 = 0xFFFF_FFFF_FFFF;

/// Spec-default sending sequence number on a fresh device.
///
/// The secure AL treats `[0,0,0,0,0,1]` as "no history"; remotes reject seq 0,
/// and ETS reconciles via `S-A_Sync`.
pub const DEFAULT_SENDING: [u8; 6] = [0, 0, 0, 0, 0, 1];

/// Near-exhaustion threshold for the 6-byte (48-bit) sending SeqNr:
/// `FF 00 00 00 00 00`. A factory reset re-initialises the counter only at or
/// above this value (03/05/01 §6.1.4 + AN194) — below it the counter is
/// preserved, since receivers have already seen those values and would reject
/// a lower re-init as a replay.
pub const SEQ_EXHAUSTION_THRESHOLD: u64 = 0xFF_0000_0000_00;

/// Re-init target after a near-exhaustion factory reset.
///
/// 03/03/07 §5.3.1 requires the re-initialised value to sit "at least 20
/// and at maximum FFFFh higher than the preceding initial value": ours is
/// [`DEFAULT_SENDING`]'s 1, so 21. A fixed target technically shortchanges
/// a *second* re-init in the same device life, but reaching one would mean
/// counting from 21 back up to the 2^48-order threshold — the spec's own
/// NOTE 33 blesses implementation-specific schemes, and storing a
/// re-init generation to add 20 each time buys nothing real.
pub const SEQ_REINIT_VALUE: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x15];
