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
// The registry lives in `zweidraehte-nv` with the views that use most of
// them, so namespace bytes stay disjoint across crates.

pub use zweidraehte_nv::{NS_MC_TIMER, NS_SENDING, NS_SIAT, NS_TOOL, SINGLETON_KEY};

// ============================================================================
// KeyValueStore — the one backend trait
// ============================================================================
//
// The trait lives in `zweidraehte-nv` next to its wear-levelled
// implementation, so the micro stack can use both without this crate.

pub use zweidraehte_nv::KeyValueStore;

// ============================================================================
// Seq <-> u64 helpers (6-octet big-endian, the KNX wire format)
// ============================================================================
//
// The codec and the spec's fixed sequence values are
// `zweidraehte_proto::security`: they describe the wire, not this crate's
// storage, and the polling stack needs the same answers. Re-exported so the
// backends and views that grew up against `storage::kv::…` keep resolving.

pub use zweidraehte_proto::security::{
    DEFAULT_SENDING, SEQ_EXHAUSTION_THRESHOLD, SEQ_REINIT_VALUE, SEQ6_MAX, seq6_to_u64, u64_to_seq6,
};
