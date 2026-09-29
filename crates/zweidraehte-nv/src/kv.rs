//! A durable `(namespace, key) -> value` map, and its wear-levelled
//! implementation over the [`AppendLog`].
//!
//! # Why key-value rather than a blob region
//!
//! The Data Secure SIAT changes one entry's 6-octet sequence number on every
//! accepted frame. A blob interface (`store(&[u8])` of the whole table) would
//! force a flash backend to re-append the entire table per update. A keyed
//! `put` of one entry *is* the delta, so the log appends one 16-octet record.

use crate::SectorIo;
use crate::log::{AppendLog, Compactor, LogGeometry};
use crate::mirror::Mirror;

/// Maximum key width across all namespaces (SIAT element index = 2 bytes).
pub const MAX_KEY: usize = 2;
/// Maximum value width across all namespaces (SIAT IA + SeqNr = 8 bytes).
pub const MAX_VAL: usize = 8;

// ============================================================================
// KeyValueStore — the one backend trait
// ============================================================================

/// A durable map keyed by `(namespace, key)` with byte-slice values.
///
/// This is the *only* trait a key/value backend implements. Table- and
/// counter-specific behaviour lives in views generic over it (the device
/// crate's `SiatStore` and `McTimerStore`), so wear-levelling is an
/// orthogonal backend choice.
///
/// `get` and `for_each` take `&self`: a backend keeps its current contents
/// readable without a per-call flash read (the wear-levelled backend keeps an
/// in-RAM [`Mirror`]; byte-medium backends read the medium directly).
/// Mutations take `&mut self`.
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
// WearLeveledKv
// ============================================================================

/// The padded record length of the KV log. The largest payload is
/// `ns(1) + flags|klen(1) + key(2) + val(8) = 12`, plus 4 octets of framing.
/// Sixteen is also whole granules for every write alignment up to 16, so
/// STM32G0 doubleword flash takes the same records as RP2040.
pub const KV_RECORD: usize = 16;

/// Set in the `klen` octet of a record that removes its key.
const TOMBSTONE: u8 = 0x80;

// The widest record must fit KV_RECORD, and a key length must stay clear of
// the tombstone bit.
const _: () = assert!(4 + 2 + MAX_KEY + MAX_VAL <= KV_RECORD, "the widest KV record exceeds KV_RECORD");
const _: () = assert!(MAX_KEY < TOMBSTONE as usize, "key lengths collide with the tombstone bit");

/// Wear-levelled [`KeyValueStore`] over an [`AppendLog`], holding at most
/// `ENTRIES` live pairs.
///
/// # Record payload
///
/// ```text
/// [ns:1][klen | TOMBSTONE:1][key:klen][val:rest]
/// ```
///
/// The value length is whatever the log's record length leaves, so it needs
/// no octet of its own. Last writer wins on replay; a tombstone cancels the
/// key.
///
/// The RAM [`Mirror`] is the authoritative current contents and the log is
/// its durable backing: `get`/`for_each` read the mirror, `put`/`remove`
/// append one record, and a full bank compacts the mirror into the next.
pub struct WearLeveledKv<F: SectorIo, const ENTRIES: usize> {
    log: AppendLog<F, KV_RECORD>,
    mirror: Mirror<ENTRIES>,
}

impl<F: SectorIo, const ENTRIES: usize> WearLeveledKv<F, ENTRIES> {
    /// Open the store tagged `magic` over `geometry`, rebuilding the mirror
    /// from the log. A blank region, or one written under another magic,
    /// yields an empty store.
    ///
    /// Distinct regions carved out of one flash use distinct magics, so a
    /// region that took over another's sectors never adopts its stale
    /// records.
    ///
    /// # Panics
    ///
    /// If a full mirror plus one new record could not fit a freshly compacted
    /// bank, or on a geometry the log itself rejects (see
    /// [`AppendLog::open`]). Both are static sizing mistakes, so failing at
    /// open beats failing at the first compaction in the field.
    pub fn open(io: F, geometry: LogGeometry, magic: u32) -> Result<Self, F::Error> {
        let worst_case_snapshot = (ENTRIES + 1) * KV_RECORD;
        assert!(
            AppendLog::<F, KV_RECORD>::header_len() as usize + worst_case_snapshot <= geometry.bank_size() as usize,
            "WearLeveledKv: ENTRIES exceeds what one bank can hold after compaction"
        );

        let mut mirror = Mirror::new();
        let log = AppendLog::open(io, geometry, magic, |payload| Self::apply(&mut mirror, payload))?;
        Ok(Self { log, mirror })
    }

    /// Apply one replayed record to the mirror. A payload that does not
    /// decode passed its CRC, so it was written by something else under our
    /// magic; it is ignored rather than trusted.
    fn apply(mirror: &mut Mirror<ENTRIES>, payload: &[u8]) {
        let [ns, flags, rest @ ..] = payload else {
            return;
        };
        let key_len = usize::from(flags & !TOMBSTONE);
        if key_len > MAX_KEY || key_len > rest.len() {
            return;
        }
        let (key, val) = rest.split_at(key_len);

        if flags & TOMBSTONE != 0 {
            mirror.remove(*ns, key);
        } else if val.len() <= MAX_VAL {
            mirror.upsert(*ns, key, val);
        }
    }

    /// Append one record; if that compacts, re-emit the mirror first.
    fn append(&mut self, ns: u8, flags: u8, key: &[u8], val: &[u8]) -> Result<(), F::Error> {
        // `log` and `mirror` are disjoint fields, so the snapshot closure can
        // read the mirror while the log is borrowed mutably.
        let mirror = &self.mirror;
        self.log.append(&[&[ns, flags], key, val], |compactor: &mut Compactor<'_, F, KV_RECORD>| {
            for entry in mirror.iter() {
                compactor.push(&[&[entry.ns(), entry.key().len() as u8], entry.key(), entry.val()])?;
            }
            Ok(())
        })
    }
}

impl<F: SectorIo, const ENTRIES: usize> KeyValueStore for WearLeveledKv<F, ENTRIES> {
    type Error = F::Error;

    fn get(&self, ns: u8, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        Ok(self.mirror.get_into(ns, key, buf))
    }

    fn put(&mut self, ns: u8, key: &[u8], val: &[u8]) -> Result<(), Self::Error> {
        assert!(key.len() <= MAX_KEY && val.len() <= MAX_VAL, "WearLeveledKv: key or value exceeds its bound");
        self.append(ns, key.len() as u8, key, val)?;
        self.mirror.upsert(ns, key, val);
        Ok(())
    }

    fn remove(&mut self, ns: u8, key: &[u8]) -> Result<(), Self::Error> {
        if !self.mirror.contains(ns, key) {
            return Ok(()); // absent — nothing to persist
        }
        self.append(ns, key.len() as u8 | TOMBSTONE, key, &[])?;
        self.mirror.remove(ns, key);
        Ok(())
    }

    fn for_each(&self, ns: u8, f: &mut dyn FnMut(&[u8], &[u8])) {
        self.mirror.for_each(ns, f);
    }
}
