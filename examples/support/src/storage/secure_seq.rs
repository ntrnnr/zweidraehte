//! Host-side sequence-number / SIAT storage for Linux Data-Secure devices.
//!
//! A KNX Data Secure (or IP Secure) device must persist its sequence-number
//! state — the sending counter, the tool-access counter, and the Security
//! Individual Address Table (SIAT, one *Last Valid SeqNr* per secure sender,
//! 03/05/01 Resources §6.3.8) — across restarts, or a reboot would re-accept
//! frames the device has already seen (replay). On the embedded targets that
//! store lives in flash/FRAM; on a Linux host there was no equivalent.
//!
//! This module is that equivalent: a plain **file-backed** [`ByteIo`] under
//! the same [`PackedSeqStore`] / [`SiatStore`] the FRAM and conformance
//! shared-memory devices use. It is the host twin of the conformance harness's
//! `ShmRegion` (which mmaps a memfd for cross-process visibility); here we want
//! plain on-disk durability instead, so we back the region with a fixed-size
//! file and address it with `pread`/`pwrite`.
//!
//! # Why not the storage task / config store
//!
//! The secure layer builders bound only `D::Storage: HasSeqStore` — not
//! `HasConfigStore` or `StorageHooks` — so the seq store is the *only* piece
//! that has to ride on the stack. Config persistence on these host targets
//! stays out-of-band through [`JsonStorage`](super::JsonStorage), exactly as
//! the insecure Linux device does, and the storage task is not spawned. The
//! IP-Secure multicast-timer watermark (03/08/09 §2.2.4.2) is likewise not
//! persisted here: its [`StorageHooks`] hooks keep their no-op defaults, so the
//! watermark starts at 0 after a restart and the timer re-acquires from the
//! group — acceptable, and it keeps the host store to a single file.

use std::cell::RefCell;
use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::path::Path;

use zweidraehte_device::restart::EraseCode;
use zweidraehte_device::storage::backends::{ByteIo, PackedSeqStore, region_len};
use zweidraehte_device::storage::region::FramSiatRegion;
use zweidraehte_device::storage::{HasSeqStore, SiatStore, StorageHooks};

// ============================================================================
// Sizing
// ============================================================================

/// SIAT capacity: the number of distinct secure senders the device tracks a
/// *Last Valid SeqNr* for. Matches the RP2040 / STM32 secure light switches
/// (`SIAT_SIZE = 32`).
pub const SIAT_SLOTS: usize = 32;

/// Peer-table capacity of the packed layout. Sized to `SIAT_SLOTS` so the
/// on-file table can hold every SIAT entry — the overflow / silent-drop path
/// is unreachable.
const PEER_SLOTS: usize = SIAT_SLOTS;

/// Bytes the packed layout occupies for `PEER_SLOTS` peers plus the header.
/// The backing file is pre-sized to exactly this, and the bound region's
/// `SIZE` must cover it (checked by `PackedSeqStore` at compile time).
const REGION_SIZE: usize = region_len(PEER_SLOTS);

// ============================================================================
// File-backed ByteIo
// ============================================================================

/// A [`ByteIo`] over a fixed-size regular file, addressed with `pread`/`pwrite`
/// ([`FileExt::read_at`] / [`FileExt::write_at`]).
///
/// The file is created and zero-filled to [`REGION_SIZE`] on first open. The
/// packed layout treats an all-zero region as "blank" (no magic yet), so a
/// fresh file boots the [`SiatStore`] to defaults, matching how the FRAM and
/// shared-memory stores rely on a zeroed medium.
pub struct FileByteIo {
    file: std::fs::File,
}

impl FileByteIo {
    /// Open (creating if absent) the seq file at `path`, ensuring it is at
    /// least [`REGION_SIZE`] bytes so every layout offset is addressable.
    ///
    /// A newly created file is zero-length; `set_len` grows it with zero
    /// bytes, which is exactly the blank-medium state the layout expects.
    /// An existing file keeps its contents (the persisted sequence state).
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).create(true).open(path)?;
        if file.metadata()?.len() < REGION_SIZE as u64 {
            file.set_len(REGION_SIZE as u64)?;
        }
        Ok(Self { file })
    }
}

impl ByteIo for FileByteIo {
    type Error = std::io::Error;

    fn read_at(&self, off: u32, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.file.read_exact_at(buf, off as u64)
    }

    fn write_at(&mut self, off: u32, data: &[u8]) -> Result<(), Self::Error> {
        self.file.write_all_at(data, off as u64)?;
        // Flush the write to disk so a crash between sends can't lose the
        // persisted counter and open a replay window on the next boot.
        self.file.sync_data()
    }
}

// ============================================================================
// Store types
// ============================================================================

/// Region marker binding the write-in-place `"KNXR"` layout to the file,
/// sized to the packed layout. It owns the whole file (offset 0), so — like
/// the conformance shared-memory region — it never appears in a `REGIONS`
/// array; `PackedSeqStore::new` places the layout at offset 0.
type LinuxSiatRegion = FramSiatRegion<REGION_SIZE, PEER_SLOTS>;

/// Packed sequence/SIAT storage over the file.
type LinuxSeqStorage = PackedSeqStore<FileByteIo, LinuxSiatRegion, PEER_SLOTS>;

/// The SIAT view over the file store. `K = 1` writes the sending counter
/// through on every send (no skip-ahead watermark): a host filesystem has no
/// wear budget to protect, so exact per-send persistence is both cheap and the
/// safest choice against replay.
pub type LinuxSiatStore = SiatStore<LinuxSeqStorage, SIAT_SLOTS, 1>;

// ============================================================================
// Stores struct
// ============================================================================

/// The device's persistent secure storage — a single file-backed SIAT store.
///
/// This is the host twin of the embedded stores structs (`SecureIpStorage`
/// etc.) and of the conformance harness's `ConformanceSecureStorage`: it
/// exposes the seq store through [`HasSeqStore`] (how the secure stack reaches
/// it) and performs the storage-side half of a factory-reset erase through
/// [`StorageHooks`]. Config persistence and the mc_timer watermark are handled
/// elsewhere (see the module docs), so only `seq` lives here.
pub struct LinuxSecureSeqStorage {
    seq: RefCell<LinuxSiatStore>,
}

impl LinuxSecureSeqStorage {
    /// Boot the SIAT store from the file at `path`, reconstructing the SIAT and
    /// sequence counters from its current contents (defaults for a fresh file).
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let io = FileByteIo::open(path)?;
        // `SiatStore::boot` reads through the packed layout; on a `FileByteIo`
        // the only failure is I/O, surfaced here as `io::Error`.
        let seq = SiatStore::boot(PackedSeqStore::new(io)).map_err(std::io::Error::other)?;
        Ok(Self { seq: RefCell::new(seq) })
    }
}

impl HasSeqStore for LinuxSecureSeqStorage {
    type Seq = LinuxSiatStore;

    fn seq_store(&self) -> &RefCell<LinuxSiatStore> {
        &self.seq
    }
}

impl StorageHooks for LinuxSecureSeqStorage {
    fn erase(&self, code: EraseCode) {
        // The seq-carrying half of a restart erase: on a factory reset, re-init
        // the sending counter if it is near exhaustion (03/05/01 §6.1.4). The
        // mc_timer no-op defaults on `StorageHooks` stand — it is not persisted.
        zweidraehte_device::storage::seq::erase_seq_on_factory_reset(&mut *self.seq.borrow_mut(), code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zweidraehte_device::storage::SequenceNumberStorage;

    /// A unique temp path per test, avoiding a `tempfile` dependency. The
    /// process id keeps concurrent test binaries from colliding.
    fn temp_path(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("zw-support-secure-seq-{}-{}", std::process::id(), tag));
        p
    }

    #[test]
    fn file_byte_io_round_trips() {
        let path = temp_path("byteio");
        let _ = std::fs::remove_file(&path);

        {
            let mut io = FileByteIo::open(&path).expect("open");
            io.write_at(4, &[1, 2, 3, 4, 5, 6]).expect("write");
            let mut buf = [0u8; 6];
            io.read_at(4, &mut buf).expect("read");
            assert_eq!(buf, [1, 2, 3, 4, 5, 6]);
        }

        // The file is sized to hold the whole packed layout.
        assert!(std::fs::metadata(&path).expect("stat").len() >= REGION_SIZE as u64);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn sending_seqnr_survives_reopen() {
        let path = temp_path("durable");
        let _ = std::fs::remove_file(&path);

        // First boot: a fresh file starts at the default sending counter, then
        // we advance it and let the write flush to disk.
        {
            let storage = LinuxSecureSeqStorage::open(&path).expect("first open");
            let mut seq = storage.seq.borrow_mut();
            seq.save_sending_seq(&[0, 0, 0, 0, 0x12, 0x34]).expect("save sending");
        }

        // Second boot from the same file must recover the persisted counter —
        // the whole point of the store (cross-restart replay protection). The
        // store resumes from the durable *watermark*, which the `K = 1`
        // batching advanced one past the last saved value (0x1234 → 0x1235) so
        // a reboot can never reissue an already-emitted counter. The property
        // that matters: the reloaded value is ≥ what we saved, never reset to
        // the tiny default.
        {
            let storage = LinuxSecureSeqStorage::open(&path).expect("reopen");
            let seq = storage.seq.borrow();
            assert_eq!(seq.load_sending_seq().expect("load sending"), [0, 0, 0, 0, 0x12, 0x35]);
        }

        std::fs::remove_file(&path).ok();
    }
}
