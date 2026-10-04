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
//! the same [`PackedSeqStore`] the FRAM and conformance shared-memory devices
//! use. It is the host twin of the conformance harness's
//! `ShmRegion` (which mmaps a memfd for cross-process visibility); here we want
//! plain on-disk durability instead, so we back the region with a fixed-size
//! file and address it with `pread`/`pwrite`.
//!
//! # How it reaches the stack
//!
//! [`open_siat_store`] yields the bare store; the device pairs it with a
//! [`LinuxConfigNv`](super::LinuxConfigNv) config backend inside the
//! framework's [`SecureRoutingStorage`](zweidraehte_device::storage::SecureRoutingStorage)
//! composite alongside a separate watermark file. The composite supplies
//! `HasSeqStore` (how the secure layers reach the SIAT) and `DeviceStorage`
//! (config persistence and the factory-reset erase). That one
//! handle rides on the stack, so the shared `storage_task` drives config
//! persistence and restart handling here exactly as it does on the embedded
//! targets.
//!
//! The IP Secure multicast-timer watermark (03/08/09 §2.2.4.2) is kept
//! in its own file. The old packed field is read only for migration.

use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::path::Path;

use zweidraehte_device::storage::{ByteIo, ByteMcTimer, PackedSeqStore, SEQUENCE_MAGIC};

// ============================================================================
// Sizing
// ============================================================================

/// SIAT capacity: the number of distinct secure senders the device tracks a
/// *Last Valid SeqNr* for. Matches the RP2040 / STM32 secure light switches
/// (`SIAT_SIZE = 32`).
pub const SIAT_SLOTS: usize = 32;

/// Bytes the packed layout occupies for `SIAT_SLOTS` elements, the header
/// and the legacy watermark field. The backing file retains that field so
/// a firmware update can move its value to the independent store.
const REGION_SIZE: usize = LinuxSiatStore::REGION_LEN;

// ============================================================================
// File-backed ByteIo
// ============================================================================

/// A [`ByteIo`] over a fixed-size regular file, addressed with `pread`/`pwrite`
/// ([`FileExt::read_at`] / [`FileExt::write_at`]).
///
/// The file is created and zero-filled to its size on first open. The
/// stores over it read a region without their magic as a fresh device, so
/// a new file starts from factory defaults. Shared by the sequence/SIAT
/// store and the config image.
pub struct FileByteIo {
    file: std::fs::File,
}

impl FileByteIo {
    /// Open (creating if absent) the file at `path`, ensuring it is at
    /// least `len` bytes so every layout offset is addressable.
    ///
    /// A newly created file is zero-length; `set_len` grows it with zero
    /// bytes, which is exactly the blank-medium state the layouts expect.
    /// An existing file keeps its contents.
    pub fn open(path: impl AsRef<Path>, len: u64) -> std::io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;

        if file.metadata()?.len() < len {
            file.set_len(len)?;
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

/// The packed sequence/SIAT store over the file. It writes every change
/// through, so each send's counter is durable before the frame leaves. It
/// retains its old mc_timer field for one-time migration.
pub type LinuxSiatStore = PackedSeqStore<FileByteIo, SIAT_SLOTS, true>;

/// The independent file-backed IP Secure multicast-timer store.
pub type LinuxMcTimerStore = ByteMcTimer<FileByteIo>;

// ============================================================================
// Constructor
// ============================================================================

/// Open the SIAT store over the file at `path` (defaults for a fresh file).
///
/// The returned store is the `S` half of the framework's
/// [`SecureRoutingStorage`](zweidraehte_device::storage::SecureRoutingStorage) composite:
/// pair it with a config backend so the device's whole persistent state — the
/// ETS configuration *and* the replay-protection counters — rides on the
/// stack behind one handle.
pub fn open_siat_store(path: impl AsRef<Path>) -> std::io::Result<LinuxSiatStore> {
    let io = FileByteIo::open(path, REGION_SIZE as u64)?;
    // The store owns the whole file, from offset 0, under the `KNXR` magic.
    Ok(PackedSeqStore::new(io, 0, SEQUENCE_MAGIC))
}

/// Open a separate file for the IP Secure multicast-timer watermark.
pub fn open_mc_timer_store(path: impl AsRef<Path>) -> std::io::Result<LinuxMcTimerStore> {
    let io = FileByteIo::open(path, ByteMcTimer::<FileByteIo>::REGION_LEN as u64)?;
    Ok(ByteMcTimer::new(io, 0))
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
            let mut io = FileByteIo::open(&path, REGION_SIZE as u64).expect("open");
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
    fn mc_timer_file_round_trips_independently() {
        use zweidraehte_device::storage::McTimerStore;

        let path = temp_path("mc-timer");
        let _ = std::fs::remove_file(&path);

        let mut store = open_mc_timer_store(&path).expect("open watermark file");
        assert_eq!(store.load().expect("read fresh"), None);
        store.save(7_200_000).expect("save watermark");
        drop(store);

        let mut store = open_mc_timer_store(&path).expect("reopen watermark file");
        assert_eq!(store.load().expect("read persisted"), Some(7_200_000));
        store.clear().expect("clear watermark");
        drop(store);

        assert_eq!(open_mc_timer_store(&path).expect("reopen cleared file").load().expect("read cleared"), None);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn sending_seqnr_survives_reopen() {
        let path = temp_path("durable");
        let _ = std::fs::remove_file(&path);

        // First boot: a fresh file starts at the default sending counter, then
        // we advance it and let the write flush to disk.
        {
            let mut seq = open_siat_store(&path).expect("first open");
            seq.save_sending_seq(&[0, 0, 0, 0, 0x12, 0x34]).expect("save sending");
        }

        // Second boot from the same file must recover the persisted counter
        // exactly — the whole point of the store (cross-restart replay
        // protection). The secure layer saves the *next* value to use, so the
        // exact value is already one past the last frame sent.
        {
            let seq = open_siat_store(&path).expect("reopen");
            assert_eq!(seq.load_sending_seq().expect("load sending"), [0, 0, 0, 0, 0x12, 0x34]);
        }

        std::fs::remove_file(&path).ok();
    }
}
