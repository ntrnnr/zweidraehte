//! Shared-memory handle used to persist device state across DUT
//! respawns. Used by both the parent and child processes; the socket
//! framing that goes with it lives in [`super::framing`], and the DUT's
//! link layer over that socket in `dut::link`.
//!
//! # Layout
//!
//! ```text
//! [magic: 4B "KNXS"] [len: 2B LE] [postcard payload ...]
//! ... padding ...
//! [seq region: last 256 bytes — secure DUT only]
//! ```
//!
//! The postcard payload is a `SystemBDutConfig` or
//! `SystemBSecureDutConfig` (see `systemb_stack.rs` /
//! `fixture_common.rs`). The 256-byte tail region backs the secure
//! DUT's per-peer sequence-number storage.
//!
//! # Who writes what
//!
//! **The payload is opaque to the parent.** It creates the region
//! zeroed and, for `TestStep::FullReset`, zeroes it again with
//! [`SharedMemory::blank`]; the DUT recognises a missing magic as
//! "blank flash" and seeds its own factory defaults
//! (`dut::common::load_or_seed_snapshot`). That is why this module can
//! be generic over `T: Serialize` and name no device type at all —
//! and in turn why the parent half of the crate compiles without the
//! device stack. Do not reintroduce a typed write on the parent side.

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

/// Magic bytes at the start of the shared memory region.
const SHM_MAGIC: [u8; 4] = *b"KNXS";
/// Header: 4 bytes magic + 2 bytes payload length.
const SHM_HEADER_SIZE: usize = 6;

/// Size of the shared memory region (64 KiB).
///
/// Generous for postcard-serialized state (typically ~2-4 KiB).
pub const SHM_SIZE: usize = 64 * 1024;

/// RAII wrapper around an anonymous, mmap-backed shared memory region.
///
/// On Linux this is backed by `O_TMPFILE` (or a temp file that's been
/// unlinked); on macOS it's backed by an unlinked temp file in
/// `TMPDIR`. Either way the file has no path on disk — the fd is the
/// only handle, and dropping it releases the storage.
///
/// The region stores postcard-serialized device state:
///
/// ```text
/// [magic: 4B "KNXS"] [len: 2B LE] [postcard payload ...]
/// ```
///
/// When the magic doesn't match, the region is uninitialized.
pub struct SharedMemory {
    fd: std::os::fd::OwnedFd,
    ptr: *mut u8,
    size: usize,
}

// SAFETY: The shared memory region is only accessed by one process at a
// time (parent writes before spawn, child has exclusive access while
// running, parent reads after child dies).
unsafe impl Send for SharedMemory {}

impl SharedMemory {
    /// Create a new anonymous shared memory region.
    pub fn create() -> io::Result<Self> {
        use nix::sys::mman;
        use std::os::fd::OwnedFd;

        let size = SHM_SIZE;

        // tempfile::tempfile() is anonymous and cross-platform: Linux
        // uses O_TMPFILE when available, macOS creates+unlinks under
        // TMPDIR. Either way we get an OwnedFd with no on-disk name.
        let file = tempfile::tempfile()?;
        file.set_len(size as u64)?;
        let fd: OwnedFd = file.into();

        let ptr = unsafe {
            mman::mmap(
                None,
                std::num::NonZeroUsize::new(size).expect("non-zero size"),
                mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
                mman::MapFlags::MAP_SHARED,
                &fd,
                0,
            )
            .map_err(io::Error::other)?
        };

        Ok(Self { fd, ptr: ptr.as_ptr() as *mut u8, size })
    }

    /// Map an existing shared memory region from a raw fd.
    ///
    /// # Safety
    ///
    /// The caller must ensure `fd` is a valid, open file descriptor
    /// referring to a shared memory region of at least `SHM_SIZE` bytes.
    /// Ownership of the fd is transferred to this struct.
    pub unsafe fn from_raw_fd(fd: RawFd) -> io::Result<Self> {
        use nix::sys::mman;
        use std::os::fd::OwnedFd;

        let size = SHM_SIZE;
        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };

        let ptr = unsafe {
            mman::mmap(
                None,
                std::num::NonZeroUsize::new(size).expect("non-zero size"),
                mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
                mman::MapFlags::MAP_SHARED,
                &owned_fd,
                0,
            )
            .map_err(io::Error::other)?
        };

        Ok(Self { fd: owned_fd, ptr: ptr.as_ptr() as *mut u8, size })
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: ptr is valid for `size` bytes; synchronization is
        // handled by process lifecycle (no concurrent access).
        unsafe { std::slice::from_raw_parts(self.ptr, self.size) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: ptr is valid for `size` bytes; we have exclusive access.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.size) }
    }

    /// Write a postcard-serialized blob into shared memory.
    pub fn write_state<T: serde::Serialize>(&mut self, state: &T) -> io::Result<()> {
        let buf = self.as_mut_slice();

        buf[..4].copy_from_slice(&SHM_MAGIC);

        let payload = postcard::to_slice(state, &mut buf[SHM_HEADER_SIZE..])
            .map_err(|e| io::Error::other(format!("postcard serialize: {e}")))?;
        let len = payload.len();

        buf[4..6].copy_from_slice(&(len as u16).to_le_bytes());

        Ok(())
    }

    /// Read and deserialize state from shared memory.
    ///
    /// Returns `None` if the magic doesn't match (uninitialized).
    pub fn read_state<T: for<'de> serde::Deserialize<'de>>(&self) -> io::Result<Option<T>> {
        let buf = self.as_slice();

        if buf[..4] != SHM_MAGIC {
            return Ok(None);
        }

        let len = u16::from_le_bytes([buf[4], buf[5]]) as usize;
        if len == 0 || SHM_HEADER_SIZE + len > self.size {
            return Ok(None);
        }

        let payload = &buf[SHM_HEADER_SIZE..SHM_HEADER_SIZE + len];
        let state = postcard::from_bytes(payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("postcard deserialize: {e}")))?;
        Ok(Some(state))
    }

    /// Raw file descriptor (for passing to a child process).
    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Raw pointer to the sequence-number region at the end of the
    /// shared memory. See `ShmSeqStorage` for the layout. The caller
    /// must ensure the pointer is only used while this `SharedMemory`
    /// is alive.
    pub fn seq_region_ptr(&self) -> *mut u8 {
        unsafe { self.ptr.add(self.size - 256) }
    }

    /// Zero the whole region — payload, magic and seq tail alike.
    ///
    /// This is the parent's factory reset (`TestStep::FullReset`): the
    /// magic goes away, so the next DUT to map the region reads it as
    /// blank flash and writes its own defaults. Zeroing the tail in the
    /// same stroke is what a secure DUT needs anyway — it starts with
    /// fresh per-peer counters instead of replay-rejecting the
    /// harness's first secure frame against a stale tool seq — so the
    /// two operations that used to be separate are one.
    ///
    /// A freshly [`create`](Self::create)d region is already zeroed, so
    /// this is only needed for reuse.
    pub fn blank(&mut self) {
        self.as_mut_slice().fill(0);
    }

    /// Clear the `FD_CLOEXEC` flag so the fd is inherited by the
    /// child. Called just before `Command::spawn()`.
    pub fn clear_cloexec(&self) -> io::Result<()> {
        use nix::fcntl;
        let raw = self.fd.as_raw_fd();
        let flags = fcntl::fcntl(raw, fcntl::FcntlArg::F_GETFD).map_err(io::Error::other)?;
        let mut fd_flags = nix::fcntl::FdFlag::from_bits_truncate(flags);
        fd_flags.remove(nix::fcntl::FdFlag::FD_CLOEXEC);
        fcntl::fcntl(raw, fcntl::FcntlArg::F_SETFD(fd_flags)).map_err(io::Error::other)?;
        Ok(())
    }
}

impl Drop for SharedMemory {
    fn drop(&mut self) {
        unsafe {
            let _ =
                nix::sys::mman::munmap(std::ptr::NonNull::new(self.ptr as *mut _).expect("non-null ptr"), self.size);
        }
    }
}
