//! The fixed-capacity security tables (03/05/01 §6.3.6–§6.3.10).
//!
//! One const-generic container serves the group key table (18-octet entries),
//! the point-to-point key table (20) and the group-object security flags (1).
//! It owns inline storage only — no allocator, no backend — so the same type
//! is usable from a full device stack, a polling BCU-era stack, and a host
//! test.

use serde::{Deserialize, Serialize};

use crate::properties::PropertyError;

/// Fixed-capacity table for security data (group keys, GO security flags).
///
/// Each entry is `ENTRY_SIZE` bytes. Up to `N` entries can be stored.
/// This type is `no_alloc`-compatible — all storage is inline.
///
/// Written by ETS during configuration (via the load state machine),
/// read by the S-AL at runtime for key lookup and GO flag checks.
///
/// # Key redaction
///
/// The `Debug` impl prints entry counts only and never the raw entry bytes
/// to prevent AES key material from appearing in logs. The `Serialize` and
/// `Deserialize` impls are unaffected — persistence requires real bytes.
#[serde_with::serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct SecurityTable<const N: usize, const ENTRY_SIZE: usize> {
    /// Entry data. Only entries `0..count` are valid.
    #[serde_as(as = "[[_; ENTRY_SIZE]; N]")]
    pub(crate) data: [[u8; ENTRY_SIZE]; N],
    count: u16,
}

impl<const N: usize, const ENTRY_SIZE: usize> core::fmt::Debug for SecurityTable<N, ENTRY_SIZE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Entry data is never shown — it may contain AES key material.
        f.debug_struct("SecurityTable")
            .field("capacity", &N)
            .field("entry_size", &ENTRY_SIZE)
            .field("count", &self.count)
            .field("data", &"[REDACTED]")
            .finish()
    }
}

impl<const N: usize, const ENTRY_SIZE: usize> Default for SecurityTable<N, ENTRY_SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const ENTRY_SIZE: usize> SecurityTable<N, ENTRY_SIZE> {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self { data: [[0u8; ENTRY_SIZE]; N], count: 0 }
    }

    /// Create a table from pre-built entry data and a count.
    ///
    /// Useful for compile-time construction in `knx_stack_config!`.
    /// Entries `0..count` are considered valid; the rest are zero-filled.
    pub const fn from_entries(data: [[u8; ENTRY_SIZE]; N], count: u16) -> Self {
        Self { data, count }
    }

    /// Current number of entries.
    pub fn count(&self) -> u16 {
        self.count
    }

    /// Get entry at 0-based index, or `None` if out of range.
    pub fn get(&self, index: u16) -> Option<&[u8; ENTRY_SIZE]> {
        if index < self.count { Some(&self.data[index as usize]) } else { None }
    }

    /// Read a range of entries into a byte buffer.
    ///
    /// `start` is 0-based. Returns the number of bytes written, or an
    /// error if `start` is out of range or `buf` is too small.
    pub fn read_entries(&self, start: u16, count: u16, buf: &mut [u8]) -> Result<usize, PropertyError> {
        if start >= self.count {
            return Err(PropertyError::InvalidStartIndex);
        }
        let end = ((start + count) as usize).min(self.count as usize);
        let actual = end - start as usize;
        let byte_count = actual * ENTRY_SIZE;
        if buf.len() < byte_count {
            return Err(PropertyError::BufferTooSmall);
        }
        for (i, idx) in (start as usize..end).enumerate() {
            let offset = i * ENTRY_SIZE;
            buf[offset..offset + ENTRY_SIZE].copy_from_slice(&self.data[idx]);
        }
        Ok(byte_count)
    }

    /// Write entries from a byte buffer, replacing existing data.
    ///
    /// `start` is 0-based. `data` must be a multiple of `ENTRY_SIZE`.
    /// Validates that the write stays within table capacity and that
    /// the data length is aligned to the entry size.
    pub fn write_entries(&mut self, start: u16, data: &[u8]) -> Result<(), PropertyError> {
        if data.is_empty() {
            return Ok(()); // Nothing to write.
        }
        if !data.len().is_multiple_of(ENTRY_SIZE) {
            return Err(PropertyError::TypeMismatch);
        }
        let entry_count = data.len() / ENTRY_SIZE;
        let end = start as usize + entry_count;
        if end > N {
            return Err(PropertyError::InvalidStartIndex);
        }
        for i in 0..entry_count {
            let src_offset = i * ENTRY_SIZE;
            self.data[start as usize + i].copy_from_slice(&data[src_offset..src_offset + ENTRY_SIZE]);
        }
        // Update count if we wrote past the current end.
        if end as u16 > self.count {
            self.count = end as u16;
        }
        Ok(())
    }

    /// Clear all entries (reset count to 0).
    ///
    /// Also zeroes the backing storage: entries hold key material, and
    /// the full `data` array — not just the active prefix — is what the
    /// persisted config serializes. Stale keys must not survive a clear.
    pub fn clear(&mut self) {
        self.data = [[0u8; ENTRY_SIZE]; N];
        self.count = 0;
    }

    /// Set the element count directly (for load state machine use).
    ///
    /// Zeroes any entries dropped by a shrinking count — same key-material
    /// rationale as [`clear()`](Self::clear): the serialized config carries
    /// the whole `data` array, so truncated entries must not leak old keys
    /// into storage.
    pub fn set_count(&mut self, count: u16) {
        let count = count.min(N as u16);
        for entry in self.data[count as usize..].iter_mut() {
            *entry = [0u8; ENTRY_SIZE];
        }
        self.count = count;
    }

    /// View active entries as a flat byte slice.
    ///
    /// Returns `count * ENTRY_SIZE` bytes covering entries `0..count`.
    pub fn as_flat_bytes(&self) -> &[u8] {
        self.data[..self.count as usize].as_flattened()
    }

    // ========================================================================
    // Property-element addressing (03/05/01 §6.3, 03/03/07 property services)
    // ========================================================================
    //
    // Interface-object array properties are addressed one-based, and element 0
    // is the element-count probe rather than data. Every consumer of these
    // tables — the full stack's Security augment, a BCU-era property router,
    // and a management client checking its own writes — needs that same rule,
    // so it lives with the table rather than being re-derived per property
    // handler.

    /// Read by one-based property element index, answering the `start = 0`
    /// probe with the two-octet element count.
    ///
    /// Returns the number of bytes written into `buf`.
    pub fn read_elements(&self, start_idx: u16, count: u16, buf: &mut [u8]) -> Result<usize, PropertyError> {
        if start_idx == 0 {
            if buf.len() < 2 {
                return Err(PropertyError::BufferTooSmall);
            }
            buf[..2].copy_from_slice(&self.count().to_be_bytes());
            return Ok(2);
        }
        self.read_entries(start_idx - 1, count, buf)
    }

    /// Write by one-based property element index.
    ///
    /// A write at element 0 sets the element count: zero clears the table,
    /// a non-zero value pre-allocates so that subsequent entry writes land
    /// inside the valid range.
    pub fn write_elements(&mut self, start_idx: u16, data: &[u8]) -> Result<(), PropertyError> {
        if start_idx == 0 {
            if data.len() < 2 {
                return Err(PropertyError::BufferTooSmall);
            }
            let new_count = u16::from_be_bytes([data[0], data[1]]);
            if new_count == 0 {
                self.clear();
            } else {
                self.set_count(new_count);
            }
            return Ok(());
        }
        self.write_entries(start_idx - 1, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Truncating via `set_count` must zero the dropped entries — the
    /// persisted config serializes the whole backing array, so stale
    /// key material above the count would otherwise reach storage.
    #[test]
    fn set_count_zeroes_truncated_entries() {
        let mut table: SecurityTable<4, 18> = SecurityTable::new();
        let key_a = [0xAA; 18];
        let key_b = [0xBB; 18];
        let mut data = [0u8; 36];
        data[..18].copy_from_slice(&key_a);
        data[18..].copy_from_slice(&key_b);
        table.write_entries(0, &data).expect("two entries fit in a 4-slot table");
        assert_eq!(table.count(), 2);

        table.set_count(1);
        assert_eq!(table.count(), 1);
        assert_eq!(table.get(0), Some(&key_a));
        // The dropped entry must be gone from the backing array, not
        // just hidden behind the count.
        assert_eq!(table.data[1], [0u8; 18]);
    }

    /// `clear` must zero the whole backing array, same rationale.
    #[test]
    fn clear_zeroes_backing_array() {
        let mut table: SecurityTable<2, 18> = SecurityTable::new();
        table.write_entries(0, &[0xCC; 18]).expect("one entry fits");
        table.clear();
        assert_eq!(table.count(), 0);
        assert_eq!(table.data, [[0u8; 18]; 2]);
    }

    /// `set_count` clamps to capacity and zeroing stays in bounds.
    #[test]
    fn set_count_clamps_to_capacity() {
        let mut table: SecurityTable<2, 8> = SecurityTable::new();
        table.set_count(100);
        assert_eq!(table.count(), 2);
    }

    #[test]
    fn element_zero_is_the_count_probe() {
        let mut table: SecurityTable<4, 2> = SecurityTable::new();
        table.write_elements(1, &[0xAA, 0xBB]).expect("entry write fits");

        let mut buf = [0u8; 8];
        assert_eq!(table.read_elements(0, 1, &mut buf).expect("count probe"), 2);
        assert_eq!(&buf[..2], &[0x00, 0x01]);
    }

    #[test]
    fn element_indices_are_one_based() {
        let mut table: SecurityTable<4, 2> = SecurityTable::new();
        table.write_elements(1, &[0x11, 0x22]).expect("first element");
        table.write_elements(2, &[0x33, 0x44]).expect("second element");

        let mut buf = [0u8; 8];
        let len = table.read_elements(1, 2, &mut buf).expect("read both");
        assert_eq!(&buf[..len], &[0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn writing_count_zero_clears_the_table() {
        let mut table: SecurityTable<4, 2> = SecurityTable::new();
        table.write_elements(1, &[0x11, 0x22]).expect("first element");
        table.write_elements(0, &[0x00, 0x00]).expect("count write");

        assert_eq!(table.count(), 0);
        // Key material must not survive the clear, not just be hidden by the
        // count — the persisted config serializes the whole array.
        assert_eq!(table.data[0], [0u8; 2]);
    }

    #[test]
    fn shrinking_the_count_zeroes_the_dropped_entries() {
        let mut table: SecurityTable<4, 2> = SecurityTable::new();
        table.write_elements(1, &[0x11, 0x22, 0x33, 0x44]).expect("two elements");
        table.write_elements(0, &[0x00, 0x01]).expect("shrink to one");

        assert_eq!(table.count(), 1);
        assert_eq!(table.data[1], [0u8; 2]);
    }
}
