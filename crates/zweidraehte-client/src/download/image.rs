//! The assembled device image.
//!
//! An ETS download writes *images*: byte content assembled from the
//! project configuration before any bus traffic happens.
//! [`DeviceImage`] is that assembly; the
//! [`Instruction::WriteImage`](super::Instruction::WriteImage) and
//! `WriteRelImage` steps of a procedure pull their bytes from it. The
//! table blobs the image holds are built by the codings in
//! [`super::table_coding`].

use std::collections::BTreeMap;

use crate::error::{Error, Result};

// ============================================================================
// Device image
// ============================================================================

/// The bytes a download writes, assembled before any bus traffic.
///
/// Two halves, because the two management models place data
/// differently:
///
/// - **Absolute regions** (System 7): the product fixes the address,
///   so content is keyed by it.
/// - **Relative content** (System B): the *device* picks the address
///   during load, so content is keyed by the interface object that
///   owns it, and the interpreter pairs it with the base the device
///   reports through `PID_TABLE_REFERENCE`.
#[derive(Debug, Clone, Default)]
pub struct DeviceImage {
    /// Start address → bytes; regions never overlap.
    regions: BTreeMap<u16, Vec<u8>>,
    /// Interface object index → the bytes that object's relative
    /// segment should hold.
    relative: BTreeMap<u8, Vec<u8>>,
}

impl DeviceImage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a region. Rejects overlaps — two sources writing the same
    /// address would mean the compile step produced garbage.
    pub fn insert(&mut self, address: u16, bytes: Vec<u8>) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }

        let end = address as usize + bytes.len();

        if end > 0x1_0000 {
            return Err(Error::DownloadConfig("image region extends past the 16-bit address space"));
        }

        // The predecessor (region starting at or before `address`) and
        // the successor both must not intrude.
        if let Some((&prev_start, prev)) = self.regions.range(..=address).next_back()
            && (prev_start as usize + prev.len()) > address as usize
        {
            return Err(Error::DownloadConfig("image regions overlap"));
        }

        if let Some((&next_start, _)) = self.regions.range(address..).next()
            && (next_start as usize) < end
        {
            return Err(Error::DownloadConfig("image regions overlap"));
        }

        self.regions.insert(address, bytes);

        Ok(())
    }

    /// The bytes for `[address, address + length)`, if a single region
    /// covers that range. A `WriteImage` step may address a region's
    /// prefix (master-data templates carry clamp-to-blob sizes), so
    /// `length` is clipped to what the region holds.
    pub fn slice(&self, address: u16, length: u16) -> Option<&[u8]> {
        let (&start, bytes) = self.regions.range(..=address).next_back()?;
        let offset = (address - start) as usize;

        if offset >= bytes.len() {
            return None;
        }

        let available = bytes.len() - offset;
        let take = (length as usize).min(available);

        Some(&bytes[offset..offset + take])
    }

    /// Iterate over all regions (for diagnostics / tests).
    pub fn regions(&self) -> impl Iterator<Item = (u16, &[u8])> {
        self.regions.iter().map(|(&addr, bytes)| (addr, bytes.as_slice()))
    }

    /// Set the content of an interface object's relative segment.
    pub fn insert_relative(&mut self, obj_idx: u8, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }

        self.relative.insert(obj_idx, bytes);
    }

    /// The content compiled for an interface object's relative
    /// segment, if any.
    pub fn relative(&self, obj_idx: u8) -> Option<&[u8]> {
        self.relative.get(&obj_idx).map(|bytes| bytes.as_slice())
    }

    /// Iterate over relative content (for diagnostics / tests).
    pub fn relative_objects(&self) -> impl Iterator<Item = (u8, &[u8])> {
        self.relative.iter().map(|(&idx, bytes)| (idx, bytes.as_slice()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_content_is_keyed_by_interface_object() {
        let mut image = DeviceImage::new();
        image.insert_relative(1, vec![1, 2, 3]);
        image.insert_relative(2, vec![]);

        assert_eq!(image.relative(1), Some(&[1, 2, 3][..]));
        assert_eq!(image.relative(2), None, "empty content is not stored");
        assert_eq!(image.relative_objects().count(), 1);
    }

    #[test]
    fn image_rejects_overlaps_and_slices() {
        let mut image = DeviceImage::new();
        image.insert(0x4000, vec![1, 2, 3, 4]).expect("empty image accepts");
        image.insert(0x4004, vec![5, 6]).expect("adjacent is not overlapping");
        assert!(image.insert(0x4003, vec![9]).is_err(), "tail overlap");
        assert!(image.insert(0x3FFF, vec![9, 9]).is_err(), "head overlap");

        assert_eq!(image.slice(0x4000, 4), Some(&[1, 2, 3, 4][..]));
        assert_eq!(image.slice(0x4002, 2), Some(&[3, 4][..]));
        // Clamp-to-blob: a template's huge size takes what's there.
        assert_eq!(image.slice(0x4004, 1000), Some(&[5, 6][..]));
        assert_eq!(image.slice(0x5000, 1), None);
    }
}
