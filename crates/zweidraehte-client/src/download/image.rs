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

    /// The sub-slices of `[address, address + length)` the image
    /// covers, in address order.
    ///
    /// A mask template's `WriteMem` window is a fixed span of device
    /// memory (BCU1's Load-all writes "230 bytes at 0119h" no matter
    /// the product); the image may cover it with several regions, or
    /// only partially. The download writes exactly the covered parts —
    /// which is also what ETS does, since its image is seeded from the
    /// same product data.
    pub fn covered(&self, address: u16, length: u16) -> impl Iterator<Item = (u16, &[u8])> + '_ {
        let start = usize::from(address);
        let end = start + usize::from(length);
        self.regions.iter().filter_map(move |(&region_start, bytes)| {
            let region_start = usize::from(region_start);
            let overlap_start = region_start.max(start);
            let overlap_end = (region_start + bytes.len()).min(end);
            (overlap_start < overlap_end)
                .then(|| (overlap_start as u16, &bytes[overlap_start - region_start..overlap_end - region_start]))
        })
    }

    /// Fill positions of `[start, start + bytes.len())` that no region
    /// covers with the given bytes, leaving covered positions alone
    /// (`LdCtrlLoadImageMem`: bytes read back from the device fill the
    /// image's gaps, but compiled content — the ETS-owned bytes —
    /// always wins over whatever the device currently holds).
    pub fn fill_holes(&mut self, start: u16, bytes: &[u8]) {
        let mut run_start = 0usize;
        let mut run: Vec<u8> = Vec::new();
        for (i, &byte) in bytes.iter().enumerate() {
            let Some(address) = u16::try_from(usize::from(start) + i).ok() else { break };
            if self.slice(address, 1).is_some() {
                if !run.is_empty() {
                    let filled = std::mem::take(&mut run);
                    self.insert(run_start as u16, filled).expect("holes cannot overlap existing regions");
                }
            } else {
                if run.is_empty() {
                    run_start = usize::from(address);
                }
                run.push(byte);
            }
        }
        if !run.is_empty() {
            self.insert(run_start as u16, run).expect("holes cannot overlap existing regions");
        }
    }

    /// Overwrite bytes the image already holds (fixups patching
    /// mask-ROM addresses into code). Unlike [`Self::fill_holes`],
    /// existing content is exactly what a patch is *for* — but a
    /// patch reaching outside it means the fixup points outside its
    /// segment's content, which is a product-data error worth
    /// stopping on.
    pub fn patch(&mut self, address: u16, bytes: &[u8]) -> Result<()> {
        let (&start, region) = self
            .regions
            .range_mut(..=address)
            .next_back()
            .ok_or(Error::DownloadConfig("a patch lands outside the image's content"))?;
        let offset = usize::from(address - start);
        if offset + bytes.len() > region.len() {
            return Err(Error::DownloadConfig("a patch lands outside the image's content"));
        }
        region[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
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

    #[test]
    fn covered_yields_the_intersections_with_a_window() {
        let mut image = DeviceImage::new();
        image.insert(0x0100, vec![1, 2]).expect("inserts");
        image.insert(0x0110, vec![3, 4, 5, 6]).expect("inserts");

        // A window spanning both regions and the gap between them.
        let parts: Vec<(u16, Vec<u8>)> =
            image.covered(0x0101, 0x11).map(|(addr, bytes)| (addr, bytes.to_vec())).collect();
        assert_eq!(parts, vec![(0x0101, vec![2]), (0x0110, vec![3, 4])]);

        // A window touching nothing yields nothing.
        assert_eq!(image.covered(0x0200, 16).count(), 0);
    }

    #[test]
    fn fill_holes_keeps_compiled_bytes_and_fills_the_rest() {
        let mut image = DeviceImage::new();
        image.insert(0x0102, vec![0x11]).expect("inserts");

        image.fill_holes(0x0100, &[0xA0, 0xA1, 0xA2, 0xA3]);

        assert_eq!(image.slice(0x0100, 2), Some(&[0xA0, 0xA1][..]), "the gap before the region filled");
        assert_eq!(image.slice(0x0102, 1), Some(&[0x11][..]), "the compiled byte survives");
        assert_eq!(image.slice(0x0103, 1), Some(&[0xA3][..]), "the gap after the region filled");
    }
}
