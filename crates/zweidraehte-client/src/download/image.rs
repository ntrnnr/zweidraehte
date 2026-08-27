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

#[derive(Debug, Clone)]
struct ImageContent {
    bytes: Vec<u8>,
    /// Set bits come from `bytes`; clear bits retain their device value.
    masks: Vec<u8>,
}

type MaskedRelativePart<'a> = (u32, &'a [u8], &'a [u8]);

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
    /// Start address → masked bytes; regions never overlap.
    regions: BTreeMap<u16, ImageContent>,
    /// Interface object index → the bytes that object's relative
    /// segment should hold.
    relative: BTreeMap<u8, ImageContent>,
}

impl DeviceImage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a region. Rejects overlaps — two sources writing the same
    /// address would mean the compile step produced garbage.
    pub fn insert(&mut self, address: u16, bytes: Vec<u8>) -> Result<()> {
        let masks = vec![0xFF; bytes.len()];

        self.insert_masked(address, bytes, masks)
    }

    /// Add masked content, omitting bytes whose mask is zero.
    pub(crate) fn insert_masked(&mut self, address: u16, bytes: Vec<u8>, masks: Vec<u8>) -> Result<()> {
        if bytes.len() != masks.len() {
            return Err(Error::DownloadConfig("image content and mask lengths differ"));
        }

        let mut cursor = 0usize;
        while cursor < bytes.len() {
            while cursor < bytes.len() && masks[cursor] == 0 {
                cursor += 1;
            }

            let start = cursor;
            while cursor < bytes.len() && masks[cursor] != 0 {
                cursor += 1;
            }

            if start < cursor {
                let run_offset = u16::try_from(start)
                    .map_err(|_| Error::DownloadConfig("image region extends past the 16-bit address space"))?;
                let run_address = address
                    .checked_add(run_offset)
                    .ok_or(Error::DownloadConfig("image region extends past the 16-bit address space"))?;
                let content =
                    ImageContent { bytes: bytes[start..cursor].to_vec(), masks: masks[start..cursor].to_vec() };

                self.insert_content(run_address, content)?;
            }
        }

        Ok(())
    }

    fn insert_content(&mut self, address: u16, content: ImageContent) -> Result<()> {
        let bytes = &content.bytes;
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
            && (prev_start as usize + prev.bytes.len()) > address as usize
        {
            return Err(Error::DownloadConfig("image regions overlap"));
        }

        if let Some((&next_start, _)) = self.regions.range(address..).next()
            && (next_start as usize) < end
        {
            return Err(Error::DownloadConfig("image regions overlap"));
        }

        self.regions.insert(address, content);

        Ok(())
    }

    /// The bytes for `[address, address + length)`, if a single region
    /// covers that range. A `WriteImage` step may address a region's
    /// prefix (master-data templates carry clamp-to-blob sizes), so
    /// `length` is clipped to what the region holds.
    pub fn slice(&self, address: u16, length: u16) -> Option<&[u8]> {
        let (&start, content) = self.regions.range(..=address).next_back()?;
        let offset = (address - start) as usize;

        if offset >= content.bytes.len() {
            return None;
        }

        let available = content.bytes.len() - offset;
        let take = (length as usize).min(available);

        Some(&content.bytes[offset..offset + take])
    }

    /// Iterate over all regions (for diagnostics / tests).
    pub fn regions(&self) -> impl Iterator<Item = (u16, &[u8])> {
        self.regions.iter().map(|(&addr, content)| (addr, content.bytes.as_slice()))
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
        self.regions.iter().filter_map(move |(&region_start, content)| {
            let region_start = usize::from(region_start);
            let overlap_start = region_start.max(start);
            let overlap_end = (region_start + content.bytes.len()).min(end);
            (overlap_start < overlap_end).then(|| {
                (overlap_start as u16, &content.bytes[overlap_start - region_start..overlap_end - region_start])
            })
        })
    }

    /// Masked sub-slices of one absolute write window.
    pub(crate) fn masked_covered(&self, address: u16, length: u16) -> impl Iterator<Item = (u16, &[u8], &[u8])> + '_ {
        let start = usize::from(address);
        let end = start + usize::from(length);

        self.regions.iter().filter_map(move |(&region_start, content)| {
            let region_start = usize::from(region_start);
            let overlap_start = region_start.max(start);
            let overlap_end = (region_start + content.bytes.len()).min(end);
            (overlap_start < overlap_end).then(|| {
                let range = overlap_start - region_start..overlap_end - region_start;

                (overlap_start as u16, &content.bytes[range.clone()], &content.masks[range])
            })
        })
    }

    /// Fill positions of `[start, start + bytes.len())` that no region
    /// covers with the given bytes, leaving covered positions alone
    /// (`LdCtrlLoadImageMem`: bytes read back from the device fill the
    /// image's gaps. Masked content is merged with the read-back value
    /// and becomes a complete byte before the later write).
    pub fn fill_holes(&mut self, start: u16, bytes: &[u8]) {
        let mut run_start = 0usize;
        let mut run: Vec<u8> = Vec::new();
        for (i, &byte) in bytes.iter().enumerate() {
            let Some(address) = u16::try_from(usize::from(start) + i).ok() else { break };
            let covered = if let Some((&region_start, content)) = self.regions.range_mut(..=address).next_back() {
                let offset = usize::from(address - region_start);

                if offset < content.bytes.len() {
                    let mask = content.masks[offset];
                    content.bytes[offset] = (content.bytes[offset] & mask) | (byte & !mask);
                    content.masks[offset] = 0xFF;
                    true
                } else {
                    false
                }
            } else {
                false
            };

            if covered {
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
        let (&start, content) = self
            .regions
            .range_mut(..=address)
            .next_back()
            .ok_or(Error::DownloadConfig("a patch lands outside the image's content"))?;
        let offset = usize::from(address - start);
        if offset + bytes.len() > content.bytes.len() {
            return Err(Error::DownloadConfig("a patch lands outside the image's content"));
        }
        content.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    /// Overwrite existing image bytes and claim holes as new content.
    ///
    /// Mask resources such as BCU2 `ApplicationId` deliberately start as
    /// holes in MTXML and are filled by ETS after the product image is
    /// assembled. Byte-wise insertion keeps surrounding unmasked bytes sparse
    /// instead of turning the whole enclosing segment into a write.
    pub fn overwrite(&mut self, address: u16, bytes: &[u8]) -> Result<()> {
        for (offset, &byte) in bytes.iter().enumerate() {
            let target = address
                .checked_add(
                    u16::try_from(offset)
                        .map_err(|_| Error::DownloadConfig("image overwrite exceeds the 16-bit address space"))?,
                )
                .ok_or(Error::DownloadConfig("image overwrite exceeds the 16-bit address space"))?;
            let overwritten = if let Some((&region_start, content)) = self.regions.range_mut(..=target).next_back() {
                let offset = usize::from(target - region_start);

                if offset < content.bytes.len() {
                    content.bytes[offset] = byte;
                    content.masks[offset] = 0xFF;
                    true
                } else {
                    false
                }
            } else {
                false
            };

            if !overwritten {
                self.insert(target, vec![byte])?;
            }
        }
        Ok(())
    }

    /// Set the content of an interface object's relative segment.
    pub fn insert_relative(&mut self, obj_idx: u8, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }

        let masks = vec![0xFF; bytes.len()];
        self.relative.insert(obj_idx, ImageContent { bytes, masks });
    }

    /// Add relative content whose clear mask bits retain device state.
    pub(crate) fn insert_masked_relative(&mut self, obj_idx: u8, bytes: Vec<u8>, masks: Vec<u8>) -> Result<()> {
        if bytes.len() != masks.len() {
            return Err(Error::DownloadConfig("relative content and mask lengths differ"));
        }
        if bytes.is_empty() {
            return Ok(());
        }
        self.relative.insert(obj_idx, ImageContent { bytes, masks });
        Ok(())
    }

    /// The content compiled for an interface object's relative
    /// segment, if any.
    pub fn relative(&self, obj_idx: u8) -> Option<&[u8]> {
        self.relative.get(&obj_idx).map(|content| content.bytes.as_slice())
    }

    /// Masked runs inside a relative write window.
    ///
    /// Offsets are relative to the device-reported allocation base. ETS uses
    /// precisely these sparse runs for masked System B parameter segments;
    /// writing the capacity-sized gaps can corrupt resident application data.
    pub(crate) fn relative_parts(&self, obj_idx: u8, offset: u32, length: u32) -> Option<Vec<MaskedRelativePart<'_>>> {
        let content = self.relative.get(&obj_idx)?;
        let start = usize::try_from(offset).ok()?.min(content.bytes.len());
        let requested_end = usize::try_from(offset.checked_add(length)?).unwrap_or(usize::MAX);
        let end = requested_end.min(content.bytes.len());
        let mut parts = Vec::new();
        let mut cursor = start;
        while cursor < end {
            while cursor < end && content.masks[cursor] == 0 {
                cursor += 1;
            }
            let run_start = cursor;
            while cursor < end && content.masks[cursor] != 0 {
                cursor += 1;
            }
            if run_start < cursor {
                parts.push((run_start as u32, &content.bytes[run_start..cursor], &content.masks[run_start..cursor]));
            }
        }
        Some(parts)
    }

    /// Iterate over relative content (for diagnostics / tests).
    pub fn relative_objects(&self) -> impl Iterator<Item = (u8, &[u8])> {
        self.relative.iter().map(|(&idx, content)| (idx, content.bytes.as_slice()))
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
    fn relative_content_preserves_exact_masks_and_unmasked_gaps() {
        let mut image = DeviceImage::new();
        image
            .insert_masked_relative(4, vec![0, 1, 2, 3, 4, 5, 6], vec![0, 0xFF, 0x0F, 0, 0xF0, 0, 0x55])
            .expect("matching mask");

        let full_window =
            vec![(1, &[1, 2][..], &[0xFF, 0x0F][..]), (4, &[4][..], &[0xF0][..]), (6, &[6][..], &[0x55][..])];
        let partial_window = vec![(2, &[2][..], &[0x0F][..]), (4, &[4][..], &[0xF0][..])];

        assert_eq!(image.relative_parts(4, 0, 7), Some(full_window));
        assert_eq!(image.relative_parts(4, 2, 3), Some(partial_window));
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
    fn masked_covered_preserves_partial_absolute_masks() {
        let mut image = DeviceImage::new();
        image.insert_masked(0x0100, vec![1, 2, 3, 4], vec![0, 0xF0, 0x0F, 0]).expect("masked content inserts");

        let parts: Vec<(u16, Vec<u8>, Vec<u8>)> = image
            .masked_covered(0x0100, 4)
            .map(|(address, bytes, masks)| (address, bytes.to_vec(), masks.to_vec()))
            .collect();

        assert_eq!(parts, vec![(0x0101, vec![2, 3], vec![0xF0, 0x0F])]);
    }

    #[test]
    fn fill_holes_keeps_compiled_bytes_and_fills_the_rest() {
        let mut image = DeviceImage::new();
        image.insert_masked(0x0102, vec![0x15], vec![0x0F]).expect("inserts");

        image.fill_holes(0x0100, &[0xA0, 0xA1, 0xA2, 0xA3]);

        assert_eq!(image.slice(0x0100, 2), Some(&[0xA0, 0xA1][..]), "the gap before the region filled");
        assert_eq!(image.slice(0x0102, 1), Some(&[0xA5][..]), "masked bits merge with the device byte");
        assert_eq!(image.slice(0x0103, 1), Some(&[0xA3][..]), "the gap after the region filled");

        let masks: Vec<Vec<u8>> = image.masked_covered(0x0100, 4).map(|(_, _, masks)| masks.to_vec()).collect();
        assert_eq!(masks, vec![vec![0xFF, 0xFF], vec![0xFF], vec![0xFF]]);
    }

    #[test]
    fn overwrite_claims_only_the_requested_holes() {
        let mut image = DeviceImage::new();
        image.insert(0x0100, vec![1]).expect("inserts");
        image.insert(0x0103, vec![4]).expect("inserts");

        image.overwrite(0x0100, &[9, 8, 7, 6]).expect("overwrites");

        assert_eq!(image.slice(0x0100, 1), Some(&[9][..]));
        assert_eq!(image.slice(0x0101, 1), Some(&[8][..]));
        assert_eq!(image.slice(0x0102, 1), Some(&[7][..]));
        assert_eq!(image.slice(0x0103, 1), Some(&[6][..]));
    }
}
