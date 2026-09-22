//! Sparse, bit-masked device images used by commissioning plans.
//!
//! An ETS image is not one flat byte buffer. Depending on the selected mask
//! profile, independent ranges may live in absolute memory, load-state-machine
//! relative memory, properties, or the line-coupler memory windows. Keeping
//! the address space in the key prevents two numerically equal offsets from
//! being merged accidentally.

use crate::commissioning::error::ImageError;
use std::collections::BTreeMap;
use zweidraehte_project::ProgrammingSection;

pub use zweidraehte_project::ImageSpace;

/// Start of one image range.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ImageLocation {
    pub space: ImageSpace,
    pub offset: u32,
}

impl ImageLocation {
    pub const fn standard_memory(offset: u32) -> Self {
        Self { space: ImageSpace::StandardMemory, offset }
    }

    fn checked_offset(&self, delta: usize) -> Result<u32, ImageError> {
        let delta =
            u32::try_from(delta).map_err(|_| ImageError::AddressOverflow { location: self.clone(), length: delta })?;

        self.offset
            .checked_add(delta)
            .ok_or_else(|| ImageError::AddressOverflow { location: self.clone(), length: delta as usize })
    }
}

/// A contiguous image range. `mask` owns individual bits, not whole bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageSegment {
    location: ImageLocation,
    data: Vec<u8>,
    mask: Vec<u8>,
}

/// A native image region, retaining the product's declared allocation geometry.
///
/// `length` spans the complete capacity, including unowned holes. `seed`
/// contains only the bytes supplied by the product; reserved capacity is not
/// confused with known zero bytes. Generated regions have no source identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeImageRegion {
    pub source_id: Option<String>,
    pub memory_type: Option<String>,
    pub seed: Vec<u8>,
    pub location: ImageLocation,
    pub length: u32,
}

impl NativeImageRegion {
    pub fn display_id(&self) -> std::borrow::Cow<'_, str> {
        self.source_id
            .as_deref()
            .map_or_else(|| format!("{:?}-{:04X}", self.location.space, self.location.offset).into(), Into::into)
    }
}

impl ImageSegment {
    /// Construct a checked segment.
    ///
    /// Zero mask bits preserve the device value. This is required for packed
    /// parameters whose neighboring bits belong to another parameter or to
    /// firmware state.
    pub fn new(location: ImageLocation, data: Vec<u8>, mask: Vec<u8>) -> Result<Self, ImageError> {
        if data.len() != mask.len() {
            return Err(ImageError::MaskLength { location, data_length: data.len(), mask_length: mask.len() });
        }

        location.checked_offset(data.len())?;

        Ok(Self { location, data, mask })
    }

    /// Construct a segment whose supplied bytes are owned completely.
    pub fn owned(location: ImageLocation, data: Vec<u8>) -> Result<Self, ImageError> {
        let mask = vec![u8::MAX; data.len()];
        Self::new(location, data, mask)
    }

    pub fn location(&self) -> &ImageLocation {
        &self.location
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn mask(&self) -> &[u8] {
        &self.mask
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn end_offset(&self) -> u32 {
        // The constructor proves this addition fits.
        self.location.offset + self.data.len() as u32
    }
}

/// A normalized sparse image.
///
/// Patches are applied in compiler-phase order. If two patches own the same
/// bit, the later phase wins; disjoint bits in the same byte are combined.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SparseDeviceImage {
    pub(super) bytes: BTreeMap<ImageSpace, BTreeMap<u32, MaskedByte>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MaskedByte {
    pub data: u8,
    pub mask: u8,
    pub owners: [u8; 6],
}

impl SparseDeviceImage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.values().all(BTreeMap::is_empty)
    }

    pub fn spaces(&self) -> impl Iterator<Item = &ImageSpace> {
        self.bytes.keys()
    }

    pub fn byte_count(&self) -> usize {
        self.bytes.values().map(BTreeMap::len).sum()
    }

    /// Exclusive end of the last represented byte in this address space.
    /// Partial ownership still represents a byte; reserved holes do not.
    pub fn end_offset(&self, space: &ImageSpace) -> Option<u32> {
        self.bytes.get(space)?.last_key_value().map(|(offset, _)| offset + 1)
    }

    /// Contiguous represented ranges without materializing their bytes or masks.
    pub fn ranges(&self) -> impl Iterator<Item = super::RequiredImageRange> + '_ {
        self.bytes.iter().flat_map(|(space, bytes)| {
            let mut offsets = bytes.keys().copied().peekable();
            std::iter::from_fn(move || {
                let start = offsets.next()?;
                // Checked segments cannot contain a byte at u32::MAX.
                let mut end = start + 1;
                while offsets.peek() == Some(&end) {
                    offsets.next();
                    end += 1;
                }
                Some(super::RequiredImageRange {
                    location: ImageLocation { space: space.clone(), offset: start },
                    length: end - start,
                })
            })
        })
    }

    /// Check presence using the same bounds and empty-space semantics as `range`.
    /// A represented byte need not own all eight bits.
    pub fn require_range(&self, location: &ImageLocation, length: u32) -> Result<(), ImageError> {
        let end = location.checked_offset(length as usize)?;
        let missing = || ImageError::MissingRange { location: location.clone(), length };
        let space = self.bytes.get(&location.space).ok_or_else(missing)?;
        if space.range(location.offset..end).count() != length as usize {
            return Err(missing());
        }
        Ok(())
    }

    /// Apply one validated patch to the image.
    pub fn apply(&mut self, segment: &ImageSegment) {
        self.patch(segment, None)
    }

    /// Apply desired bits and transfer ownership from any earlier producer.
    pub fn apply_section(&mut self, section: ProgrammingSection, segment: &ImageSegment) {
        self.patch(segment, Some(super::ownership::section_index(section)))
    }

    fn patch(&mut self, segment: &ImageSegment, owner: Option<usize>) {
        if segment.is_empty() {
            return;
        }

        let space = self.bytes.entry(segment.location.space.clone()).or_default();

        for (index, (&data, &mask)) in segment.data.iter().zip(&segment.mask).enumerate() {
            if mask == 0 {
                continue;
            }

            let offset = segment.location.offset + index as u32;
            let byte = space.entry(offset).or_insert(MaskedByte { data: 0, mask: 0, owners: [0; 6] });

            // Later compiler phases override only the bits they own. Bits not
            // selected by this patch retain the earlier phase's contribution.
            byte.data = (byte.data & !mask) | (data & mask);
            byte.mask |= mask;
            if let Some(owner) = owner {
                for owned in &mut byte.owners {
                    *owned &= !mask;
                }
                byte.owners[owner] |= mask;
            }
        }
    }

    pub fn apply_owned(&mut self, location: ImageLocation, data: Vec<u8>) -> Result<(), ImageError> {
        self.apply(&ImageSegment::owned(location, data)?);
        Ok(())
    }

    /// One observed or desired byte and its known/owned bits.
    pub fn byte(&self, location: &ImageLocation) -> Option<(u8, u8)> {
        self.bytes.get(&location.space)?.get(&location.offset).map(|byte| (byte.data, byte.mask))
    }

    /// Forget contents before a mutation whose completion may be uncertain.
    pub fn invalidate(&mut self, location: &ImageLocation, length: u32) {
        if let Some(bytes) = self.bytes.get_mut(&location.space) {
            let end = u64::from(location.offset) + u64::from(length);
            bytes.retain(|offset, _| *offset < location.offset || u64::from(*offset) >= end);
        }
    }

    pub fn invalidate_space(&mut self, space: &ImageSpace) {
        self.bytes.remove(space);
    }

    pub fn clear(&mut self) {
        self.bytes.clear();
    }

    pub(crate) fn retain_ranges(&mut self, ranges: &[super::RequiredImageRange]) -> Result<(), ImageError> {
        for range in ranges {
            if range.length != 0 {
                self.require_range(&range.location, range.length)?;
            }
        }
        for (space, bytes) in &mut self.bytes {
            bytes.retain(|offset, _| {
                ranges.iter().any(|range| {
                    &range.location.space == space
                        && *offset >= range.location.offset
                        && u64::from(*offset) < u64::from(range.location.offset) + u64::from(range.length)
                })
            });
        }
        Ok(())
    }

    /// Emit minimal contiguous ranges, preserving gaps and address spaces.
    pub fn segments(&self) -> Vec<ImageSegment> {
        let mut segments: Vec<ImageSegment> = Vec::new();
        for (space, bytes) in &self.bytes {
            for (&offset, byte) in bytes {
                if let Some(segment) = segments.last_mut()
                    && segment.location.space == *space
                    && segment.end_offset() == offset
                {
                    segment.data.push(byte.data);
                    segment.mask.push(byte.mask);
                } else {
                    segments.push(ImageSegment {
                        location: ImageLocation { space: space.clone(), offset },
                        data: vec![byte.data],
                        mask: vec![byte.mask],
                    });
                }
            }
        }
        segments
    }

    /// Return a range only when every byte in it is represented. Masked bytes
    /// remain masked in the returned segment.
    pub fn range(&self, location: &ImageLocation, length: u32) -> Result<ImageSegment, ImageError> {
        location.checked_offset(length as usize)?;

        let space = self
            .bytes
            .get(&location.space)
            .ok_or_else(|| ImageError::MissingRange { location: location.clone(), length })?;

        let mut data = Vec::with_capacity(length as usize);
        let mut mask = Vec::with_capacity(length as usize);

        for delta in 0..length {
            let offset = location.offset + delta;
            let byte =
                space.get(&offset).ok_or_else(|| ImageError::MissingRange { location: location.clone(), length })?;

            data.push(byte.data);
            mask.push(byte.mask);
        }

        ImageSegment::new(location.clone(), data, mask)
    }

    /// Overlay compiler-owned bits onto a live byte range. Bytes absent from
    /// the sparse image remain unchanged, which is the runtime meaning of a
    /// preceding `LoadImage*` control.
    pub fn overlay(&self, location: &ImageLocation, base: &[u8]) -> Result<Vec<u8>, ImageError> {
        location.checked_offset(base.len())?;

        let Some(space) = self.bytes.get(&location.space) else {
            return Ok(base.to_vec());
        };

        let mut result = base.to_vec();
        for (index, byte) in result.iter_mut().enumerate() {
            let offset = location.checked_offset(index)?;
            let Some(compiled) = space.get(&offset) else {
                continue;
            };

            *byte = (*byte & !compiled.mask) | (compiled.data & compiled.mask);
        }

        Ok(result)
    }

    /// Project an allocation without inventing ownership for absent bytes.
    ///
    /// Unlike `range`, this includes reserved gaps with a zero mask. The
    /// supplied seed remains visible there for previews but authorizes no
    /// write, allowing native segment geometry and sparse execution to agree.
    pub fn project(&self, location: &ImageLocation, seed: &[u8]) -> Result<ImageSegment, ImageError> {
        let data = self.overlay(location, seed)?;
        let bytes = self.bytes.get(&location.space);
        let mask = (0..seed.len())
            .map(|index| {
                bytes.and_then(|bytes| bytes.get(&(location.offset + index as u32))).map_or(0, |byte| byte.mask)
            })
            .collect();
        ImageSegment::new(location.clone(), data, mask)
    }
}

#[cfg(test)]
mod tests;
