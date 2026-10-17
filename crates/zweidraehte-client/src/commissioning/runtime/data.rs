//! Desired bytes remain immutable; only successful observations populate working data.
use super::ExecutionSession;
use crate::commissioning::error::Diagnostic;
use crate::commissioning::image::ImageLocation;
use crate::commissioning::procedure::operands::{MemoryAddress, ServiceRead};
use crate::commissioning::procedure::{
    CachePolicy, Comparison, OperationData, OperationExtent, OperationTarget, WriteIntent,
};
use crate::commissioning::runtime::TransferContext;

impl ExecutionSession<'_> {
    /// Authored caches only contain public observations. Private verification
    /// uses the uncached read path with its explicit transfer context.
    pub(super) async fn read_cached(
        &mut self,
        target: &OperationTarget,
        extent: OperationExtent,
        policy: CachePolicy,
        location: Option<&ImageLocation>,
    ) -> Result<Vec<u8>, Diagnostic> {
        let cached = if policy == CachePolicy::UseAndPopulate { self.images.cached(target, extent) } else { None };
        let bytes = match cached {
            Some(bytes) => bytes,
            None => self.read(target, extent, TransferContext::Public).await?,
        };
        if bytes.len() != extent.byte_length as usize {
            return Err(Diagnostic::new("read extent differs from image extent"));
        }
        if policy != CachePolicy::Bypass {
            self.images.cache_read(target.clone(), extent, location.cloned(), bytes.clone());
        }
        Ok(bytes)
    }

    async fn materialize(
        &mut self,
        target: &OperationTarget,
        data: &OperationData,
        extent: OperationExtent,
    ) -> Result<Vec<u8>, Diagnostic> {
        let (location, length) = match data {
            OperationData::Inline(bytes) => return Ok(bytes.clone()),
            OperationData::Secret(_) => {
                return Err(Diagnostic::new("secret writes require their prepared private payload"));
            }
            OperationData::ImageWindow { .. } => {
                return Err(Diagnostic::new("image windows must be split at their transfer boundary"));
            }
            OperationData::Buffer { location, length, fallback } => {
                if let Some(bytes) = self.images.complete_working(location, *length) {
                    return Ok(bytes);
                }
                if let Some(bytes) = fallback {
                    if bytes.len() >= *length as usize {
                        return Ok(bytes[..*length as usize].to_vec());
                    }
                }
                (location, *length)
            }
            OperationData::Image { location, length } => {
                if let Some(bytes) = self.images.complete_working(location, *length) {
                    return Ok(bytes);
                }
                (location, *length)
            }
        };
        let segment =
            self.images.transfer_image(location, length).map_err(|error| Diagnostic::new(error.to_string()))?;
        if segment.mask().iter().all(|mask| *mask == 255) {
            return Ok(segment.data().to_vec());
        }
        let existing = match self.images.cached_location(location, length) {
            Some(bytes) if bytes.len() == length as usize => bytes.clone(),
            _ => {
                let bytes = self.read(target, extent, TransferContext::Public).await?;
                bytes
            }
        };
        if existing.len() != length as usize {
            return Err(Diagnostic::new("masked image readback has a different extent"));
        }
        Ok(existing
            .iter()
            .zip(segment.data())
            .zip(segment.mask())
            .map(|((old, new), mask)| (old & !mask) | (new & mask))
            .collect())
    }

    pub(super) async fn comparison_data(
        &mut self,
        target: &OperationTarget,
        comparison: &Comparison,
        extent: OperationExtent,
    ) -> Result<Comparison, Diagnostic> {
        Ok(match comparison {
            Comparison::ImageExact { location, length, mask } => {
                if *length < extent.byte_length || mask.as_ref().is_some_and(|mask| mask.len() != *length as usize) {
                    return Err(Diagnostic::new("comparison image reference or mask has invalid geometry"));
                }

                let reference = self
                    .images
                    .comparison_image(location, extent.byte_length)
                    .map_err(|error| Diagnostic::new(error.to_string()))?;
                let effective = reference
                    .mask()
                    .iter()
                    .enumerate()
                    .map(|(index, owned)| owned & mask.as_ref().map_or(255, |mask| mask[index]))
                    .collect();

                Comparison::Exact {
                    data: OperationData::Inline(reference.data().to_vec()),
                    mask: Some(effective),
                    padding: crate::commissioning::procedure::ComparisonPadding::None,
                }
            }
            Comparison::Exact { data, mask, padding } => Comparison::Exact {
                data: OperationData::Inline(self.materialize(target, data, extent).await?),
                mask: mask.clone(),
                padding: *padding,
            },
            other => other.clone(),
        })
    }

    pub(super) async fn transfer(
        &mut self,
        target: &OperationTarget,
        data: &OperationData,
        extent: OperationExtent,
        intent: WriteIntent,
        tool_state: crate::commissioning::procedure::ToolState,
    ) -> Result<(), Diagnostic> {
        if let OperationData::ImageWindow { location, maximum } = data {
            let mut end =
                location.offset.checked_add(*maximum).ok_or_else(|| Diagnostic::new("image window overflows"))?;
            if intent == WriteIntent::AbsoluteSegment {
                // Native capacity includes unowned holes. A later sparse byte
                // cannot establish the allocation's start, and an adjacent
                // allocation cannot extend this control's implicit transfer.
                let Some((start, length)) = self.images.containing_region(location) else {
                    return Ok(());
                };
                end = end.min(start.offset + length);
            }
            let ranges = self.images.transfer_ranges(location, end - location.offset)?;
            for (start, length) in ranges {
                let shifted = shift_target(target, start - location.offset, 1)?;
                let data = OperationData::Image {
                    location: ImageLocation { space: location.space.clone(), offset: start },
                    length,
                };
                self.transfer_one(&shifted, &data, OperationExtent::bytes(length), intent, tool_state).await?;
            }
            return Ok(());
        }
        self.transfer_one(target, data, extent, intent, tool_state).await
    }

    async fn transfer_one(
        &mut self,
        target: &OperationTarget,
        data: &OperationData,
        extent: OperationExtent,
        intent: WriteIntent,
        tool_state: crate::commissioning::procedure::ToolState,
    ) -> Result<(), Diagnostic> {
        let policy = intent.resolve(tool_state, self.config.verify_mode);
        // Resolve once for this transfer, before comparing destination bytes.
        // Masked reads and all selected chunks share that observed address.
        let resolved = self.resolve_target(target, TransferContext::Public).await?;
        resolved.minimum_apdu(extent)?;
        if let OperationData::Secret(reference) = data {
            self.images.remember_private_target(ServiceRead { target: resolved.clone(), extent });
            // Keep the zeroizing store owned throughout the awaited transfer,
            // without copying its secret bytes to work around a mutable borrow.
            let payload = std::mem::take(&mut self.secret_payload);
            let result = async {
                let bytes = payload.resolve(*reference).map_err(|error| Diagnostic::new(error.to_string()))?;
                if bytes.len() != extent.byte_length as usize {
                    return Err(Diagnostic::new("secret payload extent differs"));
                }
                let group_keys = payload.group_keys(*reference).map_err(|error| Diagnostic::new(error.to_string()))?;
                if !group_keys.is_empty()
                    && (!matches!(target, OperationTarget::Property { .. })
                        || extent.property_elements.map(usize::from) != Some(group_keys.len()))
                {
                    return Err(Diagnostic::new("group-key payload requires complete property rows"));
                }
                let context = TransferContext::Private { group_keys };
                self.write(&resolved, bytes, extent, policy, context).await?;
                self.effects.record_credentials(
                    payload
                        .transitions(*reference)
                        .map_err(|error| Diagnostic::new(error.to_string()))?
                        .iter()
                        .copied(),
                );
                Ok(())
            }
            .await;
            self.secret_payload = payload;
            return result;
        }
        let location = match data {
            OperationData::Image { location, .. } | OperationData::Buffer { location, .. } => Some(location),
            _ => None,
        };
        // A property buffer with unowned bits is an explicit masked
        // read/write-back. Its own read proves equality but must not erase
        // the requested property write. Completed LoadImage buffers retain
        // the ordinary differential behavior because they own live bytes.
        let property_write_back = matches!(target, OperationTarget::Property { .. })
            && matches!(data, OperationData::Image { .. } | OperationData::Buffer { fallback: None, .. })
            && location.is_some_and(|location| {
                extent.byte_length != 0
                    && self.images.complete_working(location, extent.byte_length).is_none()
                    && self
                        .images
                        .transfer_image(location, extent.byte_length)
                        .is_ok_and(|segment| segment.mask().iter().any(|mask| *mask != u8::MAX))
            });
        // Resolve the selected runtime buffer before deciding what is equal.
        // An authored fallback can differ from the canonical desired image.
        let bytes = self.materialize(&resolved, data, extent).await?;
        if bytes.len() != extent.byte_length as usize {
            return Err(Diagnostic::new("materialized write extent differs"));
        }
        let width = extent.element_width()? as usize;
        let units = bytes.len() / width;
        // A copy compares the destination, never the source buffer. Properties
        // skip only whole equal elements; short equal runs stay in the transfer.
        let ranges = match location
            .filter(|_| !property_write_back)
            .and_then(|_| super::image_state::ImageState::target_location(target, extent))
        {
            Some(destination) => {
                changed_ranges(units, self.config.minimum_equal_run.max(1).div_ceil(width), false, |unit| {
                    (unit * width..(unit + 1) * width).all(|index| {
                        let byte = ImageLocation {
                            space: destination.space.clone(),
                            offset: destination.offset + index as u32,
                        };
                        self.images.known_byte(&byte).is_some_and(|(known, mask)| mask == 255 && known == bytes[index])
                    })
                })
            }
            None if units == 0 => Vec::new(),
            None => vec![0..units],
        };
        for range in ranges {
            let byte_start = range.start * width;
            let length = range.len() * width;
            let shifted = shift_target(&resolved, byte_start as u32, width as u32)?;
            let chunk_extent = if extent.property_elements.is_some() {
                OperationExtent::property(length as u32, range.len() as u16)
            } else {
                OperationExtent::bytes(length as u32)
            };
            // A transfer writes a copy of its source; it does not promote
            // unowned source bits to owned after a successful write.
            // Destination knowledge is recorded by write/observe_target.
            // Keep loaded source bytes unchanged so later masked transfers
            // merge fresh device bits instead of reusing a previous payload.
            self.write(
                &shifted,
                &bytes[byte_start..byte_start + length],
                chunk_extent,
                policy,
                TransferContext::Public,
            )
            .await?;
            if resolved != *target {
                let logical = shift_target(target, byte_start as u32, width as u32)?;
                self.observe_target(
                    &logical,
                    chunk_extent,
                    &bytes[byte_start..byte_start + length],
                    TransferContext::Public,
                )?;
            }
        }
        Ok(())
    }

    pub(super) async fn load_image(
        &mut self,
        target: &OperationTarget,
        location: &ImageLocation,
        extent: OperationExtent,
        alignment: u32,
    ) -> Result<(), Diagnostic> {
        if alignment == 0 || extent.byte_length == 0 {
            return Err(Diagnostic::new("image load requires positive extent and alignment"));
        }
        // Preserve the native selection's segment clipping without cloning its
        // contents. Failed reads can retain geometry, never fabricated bytes.
        let (region, capacity) = self.images.register_load_region(location, extent.byte_length)?;
        let initial = location.offset - region.offset;
        let length = extent.byte_length.min(capacity - initial);
        let mut offset = initial;
        let mut remaining = length;
        let owned = |offset| {
            let at = ImageLocation { space: region.space.clone(), offset: region.offset + offset };
            self.images.working_byte(&at).is_some_and(|(_, mask)| mask == 255)
        };
        while offset < capacity.min(initial + remaining) && owned(offset) {
            offset += 1;
            remaining -= 1;
        }
        while remaining > 0 && owned(offset + remaining - 1) {
            remaining -= 1;
        }
        offset = offset / alignment * alignment;
        remaining =
            remaining.checked_add(alignment - 1).ok_or_else(|| Diagnostic::new("image load alignment overflows"))?
                / alignment
                * alignment;
        if offset + remaining > capacity || (region.offset + offset) % alignment != 0 {
            return Err(Diagnostic::new("image read alignment exceeds the containing segment"));
        }
        if remaining > 0 {
            let selected = ImageLocation { space: region.space.clone(), offset: region.offset + offset };
            let delta = selected
                .offset
                .checked_sub(location.offset)
                .ok_or_else(|| Diagnostic::new("image alignment precedes prepared target"))?;
            let shifted = shift_target(target, delta, alignment)?;
            let selected_extent = if extent.property_elements.is_some() {
                let elements = u16::try_from(remaining / alignment)
                    .map_err(|_| Diagnostic::new("image read element count exceeds 16 bits"))?;
                OperationExtent::property(remaining, elements)
            } else {
                OperationExtent::bytes(remaining)
            };
            let observed = self.read(&shifted, selected_extent, TransferContext::Public).await?;
            self.images.load_observed(selected, &observed)?;
        }
        // Desired fully-owned prefixes/suffixes need no device read. They
        // become working bytes only after this LoadImage succeeds as a whole.
        let selected = ImageLocation { space: region.space, offset: location.offset };
        self.images.complete_load(&selected, length)?;
        Ok(())
    }
}

pub(super) fn shift_target(target: &OperationTarget, delta: u32, width: u32) -> Result<OperationTarget, Diagnostic> {
    let failure = || Diagnostic::new("transfer offset exceeds prepared service geometry");
    Ok(match target {
        OperationTarget::Memory { service, address } => OperationTarget::Memory {
            service: *service,
            address: match address {
                MemoryAddress::Fixed(address) => MemoryAddress::Fixed(address.checked_add(delta).ok_or_else(failure)?),
                MemoryAddress::Pointer { space, read, offset, encoding } => MemoryAddress::Pointer {
                    space: space.clone(),
                    read: read.clone(),
                    offset: offset.checked_add(delta).ok_or_else(failure)?,
                    encoding: *encoding,
                },
            },
        },
        OperationTarget::Property { address, start_element } if width > 0 && delta % width == 0 => {
            OperationTarget::Property {
                address: *address,
                start_element: start_element
                    .checked_add(u16::try_from(delta / width).map_err(|_| failure())?)
                    .ok_or_else(failure)?,
            }
        }
        _ if delta == 0 => target.clone(),
        _ => return Err(failure()),
    })
}

/// Return runs to transfer. Optimistic writes trim equal edges regardless of
/// size; differential selection retains short equal runs even at an edge.
pub(super) fn changed_ranges(
    length: usize,
    minimum_equal_run: usize,
    trim_equal_edges: bool,
    equal: impl Fn(usize) -> bool,
) -> Vec<std::ops::Range<usize>> {
    let mut ranges = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index < length {
        if !equal(index) {
            index += 1;
            continue;
        }
        let equal_start = index;
        while index < length && equal(index) {
            index += 1;
        }
        if index - equal_start >= minimum_equal_run || (trim_equal_edges && (equal_start == 0 || index == length)) {
            if start < equal_start {
                ranges.push(start..equal_start);
            }
            start = index;
        }
    }
    if start < length {
        ranges.push(start..length);
    }
    ranges
}
