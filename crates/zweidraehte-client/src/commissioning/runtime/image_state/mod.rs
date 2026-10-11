//! Desired data, authored buffers and live evidence have distinct lifetimes.
use crate::commissioning::catalog::profile::ResourceId;
use crate::commissioning::error::ImageError;
use crate::commissioning::evidence::DeviceStamp;
use crate::commissioning::image::{ImageLocation, ImageSegment, ImageSpace, SparseDeviceImage};
use crate::commissioning::procedure::operands::{
    MemoryAddress, MemoryService, OperationTarget, PropertyAddress, ServiceRead, pure_property_address,
};
use crate::commissioning::procedure::{DownloadStampOutput, OperationExtent};
use std::collections::BTreeMap;

#[derive(Default)]
pub(in crate::commissioning) struct ImageState<'a> {
    desired: Option<&'a SparseDeviceImage>,
    working: SparseDeviceImage,
    working_regions: Vec<(ImageLocation, u32)>,
    known: SparseDeviceImage,
    programmed_image: SparseDeviceImage,
    pointers: BTreeMap<ImageSpace, PointerResolution>,
    cache: Vec<CachedRead>,
    device_stamps: BTreeMap<ResourceId, Vec<u8>>,
    stamp_output: Option<&'a crate::commissioning::procedure::DownloadStampOutput>,
    stamp_observations: SparseDeviceImage,
    private_targets: Vec<ServiceRead>,
}

pub(super) struct CachedRead {
    target: crate::commissioning::procedure::OperationTarget,
    extent: crate::commissioning::procedure::OperationExtent,
    location: Option<ImageLocation>,
    bytes: Vec<u8>,
}
pub(super) struct PointerResolution {
    read: ServiceRead,
    base: u32,
}

#[cfg(test)]
mod tests;

impl<'a> ImageState<'a> {
    pub(in crate::commissioning::runtime) fn begin_program(
        &mut self,
        desired: &'a SparseDeviceImage,
        regions: &[crate::commissioning::image::NativeImageRegion],
        stamp_output: &'a DownloadStampOutput,
    ) {
        self.desired = Some(desired);
        self.stamp_output = Some(stamp_output);
        self.working_regions = desired.ranges().map(|range| (range.location, range.length)).collect();
        for region in regions {
            self.working_regions.retain(|(location, length)| {
                location.space != region.location.space
                    || location.offset + length <= region.location.offset
                    || location.offset >= region.location.offset + region.length
            });
            self.working_regions.push((region.location.clone(), region.length));
        }
    }

    pub(super) fn desired(&self) -> Result<&SparseDeviceImage, ImageError> {
        self.desired.ok_or_else(|| ImageError::InvalidState("session has no desired image".into()))
    }
    pub(super) fn known_byte(&self, at: &ImageLocation) -> Option<(u8, u8)> {
        self.known.byte(at)
    }
    pub(super) fn working_byte(&self, at: &ImageLocation) -> Option<(u8, u8)> {
        self.working.byte(at).or_else(|| self.desired.and_then(|image| image.byte(at)))
    }
    pub(super) fn transfer_ranges(&self, location: &ImageLocation, length: u32) -> Result<Vec<(u32, u32)>, ImageError> {
        let end = location
            .offset
            .checked_add(length)
            .ok_or_else(|| ImageError::InvalidState("image window overflows".into()))?;
        let mut ranges: Vec<_> = self
            .desired()?
            .ranges()
            .chain(self.working.ranges())
            .filter(|range| {
                range.location.space == location.space
                    && range.location.offset < end
                    && location.offset < range.location.offset + range.length
            })
            .map(|range| (range.location.offset.max(location.offset), (range.location.offset + range.length).min(end)))
            .collect();
        ranges.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::new();
        for (start, end) in ranges {
            if let Some(previous) = merged.last_mut()
                && start <= previous.1
            {
                previous.1 = previous.1.max(end);
            } else {
                merged.push((start, end));
            }
        }
        Ok(merged.into_iter().map(|(start, end)| (start, end - start)).collect())
    }

    pub(super) fn transfer_image(&self, location: &ImageLocation, length: u32) -> Result<ImageSegment, ImageError> {
        if length == 0 {
            return ImageSegment::owned(location.clone(), Vec::new());
        }
        // Prove complete byte ownership before allocating a requested window.
        // This combines observed holes with desired bytes without copying the
        // whole application image or inventing data for unowned gaps.
        if self.transfer_ranges(location, length)? != [(location.offset, length)] {
            return Err(ImageError::InvalidState("image operand is not completely defined: unowned holes".into()));
        }
        let desired = self.desired()?.project(location, &vec![0; length as usize])?;
        let working = self.working.project(location, desired.data())?;
        let mask = desired.mask().iter().zip(working.mask()).map(|(a, b)| a | b).collect();
        ImageSegment::new(location.clone(), working.data().to_vec(), mask)
    }
    pub(super) fn observe(&mut self, at: ImageLocation, bytes: &[u8]) -> Result<(), ImageError> {
        self.known.apply_owned(at.clone(), bytes.to_vec())?;
        self.capture_observation(&at, bytes)
    }
    pub(super) fn remember_private_target(&mut self, target: ServiceRead) {
        self.private_targets.push(target);
    }
    pub(super) fn forget_cache(&mut self) {
        self.cache.clear();
    }
    pub(super) fn capture_stamp(&mut self, resource: ResourceId, bytes: Vec<u8>) {
        self.device_stamps.insert(resource, bytes);
    }
    pub(super) fn discard_restart_snapshot(&mut self) {
        self.programmed_image.clear();
    }
    pub(super) fn preserve_restart_snapshot(&mut self, snapshot: SparseDeviceImage) {
        self.programmed_image = snapshot;
    }
    pub(super) fn remember_pointer(&mut self, space: ImageSpace, read: ServiceRead, base: u32) {
        if self.pointers.get(&space).is_some_and(|previous| previous.base != base || previous.read != read) {
            self.known.invalidate_space(&space);
            self.programmed_image.invalidate_space(&space);
        }
        self.pointers.insert(space, PointerResolution { read, base });
    }
    pub(super) fn containing_region(&self, location: &ImageLocation) -> Option<&(ImageLocation, u32)> {
        self.working_regions.iter().find(|(start, length)| {
            start.space == location.space && start.offset <= location.offset && location.offset - start.offset < *length
        })
    }
    pub(super) fn register_load_region(
        &mut self,
        location: &ImageLocation,
        length: u32,
    ) -> Result<(ImageLocation, u32), ImageError> {
        if let Some(region) = self.containing_region(location) {
            return Ok(region.clone());
        }
        // Failed reads retain geometry, never fabricated bytes.
        let end = location
            .offset
            .checked_add(length)
            .ok_or_else(|| ImageError::InvalidState("image load range overflows".into()))?;
        let mut merged_end = end;
        self.working_regions.retain(|(start, length)| {
            if start.space == location.space && start.offset < end && location.offset < start.offset + length {
                merged_end = merged_end.max(start.offset + length);
                false
            } else {
                true
            }
        });
        let region = (location.clone(), merged_end - location.offset);
        self.working_regions.push(region.clone());
        Ok(region)
    }
    pub(super) fn load_observed(&mut self, selected: ImageLocation, observed: &[u8]) -> Result<(), ImageError> {
        let merged = self.desired()?.overlay(&selected, observed)?;
        self.working.apply_owned(selected, merged)
    }
    pub(super) fn record_working_write(&mut self, at: ImageLocation, bytes: &[u8]) -> Result<(), ImageError> {
        self.working.apply_owned(at, bytes.to_vec())
    }
    pub(super) fn complete_load(&mut self, location: &ImageLocation, length: u32) -> Result<(), ImageError> {
        let projected = self.desired()?.project(location, &vec![0; length as usize])?;
        self.working.apply(&projected);
        Ok(())
    }

    pub(super) fn with_baseline(baseline: Option<SparseDeviceImage>) -> Self {
        Self { known: baseline.unwrap_or_default(), ..Self::default() }
    }

    pub(super) fn completed_stamps(&self) -> Result<Vec<DeviceStamp>, ImageError> {
        self.stamp_output.map_or_else(|| Ok(Vec::new()), |output| self.stamps(output))
    }

    // Pure image errors carry no physical effects. The execution boundary
    // attaches the session's effects before returning them to callers.

    pub(in crate::commissioning::runtime) fn forget_device(&mut self) {
        self.known.clear();
        self.programmed_image.clear();
        self.pointers.clear();
    }

    pub(super) fn invalidate_range(&mut self, location: &ImageLocation, length: u32) {
        let physical = if location.space == ImageSpace::StandardMemory {
            Some(location.offset)
        } else {
            self.pointers.get(&location.space).and_then(|pointer| pointer.base.checked_add(location.offset))
        };
        if let Some(address) = physical {
            self.invalidate_target(
                &OperationTarget::Memory { service: MemoryService::Classic, address: MemoryAddress::Fixed(address) },
                OperationExtent::bytes(length),
            );
        }
        self.known.invalidate(location, length);
        self.programmed_image.invalidate(location, length);
        self.pointers.remove(&location.space);
    }

    pub(super) fn cached(
        &self,
        target: &crate::commissioning::procedure::OperationTarget,
        extent: crate::commissioning::procedure::OperationExtent,
    ) -> Option<Vec<u8>> {
        self.cache.iter().find(|read| read.target == *target && read.extent == extent).map(|read| read.bytes.clone())
    }

    pub(super) fn cached_location(&self, location: &ImageLocation, length: u32) -> Option<&Vec<u8>> {
        self.cache
            .iter()
            .find(|read| read.location.as_ref() == Some(location) && read.bytes.len() == length as usize)
            .map(|read| &read.bytes)
    }

    pub(super) fn cache_read(
        &mut self,
        target: crate::commissioning::procedure::OperationTarget,
        extent: crate::commissioning::procedure::OperationExtent,
        location: Option<ImageLocation>,
        bytes: Vec<u8>,
    ) {
        let location = location.or_else(|| {
            self.cache
                .iter()
                .find(|read| read.target == target && read.extent == extent)
                .and_then(|read| read.location.clone())
        });
        self.cache.retain(|read| {
            (read.target != target || read.extent != extent) && (location.is_none() || read.location != location)
        });
        self.cache.push(CachedRead { target, extent, location, bytes });
    }

    pub(super) fn needs_observation(&self, location: &ImageLocation, length: u32) -> bool {
        let Some(desired) = self.desired else { return false };
        (0..length).any(|offset| {
            let at = ImageLocation { space: location.space.clone(), offset: location.offset + offset };
            let owned = desired.byte(&at).map_or(0, |(_, mask)| mask);
            let known = self.known.byte(&at).map_or(0, |(_, mask)| mask);
            let confirmed = self.programmed_image.byte(&at).map_or(0, |(_, mask)| mask);
            owned & !(known | confirmed) != 0
        })
    }

    pub(super) fn take_programmed_image(&mut self) -> SparseDeviceImage {
        let mut public = std::mem::take(&mut self.programmed_image);
        if let Some(desired) = self.desired {
            for segment in desired.segments() {
                let mut data = Vec::with_capacity(segment.data().len());
                let mut mask = Vec::with_capacity(segment.data().len());
                for (offset, owned) in segment.mask().iter().enumerate() {
                    let at = ImageLocation {
                        space: segment.location().space.clone(),
                        offset: segment.location().offset + offset as u32,
                    };
                    let (value, known) = self.known.byte(&at).unwrap_or((0, 0));
                    let known = known & owned;
                    data.push(value & known);
                    mask.push(known);
                }
                public.apply(
                    &ImageSegment::new(segment.location().clone(), data, mask)
                        .expect("projection retains checked canonical geometry"),
                );
            }
            for owner in desired.ownership() {
                let observed = public
                    .project(&owner.location, &vec![0; owner.mask.len()])
                    .expect("canonical ownership has checked geometry");
                let mask = owner.mask.iter().zip(observed.mask()).map(|(owned, known)| owned & known).collect();
                public.apply_section(
                    owner.section,
                    &ImageSegment::new(owner.location, observed.data().to_vec(), mask)
                        .expect("ownership projection retains checked geometry"),
                );
            }
        }
        for private in &self.private_targets {
            Self::invalidate_image_target(&mut public, &private.target, private.extent, &self.pointers, false);
        }
        public
    }

    pub(super) fn complete_working(&self, location: &ImageLocation, length: u32) -> Option<Vec<u8>> {
        let segment = self.working.range(location, length).ok()?;
        segment.mask().iter().all(|mask| *mask == 255).then(|| segment.data().to_vec())
    }

    pub(super) fn target_location(
        target: &OperationTarget,
        extent: OperationExtent,
    ) -> Option<crate::commissioning::image::ImageLocation> {
        use crate::commissioning::catalog::profile::{ObjectSelector, Occurrence};
        use crate::commissioning::image::{ImageLocation, ImageSpace};
        match target {
            OperationTarget::Memory { address: MemoryAddress::Pointer { space, offset, .. }, .. } => {
                Some(ImageLocation { space: space.clone(), offset: *offset })
            }
            OperationTarget::Memory { service, address: MemoryAddress::Fixed(address) } => Some(ImageLocation {
                space: match service {
                    MemoryService::Classic | MemoryService::Extended | MemoryService::Standard => {
                        ImageSpace::StandardMemory
                    }
                    MemoryService::User => ImageSpace::UserMemory,
                    MemoryService::Filter => ImageSpace::LineCouplerFilter,
                    MemoryService::Router => ImageSpace::LineCouplerSlave,
                },
                offset: *address,
            }),
            OperationTarget::Property { address, start_element } => {
                let (object, property_id) = match address {
                    PropertyAddress::Indexed { object_index, property_id } => {
                        (ObjectSelector::Index { index: u16::from(*object_index) }, u16::from(*property_id))
                    }
                    PropertyAddress::Extended { object_type, object_instance, property_id } => (
                        ObjectSelector::Type {
                            object_type: u16::from(*object_type),
                            occurrence: Occurrence::from_option(Some(*object_instance - 1)),
                        },
                        *property_id,
                    ),
                };
                let width =
                    extent.byte_length / u32::from(extent.property_elements.expect("validated property extent"));
                (*start_element > 0).then(|| ImageLocation {
                    space: ImageSpace::Property { object, property_id },
                    offset: u32::from(*start_element - 1) * width,
                })
            }
            _ => None,
        }
    }

    pub(super) fn invalidate_target(&mut self, target: &OperationTarget, extent: OperationExtent) {
        Self::invalidate_image_target(&mut self.known, target, extent, &self.pointers, true);
        Self::invalidate_image_target(&mut self.programmed_image, target, extent, &self.pointers, true);
        // Mutating the pointer itself invalidates the allocation's identity;
        // a subsequent transfer must resolve it again before using knowledge.
        let changed = self
            .pointers
            .iter()
            .filter_map(|(space, pointer)| {
                let written = Self::target_location(target, extent)?;
                let read = Self::target_location(&pointer.read.target, pointer.read.extent)?;
                (spaces_may_alias(&written.space, &read.space)
                    && (written.space != read.space
                        || ranges_overlap(
                            written.offset,
                            extent.byte_length,
                            read.offset,
                            pointer.read.extent.byte_length,
                        )))
                .then(|| space.clone())
            })
            .collect::<Vec<_>>();
        for space in changed {
            self.known.invalidate_space(&space);
            self.programmed_image.invalidate_space(&space);
            self.pointers.remove(&space);
        }
    }

    pub(super) fn invalidate_image_target(
        image: &mut SparseDeviceImage,
        target: &OperationTarget,
        extent: OperationExtent,
        pointers: &std::collections::BTreeMap<ImageSpace, PointerResolution>,
        conservative: bool,
    ) {
        let location = Self::target_location(target, extent);
        let physical = location.as_ref().and_then(|location| match &location.space {
            ImageSpace::StandardMemory => Some(location.offset),
            ImageSpace::RelativeMemory { .. } | ImageSpace::Pointer { .. } => {
                pointers.get(&location.space)?.base.checked_add(location.offset)
            }
            _ => None,
        });
        let spaces = image.spaces().cloned().collect::<Vec<_>>();
        for space in spaces {
            if let Some(address) = physical {
                if space == ImageSpace::StandardMemory {
                    image.invalidate(&ImageLocation::standard_memory(address), extent.byte_length);
                } else if matches!(space, ImageSpace::RelativeMemory { .. } | ImageSpace::Pointer { .. }) {
                    if let Some(pointer) = pointers.get(&space) {
                        let end = u64::from(address) + u64::from(extent.byte_length);
                        if end > u64::from(pointer.base) {
                            let start = address.max(pointer.base);
                            image.invalidate(
                                &ImageLocation { space: space.clone(), offset: start - pointer.base },
                                (end - u64::from(start)) as u32,
                            );
                        }
                    } else if conservative {
                        image.invalidate_space(&space);
                    }
                }
            }
            if let OperationTarget::Property { address, .. } = target {
                if let ImageSpace::Property { object, property_id } = &space {
                    let alias = pure_property_address(object, *property_id)
                        .map_or(true, |other| properties_may_alias(*address, other));
                    if alias && location.as_ref().is_none_or(|location| location.space != space) {
                        image.invalidate_space(&space);
                    }
                }
            }
        }
        if let Some(location) = &location {
            image.invalidate(location, extent.byte_length);
        }
    }

    pub(super) fn stamps(&self, output: &DownloadStampOutput) -> Result<Vec<DeviceStamp>, ImageError> {
        let DownloadStampOutput::ImageProperties(bindings) = output else {
            return Ok(if *output == DownloadStampOutput::None {
                Vec::new()
            } else {
                self.device_stamps
                    .iter()
                    .map(|(resource, value)| DeviceStamp { resource: resource.clone(), value: value.clone() })
                    .collect()
            });
        };
        let mut stamps = Vec::new();
        for observed in self.stamp_observations.segments() {
            if observed.location().offset != 0 {
                continue;
            }
            let mut matching = bindings.iter().filter(|binding| binding.image_location == *observed.location());
            let binding = matching
                .next()
                .ok_or_else(|| ImageError::InvalidState("completed stamp property has no resource binding".into()))?;
            if matching.next().is_some() {
                return Err(ImageError::InvalidState("completed stamp property has multiple resource bindings".into()));
            }
            // A binding names one record; an object's PID 27 holds one per
            // load segment, and the stamp keeps every observed record.
            let record = binding.read.extent.byte_length as usize;
            if record == 0 || observed.data().is_empty() || !observed.data().len().is_multiple_of(record) {
                return Err(ImageError::InvalidState(
                    "completed stamp byte length is not a whole number of records".into(),
                ));
            }
            stamps.push(DeviceStamp { resource: binding.id.clone(), value: observed.data().to_vec() });
        }
        Ok(stamps)
    }

    pub(super) fn capture_observation(&mut self, location: &ImageLocation, bytes: &[u8]) -> Result<(), ImageError> {
        let Some(DownloadStampOutput::ImageProperties(bindings)) = self.stamp_output else {
            return Ok(());
        };
        if !bindings.iter().any(|binding| binding.image_location.space == location.space) {
            return Ok(());
        }
        self.stamp_observations.apply_owned(location.clone(), bytes.to_vec())
    }
}
fn ranges_overlap(start: u32, length: u32, other: u32, other_length: u32) -> bool {
    u64::from(start) < u64::from(other) + u64::from(other_length)
        && u64::from(other) < u64::from(start) + u64::from(length)
}

fn spaces_may_alias(first: &ImageSpace, second: &ImageSpace) -> bool {
    if first == second {
        return true;
    }
    match (first, second) {
        (
            ImageSpace::Property { object: left, property_id: left_id },
            ImageSpace::Property { object: right, property_id: right_id },
        ) => match (pure_property_address(left, *left_id), pure_property_address(right, *right_id)) {
            (Ok(left), Ok(right)) => properties_may_alias(left, right),
            _ => true,
        },
        _ => false,
    }
}

fn properties_may_alias(first: PropertyAddress, second: PropertyAddress) -> bool {
    match (first, second) {
        (PropertyAddress::Indexed { .. }, PropertyAddress::Indexed { .. })
        | (PropertyAddress::Extended { .. }, PropertyAddress::Extended { .. }) => first == second,
        (PropertyAddress::Indexed { property_id: left, .. }, PropertyAddress::Extended { property_id: right, .. })
        | (PropertyAddress::Extended { property_id: right, .. }, PropertyAddress::Indexed { property_id: left, .. }) => {
            u16::from(left) == right
        }
    }
}
