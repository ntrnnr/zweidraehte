//! Build the desired bytes once, in producer order.

mod communication;
mod parameters;
mod placement;
#[cfg(test)]
mod preview_tests;
mod scope;
pub mod tables;

use crate::commissioning::catalog::profile::{ProfileDisposition, ResolvedProfile};
use crate::commissioning::catalog::rules;
use crate::commissioning::compiler::ProgramCompiler;
use crate::commissioning::compiler::RecipeSet;
use crate::commissioning::compiler::secrets::SecretCommissioningPayload;
use crate::commissioning::error::CompileError;
use crate::commissioning::error::ImageError;
use crate::commissioning::image::{
    ImageLocation, ImageOwnership, ImageSegment, ImageSpace, NativeImageRegion, RequiredImageRange, SparseDeviceImage,
    fingerprint_image, fingerprint_product,
};
use crate::commissioning::input::{CommissioningIntent, ProgramSections};
use communication::CommunicationTables;
use parameters::{apply_parameters, apply_property_parameters};
use std::collections::BTreeMap;
use zweidraehte_ets_files::product::ProductData;
use zweidraehte_ets_files::schema::master_data::AddressSpaceLocation;
use zweidraehte_project::{DesiredProgrammingManifest, ProgrammingSection};

impl ProgramCompiler<'_> {
    pub(in crate::commissioning) fn build_image(&mut self) -> Result<(), CompileError> {
        let input = self.input;
        let device = &input.device;
        let profile = &self.profile;
        let product = device.product();
        let configuration = device.configuration();
        let sections = self.feature_sections;
        let unloading = matches!(input.intent, CommissioningIntent::Unload(_));
        let empty =
            input.intent == CommissioningIntent::AssignAddress || unloading && self.unload_required_ranges.is_empty();
        profile.validate_programming()?;
        ensure_profile_can_compile(profile, !empty && sections.contains(ProgramSections::GROUP_COMMUNICATION))?;
        if empty {
            self.image = ProgramImage::new(product);
            return Ok(());
        }

        let required_ranges = std::mem::take(&mut self.unload_required_ranges);
        let demand = if unloading { ImageDemand::Ranges(&required_ranges) } else { ImageDemand::Complete };
        let output = &mut self.image;
        let product_fingerprint = output.product_fingerprint;
        let image = &mut output.image;
        let mut buffers = seed_segments(product, demand, image)?;
        apply_fixups(profile, product, &buffers, image, demand)?;
        let tables = CommunicationTables::prepare(profile, product, configuration, &buffers, image, demand)?;

        // Each producer transfers only its declared bits. Equal parameter defaults
        // still own their bits; ownership never depends on a value comparison.
        apply_parameters(product, configuration, &buffers, image, demand)?;
        apply_property_parameters(product, configuration, image, demand)?;
        let table_spans = tables.write(image)?;
        let relocations = tables.relocations();
        apply_application_identity(profile, product, image, demand)?;

        if demand.is_complete() {
            self.contribute_data_secure()?;
            self.contribute_ip()?;
            self.contribute_topology()?;
        }
        if let Some(request) = self.recipes.request()
            && request.procedure_type == "Load"
            && !request.applicability.full
        {
            // An overlapping published source does not authorize bytes from
            // unselected producers. Keep allocation geometry for reads and
            // masked writes, but project only the selected desired ownership.
            scope::retain_download_sections(&mut self.image.image, request.applicability.sections)?;
        }
        let output = &mut self.image;
        let image = &mut output.image;
        if let ImageDemand::Ranges(required) = demand {
            image.retain_ranges(required)?;
        }
        validate_capacities(&self.profile, &buffers, image)?;
        let mut manifest = image.manifest();
        if demand.is_complete() {
            manifest.mix(ProgrammingSection::ApplicationProgram1, "product", "primary", &product_fingerprint);
            manifest.mix(ProgrammingSection::Parameters, "product-layout", "parameters", &product_fingerprint);
            manifest.mix(
                ProgrammingSection::GroupCommunication,
                "product-layout",
                "group-communication",
                &product_fingerprint,
            );
            manifest.mix(ProgrammingSection::GroupCommunication, "data-secure", "enabled", &[u8::from(
                device.key_material().application_security().is_some(),
            )]);
            if sections.contains(ProgramSections::CONFIGURATION) {
                manifest.mix(
                    ProgrammingSection::Configuration,
                    "product-layout",
                    "configuration",
                    &product_fingerprint,
                );
            }
        } else {
            manifest = Default::default();
        }
        // Resized table allocations bound their implicit transfers at runtime.
        for relocation in &relocations {
            if let Some(region) = buffers.get_mut(&relocation.segment_id) {
                region.location = ImageLocation::standard_memory(relocation.to.0);
                region.length = relocation.to.1;
                region.seed.clear();
            }
        }
        output.regions = native_regions(product, buffers, image);
        output.manifest = manifest;
        output.table_spans = if demand.is_complete() { table_spans } else { Vec::new() };

        // The selected procedure allocates the same segments; move its
        // records with them so the device and the image agree on the layout.
        if let RecipeSet::Exact { procedure, .. } = &mut self.recipes {
            placement::relocate_allocations(&mut procedure.program, &relocations)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledTableKind {
    GroupAddress,
    Association,
    GroupObject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledTableSpan {
    pub kind: CompiledTableKind,
    pub location: ImageLocation,
    pub len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramImage {
    pub(crate) image: SparseDeviceImage,
    pub(crate) regions: Vec<NativeImageRegion>,
    pub(crate) manifest: DesiredProgrammingManifest,
    pub(crate) table_spans: Vec<CompiledTableSpan>,
    pub(crate) secret_payload: SecretCommissioningPayload,
    pub(crate) product_fingerprint: [u8; 32],
    pub(crate) requirements: Vec<crate::commissioning::catalog::profile::ImageRequirement>,
}

impl ProgramImage {
    pub(in crate::commissioning::compiler) fn add_section(
        &mut self,
        section: ProgrammingSection,
        segment: ImageSegment,
    ) {
        self.image.apply_section(section, &segment);
    }

    pub(crate) fn new(product: &ProductData) -> Self {
        Self {
            image: SparseDeviceImage::new(),
            regions: Vec::new(),
            manifest: Default::default(),
            table_spans: Vec::new(),
            secret_payload: Default::default(),
            product_fingerprint: fingerprint_product(product),
            requirements: Vec::new(),
        }
    }

    pub fn image(&self) -> &SparseDeviceImage {
        &self.image
    }

    /// Missing observations; an incomplete preview contains no compiled image.
    pub fn requirements(&self) -> &[crate::commissioning::catalog::profile::ImageRequirement] {
        &self.requirements
    }

    pub fn is_complete(&self) -> bool {
        self.requirements.is_empty()
    }

    pub fn regions(&self) -> &[NativeImageRegion] {
        &self.regions
    }

    /// Project authored regions in display order, including reserved holes.
    /// Metadata is borrowed; only the projected bytes are produced.
    pub fn projected_regions(&self) -> impl Iterator<Item = (&NativeImageRegion, ImageSegment)> {
        let mut regions: Vec<_> = self.regions.iter().collect();
        regions.sort_by(|a, b| {
            (&a.location.space, a.location.offset, a.display_id()).cmp(&(
                &b.location.space,
                b.location.offset,
                b.display_id(),
            ))
        });
        regions.into_iter().map(|region| {
            let mut seed = region.seed.clone();
            seed.resize(region.length as usize, 0);
            let bytes = self.image.project(&region.location, &seed).expect("native region geometry is checked");
            (region, bytes)
        })
    }

    pub fn ownership(&self) -> Vec<ImageOwnership> {
        self.image.ownership()
    }

    pub fn manifest(&self) -> &DesiredProgrammingManifest {
        &self.manifest
    }

    pub fn table_spans(&self) -> &[CompiledTableSpan] {
        &self.table_spans
    }

    pub fn product_fingerprint(&self) -> [u8; 32] {
        self.product_fingerprint
    }

    pub fn image_fingerprint(&self) -> [u8; 32] {
        fingerprint_image(&self.image)
    }
}

fn ensure_profile_can_compile(profile: &ResolvedProfile, includes_group_filter: bool) -> Result<(), CompileError> {
    match &profile.disposition() {
        ProfileDisposition::Executable | ProfileDisposition::ProductProcedureRequired => Ok(()),
        ProfileDisposition::CouplerRoutingRequired if !includes_group_filter => Ok(()),
        ProfileDisposition::CouplerRoutingRequired => {
            // TODO: bind the product-specific routing selector when its
            // parameter/property mapping is available. A filter bitmap alone
            // cannot establish the requested routing policy on this family.
            Err(CompileError::unsupported(format!(
                "profile is not executable: {0}",
                "Coupler Model 2.0 requires a product routing selector".to_owned()
            )))
        }
        disposition => {
            Err(CompileError::unsupported(format!("profile is not executable: {0}", format!("{disposition:?}"))))
        }
    }
}

#[cfg(test)]
mod tests;

/// A single image pipeline, with demand controlling which producers run.
#[derive(Clone, Copy)]
pub(super) enum ImageDemand<'a> {
    Complete,
    Ranges(&'a [RequiredImageRange]),
}

impl ImageDemand<'_> {
    pub(super) fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }

    pub(super) fn includes(self, location: &ImageLocation, length: u32) -> bool {
        match self {
            Self::Complete => true,
            Self::Ranges(required) => required_intersects(required, location, length),
        }
    }
}

pub(super) fn seed_segments(
    product: &ProductData,
    demand: ImageDemand<'_>,
    image: &mut SparseDeviceImage,
) -> Result<BTreeMap<String, NativeImageRegion>, CompileError> {
    let mut buffers = BTreeMap::new();
    for segment in product.segments() {
        let location = match rules::product_segment(product, segment) {
            Ok(location) => location,
            Err(_) if !demand.is_complete() => {
                continue;
            }
            Err(error) => return Err(error),
        };
        if !demand.includes(&location, segment.size) {
            continue;
        }
        let size = usize::try_from(segment.size).map_err(|_| {
            CompileError::invalid(format!("product segment {0:?} is too large for this host", segment.id.clone()))
        })?;
        if segment.data.len() > size {
            return Err(CompileError::invalid(format!(
                "product segment {segment:?} has {data_length} data bytes but size {size}",
                segment = segment.id.clone(),
                data_length = segment.data.len(),
                size = segment.size
            )));
        }
        if let Some(mask) = &segment.mask
            && mask.len() != segment.data.len()
        {
            return Err(CompileError::invalid(format!(
                "product segment {segment:?} has {data_length} data bytes but {mask_length} mask bytes",
                segment = segment.id.clone(),
                data_length = segment.data.len(),
                mask_length = mask.len()
            )));
        }
        location
            .offset
            .checked_add(segment.size)
            .ok_or_else(|| ImageError::AddressOverflow { location: location.clone(), length: size })?;
        // Without an explicit mask, the whole allocation is owned and any
        // bytes beyond the supplied data are zero-filled. An explicit mask
        // keeps its authored extent.
        let (data, mask) = match &segment.mask {
            Some(mask) => (segment.data.clone(), mask.clone()),
            None => {
                let mut data = segment.data.clone();
                data.resize(size, 0);
                (data, vec![u8::MAX; size])
            }
        };
        image.apply_section(ProgrammingSection::ApplicationProgram1, &ImageSegment::new(location.clone(), data, mask)?);
        let region = NativeImageRegion {
            source_id: Some(segment.id.clone()),
            memory_type: segment.memory_type.clone(),
            seed: segment.data.clone(),
            location,
            length: segment.size,
        };
        if buffers.insert(segment.id.clone(), region).is_some() {
            return Err(CompileError::invalid(format!(
                "product declares segment {0:?} more than once",
                segment.id.clone()
            )));
        }
    }
    Ok(buffers)
}

/// Bound a generated patch by its native allocation.
pub(super) fn region_patch(
    region: &NativeImageRegion,
    offset: u32,
    data: Vec<u8>,
    mask: Vec<u8>,
) -> Result<ImageSegment, CompileError> {
    if u64::from(offset) + data.len() as u64 > u64::from(region.length) {
        return Err(CompileError::invalid("compiled patch lies outside its product segment"));
    }
    let offset = region
        .location
        .offset
        .checked_add(offset)
        .ok_or(CompileError::invalid("compiled patch lies outside its product segment"))?;
    Ok(ImageSegment::new(ImageLocation { space: region.location.space.clone(), offset }, data, mask)?)
}

/// Reject owned absolute bytes outside every memory the device can hold.
///
/// That memory is the profile's `MemorySegments` windows together with the
/// product's own absolute segments, which its load procedure allocates
/// (`LdCtrlAbsSegment`). ETS programs products whose segments extend beyond
/// the mask's base windows (BCU 2.5 products with 2 KB beyond the 880-byte
/// EEPROM window), and images that run across two adjacent windows (System 7
/// 0x4000 + 0x6000), so coverage is the merged union of both sources rather
/// than one window per image run.
pub(super) fn validate_capacities(
    profile: &ResolvedProfile,
    regions: &BTreeMap<String, NativeImageRegion>,
    image: &SparseDeviceImage,
) -> Result<(), CompileError> {
    let windows = profile.source().memory_segments.as_ref().map_or(&[][..], |memory| memory.segments.as_slice());

    // Property/relative images are bounded by their resource declarations,
    // not the physical MemorySegments list. Absolute profiles that publish
    // no memory map are validated later by their procedure write ranges.
    if windows.is_empty() {
        return Ok(());
    }

    let declared = windows
        .iter()
        .filter_map(|window| match window.location.to_address_space() {
            Ok(AddressSpaceLocation::StandardMemory { start_address }) => {
                Some((ImageSpace::StandardMemory, start_address, window.length))
            }
            Ok(AddressSpaceLocation::UserMemory { start_address }) => {
                Some((ImageSpace::UserMemory, start_address, window.length))
            }
            _ => None,
        })
        .chain(regions.values().map(|region| (region.location.space.clone(), region.location.offset, region.length)));
    let coverage = merged_coverage(declared);

    for segment in image.segments() {
        let location = segment.location();
        if !matches!(location.space, ImageSpace::StandardMemory | ImageSpace::UserMemory) {
            continue;
        }

        let start = u64::from(location.offset);
        let end = u64::from(segment.end_offset());
        let covered = coverage.iter().any(|(space, covered_start, covered_end)| {
            *space == location.space && start >= *covered_start && end <= *covered_end
        });
        if !covered {
            return Err(CompileError::invalid(format!(
                "image range {location:?}, length {length} lies outside declared memory segments",
                location = location.clone(),
                length = segment.data().len()
            )));
        }
    }

    Ok(())
}

/// Merge overlapping and adjacent `(space, start, length)` intervals into
/// half-open `(space, start, end)` ranges, so a range spanning two touching
/// declarations is covered.
fn merged_coverage(declared: impl Iterator<Item = (ImageSpace, u32, u32)>) -> Vec<(ImageSpace, u64, u64)> {
    let mut intervals: Vec<(ImageSpace, u64, u64)> = declared
        .map(|(space, start, length)| (space, u64::from(start), u64::from(start) + u64::from(length)))
        .collect();
    intervals.sort_by(|left, right| (&left.0, left.1).cmp(&(&right.0, right.1)));

    let mut merged: Vec<(ImageSpace, u64, u64)> = Vec::new();
    for (space, start, end) in intervals {
        match merged.last_mut() {
            Some((last_space, _, last_end)) if *last_space == space && start <= *last_end => {
                *last_end = (*last_end).max(end);
            }
            _ => merged.push((space, start, end)),
        }
    }
    merged
}

/// Preserve declared allocations before presenting any uncovered generated ranges.
pub(super) fn native_regions(
    product: &ProductData,
    mut buffers: BTreeMap<String, NativeImageRegion>,
    image: &SparseDeviceImage,
) -> Vec<NativeImageRegion> {
    let mut regions: Vec<_> = product.segments().iter().filter_map(|source| buffers.remove(&source.id)).collect();
    // Adjacent product allocations remain separate even when their desired
    // bits coalesce in the execution image. Generated property and table
    // regions fill only ranges not represented by those native allocations.
    let declared: Vec<_> =
        regions.iter().map(|region| (region.location.clone(), region.location.offset + region.length)).collect();
    for segment in image.segments() {
        let mut start = None;
        for index in 0..=segment.data().len() {
            let covered = index == segment.data().len()
                || declared.iter().any(|(location, end)| {
                    location.space == segment.location().space
                        && segment.location().offset + index as u32 >= location.offset
                        && segment.location().offset + (index as u32) < *end
                });
            match (start, covered) {
                (None, false) => start = Some(index),
                (Some(first), true) => {
                    let location = ImageLocation {
                        space: segment.location().space.clone(),
                        offset: segment.location().offset + first as u32,
                    };
                    regions.push(NativeImageRegion {
                        source_id: None,
                        memory_type: None,
                        seed: Vec::new(),
                        location,
                        length: (index - first) as u32,
                    });
                    start = None;
                }
                _ => {}
            }
        }
    }
    regions
}

pub(super) fn required_intersects(required: &[RequiredImageRange], location: &ImageLocation, length: u32) -> bool {
    let Some(end) = location.offset.checked_add(length) else {
        return true;
    };

    required.iter().any(|range| {
        if range.location.space != location.space {
            return false;
        }
        let Some(required_end) = range.location.offset.checked_add(range.length) else {
            return true;
        };

        location.offset < required_end && range.location.offset < end
    })
}

pub(super) fn apply_fixups(
    profile: &ResolvedProfile,
    product: &ProductData,
    buffers: &BTreeMap<String, NativeImageRegion>,
    image: &mut SparseDeviceImage,
    demand: ImageDemand<'_>,
) -> Result<(), CompileError> {
    for fixup in product.fixups() {
        let Some(buffer) = buffers.get(&fixup.code_segment) else {
            if !demand.is_complete() {
                continue;
            }
            return Err(CompileError::invalid(format!(
                "{purpose} refers to missing product segment {segment:?}",
                purpose = format!("fixup {}", fixup.function),
                segment = fixup.code_segment.clone()
            )));
        };
        let mut offsets = Vec::new();
        for &offset in &fixup.offsets {
            let Some(absolute) = buffer.location.offset.checked_add(offset) else {
                // A complete image owns every fixup. A demand for representable
                // ranges cannot select an address beyond the image space.
                if demand.is_complete() {
                    return Err(CompileError::invalid(format!("fixup {:?} address overflows", fixup.function)));
                }
                continue;
            };
            if demand.includes(&ImageLocation { space: buffer.location.space.clone(), offset: absolute }, 2) {
                offsets.push(offset);
            }
        }
        if offsets.is_empty() {
            continue;
        }
        let address = profile.mask_source().mask_entry_address(&fixup.function).ok_or_else(|| {
            CompileError::invalid(format!(
                "mask {} has no entry point for referenced fixup {:?}",
                profile.mask().full_id,
                fixup.function
            ))
        })?;
        let encoded = u16::try_from(address).map_err(|_| {
            CompileError::invalid(format!(
                "fixup {function:?} resolves to {address:#x}, beyond its 16-bit native pointer",
                function = fixup.function.clone(),
                address = address
            ))
        })?;
        for offset in offsets {
            image.apply_section(
                ProgrammingSection::ApplicationProgram1,
                &region_patch(buffer, offset, encoded.to_be_bytes().to_vec(), vec![u8::MAX; 2])?,
            );
        }
    }
    Ok(())
}

pub(super) fn apply_application_identity(
    profile: &ResolvedProfile,
    product: &ProductData,
    image: &mut SparseDeviceImage,
    demand: ImageDemand<'_>,
) -> Result<(), CompileError> {
    let identity = product.application_identity();
    for (name, value) in [
        ("ApplicationId", identity.application_id.as_slice()),
        ("ApplicationPeiType", core::slice::from_ref(&identity.pei_type)),
    ] {
        let Some(resource) = profile.resource(name)? else {
            continue;
        };
        let location = match rules::resource(&resource) {
            Ok(location) => location,
            Err(_) if !demand.is_complete() => continue,
            Err(error) => return Err(error),
        };
        if !demand.includes(&location, resource.length().max(value.len() as u32)) {
            continue;
        }
        let value = application_identity_resource_value(name, resource.length(), value)?;
        let segment = ImageSegment::owned(location, value.to_vec())?;
        image.apply_section(ProgrammingSection::ApplicationProgram1, &segment);
    }
    Ok(())
}

/// Fit the product-wide identity representation to the exact resource codec.
///
/// BCU1 publishes a four-byte `ApplicationId`: one manufacturer octet, the
/// two-octet application number, and its version. `ApplicationIdentity` keeps
/// the later, universal two-octet manufacturer representation, so only a
/// zero-extended manufacturer can be encoded in that legacy resource. The
/// resource width is the layout authority; `ManagementModel` is deliberately
/// not used as a surrogate format switch.
pub(in crate::commissioning) fn application_identity_resource_value<'a>(
    resource_name: &str,
    resource_length: u32,
    value: &'a [u8],
) -> Result<&'a [u8], CompileError> {
    let valid_length = match resource_name {
        "ApplicationId" => matches!(resource_length, 4 | 5),
        "PeiprogId" => resource_length == 5,
        "ApplicationPeiType" => resource_length == 1,
        _ => true,
    };
    if !valid_length {
        return Err(CompileError::invalid(format!(
            "identity resource {resource:?} has unsupported length {length}",
            resource = resource_name.to_owned(),
            length = resource_length
        )));
    }

    let value = if resource_name == "ApplicationId" && resource_length == 4 && value.first() == Some(&0) {
        &value[1..]
    } else {
        value
    };

    if resource_length != 0 && value.len() > resource_length as usize {
        return Err(CompileError::invalid(format!(
            "resource {resource:?} has capacity {capacity}, but its value has {value_length} bytes",
            resource = resource_name.to_owned(),
            value_length = value.len(),
            capacity = resource_length
        )));
    }

    Ok(value)
}
