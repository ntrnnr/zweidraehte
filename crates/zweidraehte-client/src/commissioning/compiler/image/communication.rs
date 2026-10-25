//! Compile every communication table through the same masked-byte contract.

use super::placement::TablePlacement;
use super::tables::{TableCodec, TableInput, TableSeed};
use super::{CompiledTableKind, CompiledTableSpan, ImageDemand};
use crate::commissioning::catalog::profile::{ResolvedProfile, ResourceFlavour};
use crate::commissioning::catalog::rules;
use crate::commissioning::error::{CompileError, OverflowedTable};
use crate::commissioning::image::{ImageLocation, ImageSegment, ImageSpace, NativeImageRegion, SparseDeviceImage};
use crate::configuration::MaterializedDevice;
use std::collections::BTreeMap;
use zweidraehte_ets_files::product::ProductData;
use zweidraehte_project::ProgrammingSection;

/// A scoped read of the end of a physical header also needs the segment that
/// contains its beginning. Keep lazy capability checks for unrelated reads:
/// unknown flavours still receive their normal diagnostic if selected later.
pub(super) fn seed_segments_with_table_headers(
    profile: &ResolvedProfile,
    product: &ProductData,
    demand: ImageDemand<'_>,
    image: &mut SparseDeviceImage,
) -> Result<BTreeMap<String, NativeImageRegion>, CompileError> {
    let ImageDemand::Ranges(required) = demand else { return super::seed_segments(product, demand, image) };
    let header = profile
        .resource("GroupObjectTable")
        .ok()
        .flatten()
        .and_then(|resource| resource.flavour().ok().flatten())
        .and_then(TableCodec::legacy_object_header_len);
    let segment =
        product.com_object_table_segment().and_then(|id| product.segments().iter().find(|segment| segment.id == id));
    if let (Some(length), Some(segment)) = (header, segment)
        && let Ok(mut location) = rules::product_segment(product, segment)
        && let Some(offset) = location.offset.checked_add(product.com_object_table_offset())
    {
        location.offset = offset;
        if demand.includes(&location, length) {
            let mut expanded = required.to_vec();
            expanded.push(crate::commissioning::image::RequiredImageRange { location, length });
            return super::seed_segments(product, ImageDemand::Ranges(&expanded), image);
        }
    }
    super::seed_segments(product, demand, image)
}

/// Owns one device's table input and selected allocation policy across producers.
pub(super) struct CommunicationTables<'a> {
    profile: &'a ResolvedProfile,
    input: TableInput<'a>,
    buffers: &'a BTreeMap<String, NativeImageRegion>,
    demand: ImageDemand<'a>,
    placement: TablePlacement,
}

impl<'a> CommunicationTables<'a> {
    #[cfg(test)]
    pub fn prepare(
        profile: &'a ResolvedProfile,
        product: &'a ProductData,
        device: &'a MaterializedDevice,
        buffers: &'a BTreeMap<String, NativeImageRegion>,
        image: &mut SparseDeviceImage,
        demand: ImageDemand<'a>,
    ) -> Result<Self, CompileError> {
        Self::prepare_for_program(profile, product, device, buffers, image, demand, None)
    }

    pub fn prepare_for_program(
        profile: &'a ResolvedProfile,
        product: &'a ProductData,
        device: &'a MaterializedDevice,
        buffers: &'a BTreeMap<String, NativeImageRegion>,
        image: &mut SparseDeviceImage,
        demand: ImageDemand<'a>,
        program: Option<&crate::commissioning::procedure::NormalizedProcedure>,
    ) -> Result<Self, CompileError> {
        let input = TableInput::new(product, device);
        let placement = TablePlacement::prepare(profile, &input, buffers, image, demand, program)?;
        Ok(Self { profile, input, buffers, demand, placement })
    }

    /// Parameter loading also fills wholly unowned System 300 descriptor bytes.
    pub fn with_parameter_loading(mut self, enabled: bool) -> Self {
        self.input.load_parameters = enabled;
        self
    }

    /// Product allocations the selected placement resized or moved.
    pub fn relocations(&self) -> Vec<super::placement::SegmentRelocation> {
        self.placement.relocations()
    }

    pub fn write(&self, image: &mut SparseDeviceImage) -> Result<Vec<CompiledTableSpan>, CompileError> {
        let mut spans = Vec::new();
        self.placement.write_pointer(image);
        let system300 =
            self.profile.resource("GroupObjectTable")?.map(|resource| resource.flavour()).transpose()?.flatten()
                == Some(ResourceFlavour::GroupObjectTableSystem300);

        for mut table in TableSpec::for_product(self.input.product) {
            self.placement.configure(&mut table);
            // Resolve the location and demand before selecting a codec. Scoped
            // identity reads must not require unrelated table capabilities.
            let Some(resource) = self.profile.resource(table.name)? else { continue };
            let profile_location = rules::resource(&resource);
            let flavour = resource.flavour();
            // System B's formatters own the profile-relative table locations.
            // A legacy product's table references describe its firmware storage,
            // not a relocation of these tables into absolute memory.
            let profile_relative = matches!(
                (&profile_location, &flavour),
                (
                    Ok(ImageLocation { space: ImageSpace::RelativeMemory { .. }, .. }),
                    Ok(Some(
                        ResourceFlavour::AddressTableSystemB
                            | ResourceFlavour::AssociationTableSystemB
                            | ResourceFlavour::AssociationTableSystemBSmall
                            | ResourceFlavour::AssociationTableSystemBBig
                            | ResourceFlavour::GroupObjectTableSystemB
                    ))
                )
            );
            // System 300's formatters write property arrays. Legacy XML table
            // offsets do not relocate those arrays into a product code segment.
            let property_array =
                system300 && matches!(&profile_location, Ok(ImageLocation { space: ImageSpace::Property { .. }, .. }));
            let region = if profile_relative || property_array {
                None
            } else {
                match (&table.region, table.segment) {
                    (Some(region), _) => Some(region),
                    (None, segment) => match segment {
                        Some(id) => match self.buffers.get(id) {
                            Some(region) => Some(region),
                            None if !self.demand.is_complete() => continue,
                            None => {
                                return Err(CompileError::invalid(format!(
                                    "{name} refers to missing product segment {id:?}",
                                    name = table.name,
                                )));
                            }
                        },
                        None => None,
                    },
                }
            };
            let location = match region {
                Some(region) => ImageLocation {
                    space: region.location.space.clone(),
                    offset: region
                        .location
                        .offset
                        .checked_add(table.offset)
                        .ok_or(CompileError::invalid("compiled patch lies outside its product segment"))?,
                },
                None => match profile_location {
                    Ok(location) => location,
                    Err(_) if !self.demand.is_complete() => continue,
                    Err(error) => return Err(error.into()),
                },
            };
            // BCU2's formatter returns without an object-table patch when
            // FindSegment at the product's default table address (zero)
            // finds no storage. Interfaces with no object roster use this
            // path; an empty declared table still formats its real header.
            // Keep other missing-storage shapes as errors until proven.
            if table.kind == CompiledTableKind::GroupObject
                && matches!(&flavour, Ok(Some(ResourceFlavour::GroupObjectTableBcu2)))
                && matches!(&self.placement, TablePlacement::Fixed)
                && region.is_none()
                && table.segment.is_none()
                && self.input.product.com_object_numbers().is_empty()
                && self.input.device.com_objects().is_empty()
                && self.input.groups.is_empty()
                && matches!(&location.space, ImageSpace::Pointer { .. })
                && location.offset == 0
                && image.byte(&ImageLocation::standard_memory(0)).is_none()
            {
                continue;
            }
            // Native formatting addresses a physical header, which can cross
            // touching XML segments. Borrow only its missing header bytes from
            // compatible declared storage; keep original region metadata and
            // placement-defined allocation boundaries intact.
            let extension = if table.kind == CompiledTableKind::GroupObject
                && matches!(&self.placement, TablePlacement::Fixed)
                && let Some(region) = region
                && let Ok(Some(flavour)) = &flavour
                && let Some(length) = TableCodec::legacy_object_header_len(*flavour)
            {
                table.header_extension(region, length, self.buffers)
            } else {
                Vec::new()
            };
            // A resource may describe only the count header; the native
            // allocation bounds rows that follow it.
            let capacity = region
                .map(|r| r.length.saturating_sub(table.offset) + extension.len() as u32)
                .unwrap_or_else(|| if resource.length() != 0 { resource.length() } else { u32::MAX - location.offset });
            if !self.demand.includes(&location, capacity) {
                continue;
            }

            let flavour = flavour?
                .ok_or_else(|| CompileError::invalid(format!("table resource {:?} has no flavour", table.name,)))?;
            let codec = TableCodec::new(table.kind, flavour)?;
            let mut encoded = codec.encode(&self.input, || {
                if property_array && flavour == ResourceFlavour::GroupObjectTableSystem300 {
                    // Property parameters may seed DPT bytes for inactive
                    // static objects beyond the highest active instance.
                    let length = self.input.roster_numbers().into_iter().map(usize::from).max().unwrap_or(0) * 6;
                    location.offset.checked_add(length as u32).ok_or_else(|| {
                        CompileError::invalid("System 300 object table exceeds the image address space")
                    })?;
                    let mut data = Vec::with_capacity(length);
                    let mut mask = Vec::with_capacity(length);
                    for offset in 0..length {
                        let at =
                            ImageLocation { space: location.space.clone(), offset: location.offset + offset as u32 };
                        let (value, owned) = image.byte(&at).unwrap_or((0, 0));
                        data.push(value);
                        mask.push(owned);
                    }
                    return Ok(TableSeed { data, first_byte_owned: mask.first().is_some_and(|mask| *mask != 0), mask });
                }
                let region = region.ok_or_else(|| {
                    CompileError::invalid(format!(
                        "{} with flavour {:?} requires product-owned table data",
                        table.name,
                        flavour.to_string(),
                    ))
                })?;
                let data = table.seed(region, &extension, &location, image)?;
                location
                    .offset
                    .checked_add(data.len() as u32)
                    .ok_or_else(|| CompileError::invalid("table seed exceeds the image address space"))?;
                let mask = (0..data.len())
                    .map(|offset| {
                        let at =
                            ImageLocation { space: location.space.clone(), offset: location.offset + offset as u32 };
                        image.byte(&at).map_or(0, |(_, mask)| mask)
                    })
                    .collect();
                Ok(TableSeed { data, mask, first_byte_owned: image.byte(&location).is_some_and(|(_, mask)| mask != 0) })
            })?;
            if property_array && table.kind != CompiledTableKind::GroupObject {
                // The memory formats prefix their count; property element zero
                // carries that count separately from the ordinary array values.
                if encoded.data.len() < 2 || encoded.mask.len() < 2 {
                    return Err(CompileError::invalid("System 300 table lacks its encoded count"));
                }
                drop(encoded.data.drain(..2));
                drop(encoded.mask.drain(..2));
            }
            if table.max_entries.is_some_and(|max| encoded.entries as u64 > u64::from(max)) {
                let message = format!("{} exceeds its declared table capacity", table.name);
                return Err(match table.kind {
                    CompiledTableKind::GroupAddress => {
                        CompileError::table_overflow(OverflowedTable::GroupAddress, message)
                    }
                    CompiledTableKind::Association => {
                        CompileError::table_overflow(OverflowedTable::Association, message)
                    }
                    // Object tables declare no entry maximum.
                    CompiledTableKind::GroupObject => CompileError::invalid(message),
                });
            }
            if region.is_some() && encoded.data.len() as u64 > u64::from(capacity) {
                return Err(CompileError::invalid("compiled patch lies outside its product segment"));
            }
            // Published memory windows allocate native storage just as product
            // segments do; either can contain the legacy association pointer.
            let association_pointer = match flavour {
                ResourceFlavour::AssociationTableBcu1 => true,
                ResourceFlavour::AssociationTableBcu2 => {
                    self.input
                        .product
                        .association_table_segment()
                        .and_then(|id| self.buffers.get(id))
                        .and_then(|region| {
                            region.location.offset.checked_add(self.input.product.association_table_offset())
                        })
                        .is_some_and(|nominal| (0x100..=0x1ff).contains(&nominal))
                        && super::allocation_coverage(self.profile, self.buffers).iter().any(|(space, start, end)| {
                            *space == ImageSpace::StandardMemory && *start <= 0x111 && *end > 0x111
                        })
                }
                _ => false,
            };
            if table.kind == CompiledTableKind::Association
                && association_pointer
                && location.space == ImageSpace::StandardMemory
                && self.demand.includes(&ImageLocation::standard_memory(0x111), 1)
            {
                // The legacy formatter writes the association pointer even
                // when fixed allocation leaves the table at its authored address.
                // BCU2 uses this one-byte pointer only for nominal page 0x100.
                image.apply_section(
                    ProgrammingSection::GroupCommunication,
                    &ImageSegment::owned(ImageLocation::standard_memory(0x111), vec![location.offset as u8])?,
                );
            }
            // Only encoded rows belong to the table transfer. Release seeded
            // spare capacity even when the product segment's mask owns it.
            if let (Some(region), Some(max_entries)) = (region, table.max_entries)
                && let Some(capacity) = codec.capacity(max_entries)?
            {
                let used = u64::from(location.offset) + encoded.data.len() as u64;
                let reserved = (u64::from(location.offset) + capacity)
                    .min(u64::from(region.location.offset) + u64::from(region.length));
                if reserved > used {
                    let start = ImageLocation { space: location.space.clone(), offset: used as u32 };
                    image.invalidate(&start, (reserved - used) as u32);
                }
            }
            // The legacy individual-address slot belongs to address
            // assignment. Authored seed bytes keep their ownership, but bytes
            // owned only because an unmasked allocation was zero-filled are
            // not configuration: M-006C_A-0908's unauthored BCU2 address
            // segment would otherwise send 00 00 into the device's address.
            if let (Some((start, length)), Some(region)) = (codec.individual_address_slot(), region)
                && location.offset + start >= region.location.offset + region.seed.len() as u32
            {
                let at = ImageLocation { space: location.space.clone(), offset: location.offset + start };
                image.invalidate(&at, length);
            }
            let patch = ImageSegment::new(location, encoded.data, encoded.mask)?;
            spans.push(CompiledTableSpan {
                kind: table.kind,
                location: patch.location().clone(),
                len: patch.data().len(),
            });
            image.apply_section(ProgrammingSection::GroupCommunication, &patch);
        }
        Ok(spans)
    }
}

/// Authored geometry plus the ownership changes made by the placement policy.
pub(super) struct TableSpec<'a> {
    pub kind: CompiledTableKind,
    name: &'static str,
    segment: Option<&'a str>,
    pub offset: u32,
    pub max_entries: Option<u32>,
    /// A placement-defined allocation replacing the product segment's.
    pub region: Option<NativeImageRegion>,
}

impl<'a> TableSpec<'a> {
    fn for_product(product: &'a ProductData) -> [Self; 3] {
        [
            Self {
                kind: CompiledTableKind::GroupAddress,
                name: "GroupAddressTable",
                segment: product.address_table_segment(),
                offset: product.address_table_offset(),
                max_entries: product.address_table_max_entries(),
                region: None,
            },
            Self {
                kind: CompiledTableKind::Association,
                name: "GroupAssociationTable",
                segment: product.association_table_segment(),
                offset: product.association_table_offset(),
                max_entries: product.association_table_max_entries(),
                region: None,
            },
            Self {
                kind: CompiledTableKind::GroupObject,
                name: "GroupObjectTable",
                segment: product.com_object_table_segment(),
                offset: product.com_object_table_offset(),
                max_entries: None,
                region: None,
            },
        ]
    }

    fn seed(
        &self,
        region: &NativeImageRegion,
        extension: &[u8],
        location: &ImageLocation,
        image: &SparseDeviceImage,
    ) -> Result<Vec<u8>, CompileError> {
        let offset = self.offset as usize;
        if self.offset > region.length {
            return Err(CompileError::invalid("group object table exceeds its declared table capacity"));
        }
        // Descriptor pointers may have been fixed up or parameterized. Preserve
        // their current image values, falling back to the product's seed.
        let mut seed = region.seed.clone();
        seed.resize(region.length as usize, 0);
        seed.extend_from_slice(extension);
        Ok(image.overlay(location, &seed[offset..])?)
    }

    fn header_extension(
        &self,
        region: &NativeImageRegion,
        header: u32,
        buffers: &BTreeMap<String, NativeImageRegion>,
    ) -> Vec<u8> {
        if self.offset > region.length {
            return Vec::new();
        }
        let mut missing = header.saturating_sub(region.length - self.offset);
        let Some(mut end) = region.location.offset.checked_add(region.length) else { return Vec::new() };
        let mut extension = Vec::new();
        while missing != 0 {
            let mut adjacent = buffers.values().filter(|next| {
                next.length != 0
                    && next.location.space == region.location.space
                    && next.memory_type == region.memory_type
                    && next.location.offset == end
            });
            let Some(next) = adjacent.next() else { return Vec::new() };
            if adjacent.next().is_some() {
                return Vec::new();
            }
            let take = missing.min(next.length);
            extension.extend((0..take).map(|offset| next.seed.get(offset as usize).copied().unwrap_or(0)));
            missing -= take;
            let Some(next_end) = end.checked_add(take) else { return Vec::new() };
            end = next_end;
        }
        // TODO: Establish cross-allocation row semantics before borrowing more
        // than the fixed header. Existing row and allocation bounds still apply.
        extension
    }
}
