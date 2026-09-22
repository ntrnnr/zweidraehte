//! Compile every communication table through the same masked-byte contract.

use super::placement::TablePlacement;
use super::tables::{TableCodec, TableInput};
use super::{CompiledTableKind, CompiledTableSpan, ImageDemand};
use crate::commissioning::catalog::profile::ResolvedProfile;
use crate::commissioning::catalog::rules;
use crate::commissioning::error::CompileError;
use crate::commissioning::image::{ImageLocation, ImageSegment, NativeImageRegion, SparseDeviceImage};
use crate::configuration::LoweredDeviceConfiguration;
use std::collections::BTreeMap;
use std::ops::Range;
use zweidraehte_ets_files::product::ProductData;
use zweidraehte_project::ProgrammingSection;

/// Owns one device's table input and selected allocation policy across producers.
pub(super) struct CommunicationTables<'a> {
    profile: &'a ResolvedProfile,
    input: TableInput<'a>,
    buffers: &'a BTreeMap<String, NativeImageRegion>,
    demand: ImageDemand<'a>,
    placement: TablePlacement,
}

impl<'a> CommunicationTables<'a> {
    pub fn prepare(
        profile: &'a ResolvedProfile,
        product: &'a ProductData,
        configuration: &'a LoweredDeviceConfiguration,
        buffers: &'a BTreeMap<String, NativeImageRegion>,
        image: &mut SparseDeviceImage,
        demand: ImageDemand<'a>,
    ) -> Result<Self, CompileError> {
        let input = TableInput::new(product, configuration);
        let placement = TablePlacement::prepare(profile, &input, buffers, image, demand)?;
        Ok(Self { profile, input, buffers, demand, placement })
    }

    pub fn write(&self, image: &mut SparseDeviceImage) -> Result<Vec<CompiledTableSpan>, CompileError> {
        let mut spans = Vec::new();
        self.placement.write_pointer(image);

        for mut table in TableSpec::for_product(self.input.product) {
            self.placement.configure(&mut table);
            // Resolve the location and demand before selecting a codec. Scoped
            // identity reads must not require unrelated table capabilities.
            let Some(resource) = self.profile.resource(table.name)? else { continue };
            let region = match table.segment {
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
                None => match rules::resource(&resource) {
                    Ok(location) => location,
                    Err(_) if !self.demand.is_complete() => continue,
                    Err(error) => return Err(error),
                },
            };
            // A resource may describe only the count header; the native
            // allocation bounds rows that follow it.
            let capacity = region
                .map(|r| r.length.saturating_sub(table.offset))
                .unwrap_or_else(|| if resource.length() != 0 { resource.length() } else { u32::MAX - location.offset });
            if !self.demand.includes(&location, capacity) {
                continue;
            }

            let flavour = resource
                .flavour()?
                .ok_or_else(|| CompileError::invalid(format!("table resource {:?} has no flavour", table.name,)))?;
            let codec = TableCodec::new(table.kind, flavour)?;
            let mut encoded = codec.encode(&self.input, || {
                let region = region.ok_or_else(|| {
                    CompileError::invalid(format!(
                        "{} with flavour {:?} requires product-owned table data",
                        table.name,
                        flavour.to_string(),
                    ))
                })?;
                table.seed(region, &location, image)
            })?;
            if table.max_entries.is_some_and(|max| encoded.entries > usize::from(max)) {
                return Err(CompileError::invalid(format!("{} exceeds its declared table capacity", table.name)));
            }
            if region.is_some_and(|r| u64::from(table.offset) + encoded.data.len() as u64 > u64::from(r.length)) {
                return Err(CompileError::invalid("compiled patch lies outside its product segment"));
            }
            encoded.mask[table.preserve.clone()].fill(0);
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
    pub max_entries: Option<u16>,
    pub preserve: Range<usize>,
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
                preserve: 0..0,
            },
            Self {
                kind: CompiledTableKind::Association,
                name: "GroupAssociationTable",
                segment: product.association_table_segment(),
                offset: product.association_table_offset(),
                max_entries: product.association_table_max_entries(),
                preserve: 0..0,
            },
            Self {
                kind: CompiledTableKind::GroupObject,
                name: "GroupObjectTable",
                segment: product.com_object_table_segment(),
                offset: product.com_object_table_offset(),
                max_entries: None,
                preserve: 0..0,
            },
        ]
    }

    fn seed(
        &self,
        region: &NativeImageRegion,
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
        Ok(image.overlay(location, &seed[offset..])?)
    }
}
