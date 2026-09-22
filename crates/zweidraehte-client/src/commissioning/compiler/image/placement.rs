//! Table allocation is independent of wire encoding.
//! Most resources keep authored locations. BCU1's shared pool relocates the
//! association table and releases unused firmware seed bytes before parameters.

use super::communication::TableSpec;
use super::tables::{AssociationTable, TableInput};
use super::{CompiledTableKind, ImageDemand, region_patch};
use crate::commissioning::catalog::profile::{ResolvedProfile, ResourceFlavour};
use crate::commissioning::error::CompileError;
use crate::commissioning::image::{ImageLocation, ImageSegment, ImageSpace, NativeImageRegion, SparseDeviceImage};
use std::collections::BTreeMap;
use zweidraehte_project::ProgrammingSection;

pub(super) enum TablePlacement {
    Fixed,
    Shared(Bcu1Allocation),
}

impl TablePlacement {
    pub fn prepare(
        profile: &ResolvedProfile,
        input: &TableInput<'_>,
        buffers: &BTreeMap<String, NativeImageRegion>,
        image: &mut SparseDeviceImage,
        demand: ImageDemand<'_>,
    ) -> Result<Self, CompileError> {
        if !input.product.dynamic_table_management() {
            return Ok(Self::Fixed);
        }
        // Table realizations, not mask suffixes, select the allocation rules.
        // TODO: add the other dynamic layouts when their ownership rules are established.
        // Stop at the first incompatible realization. A scoped operation may
        // have no dependency on the other table's unrecognized format.
        if profile.resource("GroupAssociationTable")?.map(|r| r.flavour()).transpose()?.flatten()
            != Some(ResourceFlavour::AssociationTableBcu1)
            || profile.resource("GroupAddressTable")?.map(|r| r.flavour()).transpose()?.flatten()
                != Some(ResourceFlavour::AddressTableBcu1)
        {
            return Ok(Self::Fixed);
        }
        Ok(Bcu1Allocation::prepare(input, buffers, image, demand)?.map_or(Self::Fixed, Self::Shared))
    }

    pub fn configure(&self, table: &mut TableSpec<'_>) {
        if let Self::Shared(allocation) = self {
            match table.kind {
                CompiledTableKind::GroupAddress => {
                    table.max_entries = None;
                    // Address assignment owns the IA slot, including its seed.
                    table.preserve = 1..3;
                }
                CompiledTableKind::Association => {
                    table.offset = allocation.association_offset;
                    table.max_entries = None;
                }
                CompiledTableKind::GroupObject => {}
            }
        }
    }

    pub fn write_pointer(&self, image: &mut SparseDeviceImage) {
        if let Self::Shared(allocation) = self {
            image.apply_section(ProgrammingSection::GroupCommunication, &allocation.pointer);
        }
    }
}

pub(super) struct Bcu1Allocation {
    association_offset: u32,
    pointer: ImageSegment,
}

impl Bcu1Allocation {
    fn prepare(
        input: &TableInput<'_>,
        buffers: &BTreeMap<String, NativeImageRegion>,
        image: &mut SparseDeviceImage,
        demand: ImageDemand<'_>,
    ) -> Result<Option<Self>, CompileError> {
        let product = input.product;
        let capacity_error = || {
            CompileError::invalid(format!(
                "{0} exceeds its declared table capacity",
                "BCU1 dynamic communication allocation"
            ))
        };
        let segment = product.association_table_segment().ok_or_else(capacity_error)?;
        if product.address_table_segment() != Some(segment) {
            return Err(capacity_error());
        }
        let Some(buffer) = buffers.get(segment) else {
            if !demand.is_complete() {
                return Ok(None);
            }
            return Err(CompileError::invalid(format!(
                "{purpose} refers to missing product segment {segment:?}",
                purpose = "BCU1 dynamic communication allocation".to_owned(),
                segment = segment.to_owned()
            )));
        };
        let base = buffer.location.offset;
        if buffer.location.space != ImageSpace::StandardMemory
            || base.checked_add(product.address_table_offset()) != Some(0x116)
        {
            return Err(capacity_error());
        }
        let nominal_association = base.checked_add(product.association_table_offset()).ok_or_else(capacity_error)?;
        let nominal_addresses = u32::from(product.address_table_max_entries().ok_or_else(capacity_error)?);
        let nominal_associations = u32::from(product.association_table_max_entries().ok_or_else(capacity_error)?);
        let allocation_end =
            nominal_association.checked_add(1 + 2 * nominal_associations).ok_or_else(capacity_error)?;
        if nominal_association < 0x119 || allocation_end < 0x119 {
            return Err(capacity_error());
        }
        if product.com_object_table_segment() == Some(segment)
            && base.checked_add(product.com_object_table_offset()).is_none_or(|start| start < allocation_end)
        {
            return Err(capacity_error());
        }
        if !demand.includes(&ImageLocation::standard_memory(0x119), allocation_end - 0x119)
            && !demand.includes(&ImageLocation::standard_memory(0x111), 1)
            && !demand.includes(&ImageLocation::standard_memory(0x116), 1)
        {
            return Ok(None);
        }

        let address_size = u32::try_from(input.groups.len())
            .ok()
            .and_then(|count| count.checked_mul(2))
            .and_then(|size| size.checked_add(3))
            .ok_or_else(capacity_error)?;
        let association_size = u32::try_from(
            AssociationTable::from_flavour(ResourceFlavour::AssociationTableBcu1)?
                .encode(&input.associations()?, product.com_object_numbers())?
                .data
                .len(),
        )
        .map_err(|_| capacity_error())?;
        // Dynamic management borrows capacity between the two nominal tables.
        // Their total allocation still bounds the used bytes, including headers.
        let used = address_size.checked_add(association_size).ok_or_else(capacity_error)?;
        if used > 3 + 2 * nominal_addresses + 1 + 2 * nominal_associations
            || 0x116u32.checked_add(used).is_none_or(|end| end > allocation_end)
        {
            return Err(capacity_error());
        }
        let association_address = 0x116u32.checked_add(address_size).ok_or_else(capacity_error)?;
        let pointer = u8::try_from(association_address.checked_sub(0x100).ok_or_else(capacity_error)?)
            .map_err(|_| capacity_error())?;
        let start =
            usize::try_from(0x119u32.checked_sub(base).ok_or_else(capacity_error)?).map_err(|_| capacity_error())?;
        let end = usize::try_from(allocation_end.checked_sub(base).ok_or_else(capacity_error)?)
            .map_err(|_| capacity_error())?;
        let pointer_offset = 0x111u32.checked_sub(base).ok_or_else(capacity_error)?;
        if pointer_offset >= buffer.length || end > buffer.length as usize || start > end {
            return Err(capacity_error());
        }
        let pointer = region_patch(buffer, pointer_offset, vec![pointer], vec![u8::MAX])?;
        image.invalidate(&ImageLocation::standard_memory(base + start as u32), (end - start) as u32);
        Ok(Some(Self { association_offset: association_address - base, pointer }))
    }
}
