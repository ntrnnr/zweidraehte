//! Table allocation is independent of wire encoding.
//! Most resources keep authored locations. BCU1's shared pool relocates the
//! association table and releases unused firmware seed bytes before parameters.
//! BCU2's adjacent table segments are resized so the association table follows
//! the used address table, which also moves their allocation records.

use super::communication::TableSpec;
use super::tables::{AssociationTable, TableInput};
use super::{CompiledTableKind, ImageDemand, region_patch};
use crate::commissioning::catalog::profile::{ResolvedProfile, ResourceFlavour};
use crate::commissioning::error::CompileError;
use crate::commissioning::image::{ImageLocation, ImageSegment, ImageSpace, NativeImageRegion, SparseDeviceImage};
use crate::commissioning::procedure::operands::MemoryAddress;
use crate::commissioning::procedure::{
    LoadEffect, NormalizedProcedure, OperationData, OperationExtent, OperationTarget, ProcedureOperation,
};
use std::collections::BTreeMap;
use zweidraehte_project::ProgrammingSection;

pub(super) enum TablePlacement {
    Fixed,
    Shared(Bcu1Allocation),
    Split(Bcu2Allocation),
}

/// A product segment whose allocation the placement policy changed. The
/// image regions and the load procedure's allocation records follow it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commissioning::compiler) struct SegmentRelocation {
    pub segment_id: String,
    pub from: (u32, u32),
    pub to: (u32, u32),
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
        // Only complete downloads relocate BCU2 tables. A scoped operation must
        // not depend on the address table's format, which may be unknown, so
        // that format is read only once the association format selects BCU2.
        if demand.is_complete()
            && profile.resource("GroupAssociationTable")?.map(|r| r.flavour()).transpose()?.flatten()
                == Some(ResourceFlavour::AssociationTableBcu2)
        {
            let address_flavour =
                profile.resource("GroupAddressTable")?.map(|r| r.flavour()).transpose().ok().flatten().flatten();
            if address_flavour != Some(ResourceFlavour::AddressTableBcu1) {
                return Ok(Self::Fixed);
            }
            return Ok(Bcu2Allocation::prepare(input, buffers, image, demand)?.map_or(Self::Fixed, Self::Split));
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
        if let Self::Split(allocation) = self {
            match table.kind {
                CompiledTableKind::GroupAddress => {
                    table.max_entries = None;
                    table.region = Some(allocation.address.clone());
                    // Address assignment owns the IA slot, as for BCU1.
                    table.preserve = 1..3;
                }
                CompiledTableKind::Association => {
                    table.offset = 0;
                    table.max_entries = None;
                    table.region = Some(allocation.association.clone());
                }
                CompiledTableKind::GroupObject => {}
            }
        }
    }

    pub fn write_pointer(&self, image: &mut SparseDeviceImage) {
        match self {
            Self::Shared(allocation) => {
                image.apply_section(ProgrammingSection::GroupCommunication, &allocation.pointer)
            }
            Self::Split(allocation) => image.apply_section(ProgrammingSection::GroupCommunication, &allocation.pointer),
            Self::Fixed => {}
        }
    }

    /// Allocations whose product geometry this placement changed.
    pub fn relocations(&self) -> Vec<SegmentRelocation> {
        match self {
            Self::Split(allocation) => allocation.relocations.clone(),
            Self::Fixed | Self::Shared(_) => Vec::new(),
        }
    }
}

/// BCU2 dynamic table management over two adjacent segments.
///
/// ETS resizes the address-table segment to the used table, rounded up to an
/// even length (`4 + 2 * groups`: count, individual address and one word per
/// group, plus a pad byte), and moves the association-table segment to start
/// right after it while keeping its end. The association pointer at 0x0111
/// names the new start. Measured with Hawk for 0, 1, 3, 9 and 16 groups on
/// M-00EE_A-4301 (segments 0x116+52 and 0x14A+50): address segment lengths
/// 4, 6, 10, 22 and 36, association segments following up to 0x17C.
pub(super) struct Bcu2Allocation {
    address: NativeImageRegion,
    association: NativeImageRegion,
    pointer: ImageSegment,
    relocations: Vec<SegmentRelocation>,
}

impl Bcu2Allocation {
    fn prepare(
        input: &TableInput<'_>,
        buffers: &BTreeMap<String, NativeImageRegion>,
        image: &mut SparseDeviceImage,
        demand: ImageDemand<'_>,
    ) -> Result<Option<Self>, CompileError> {
        let product = input.product;
        let capacity_error = || {
            CompileError::invalid(format!("{0} exceeds its declared table capacity", "BCU2 dynamic table allocation"))
        };

        // TODO: scoped reads and other BCU2 layouts (both tables in one
        // segment, as M-00E1_A-B002 declares) keep their authored geometry
        // until their ETS allocation is measured as well.
        if !demand.is_complete() {
            return Ok(None);
        }
        let (Some(address_id), Some(association_id)) =
            (product.address_table_segment(), product.association_table_segment())
        else {
            return Ok(None);
        };
        let (Some(address_buffer), Some(association_buffer)) = (buffers.get(address_id), buffers.get(association_id))
        else {
            return Ok(None);
        };
        let start = address_buffer.location.offset;
        let end = association_buffer.location.offset + association_buffer.length;
        if address_id == association_id
            || product.address_table_offset() != 0
            || product.association_table_offset() != 0
            || address_buffer.location != ImageLocation::standard_memory(0x116)
            || association_buffer.location.space != ImageSpace::StandardMemory
            || start + address_buffer.length != association_buffer.location.offset
        {
            return Ok(None);
        }

        let groups = u32::try_from(input.groups.len()).map_err(|_| capacity_error())?;
        let address_length = groups.checked_mul(2).and_then(|words| words.checked_add(4)).ok_or_else(capacity_error)?;
        let association_start = start.checked_add(address_length).ok_or_else(capacity_error)?;
        let association_used = u32::try_from(
            AssociationTable::from_flavour(ResourceFlavour::AssociationTableBcu2)?
                .encode(&input.associations()?, product.com_object_numbers())?
                .data
                .len(),
        )
        .map_err(|_| capacity_error())?;
        if association_start.checked_add(association_used).is_none_or(|used_end| used_end > end) {
            return Err(capacity_error());
        }
        let pointer = u8::try_from(association_start - 0x100).map_err(|_| capacity_error())?;

        // The resized segments carry the tables only; the product's seed bytes
        // for the old geometry no longer describe the device.
        image.invalidate(&ImageLocation::standard_memory(start), end - start);
        let region = |id: &str, offset: u32, length: u32| NativeImageRegion {
            source_id: Some(id.to_owned()),
            memory_type: None,
            seed: Vec::new(),
            location: ImageLocation::standard_memory(offset),
            length,
        };
        Ok(Some(Self {
            address: region(address_id, start, address_length),
            association: region(association_id, association_start, end - association_start),
            pointer: ImageSegment::new(ImageLocation::standard_memory(0x111), vec![pointer], vec![u8::MAX])?,
            relocations: vec![
                SegmentRelocation {
                    segment_id: address_id.to_owned(),
                    from: (start, address_buffer.length),
                    to: (start, address_length),
                },
                SegmentRelocation {
                    segment_id: association_id.to_owned(),
                    from: (association_buffer.location.offset, association_buffer.length),
                    to: (association_start, end - association_start),
                },
            ],
        }))
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

/// Move the load procedure's allocation records with their segments.
///
/// ETS sends the relocated geometry in the `LdCtrlAbsSegment` records, so each
/// record allocating an old segment, its invalidation effect and its implicit
/// transfer follow the new address and length. Both record spellings carry the
/// address and length as big-endian words after the type octet: property form
/// `[event][type][address][length]...`, memory form with a segment-ID octet
/// before the address.
pub(in crate::commissioning::compiler) fn relocate_allocations(
    procedure: &mut NormalizedProcedure,
    relocations: &[SegmentRelocation],
) -> Result<(), CompileError> {
    for step in &mut procedure.steps {
        let ProcedureOperation::AbsoluteSegment { record, transfers } = &mut step.operation else { continue };
        let offset = match record.bytes.len() {
            10 => 2,
            11 => 3,
            _ => continue,
        };
        let word = |bytes: &[u8], at: usize| u32::from(u16::from_be_bytes([bytes[at], bytes[at + 1]]));
        let declared = (word(&record.bytes, offset), word(&record.bytes, offset + 2));
        let Some(relocation) = relocations.iter().find(|relocation| relocation.from == declared) else { continue };

        let invalid = || CompileError::invalid("relocated allocation does not fit a load record");
        let (address, length) = relocation.to;
        let address_word = u16::try_from(address).map_err(|_| invalid())?.to_be_bytes();
        let length_word = u16::try_from(length).map_err(|_| invalid())?.to_be_bytes();
        record.bytes[offset..offset + 2].copy_from_slice(&address_word);
        record.bytes[offset + 2..offset + 4].copy_from_slice(&length_word);
        record.effect = LoadEffect::Invalidate { location: ImageLocation::standard_memory(address), length };

        for transfer in transfers.iter_mut() {
            let OperationData::ImageWindow { location, maximum } = &mut transfer.data else {
                return Err(CompileError::invalid("relocated allocation carries a non-window transfer"));
            };
            let OperationTarget::Memory { address: MemoryAddress::Fixed(target), .. } = &mut transfer.target else {
                return Err(CompileError::invalid("relocated allocation transfers through a non-absolute target"));
            };
            *location = ImageLocation::standard_memory(address);
            *maximum = length;
            *target = address;
            transfer.extent = OperationExtent::bytes(length);
        }
    }
    Ok(())
}
