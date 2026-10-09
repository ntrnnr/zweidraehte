//! Table allocation is independent of wire encoding.
//! Most resources keep authored locations. BCU1's shared pool relocates the
//! association table and releases unused firmware seed bytes before parameters.
//! BCU2 and System 7 adjacent segments are resized so the association table follows
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
    Split(AdjacentTableAllocation),
}

/// A product segment whose allocation the placement policy changed. The
/// image regions and the load procedure's allocation records follow it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commissioning::compiler) struct SegmentRelocation {
    pub segment_id: String,
    pub from: (u32, u32),
    pub to: (u32, u32),
    /// System 7 also announces the association address with a task record.
    pub move_task: bool,
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
        // Complete downloads can resize adjacent legacy table segments. Scoped
        // reads retain authored geometry and need not resolve unrelated codecs.
        let association = profile.resource("GroupAssociationTable")?.map(|r| r.flavour()).transpose()?.flatten();
        if demand.is_complete()
            && matches!(
                association,
                Some(ResourceFlavour::AssociationTableBcu2 | ResourceFlavour::AssociationTableM112)
            )
        {
            let address_flavour =
                profile.resource("GroupAddressTable")?.map(|r| r.flavour()).transpose().ok().flatten().flatten();
            if address_flavour != Some(ResourceFlavour::AddressTableBcu1) {
                return Ok(Self::Fixed);
            }
            let flavour = association.expect("adjacent table flavour matched");
            return Ok(
                AdjacentTableAllocation::prepare(input, buffers, image, flavour)?.map_or(Self::Fixed, Self::Split)
            );
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
            Self::Split(allocation) => {
                if let Some(pointer) = &allocation.pointer {
                    image.apply_section(ProgrammingSection::GroupCommunication, pointer);
                }
            }
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

/// Dynamic legacy tables share the capacity of two adjacent segments.
///
/// BCU2 uses an even address-table length (`4 + 2 * groups`) and updates
/// the byte pointer at 0x111. System 7 uses exactly `3 + 2 * groups` at
/// 0x4000 and announces its association address through a task record instead.
/// Both keep the combined allocation end.
pub(super) struct AdjacentTableAllocation {
    address: NativeImageRegion,
    association: NativeImageRegion,
    pointer: Option<ImageSegment>,
    relocations: Vec<SegmentRelocation>,
}

impl AdjacentTableAllocation {
    fn prepare(
        input: &TableInput<'_>,
        buffers: &BTreeMap<String, NativeImageRegion>,
        image: &mut SparseDeviceImage,
        flavour: ResourceFlavour,
    ) -> Result<Option<Self>, CompileError> {
        let product = input.product;
        let system7 = flavour == ResourceFlavour::AssociationTableM112;
        let capacity_error =
            || CompileError::invalid("dynamic adjacent table allocation exceeds its declared table capacity");

        // TODO: measure shared-segment and non-adjacent dynamic layouts before
        // changing their authored geometry. These rules describe two full table
        // segments, not arbitrary regions that happen to contain table bytes.
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
        let end =
            association_buffer.location.offset.checked_add(association_buffer.length).ok_or_else(capacity_error)?;
        if address_id == association_id
            || product.address_table_offset() != 0
            || product.association_table_offset() != 0
            || address_buffer.location != ImageLocation::standard_memory(if system7 { 0x4000 } else { 0x116 })
            || association_buffer.location.space != ImageSpace::StandardMemory
            || start.checked_add(address_buffer.length) != Some(association_buffer.location.offset)
        {
            return Ok(None);
        }

        let groups = u32::try_from(input.groups.len()).map_err(|_| capacity_error())?;
        let address_length = groups
            .checked_mul(2)
            .and_then(|words| words.checked_add(if system7 { 3 } else { 4 }))
            .ok_or_else(capacity_error)?;
        let association_start = start.checked_add(address_length).ok_or_else(capacity_error)?;
        let association_used = u32::try_from(
            AssociationTable::from_flavour(flavour)?
                .encode(&input.associations()?, product.com_object_numbers())?
                .data
                .len(),
        )
        .map_err(|_| capacity_error())?;
        if association_start.checked_add(association_used).is_none_or(|used_end| used_end > end) {
            return Err(capacity_error());
        }
        let pointer = if system7 {
            None
        } else {
            let value = u8::try_from(association_start - 0x100).map_err(|_| capacity_error())?;
            Some(ImageSegment::new(ImageLocation::standard_memory(0x111), vec![value], vec![u8::MAX])?)
        };

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
            pointer,
            relocations: vec![
                SegmentRelocation {
                    segment_id: address_id.to_owned(),
                    from: (start, address_buffer.length),
                    to: (start, address_length),
                    move_task: false,
                },
                SegmentRelocation {
                    segment_id: association_id.to_owned(),
                    from: (association_buffer.location.offset, association_buffer.length),
                    to: (association_start, end - association_start),
                    move_task: system7,
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
/// The relocated geometry belongs in the `LdCtrlAbsSegment` records, so each
/// record allocating an old segment, its invalidation effect and its implicit
/// transfer follow the new address and length. LoadRecord adapts the endpoint
/// framing to the shared protocol codecs; placement only changes typed fields.
pub(in crate::commissioning::compiler) fn relocate_allocations(
    procedure: &mut NormalizedProcedure,
    relocations: &[SegmentRelocation],
) -> Result<(), CompileError> {
    for step in &mut procedure.steps {
        // A System 7 association task points at the relocated table; its
        // application identity and PEI type remain unchanged.
        if let ProcedureOperation::LoadRecord(record) = &mut step.operation {
            let Some(mut segment) = record.task_segment() else { continue };
            if let Some(relocation) =
                relocations.iter().find(|r| r.move_task && r.from.0 == u32::from(segment.start_address))
            {
                segment.start_address = u16::try_from(relocation.to.0)
                    .map_err(|_| CompileError::invalid("relocated task address does not fit a load record"))?;
                record.set_task_segment(segment)?;
            }
            continue;
        }
        let ProcedureOperation::AbsoluteSegment { record, transfers } = &mut step.operation else { continue };
        let mut segment = record
            .absolute_segment()
            .ok_or_else(|| CompileError::invalid("absolute allocation has an invalid load record"))?;
        let declared = (u32::from(segment.start_address), u32::from(segment.length));
        let Some(relocation) = relocations.iter().find(|relocation| relocation.from == declared) else { continue };

        let invalid = || CompileError::invalid("relocated allocation does not fit a load record");
        let (address, length) = relocation.to;
        segment.start_address = u16::try_from(address).map_err(|_| invalid())?;
        segment.length = u16::try_from(length).map_err(|_| invalid())?;
        record.set_absolute_segment(segment)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commissioning::compiler::binding::procedure::test_support::compile_fixture;
    use zweidraehte_ets_files::schema::{LdCtrlAbsSegment, LoadControl, LoadProcedure};

    #[test]
    fn system7_task_relocation_preserves_identity_and_unrelated_records() {
        use zweidraehte_ets_files::schema::LdCtrlTaskSegment;
        use zweidraehte_proto::messages::apdu::load_control::{LoadControlRecord, LsmMachine, MemLoadControlRecord};

        let mut procedure = compile_fixture(
            LoadProcedure {
                merge_id: None,
                controls: vec![LoadControl::LdCtrlTaskSegment(LdCtrlTaskSegment {
                    lsm_idx: Some(2),
                    address: 0x41f7,
                    ..Default::default()
                })],
            },
            Vec::new(),
        )
        .expect("task compiles");
        let original = procedure.steps[0].clone();
        for memory in [false, true] {
            let encode = |address| {
                if memory {
                    MemLoadControlRecord::task_segment(LsmMachine::AssociationTable, address, 7, [1, 2, 3, 4, 5])
                        .to_vec()
                } else {
                    LoadControlRecord::task_segment(address, 7, [1, 2, 3, 4, 5]).to_vec()
                }
            };
            let mut unrelated = original.clone();
            let ProcedureOperation::LoadRecord(record) = &mut unrelated.operation else { panic!("task record") };
            record.bytes = LoadControlRecord::task_segment(0x4300, 7, [1, 2, 3, 4, 5]).to_vec();
            procedure.steps = vec![original.clone(), unrelated.clone()];
            let ProcedureOperation::LoadRecord(record) = &mut procedure.steps[0].operation else {
                panic!("task record")
            };
            record.bytes = encode(0x41f7);
            if memory {
                record.write.target = OperationTarget::Memory {
                    service: crate::commissioning::procedure::operands::MemoryService::Classic,
                    address: MemoryAddress::Fixed(0x104),
                };
            }
            let relocation = SegmentRelocation {
                segment_id: "associations".into(),
                from: (0x41f7, 501),
                to: (0x4009, 995),
                move_task: true,
            };
            relocate_allocations(&mut procedure, &[relocation.clone()]).expect("task relocates");
            let ProcedureOperation::LoadRecord(record) = &procedure.steps[0].operation else { panic!("task record") };
            assert_eq!(record.bytes, encode(0x4009), "only the task address changes");
            assert_eq!(procedure.steps[1], unrelated, "other tasks retain their address");

            procedure.steps = vec![original.clone()];
            relocate_allocations(&mut procedure, &[SegmentRelocation { move_task: false, ..relocation }])
                .expect("BCU2 leaves task records alone");
            assert_eq!(procedure.steps[0], original);
        }
    }

    #[test]
    fn relocation_moves_the_allocation_record_effect_and_transfer() {
        let allocation = |address, size| {
            LoadControl::LdCtrlAbsSegment(LdCtrlAbsSegment {
                lsm_idx: Some(2),
                address,
                size,
                mem_type: 3,
                ..Default::default()
            })
        };
        // The association segment of M-00EE_A-4301 moves to follow a
        // 16-group address table; an unrelated allocation stays put.
        let mut procedure = compile_fixture(
            LoadProcedure { merge_id: None, controls: vec![allocation(330, 50), allocation(461, 675)] },
            Vec::new(),
        )
        .expect("allocations compile");
        let relocation =
            SegmentRelocation { segment_id: "AS-014A".to_owned(), from: (330, 50), to: (314, 66), move_task: false };
        relocate_allocations(&mut procedure, &[relocation]).expect("relocation applies");

        let ProcedureOperation::AbsoluteSegment { record, transfers } = &procedure.steps[0].operation else {
            panic!("allocation step")
        };
        let segment = record.absolute_segment().expect("allocation decodes");
        assert_eq!((segment.start_address, segment.length), (314, 66));
        assert_eq!(record.effect, LoadEffect::Invalidate { location: ImageLocation::standard_memory(314), length: 66 });
        let [transfer] = transfers.as_slice() else { panic!("one implicit transfer") };
        assert_eq!(transfer.data, OperationData::ImageWindow {
            location: ImageLocation::standard_memory(314),
            maximum: 66
        });
        assert_eq!(transfer.extent, OperationExtent::bytes(66));
        assert!(matches!(transfer.target, OperationTarget::Memory { address: MemoryAddress::Fixed(314), .. }));

        let ProcedureOperation::AbsoluteSegment { record, .. } = &procedure.steps[1].operation else {
            panic!("second allocation")
        };
        let segment = record.absolute_segment().expect("unrelated allocation decodes");
        assert_eq!((segment.start_address, segment.length), (461, 675), "unrelated allocation unchanged");
    }
}
