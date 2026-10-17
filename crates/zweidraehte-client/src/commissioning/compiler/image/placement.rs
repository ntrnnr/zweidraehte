//! Table allocation is independent of wire encoding.
//! Most resources keep authored locations. BCU1/BCU2 shared pools relocate the
//! association tables and release unused firmware seed bytes before parameters.
//! BCU2 and System 7 adjacent segments are resized so the association table follows
//! the used address table, which also moves their allocation records.

use super::communication::TableSpec;
use super::tables::{AddressTable, AssociationTable, TableInput};
use super::{CompiledTableKind, ImageDemand, region_patch};
use crate::commissioning::catalog::profile::{ManagementModel, ResolvedProfile, ResourceFlavour};
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
    Shared(SharedTableAllocation),
    Split(AdjacentTableAllocation),
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
        program: Option<&NormalizedProcedure>,
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
            if let Some(allocation) =
                AdjacentTableAllocation::prepare(profile, input, buffers, image, flavour, program)?
            {
                return Ok(Self::Split(allocation));
            }
            // BCU2 also uses the legacy shared pool at 0x116. Its pointer
            // follows the used address bytes without segment-boundary
            // padding. Keep other layouts and unload geometry unchanged.
            if flavour == ResourceFlavour::AssociationTableBcu2
                && input.product.address_table_segment().is_some()
                && input.product.address_table_segment() == input.product.association_table_segment()
            {
                return Ok(SharedTableAllocation::prepare(profile, input, buffers, image, demand, flavour)?
                    .map_or(Self::Fixed, Self::Shared));
            }
            return Ok(Self::Fixed);
        }
        // Table realizations, not mask suffixes, select the allocation rules.
        // TODO: add the other dynamic layouts when their ownership rules are established.
        // Stop at the first incompatible realization. A scoped operation may
        // have no dependency on the other table's unrecognized format.
        if profile.resource("GroupAssociationTable")?.map(|r| r.flavour()).transpose()?.flatten()
            != Some(ResourceFlavour::AssociationTableBcu1)
            || !matches!(
                profile.resource("GroupAddressTable")?.map(|r| r.flavour()).transpose()?.flatten(),
                Some(ResourceFlavour::AddressTableBcu1 | ResourceFlavour::AddressTableBcu1Pl)
            )
        {
            return Ok(Self::Fixed);
        }
        Ok(SharedTableAllocation::prepare(
            profile,
            input,
            buffers,
            image,
            demand,
            ResourceFlavour::AssociationTableBcu1,
        )?
        .map_or(Self::Fixed, Self::Shared))
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
/// BCU2 adds an alignment byte to `3 + 2 * groups` when the address
/// allocation requests it (flag 0x80). System 7 uses exactly that length at
/// 0x4000 and has no pointer. Both keep the combined allocation end, and an
/// association task record follows the moved table.
pub(super) struct AdjacentTableAllocation {
    address: NativeImageRegion,
    association: NativeImageRegion,
    pointer: Option<ImageSegment>,
    relocations: Vec<SegmentRelocation>,
}

impl AdjacentTableAllocation {
    fn prepare(
        profile: &ResolvedProfile,
        input: &TableInput<'_>,
        buffers: &BTreeMap<String, NativeImageRegion>,
        image: &mut SparseDeviceImage,
        flavour: ResourceFlavour,
        program: Option<&NormalizedProcedure>,
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
        // The association segment follows the address segment, directly or
        // after a gap that no other segment uses: M-0001_A-9207 (BCU2) leaves
        // one byte between 0x116+205 and 0x1E4, M-017A_A-6138 (M112) two
        // after 0x4000+511. The reference compacts both the same way.
        let address_end = start.checked_add(address_buffer.length).ok_or_else(capacity_error)?;
        let gap = address_end..association_buffer.location.offset;
        let gap_is_free = buffers.iter().all(|(id, region)| {
            id == address_id
                || id == association_id
                || region.location.space != ImageSpace::StandardMemory
                || region.location.offset.saturating_add(region.length) <= gap.start
                || region.location.offset >= gap.end
        });
        if address_id == association_id
            || product.address_table_offset() != 0
            || product.association_table_offset() != 0
            || address_buffer.location != ImageLocation::standard_memory(if system7 { 0x4000 } else { 0x116 })
            || association_buffer.location.space != ImageSpace::StandardMemory
            || gap.start > gap.end
            || !gap_is_free
        {
            return Ok(None);
        }

        let padded = !system7 && address_allocation_flags(profile, product, address_buffer, program)? & 0x80 != 0;
        let address_capacity = product
            .address_table_max_entries()
            .map(|max| AddressTable::WithIndividualAddress.capacity(max) as u32)
            .ok_or_else(capacity_error)?;
        let association_capacity = u32::try_from(
            AssociationTable::from_flavour(flavour)?
                .capacity(product.association_table_max_entries().ok_or_else(capacity_error)?)?,
        )
        .map_err(|_| capacity_error())?;
        if address_capacity > address_buffer.length || association_capacity > association_buffer.length {
            return Err(capacity_error());
        }
        let groups = u32::try_from(input.groups.len()).map_err(|_| capacity_error())?;
        let address_length = groups
            .checked_mul(2)
            .and_then(|words| words.checked_add(3 + u32::from(padded)))
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

        // Release nominal table storage, preserving authored code bytes and
        // partial-bit ownership outside it at their absolute addresses. System
        // 7 does the same: authored seed bytes past each table's capacity (the
        // tail of a 513-byte address segment with 254 groups, for example)
        // stay owned and travel with the relocated association transfer.
        image.invalidate(&address_buffer.location, address_capacity);
        image.invalidate(&association_buffer.location, association_capacity);
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

pub(super) struct SharedTableAllocation {
    association_offset: u32,
    pointer: ImageSegment,
}

/// Select alignment from the exact typed program when it declares this
/// allocation. Partial programs and automatic previews may omit the record;
/// then inspect static allocation metadata without parsing unrelated controls.
fn address_allocation_flags(
    profile: &ResolvedProfile,
    product: &zweidraehte_ets_files::product::ProductData,
    region: &NativeImageRegion,
    program: Option<&NormalizedProcedure>,
) -> Result<u8, CompileError> {
    use std::collections::BTreeSet;
    use zweidraehte_ets_files::product::LoadProcedureStyle;
    use zweidraehte_ets_files::schema::LoadControl;

    let mut flags = BTreeSet::new();
    if let Some(program) = program {
        for step in &program.steps {
            let record = match &step.operation {
                ProcedureOperation::AbsoluteSegment { record, .. } | ProcedureOperation::LoadRecord(record) => record,
                _ => continue,
            };
            if let Some(segment) = record.absolute_segment()
                && segment.segment_type == zweidraehte_proto::messages::apdu::load_control::LoadSegment::AbsoluteData
                && u32::from(segment.start_address) == region.location.offset
                && u32::from(segment.length) == region.length
            {
                flags.insert(segment.memory_attributes);
            }
        }
    }
    if flags.is_empty() {
        let mut collect = |controls: &[LoadControl]| {
            for control in controls {
                if let LoadControl::LdCtrlAbsSegment(segment) = control
                    && segment.seg_type == 0
                    && u32::from(segment.address) == region.location.offset
                    && u32::from(segment.size) == region.length
                {
                    flags.insert(segment.seg_flags);
                }
            }
        };
        match product.load_procedure_style() {
            LoadProcedureStyle::Product => {
                for procedure in product.load_procedures() {
                    collect(&procedure.controls);
                }
            }
            LoadProcedureStyle::Default => {
                // The full source supplies geometry even for selective
                // downloads whose own procedure has no allocation record.
                let (_, source) = crate::commissioning::compiler::selection::sources::select_master_procedure(
                    profile, "Load", "all",
                )?;
                collect(&source.controls);
            }
            LoadProcedureStyle::Merged => {}
        }
    }
    match flags.len() {
        1 => Ok(*flags.first().expect("one allocation flag")),
        0 => Err(CompileError::missing_evidence("BCU2 adjacent address allocation has no resolved alignment flags")),
        _ => Err(CompileError::invalid("BCU2 adjacent address allocation has ambiguous alignment flags")),
    }
}

impl SharedTableAllocation {
    fn prepare(
        profile: &ResolvedProfile,
        input: &TableInput<'_>,
        buffers: &BTreeMap<String, NativeImageRegion>,
        image: &mut SparseDeviceImage,
        demand: ImageDemand<'_>,
        association_flavour: ResourceFlavour,
    ) -> Result<Option<Self>, CompileError> {
        let product = input.product;
        let family = if association_flavour == ResourceFlavour::AssociationTableBcu2 { "BCU2" } else { "BCU1" };
        let capacity_error = || {
            CompileError::invalid(format!(
                "{family} dynamic communication allocation exceeds its declared table capacity"
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
        if allocation_end < 0x119 {
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
            AssociationTable::from_flavour(association_flavour)?
                .encode(&input.associations()?, &input.active_numbers())?
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
        if profile.management_model() == ManagementModel::Bcu2 {
            // BCU2 releases the nominal table spans separately. Authored code
            // in their gap retains its values and ownership, even with simple
            // management's BCU1 association format. Relocated table writes can
            // subsequently own gap bytes when they borrow nominal capacity.
            image.invalidate(
                &ImageLocation::standard_memory(0x119),
                (2 * nominal_addresses).min(allocation_end - 0x119),
            );
            image
                .invalidate(&ImageLocation::standard_memory(nominal_association), allocation_end - nominal_association);
        } else if nominal_association > 0x119 {
            // The System 1 formatter clears the nominal pool only when its
            // authored association address follows the address-table header.
            // Earlier addresses still relocate, but retain unrelated seed
            // bytes. Nominal capacity may overlap the object table: its later
            // producer restores the formatted object bytes after this clear.
            image.invalidate(&ImageLocation::standard_memory(base + start as u32), (end - start) as u32);
        }
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
        // An association task points at the relocated table on BCU2 and
        // System 7 alike; its application identity and PEI type remain
        // unchanged. M-00EE_A-4301's BCU2 task moves from 0x14A to 0x13A
        // with its 16-group allocation.
        if let ProcedureOperation::LoadRecord(record) = &mut step.operation {
            let Some(mut segment) = record.task_segment() else { continue };
            if let Some(relocation) = relocations.iter().find(|r| r.from.0 == u32::from(segment.start_address)) {
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
    fn task_relocation_preserves_identity_and_unrelated_records() {
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
            let relocation =
                SegmentRelocation { segment_id: "associations".into(), from: (0x41f7, 501), to: (0x4009, 995) };
            relocate_allocations(&mut procedure, &[relocation]).expect("task relocates");
            let ProcedureOperation::LoadRecord(record) = &procedure.steps[0].operation else { panic!("task record") };
            assert_eq!(record.bytes, encode(0x4009), "only the task address changes");
            assert_eq!(procedure.steps[1], unrelated, "other tasks retain their address");
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
        let relocation = SegmentRelocation { segment_id: "AS-014A".to_owned(), from: (330, 50), to: (314, 66) };
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
