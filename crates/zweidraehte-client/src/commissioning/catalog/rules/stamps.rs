//! Concrete stamp reads selected from exact resource or procedure evidence.

use crate::commissioning::catalog::profile::{ObjectSelector, Occurrence, ReadAccess, ResolvedProfile, ResourceId};
use crate::commissioning::catalog::{ResourceOrder, SelectedResource};
use crate::commissioning::error::CompileError;
use crate::commissioning::image::{ImageLocation, ImageSpace};
use crate::commissioning::procedure::operands::{
    OperationTarget, ServiceRead, StandardMemoryService, pure_property_address,
};
use crate::commissioning::procedure::{AppliesToScope, parse_applies_to_token};
use crate::commissioning::procedure::{
    DownloadStampOutput, OperationExtent, ProcedureOperation, ProcedureStep, StampDescriptor,
};
use std::collections::BTreeSet;
use zweidraehte_ets_files::schema::LoadControl;
use zweidraehte_proto::pid;

fn runtime_stamp_resources(profile: &ResolvedProfile) -> Result<Vec<SelectedResource<'_>>, CompileError> {
    let selected = profile.selected_resources_matching(ResourceOrder::FirstDemandedName, |resource| {
        resource.resource_type.as_ref().and_then(|kind| kind.flavour.as_deref()) == Some("Stamp_SystemB")
    })?;
    let mut resources = Vec::new();
    for resource in selected {
        if resource.access_rights()?.read == ReadAccess::Runtime {
            resources.push(resource);
        }
    }
    Ok(resources)
}

pub(crate) fn stamp_descriptor(
    resource: SelectedResource<'_>,
    service: StandardMemoryService,
) -> Result<StampDescriptor, CompileError> {
    let image_location = if let Some((object, property_id, offset)) = resource.property_location()? {
        ImageLocation { space: ImageSpace::Property { object, property_id }, offset }
    } else {
        resource
            .image_location()?
            .ok_or_else(|| CompileError::invalid(format!("stamp resource {} has no image location", resource.id)))?
    };
    Ok(StampDescriptor {
        optional: resource.optional(),
        read: resource.read(service)?,
        image_location,
        id: resource.id,
    })
}

pub(crate) fn resolved_download_stamp_resources(
    profile: &ResolvedProfile,
    service: StandardMemoryService,
) -> Result<Vec<StampDescriptor>, CompileError> {
    download_stamp_resources(profile, service, false)
}

/// Stamp resources of a download whose second application slot holds a bound
/// PEI Program. The reference extracts every final PID 27 segment in the
/// stamp index range; a PEI Program's fragment reads `PeiprogStamp` into the
/// image, so that stamp is then part of the output.
pub(crate) fn resolved_download_stamp_resources_with_pei_program(
    profile: &ResolvedProfile,
    service: StandardMemoryService,
) -> Result<Vec<StampDescriptor>, CompileError> {
    download_stamp_resources(profile, service, true)
}

fn download_stamp_resources(
    profile: &ResolvedProfile,
    service: StandardMemoryService,
    pei_program_bound: bool,
) -> Result<Vec<StampDescriptor>, CompileError> {
    let flavour = profile.feature("DownloadStamp")?.unwrap_or(0);
    let Some(end) = download_stamp_end(profile, flavour)? else {
        return Ok(Vec::new());
    };

    let mut candidates = runtime_stamp_resources(profile)?
        .into_iter()
        .map(|resource| stamp_descriptor(resource, service))
        .collect::<Result<Vec<_>, _>>()?;
    if candidates.is_empty() {
        candidates.push(procedure_download_stamp(profile)?);
    }
    let mut selected = Vec::new();
    let mut locations = BTreeSet::new();
    for resource in candidates {
        if resource.id.0 == "PeiprogStamp" && !pei_program_bound {
            continue;
        }
        let location = download_stamp_location(&resource)?;
        let ImageSpace::Property { object: ObjectSelector::Index { index }, .. } = &location.space else {
            unreachable!("stamp location validates an indexed property")
        };
        if !(3..end).contains(&u32::from(*index)) {
            continue;
        }
        if !locations.insert(location) {
            return Err(CompileError::invalid(format!(
                "download-stamp resource {} aliases another output property",
                resource.id
            )));
        }
        selected.push(resource);
    }
    Ok(selected)
}

/// Coupler Model 2.0 declares its stamp in the full source procedure. This
/// fallback runs only after enabled output selection finds no runtime resource.
/// Exact selected targets and eight-byte PDT establish the binding.
fn procedure_download_stamp(profile: &ResolvedProfile) -> Result<StampDescriptor, CompileError> {
    let mut targets = BTreeSet::new();
    for procedure in
        profile.source().procedures.iter().flat_map(|procedures| &procedures.procedures).filter(|procedure| {
            procedure.is_load() && procedure.procedure_sub_type.as_deref() == Some("all") && procedure.allows_remote()
        })
    {
        crate::commissioning::catalog::validate_access(procedure.access.as_ref())?;
        collect_procedure_download_stamp_targets(&procedure.controls, &mut targets)?;
    }
    let target = match targets.len() {
        0 => {
            return Err(CompileError::invalid(format!(
                "mask {} enables DownloadStamp, but remote access and management style {:?} resolve no runtime-readable Stamp_SystemB resource",
                profile.mask.full_id, profile.management_style
            )));
        }
        1 => targets.into_iter().next().expect("one stamp target"),
        _ => {
            return Err(CompileError::invalid(format!(
                "mask {} resolves multiple procedure-owned download-stamp targets: {targets:?}",
                profile.mask.full_id
            )));
        }
    };
    let width = profile.property_element_size(&target, pid::MCB_TABLE, true)?;
    if width != Some(8) {
        return Err(CompileError::invalid(format!(
            "mask {} procedure-owned download stamp {target:?} requires eight bytes; resolved width is {width:?}",
            profile.mask.full_id
        )));
    }
    let address = pure_property_address(&target, pid::MCB_TABLE)
        .map_err(|error| CompileError::invalid(format!("procedure download stamp: {error}")))?;
    Ok(StampDescriptor {
        id: ResourceId("ProcedureDownloadStamp".to_owned()),
        read: ServiceRead {
            target: OperationTarget::Property { address, start_element: 1 },
            extent: OperationExtent::property(8, 1),
        },
        image_location: ImageLocation {
            space: ImageSpace::Property { object: target, property_id: pid::MCB_TABLE },
            offset: 0,
        },
        optional: false,
    })
}

fn collect_procedure_download_stamp_targets(
    controls: &[LoadControl],
    targets: &mut BTreeSet<ObjectSelector>,
) -> Result<(), CompileError> {
    for control in controls {
        match control {
            LoadControl::LdCtrlLoadImageProp(control)
                if control.prop_id == pid::MCB_TABLE && control_applies_to_full(control.applies_to.as_deref())? =>
            {
                if control.start_element.unwrap_or(1) != 1 || control.count.unwrap_or(1) != 1 {
                    return Err(CompileError::unsupported(format!(
                        "procedure-owned download stamp uses unsupported property range start={}, count={}",
                        control.start_element.unwrap_or(1),
                        control.count.unwrap_or(1)
                    )));
                }
                let target = match (control.obj_idx, control.obj_type, control.occurrence) {
                    (Some(index), None, None) => ObjectSelector::Index { index: u16::from(index) },
                    (None, Some(object_type), occurrence) => {
                        ObjectSelector::Type { object_type, occurrence: Occurrence::from_schema(occurrence) }
                    }
                    _ => {
                        return Err(CompileError::invalid(format!(
                            "procedure-owned download stamp has invalid selector index={:?}, type={:?}, occurrence={:?}",
                            control.obj_idx, control.obj_type, control.occurrence
                        )));
                    }
                };
                targets.insert(target);
            }
            LoadControl::Choose(choice) => {
                for branch in &choice.when {
                    collect_procedure_download_stamp_targets(&branch.controls, targets)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn control_applies_to_full(applies_to: Option<&str>) -> Result<bool, CompileError> {
    let mut applies = false;
    for token in applies_to.unwrap_or("auto").split(',').map(str::trim) {
        applies |= match parse_applies_to_token(token).ok_or_else(|| {
            CompileError::unsupported(format!("procedure-owned download stamp has unknown AppliesTo token {token:?}"))
        })? {
            AppliesToScope::Full | AppliesToScope::All | AppliesToScope::Automatic => true,
            _ => false,
        };
    }
    Ok(applies)
}

/// The exclusive end of the object indices whose PID 27 records form the
/// download stamp, or `None` when the profile declares no stamp.
///
/// Flavour 1 is a property of the mask, not of its management model: System 7
/// masks declare it too. Their images carry no PID 27 records, so their
/// selection is empty and no stamp is published.
pub(super) fn download_stamp_end(profile: &ResolvedProfile, flavour: u32) -> Result<Option<u32>, CompileError> {
    if flavour == 0 {
        return Ok(None);
    }
    if flavour != 1 {
        return Err(CompileError::unsupported(format!(
            "profile {} declares unsupported DownloadStamp flavour {flavour}",
            profile.mask
        )));
    }
    // Flavour 1 extracts PID 27 records from indices 3..FirstAppObjectIdx. A
    // profile without the feature reads as 1 (RF couplers such as MV-2920), so
    // that range, like any end at or below 3, is empty and no stamp exists.
    let end = profile.feature("FirstAppObjectIdx")?.unwrap_or(1);
    if end <= 3 {
        return Ok(None);
    }
    if end > u16::MAX.into() {
        return Err(CompileError::invalid(format!(
            "profile {} has invalid FirstAppObjectIdx {end} for stamp selection",
            profile.mask
        )));
    }
    Ok(Some(end))
}

/// Flavour 1 stamps are indexed PID 27 records with exactly eight octets.
pub(crate) fn download_stamp_location(resource: &StampDescriptor) -> Result<ImageLocation, CompileError> {
    match &resource.image_location {
        ImageLocation {
            space: ImageSpace::Property { object: ObjectSelector::Index { .. }, property_id: 27 },
            offset: 0,
        } if resource.read.extent.byte_length == 8 => Ok(resource.image_location.clone()),
        _ => Err(CompileError::invalid(format!(
            "download-stamp resource {} requires an indexed PID 27 property at offset 0 with length 8",
            resource.id
        ))),
    }
}

/// Keeps the stamp candidates whose PID 27 record the procedure reads into
/// its image.
///
/// The reference publishes a stamp record only when the final image has a
/// PID 27 segment for it, and only the procedure's image reads
/// (`LdCtrlLoadImageProp`) create one. Product procedures without them
/// (M-00FA) therefore publish no stamp at all.
// TODO: an image-owned PID 27 range would also give the reference a segment;
// no witness writes one.
pub(crate) fn stamps_read_by_procedure(
    steps: &[ProcedureStep],
    candidates: Vec<StampDescriptor>,
) -> Vec<StampDescriptor> {
    let loaded: Vec<&ImageLocation> = steps
        .iter()
        .filter_map(|step| match &step.operation {
            ProcedureOperation::ReadIntoImage { image_location, .. }
            | ProcedureOperation::LoadImage { image_location, .. } => Some(image_location),
            _ => None,
        })
        .collect();
    candidates
        .into_iter()
        .filter(|stamp| loaded.iter().any(|location| location.space == stamp.image_location.space))
        .collect()
}

/// Stamps are selected from the final image on every management model. No
/// mask gains extra device reads merely to record a stamp: a download only
/// publishes PID 27 records that its own procedure observed.
pub(crate) fn resolved_download_stamp_output(
    profile: &ResolvedProfile,
    candidates: Vec<StampDescriptor>,
) -> Result<DownloadStampOutput, CompileError> {
    let flavour = profile.feature("DownloadStamp")?.unwrap_or(0);
    let Some(_) = download_stamp_end(profile, flavour)? else {
        return Ok(DownloadStampOutput::None);
    };
    for resource in &candidates {
        download_stamp_location(resource)?;
    }
    // Without a selected record the reference extracts no stamp at all.
    if candidates.is_empty() {
        return Ok(DownloadStampOutput::None);
    }
    Ok(DownloadStampOutput::ImageProperties(candidates))
}

#[cfg(test)]
mod tests;
