//! Concrete stamp reads selected from exact resource or procedure evidence.

use crate::commissioning::catalog::profile::{
    ManagementModel, ObjectSelector, Occurrence, ReadAccess, ResolvedProfile, ResourceId,
};
use crate::commissioning::catalog::{ResourceOrder, SelectedResource};
use crate::commissioning::error::CompileError;
use crate::commissioning::image::{ImageLocation, ImageSpace};
use crate::commissioning::procedure::operands::{
    OperationTarget, ServiceRead, StandardMemoryService, pure_property_address,
};
use crate::commissioning::procedure::{AppliesToScope, parse_applies_to_token};
use crate::commissioning::procedure::{DownloadStampOutput, OperationExtent, StampDescriptor};
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
    let flavour = profile.feature("DownloadStamp")?.unwrap_or(0);
    let system_b_end = system_b_download_stamp_end(profile, flavour)?;
    if flavour == 0 {
        return Ok(Vec::new());
    }

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
        if resource.id.0 == "PeiprogStamp" {
            continue;
        }
        if let Some(end) = system_b_end {
            let location = system_b_download_stamp_location(&resource)?;
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
                        ObjectSelector::Type { object_type, occurrence: Occurrence::from_option(occurrence) }
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

pub(super) fn system_b_download_stamp_end(
    profile: &ResolvedProfile,
    flavour: u32,
) -> Result<Option<u32>, CompileError> {
    if profile.management_model != ManagementModel::SystemB || flavour == 0 {
        return Ok(None);
    }
    if flavour != 1 {
        return Err(CompileError::unsupported(format!(
            "profile {} declares unsupported System B DownloadStamp flavour {flavour}",
            profile.mask
        )));
    }
    let end = profile.feature("FirstAppObjectIdx")?.ok_or_else(|| {
        CompileError::invalid(format!(
            "profile {} requires FirstAppObjectIdx for System B DownloadStamp flavour 1",
            profile.mask
        ))
    })?;
    if end <= 3 || end > u16::MAX.into() {
        return Err(CompileError::invalid(format!(
            "profile {} has invalid FirstAppObjectIdx {end} for stamp selection",
            profile.mask
        )));
    }
    Ok(Some(end))
}

/// Flavour 1 stamps are indexed PID 27 records with exactly eight octets.
pub(crate) fn system_b_download_stamp_location(resource: &StampDescriptor) -> Result<ImageLocation, CompileError> {
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

pub(crate) fn resolved_download_stamp_output(
    profile: &ResolvedProfile,
    candidates: Vec<StampDescriptor>,
) -> Result<DownloadStampOutput, CompileError> {
    if profile.management_model != ManagementModel::SystemB {
        return Ok(DownloadStampOutput::StagedReads(candidates));
    }
    let flavour = profile.feature("DownloadStamp")?.unwrap_or(0);
    let Some(_) = system_b_download_stamp_end(profile, flavour)? else {
        return Ok(DownloadStampOutput::None);
    };
    for resource in &candidates {
        system_b_download_stamp_location(resource)?;
    }
    Ok(DownloadStampOutput::ImageProperties(candidates))
}

#[cfg(test)]
mod tests;
