//! Exact PEI application resource contract and unannotated partial-procedure blocks.

use super::{control_object_selector, count_property_writes};
use crate::commissioning::compiler::selection::syntax::control_metadata;
use crate::commissioning::error::CompileError;

use crate::commissioning::catalog::profile::{ObjectSelector, ResolvedProfile};
use std::collections::BTreeSet;
use zweidraehte_ets_files::schema::{LoadControl, LoadProcedure};
use zweidraehte_proto::pid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeiprogPartialControl {
    LoadImagePointer,
    Unload,
    Load,
    ComparePointer,
    WriteIdentity,
    LoadCompleted,
    AllocationMerge,
    DataMerge,
}

impl PeiprogPartialControl {
    const ORDER: [Self; 8] = [
        Self::LoadImagePointer,
        Self::Unload,
        Self::Load,
        Self::AllocationMerge,
        Self::ComparePointer,
        Self::DataMerge,
        Self::WriteIdentity,
        Self::LoadCompleted,
    ];
}

/// Select the fixed AP2 block to omit from a primary-only parameter load.
/// Keeping indices preserves the authored XML paths of every retained control.
///
/// Project-20 through project-23 publish the same eight anchors around the
/// optional AP2 product contribution. They are not annotated with `AppliesTo`,
/// so ordinary applicability filtering cannot remove them. The exact Peiprog
/// resources identify the object; every expected anchor must be present
/// exactly once. Any different shape is a new Master Data contract and fails
/// preflight rather than broadening this omission by guesswork.
pub(super) fn omit_absent_peiprog_partial_block(
    profile: &ResolvedProfile,
    controls: &[LoadControl],
) -> Result<Vec<usize>, CompileError> {
    let peiprog = peiprog_contract_object(profile)?.ok_or_else(|| {
        CompileError::invalid(format!(
            "profile {mask} has an invalid Application Program 2 contract: {reason}",
            mask = profile.mask().full_id.clone(),
            reason =
                "parameter procedure exposes AP2 semantics but the profile has no complete Peiprog resource contract"
                    .to_owned()
        ))
    })?;
    let mut order = Vec::with_capacity(8);
    let mut omitted = Vec::with_capacity(8);

    for (index, control) in controls.iter().enumerate() {
        if let Some(kind) = classify_fixed_peiprog_partial_control(control, &peiprog) {
            order.push(kind);
            omitted.push(index);
            continue;
        }
        if control_contains_peiprog_marker(control, &peiprog) {
            return Err(CompileError::invalid(format!(
                "profile {mask} has an invalid Application Program 2 contract: {reason}",
                mask = profile.mask().full_id.clone(),
                reason = format!("parameter procedure contains an unrecognized Peiprog control {control:?}")
            )));
        }
    }

    if order.as_slice() != PeiprogPartialControl::ORDER {
        return Err(CompileError::invalid(format!(
            "profile {mask} has an invalid Application Program 2 contract: {reason}",
            mask = profile.mask().full_id.clone(),
            reason = format!("parameter procedure has incomplete, repeated, or reordered Peiprog anchors: {order:?}")
        )));
    }

    Ok(omitted)
}

fn classify_fixed_peiprog_partial_control(
    control: &LoadControl,
    peiprog: &ObjectSelector,
) -> Option<PeiprogPartialControl> {
    let metadata = control_metadata(control)?;
    if metadata.applies_to.is_some() || metadata.internal_description.is_some() || !metadata.on_errors.is_empty() {
        return None;
    }
    let targets_peiprog = control_object_selector(control).as_ref() == Some(peiprog);

    match control {
        LoadControl::LdCtrlLoadImageProp(control)
            if targets_peiprog
                && control.prop_id == pid::TABLE_REFERENCE
                && control.start_element.is_none()
                && control.count.is_none() =>
        {
            Some(PeiprogPartialControl::LoadImagePointer)
        }
        LoadControl::LdCtrlUnload(control) if targets_peiprog => Some(PeiprogPartialControl::Unload),
        LoadControl::LdCtrlLoad(control) if targets_peiprog => Some(PeiprogPartialControl::Load),
        LoadControl::LdCtrlCompareProp(control)
            if targets_peiprog
                && control.prop_id == pid::TABLE_REFERENCE
                && control.start_element.is_none()
                && control.count.is_none()
                && control.allow_cached_value.is_none()
                && control.inline_data.as_deref() == Some("00000000")
                && control.mask.is_none()
                && control.range.is_none()
                && control.invert.is_none()
                && control.retry_interval.is_none()
                && control.time_out.is_none() =>
        {
            Some(PeiprogPartialControl::ComparePointer)
        }
        LoadControl::LdCtrlWriteProp(control)
            if targets_peiprog
                && control.prop_id == pid::PROGRAM_VERSION
                && control.start_element.is_none()
                && control.count.is_none()
                && control.verify
                && control.inline_data.as_deref() == Some("0000000000")
                && control.trim.is_none() =>
        {
            Some(PeiprogPartialControl::WriteIdentity)
        }
        LoadControl::LdCtrlLoadCompleted(control) if targets_peiprog => Some(PeiprogPartialControl::LoadCompleted),
        LoadControl::LdCtrlMerge(control) if control.merge_id == 3 => Some(PeiprogPartialControl::AllocationMerge),
        LoadControl::LdCtrlMerge(control) if control.merge_id == 5 => Some(PeiprogPartialControl::DataMerge),
        _ => None,
    }
}

fn control_contains_peiprog_marker(control: &LoadControl, peiprog: &ObjectSelector) -> bool {
    if control_object_selector(control).as_ref() == Some(peiprog)
        || matches!(control, LoadControl::LdCtrlMerge(control) if matches!(control.merge_id, 3 | 5))
    {
        return true;
    }

    match control {
        LoadControl::Choose(choice) => choice
            .when
            .iter()
            .flat_map(|branch| &branch.controls)
            .any(|control| control_contains_peiprog_marker(control, peiprog)),
        _ => false,
    }
}

fn peiprog_contract_object(profile: &ResolvedProfile) -> Result<Option<ObjectSelector>, CompileError> {
    let expected = [
        ("PeiprogId", pid::PROGRAM_VERSION, 5),
        ("PeiprogLoadControl", pid::LOAD_STATE_CONTROL, 10),
        ("PeiprogDataPtr", pid::TABLE_REFERENCE, 4),
    ];
    let mut contract_object = None;
    let mut present = 0;

    for (name, expected_property_id, expected_length) in expected {
        let Some(resource) = profile.resource(name)? else {
            continue;
        };
        present += 1;

        let Some((object, property_id, offset)) = resource.property_location()? else {
            return Err(CompileError::invalid(format!(
                "profile {mask} has an invalid Application Program 2 contract: {reason}",
                mask = profile.mask().full_id.clone(),
                reason = format!("{name} is not property-backed")
            )));
        };
        if property_id != expected_property_id || offset != 0 || resource.length() != expected_length {
            return Err(CompileError::invalid(format!(
                "profile {mask} has an invalid Application Program 2 contract: {reason}",
                mask = profile.mask().full_id.clone(),
                reason = format!(
                    "{name} resolves PID {property_id} offset {offset} length {}, expected PID {expected_property_id} offset 0 length {expected_length}",
                    resource.length()
                )
            )));
        }
        if contract_object.as_ref().is_some_and(|candidate| candidate != &object) {
            return Err(CompileError::invalid(format!(
                "profile {mask} has an invalid Application Program 2 contract: {reason}",
                mask = profile.mask().full_id.clone(),
                reason = "Peiprog resources resolve different interface objects".to_owned()
            )));
        }
        contract_object = Some(object.clone());
    }

    match present {
        0 => Ok(None),
        3 => Ok(contract_object),
        _ => Err(CompileError::invalid(format!(
            "profile {mask} has an invalid Application Program 2 contract: {reason}",
            mask = profile.mask().full_id.clone(),
            reason = format!("profile resolves only {present} of 3 required Peiprog resources")
        ))),
    }
}

pub(super) fn procedure_writes_peiprog_identity(
    profile: &ResolvedProfile,
    controls: &[LoadControl],
    fragments: &[&LoadProcedure],
    merge_ids: &BTreeSet<u8>,
) -> Result<bool, CompileError> {
    if !merge_ids.contains(&3) && !merge_ids.contains(&5) {
        return Ok(false);
    }

    // Merge points 3 and 5 are AP2 anchors only on profiles that publish the
    // Peiprog resources. Coupler masks number their own merge points 1..4
    // and have no second application at all.
    let Some(peiprog) = peiprog_contract_object(profile)? else {
        return Ok(false);
    };
    if !(merge_ids.contains(&3) && merge_ids.contains(&5)) {
        return Err(CompileError::invalid(format!(
            "profile {mask} has an invalid Application Program 2 contract: {reason}",
            mask = profile.mask().full_id.clone(),
            reason = format!("selected procedure has incomplete AP2 merge points {merge_ids:?}")
        )));
    }

    let mut writes = count_property_writes(controls, &peiprog, pid::PROGRAM_VERSION);
    for fragment in fragments {
        writes += count_property_writes(&fragment.controls, &peiprog, pid::PROGRAM_VERSION);
    }

    if writes != 1 {
        return Err(CompileError::invalid(format!(
            "profile {mask} has an invalid Application Program 2 contract: {reason}",
            mask = profile.mask().full_id.clone(),
            reason = format!("selected AP2 path writes PeiprogId {writes} times instead of once")
        )));
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commissioning::catalog::profile::testing::fixture_profile;

    // Coupler masks number their own merge points 1..4. Without the Peiprog
    // resources, merge point 3 is no second-application anchor.
    #[test]
    fn merge_points_without_peiprog_resources_have_no_ap2_semantics() {
        let profile = fixture_profile("MV-0912", "Bcu1", "MT-0", "");
        let merge_ids = BTreeSet::from([1, 2, 3, 4]);

        assert!(!procedure_writes_peiprog_identity(&profile, &[], &[], &merge_ids).expect("no AP2 contract applies"));
    }
}
