//! Bind the selected load-machine's two endpoints before opening a session.
use super::*;
use crate::commissioning::catalog::{ResourceOrder, SelectedResource, property_object_matches};

pub(crate) fn load_endpoint(
    profile: &ResolvedProfile,
    target: &LoadMachineTarget,
    service: StandardMemoryService,
) -> Result<(ServiceRead, ServiceRead, Option<LsmMachine>), CompileError> {
    let property = |control, status| {
        (
            ServiceRead {
                target: OperationTarget::Property { address: control, start_element: 1 },
                extent: OperationExtent::property(10, 1),
            },
            ServiceRead {
                target: OperationTarget::Property { address: status, start_element: 1 },
                extent: OperationExtent::property(1, 1),
            },
            None,
        )
    };
    // BIM M112's compatibility memory window remains declared when this
    // feature selects its preferred property service.
    if profile.feature("PropertyMappedLsms").map_err(metadata_error)?.is_some_and(|value| value != 0)
        && let LoadMachineTarget::Index(index) = target
    {
        let address = pure_property_address(&ObjectSelector::Index { index: *index }, pid::LOAD_STATE_CONTROL)?;
        return Ok(property(address, address));
    }
    let selector = match target {
        LoadMachineTarget::Index(index) => ObjectSelector::Index { index: *index },
        LoadMachineTarget::Object(object) => object.clone(),
    };
    let mut controls = Vec::new();
    for resource in profile
        .selected_resources_matching(ResourceOrder::SelectedDeclaration, |source| {
            source.name.ends_with("LoadControl")
                && source.location.as_ref().is_some_and(|location| property_object_matches(location, &selector))
        })
        .map_err(metadata_error)?
    {
        if let Some((object, pid, 0)) = resource.property_location().map_err(metadata_error)?
            && object == selector
        {
            controls.push((resource, pid));
        }
    }
    if let [(control, control_pid)] = controls.as_slice() {
        let status_name =
            control.name().strip_suffix("LoadControl").expect("selected suffix").to_owned() + "LoadStatus";
        let status = required_resource(profile, &status_name)?;
        validate_resource(control, ResourceFlavour::LoadControlBcu2, 10)?;
        validate_resource(&status, ResourceFlavour::LoadControlBcu2, 1)?;
        let control_address = pure_property_address(&selector, *control_pid)?;
        let (object, pid, offset) = status
            .property_location()
            .map_err(metadata_error)?
            .ok_or_else(|| required_apdu_error("load-machine resource is not a property"))?;
        if offset != 0 {
            return Err(required_apdu_error("load-control property resources have non-zero offsets"));
        }
        let status_address = pure_property_address(&object, pid)?;
        if control_address.overhead() != status_address.overhead() {
            return Err(required_apdu_error(
                "load-control and load-status resources use different property service forms",
            ));
        }
        return Ok(property(control_address, status_address));
    }
    if !controls.is_empty() {
        return Err(required_apdu_error(format!(
            "load-machine target {target:?} resolves to {} property controls",
            controls.len()
        )));
    }
    let (prefix, machine) = match target {
        LoadMachineTarget::Index(1) => ("GroupAddressTable", LsmMachine::AddressTable),
        LoadMachineTarget::Index(2) => ("GroupAssociationTable", LsmMachine::AssociationTable),
        LoadMachineTarget::Index(3) => ("Application", LsmMachine::ApplicationProgram),
        LoadMachineTarget::Index(4) => ("Peiprog", LsmMachine::PeiProgram),
        _ => {
            return Err(required_apdu_error(format!(
                "load-machine target {target:?} has no memory-mapped machine definition"
            )));
        }
    };
    let memory = |suffix, length| -> Result<ServiceRead, CompileError> {
        let resource = required_resource(profile, &format!("{prefix}{suffix}"))?;
        validate_resource(&resource, ResourceFlavour::LoadControlM112, length)?;
        let location = resource
            .source
            .location
            .as_ref()
            .ok_or_else(|| required_apdu_error("memory-mapped load machine has no location"))?
            .to_address_space()
            .map_err(metadata_error)?;
        let zweidraehte_ets_files::schema::master_data::AddressSpaceLocation::StandardMemory { start_address } =
            location
        else {
            return Err(required_apdu_error(
                "memory-mapped load machine requires StandardMemory control and status resources",
            ));
        };
        Ok(ServiceRead {
            target: OperationTarget::Memory {
                service: service.for_range(start_address, length),
                address: MemoryAddress::Fixed(start_address),
            },
            extent: OperationExtent::bytes(length),
        })
    };
    Ok((memory("LoadControl", 12)?, memory("LoadStatus", 1)?, Some(machine)))
}

fn required_resource<'a>(profile: &'a ResolvedProfile, name: &str) -> Result<SelectedResource<'a>, CompileError> {
    profile
        .resource(name)
        .map_err(metadata_error)?
        .ok_or_else(|| required_apdu_error(format!("profile has no resolved {name} resource")))
}

fn validate_resource(
    resource: &SelectedResource<'_>,
    flavour: ResourceFlavour,
    length: u32,
) -> Result<(), CompileError> {
    if resource.flavour().map_err(metadata_error)? != Some(flavour) || resource.length() != length {
        return Err(required_apdu_error(format!(
            "load resource {} requires {flavour:?} coding and {length} bytes",
            resource.id
        )));
    }
    Ok(())
}

fn metadata_error(error: impl std::fmt::Display) -> CompileError {
    required_apdu_error(error.to_string())
}
