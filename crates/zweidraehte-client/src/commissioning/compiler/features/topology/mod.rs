//! Compilation of installation topology into mask-specific image resources.
//!
//! The project model owns topology and membership semantics. This module owns
//! only the exact Master Data representation: resource widths, address spaces,
//! and the Realisation Type 1 filter bitmap. The open-medium domain address
//! stays out of the application image: it is network configuration, loaded
//! with the individual address. A full RF download states the RF Multi type.

use crate::commissioning::error::CompileError;
use zweidraehte_project::DomainAddress;
use zweidraehte_project::RfDeviceMode;

use crate::configuration::TopologyConfiguration;

use crate::commissioning::compiler::ProgramCompiler;

use crate::commissioning::catalog::profile::{ObjectSelector, Occurrence, ResolvedProfile};
use crate::commissioning::image::{ImageLocation, ImageSegment, ImageSpace};
use crate::commissioning::input::ProgramSections;
use crate::commissioning::procedure::operands::property_target;
use crate::commissioning::procedure::{
    ErrorAction, ErrorHandler, LoadControlCause, OperationData, OperationExtent, ProcedureOperation, WriteIntent,
};
use zweidraehte_project::ProgrammingSection;
use zweidraehte_proto::pid::rf::RF_MULTI_TYPE;

mod routing;

use crate::commissioning::catalog::rules::resource as resource_image_location;
use routing::compile_group_filter;

const RF_MEDIUM_OBJECT: ObjectSelector = ObjectSelector::Type { object_type: 19, occurrence: Occurrence::Zero };
const ROUTER_OBJECT: ObjectSelector = ObjectSelector::Type { object_type: 6, occurrence: Occurrence::Zero };
/// Router object PID 59, which the reference sets to 01 for modern MV-0912
/// line couplers below a coupler address.
const ROUTER_CONFIGURATION: u16 = 59;

impl ProgramCompiler<'_> {
    pub(in crate::commissioning::compiler) fn contribute_topology(&mut self) -> Result<(), CompileError> {
        let input = self.input;
        let profile = &self.profile;
        let topology = &input.device.configuration().topology;
        let include_medium_configuration = self.feature_sections.contains(ProgramSections::CONFIGURATION);
        validate_network_topology(profile, topology)?;

        // The open-medium domain address is not part of the application
        // image. It is network configuration, written together with the
        // individual address (see the network binding), so no download owns
        // or transmits the profile's DomainAddress resource.

        if include_medium_configuration && let Some(mode) = topology.rf_device_mode {
            match profile.resource("RfDeviceMode")? {
                Some(resource) => {
                    if resource.length() != 1 {
                        return Err(CompileError::invalid(format!(
                            "resource {resource:?} has length {actual}, expected {expected}",
                            resource = resource.name().to_owned(),
                            expected = "one octet",
                            actual = resource.length()
                        )));
                    }
                    if resource.property_location()?.is_none() {
                        return Err(CompileError::invalid("RF mode resource is not a property"));
                    }
                }
                None if mode == RfDeviceMode::Ready => {
                    // Resources §4.15.3.3 defines an RF device without PID 51 as
                    // natively Ready.
                }
                None => {
                    return Err(CompileError::invalid(
                        "RF Multi requires an RfDeviceMode resource on the selected profile",
                    ));
                }
            }
        }

        if supports_rf(profile)
            && self
                .recipes
                .request()
                .is_some_and(|request| request.procedure_type == "Load" && request.applicability.full)
        {
            // A full download of an RF device states its RF Multi type in the
            // RF Medium Object's PID 51 right after the last unload: 01 for an
            // RF Multi device and 00 otherwise. A Ready device without the
            // property refuses the write, which the download ignores; an RF
            // Multi device must accept it.
            let multi = topology.rf_device_mode == Some(RfDeviceMode::Multi);
            let handlers = if multi {
                Vec::new()
            } else {
                vec![ErrorHandler { cause: LoadControlCause::ResourceNotFound, action: ErrorAction::Ignore }]
            };
            let target = property_target(&RF_MEDIUM_OBJECT, RF_MULTI_TYPE, 1)
                .expect("builtin property selector fits service fields");
            self.recipes.rf_medium_configuration(
                ProcedureOperation::Write {
                    target,
                    data: OperationData::Inline(vec![u8::from(multi)]),
                    extent: OperationExtent::property(1, 1),
                    policy: WriteIntent::Property { verify: true },
                },
                handlers,
            );
        }

        // The reference loads a coupler's filter table only at a main-line
        // address (x.y.0); below it the table stays out of the image.
        //
        // TODO: Segment couplers also load it at other addresses; the
        // project model does not mark segment couplers yet.
        let filter_address = input.device.configuration().individual_address.device() == 0;
        if self.feature_sections.contains(ProgramSections::GROUP_COMMUNICATION) && filter_address {
            match (profile.resource("GroupFilterTable")?, &topology.group_filter) {
                (Some(_), None) => {
                    return Err(CompileError::invalid(
                        "profile requires a group-filter table, but the project coupler has no routing policy",
                    ));
                }
                (None, Some(_)) => {
                    return Err(CompileError::unsupported(
                        "project supplies a group-filter table for a profile without that resource",
                    ));
                }
                (None, None) => {}
                (Some(resource), Some(filter)) => {
                    for segment in compile_group_filter(profile, &resource, filter.policy, &filter.addresses)? {
                        self.image.add_section(ProgrammingSection::Configuration, segment);
                    }
                }
            }
        }

        Ok(())
    }

    /// Router configuration belongs to every download rather than to the
    /// selected sections, so it is contributed after a partial download has
    /// projected the image onto its sections. The byte stays owned by
    /// Configuration: a partial download without that section writes it but
    /// establishes nothing for it.
    pub(in crate::commissioning::compiler) fn contribute_router_configuration(&mut self) -> Result<(), CompileError> {
        let input = self.input;
        let profile = &self.profile;
        let topology = &input.device.configuration().topology;

        // The reference adds router configuration for a modern MV-0912 line
        // coupler without a second domain whose individual address is not a
        // coupler address (x.y.z with z != 0): it owns the router object's
        // PID 59 as 01 and writes it from the image right after the router
        // object starts loading, ignoring a coupler that lacks the property.
        // At x.y.0 and x.0.0 it neither owns nor writes the property. The
        // decision does not depend on the download's sections, so partial
        // downloads write it too.
        //
        // TODO: Map the other router-configuration branches (segment coupler,
        // second-domain medium, RF Multi, backbone coupler, security proxy and
        // firewall) once a witness needs them.
        if profile.mask().full_id == "MV-0912"
            && topology.domain_address.is_none()
            && input.device.configuration().individual_address.device() != 0
            && input.device.product().programming_options().line_coupler_0912_new_programming_style().value
            && self.recipes.request().is_some_and(|request| request.procedure_type == "Load")
        {
            let location = ImageLocation {
                space: ImageSpace::Property { object: ROUTER_OBJECT, property_id: ROUTER_CONFIGURATION },
                offset: 0,
            };
            self.image.add_section(
                ProgrammingSection::Configuration,
                ImageSegment::owned(location.clone(), vec![0x01]).expect("one owned octet is a valid segment"),
            );
            let target = property_target(&ROUTER_OBJECT, ROUTER_CONFIGURATION, 1)
                .expect("builtin property selector fits service fields");
            self.recipes.router_configuration(
                ProcedureOperation::Write {
                    target,
                    data: OperationData::Image { location, length: 1 },
                    extent: OperationExtent::property(1, 1),
                    policy: WriteIntent::Property { verify: true },
                },
                vec![ErrorHandler { cause: LoadControlCause::ResourceNotFound, action: ErrorAction::Ignore }],
            )?;
        }
        Ok(())
    }
}

pub(crate) fn validate_network_topology(
    profile: &ResolvedProfile,
    topology: &TopologyConfiguration,
) -> Result<(), CompileError> {
    let supports_rf = supports_rf(profile);

    match topology.domain_address {
        Some(DomainAddress::Ip(_)) => {
            return Err(CompileError::unsupported(
                "KNX/IP multicast belongs to the IP Parameter Object, not open-medium domain configuration",
            ));
        }
        Some(DomainAddress::Rf(_)) if !supports_rf => {
            return Err(CompileError::invalid(format!(
                "project supplies a {expected} domain address for incompatible profile {profile}",
                expected = "RF",
                profile = profile.mask().full_id.clone()
            )));
        }
        Some(DomainAddress::Rf(value)) if value == [0; 6] || value == [u8::MAX; 6] => {
            return Err(CompileError::invalid(format!(
                "RF domain address {value:02x?} is reserved as a void or ex-factory value"
            )));
        }
        None if supports_rf => {
            return Err(CompileError::invalid(
                "profile requires an open-medium domain address, but the project line has none",
            ));
        }
        _ => {}
    }

    if topology.rf_device_mode.is_some() && !supports_rf {
        return Err(CompileError::unsupported(format!(
            "project supplies RF device mode for non-RF profile {0}",
            profile.mask().full_id.clone()
        )));
    }

    if profile.mask_source().medium_type_ref_id.as_deref() == Some("MT-2")
        && profile.resource("RfDeviceMode")?.is_some()
        && topology.rf_device_mode.is_none()
    {
        return Err(CompileError::invalid("RF device mode is required by the selected profile"));
    }

    Ok(())
}

/// Whether the selected mask uses KNX RF as its primary or secondary medium.
fn supports_rf(profile: &ResolvedProfile) -> bool {
    profile.mask_source().medium_type_ref_id.as_deref() == Some("MT-2")
        || profile.mask_source().other_medium_type_ref_id.as_deref() == Some("MT-2")
}

#[cfg(test)]
mod tests;
