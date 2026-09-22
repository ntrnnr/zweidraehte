//! Compilation of installation topology into mask-specific image resources.
//!
//! The project model owns topology and membership semantics. This module owns
//! only the exact Master Data representation: resource widths, address spaces,
//! and the Realisation Type 1 filter bitmap. Domain and RF-mode values remain
//! in the public commissioning plan as well, because profiles may program them
//! through network management instead of an application image.

use crate::commissioning::error::CompileError;
use zweidraehte_project::DomainAddress;
use zweidraehte_project::RfDeviceMode;

use crate::configuration::TopologyConfiguration;

use crate::commissioning::compiler::ProgramCompiler;

use crate::commissioning::catalog::SelectedResource;
use crate::commissioning::catalog::profile::ResolvedProfile;
use crate::commissioning::image::ImageSegment;
use crate::commissioning::input::ProgramSections;
use zweidraehte_project::ProgrammingSection;

mod routing;

use crate::commissioning::catalog::rules::resource as resource_image_location;
use routing::compile_group_filter;

impl ProgramCompiler<'_> {
    pub(in crate::commissioning::compiler) fn contribute_topology(&mut self) -> Result<(), CompileError> {
        let input = self.input;
        let profile = &self.profile;
        let topology = &input.device.configuration().topology;
        let include_medium_configuration = self.feature_sections.contains(ProgramSections::CONFIGURATION);
        validate_network_topology(profile, topology)?;

        if include_medium_configuration
            && let Some(domain) = topology.domain_address
            && let Some(resource) = profile.resource("DomainAddress")?
        {
            let data = encode_domain_address(&resource, domain)?;
            self.image.add_section(
                ProgrammingSection::Configuration,
                ImageSegment::owned(resource_image_location(&resource)?, data)?,
            );
        }

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

                    // PID 51 is online-only in the published RF profiles. AN186
                    // requires a connectionless point-to-point write while the
                    // device is proven ex-factory, and the new mode applies
                    // before the response is sent. Keep the desired value in the
                    // plan for RF network orchestration; it must never become a
                    // connected load-control operation.
                    if resource.property_location()?.is_none() {
                        return Err(CompileError::invalid("RF mode resource is not a property"));
                    }
                }
                None if mode == RfDeviceMode::Ready => {
                    // Resources §4.15.3.3 defines an RF device without PID 51 as
                    // natively Ready. No write is needed or permitted.
                }
                None => {
                    return Err(CompileError::invalid(
                        "RF Multi requires an RfDeviceMode resource on the selected profile",
                    ));
                }
            }
        }

        if self.feature_sections.contains(ProgramSections::GROUP_COMMUNICATION) {
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
}

pub(crate) fn validate_network_topology(
    profile: &ResolvedProfile,
    topology: &TopologyConfiguration,
) -> Result<(), CompileError> {
    let supports_rf = profile.mask_source().medium_type_ref_id.as_deref() == Some("MT-2")
        || profile.mask_source().other_medium_type_ref_id.as_deref() == Some("MT-2");

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

fn encode_domain_address(resource: &SelectedResource<'_>, domain: DomainAddress) -> Result<Vec<u8>, CompileError> {
    match (domain, resource.length()) {
        (DomainAddress::Rf(value), 6) => Ok(value.to_vec()),
        (DomainAddress::Rf(_), actual) => Err(CompileError::invalid(format!(
            "resource {resource:?} has length {actual}, expected {expected}",
            resource = resource.name().to_owned(),
            expected = "six octets for RF"
        ))),
        (DomainAddress::Ip(_), _) => Err(CompileError::unsupported(
            "KNX/IP multicast belongs to the IP Parameter Object, not open-medium domain configuration",
        )),
    }
}

#[cfg(test)]
mod tests;
