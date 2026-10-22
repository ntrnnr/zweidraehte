//! Tool-owned KNX/IP configuration, bound once to the exact product and profile.

mod security;
#[cfg(test)]
mod tests;

use crate::commissioning::catalog::rules::ip::IP_OBJECT;
#[cfg(test)]
use crate::commissioning::catalog::rules::ip::prepare_classic_ip_profile;
use crate::commissioning::compiler::ProgramCompiler;
use crate::commissioning::compiler::credentials::CredentialEffects;
use crate::commissioning::error::CompileError;
use crate::commissioning::image::{ImageLocation, ImageSegment, ImageSpace};
use crate::commissioning::input::ProgramSections;
use crate::commissioning::procedure::{
    OperationData, OperationExtent, OperationTarget, ProcedureOperation, WriteIntent, WritePolicy,
};
use crate::configuration::{MaterializedDevice, ToolManagedIpConfiguration};
use std::collections::BTreeSet;
use zweidraehte_ets_files::product::ProductData;
use zweidraehte_project::{IpAssignment, ProgrammingSection};
use zweidraehte_proto::pid;

const FRIENDLY_NAME_ELEMENTS: usize = 30;
const KEY_LENGTH: usize = 16;

impl ProgramCompiler<'_> {
    pub(in crate::commissioning::compiler) fn contribute_ip(&mut self) -> Result<(), CompileError> {
        let input = self.input;
        if !self.feature_sections.contains(ProgramSections::CONFIGURATION) {
            return Ok(());
        }
        let profile = &self.profile;
        let product = input.device.product();
        let device = &input.device;
        // Resolution already checks product ownership, exact family, and medium.
        if profile.tool_managed_ip.is_none() {
            return Ok(());
        }

        let intent = device
            .topology()
            .ip
            .as_ref()
            .ok_or(CompileError::invalid("Tool-mode classic IP download has no IP configuration"))?;
        validate_basic_intent(product, device, intent)?;

        // Live device identity belongs to the working image, so later image
        // transfers can consume it without changing desired project state.
        // Reuse the same load/merge operation as authored image reads.
        self.recipes.before_close(false, ProcedureOperation::LoadImage {
            target: property_target(pid::ip::MAC_ADDRESS, 1),
            image_location: property_image_location(pid::ip::MAC_ADDRESS),
            extent: OperationExtent::property(6, 1),
            alignment: 6,
        });

        self.add_image_property_write(
            pid::ip::PROJECT_INSTALLATION_ID,
            intent.project_installation_id.encode().to_be_bytes().to_vec(),
            1,
        )?;

        let additional_capacity = product.programming_options().additional_addresses_count().value;
        if additional_capacity != 0 {
            let capacity = u16::try_from(additional_capacity).map_err(|_| {
                CompileError::invalid(format!(
                    "additional-address capacity {additional_capacity} cannot be represented by the property service"
                ))
            })?;
            let mut addresses = vec![u8::MAX; usize::from(capacity) * 2];
            for (slot, address) in intent.additional_individual_addresses.iter().enumerate() {
                addresses[slot * 2..slot * 2 + 2].copy_from_slice(address.as_bytes());
            }
            self.add_image_property_write(pid::ip::ADDITIONAL_INDIVIDUAL_ADDRESSES, addresses, capacity)?;
        }

        if let IpAssignment::Fixed { address, subnet_mask, default_gateway } = intent.assignment {
            for (property_id, value) in [
                (pid::ip::IP_ADDRESS, address),
                (pid::ip::SUBNET_MASK, subnet_mask),
                (pid::ip::DEFAULT_GATEWAY, default_gateway),
            ] {
                self.add_image_property_write(property_id, value.to_vec(), 1)?;
            }
        }

        self.add_image_property_write(
            pid::ip::ROUTING_MULTICAST_ADDRESS,
            intent.routing_multicast_address.to_vec(),
            1,
        )?;
        self.add_image_property_write(pid::ip::TTL, vec![intent.multicast_ttl], 1)?;
        self.add_image_property_write(
            pid::ip::FRIENDLY_NAME,
            encode_friendly_name(&intent.friendly_name)?,
            FRIENDLY_NAME_ELEMENTS as u16,
        )?;

        // Applying the assignment method may activate the configured network
        // settings, so write it after their values are in place.
        let assignment = match intent.assignment {
            IpAssignment::AutomaticDhcp => 4,
            IpAssignment::Fixed { .. } => 1,
        };
        self.add_image_property_write(pid::ip::IP_ASSIGNMENT_METHOD, vec![assignment], 1)?;

        if product.programming_options().is_secure_enabled().value {
            self.compile_ip_secure(intent)?;
        }

        // IP configuration requires a restart even when the selected source
        // procedure is empty. The Data Secure application profile enables the confirmed
        // service independently of the desired security mode or credentials.
        let kind = if product.supports_data_secure() {
            crate::commissioning::RestartKind::Confirmed
        } else {
            crate::commissioning::RestartKind::Basic
        };
        self.recipes.require_restart(kind, zweidraehte_project::ProgrammingSection::Configuration);

        Ok(())
    }
}

pub(super) fn validate_basic_intent(
    product: &ProductData,
    device: &MaterializedDevice,
    intent: &ToolManagedIpConfiguration,
) -> Result<(), CompileError> {
    let capacity = product.programming_options().additional_addresses_count().value;
    if intent.additional_individual_addresses.len() > usize::try_from(capacity).unwrap_or(usize::MAX) {
        return Err(CompileError::invalid(format!(
            "configured {configured} additional addresses, exceeding product capacity {capacity}",
            configured = intent.additional_individual_addresses.len()
        )));
    }

    let primary = device.individual_address();
    let mut unique = BTreeSet::new();
    for address in &intent.additional_individual_addresses {
        if address.subnet() != primary.subnet() {
            return Err(CompileError::invalid(format!(
                "additional address {additional} is not on primary address {primary}'s subnet",
                additional = *address
            )));
        }
        if *address == primary || !unique.insert(*address) {
            return Err(CompileError::invalid(format!(
                "individual address {0} is duplicated in the IP parameter configuration",
                *address
            )));
        }
    }

    if !(224..=239).contains(&intent.routing_multicast_address[0]) {
        return Err(CompileError::invalid(format!(
            "routing multicast address {0:?} is not IPv4 multicast",
            intent.routing_multicast_address
        )));
    }
    if intent.multicast_ttl == 0 {
        return Err(CompileError::invalid("multicast TTL must not be zero"));
    }

    let secure_product = product.programming_options().is_secure_enabled().value;
    match (secure_product, &intent.security) {
        (true, None) => return Err(CompileError::invalid("secure IP product has no public IP security intent")),
        (false, Some(_)) => return Err(CompileError::invalid("plain IP product was given IP security intent")),
        (false, None) if !intent.password_users.is_empty() => {
            return Err(CompileError::invalid("plain IP product was given password users"));
        }
        _ => {}
    }

    Ok(())
}

pub(super) fn encode_friendly_name(value: &str) -> Result<Vec<u8>, CompileError> {
    let value = value.trim();
    let mut encoded = Vec::with_capacity(FRIENDLY_NAME_ELEMENTS);
    for character in value.chars() {
        // KNX defines this property as a fixed Latin-1 array but does not
        // define a transliteration table. Rejecting unsupported characters
        // keeps the compiled image independent of the host locale.
        let code = u32::from(character);
        if code > u32::from(u8::MAX) {
            return Err(CompileError::invalid(format!("friendly name contains non-Latin-1 character {character:?}")));
        }
        if encoded.len() == FRIENDLY_NAME_ELEMENTS {
            break;
        }
        encoded.push(code as u8);
    }
    encoded.resize(FRIENDLY_NAME_ELEMENTS, 0);
    Ok(encoded)
}

impl ProgramCompiler<'_> {
    pub(in crate::commissioning::compiler) fn add_image_property_write(
        &mut self,
        property_id: u16,
        data: Vec<u8>,
        elements: u16,
    ) -> Result<(), CompileError> {
        self.add_image_property_write_with_security(property_id, data, elements, false)
    }
}

impl ProgramCompiler<'_> {
    pub(in crate::commissioning::compiler) fn add_image_property_write_secure(
        &mut self,
        property_id: u16,
        data: Vec<u8>,
        elements: u16,
    ) -> Result<(), CompileError> {
        self.add_image_property_write_with_security(property_id, data, elements, true)
    }
}

impl ProgramCompiler<'_> {
    pub(in crate::commissioning::compiler) fn add_image_property_write_with_security(
        &mut self,
        property_id: u16,
        data: Vec<u8>,
        elements: u16,
        secure_only: bool,
    ) -> Result<(), CompileError> {
        if elements == 0 || data.is_empty() || data.len() % usize::from(elements) != 0 {
            return Err(CompileError::invalid(format!(
                "property {property_id} has {byte_length} bytes across {elements} elements",
                byte_length = data.len()
            )));
        }
        let byte_length = u32::try_from(data.len()).map_err(|_| {
            CompileError::invalid(format!("property {property_id} value is too large for the commissioning IR"))
        })?;
        let location = property_image_location(property_id);
        self.image.add_section(ProgrammingSection::Configuration, ImageSegment::owned(location.clone(), data)?);
        self.recipes.before_close(secure_only, ProcedureOperation::Write {
            target: property_target(property_id, 1),
            data: OperationData::Image { location, length: byte_length },
            extent: OperationExtent::property(byte_length, elements),
            policy: WriteIntent::Explicit(WritePolicy::ReadBack),
        });
        Ok(())
    }

    /// Write a credential from the program image like any other secure IP
    /// property; `effects` names what its confirmed write replaces.
    pub(in crate::commissioning::compiler) fn add_credential_property_write(
        &mut self,
        property_id: u16,
        data: Vec<u8>,
        elements: u16,
        effects: CredentialEffects,
    ) -> Result<(), CompileError> {
        let byte_length = u32::try_from(data.len()).map_err(|_| {
            CompileError::invalid(format!("credential property {property_id} is too large for the commissioning IR"))
        })?;
        if elements == 0 || data.is_empty() || data.len() % usize::from(elements) != 0 {
            return Err(CompileError::invalid(format!(
                "credential property {property_id} has {byte_length} bytes across {elements} elements"
            )));
        }
        let location = property_image_location(property_id);
        self.image.add_section(ProgrammingSection::Configuration, ImageSegment::owned(location.clone(), data)?);
        self.recipes.before_close(true, ProcedureOperation::Write {
            target: property_target(property_id, 1),
            data: OperationData::Credential { location, length: byte_length, effects },
            extent: OperationExtent::property(byte_length, elements),
            // Every KNXnet/IP Secure property write of the reference download is
            // verified, credentials and element counts included.
            policy: WriteIntent::Explicit(WritePolicy::ReadBack),
        });
        Ok(())
    }
}

pub(super) fn property_target(property_id: u16, start_element: u16) -> OperationTarget {
    crate::commissioning::procedure::operands::property_target(&IP_OBJECT, property_id, start_element)
        .expect("builtin property selector fits service fields")
}

pub(super) fn property_image_location(property_id: u16) -> ImageLocation {
    ImageLocation { space: ImageSpace::Property { object: IP_OBJECT, property_id }, offset: 0 }
}
