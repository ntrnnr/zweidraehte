//! Observe one selected device, its management access, and its exact profile.
use crate::commissioning::runtime::TransferContext;

use crate::bus::access::ManagementCredential;
use crate::commissioning::catalog::profile::{ProfileDiscovery, ProfileSelection, ResolvedProfile, VariantHint};
use crate::commissioning::catalog::{requires_management_descriptor_01, resolve_profile};
use crate::commissioning::error::{Diagnostic, DiagnosticResult as Result};
use crate::commissioning::input::security::ObservedDataSecurity;
use crate::commissioning::input::{CommissioningIntent, ProgrammingInput, TargetSelection};
use crate::commissioning::procedure::operands::{OperationTarget, PropertyAddress, StandardMemoryService};
use crate::commissioning::procedure::{LoadEffect, OperationExtent};
use crate::commissioning::runtime::ExecutionSession;
use crate::commissioning::runtime::commissioner::{Commissioner, STANDARD_APDU_LENGTH};
use crate::commissioning::runtime::credentials::ManagementAccessOptions;
use crate::commissioning::runtime::policy::resolve_profile_authorization;
use std::sync::Arc;
use zweidraehte_ets_files::MasterData;
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::dpt::InterfaceObjectType;
use zweidraehte_proto::pid;

use super::capabilities::observe_association_table_entry_size;
use crate::commissioning::error::PreparationFailure;

#[derive(Debug, Clone, Copy)]
pub(in crate::commissioning) struct AcquiredTarget {
    pub(in crate::commissioning) address: IndividualAddress,
    pub(in crate::commissioning) serial_number: Option<[u8; 6]>,
}

pub(crate) struct ProfileObservation {
    pub(crate) profile: ResolvedProfile,
    pub(crate) target_max_apdu: u16,
    pub(crate) data_security: ObservedDataSecurity,
}

impl Commissioner<'_> {
    pub(in crate::commissioning) async fn observe_profile(
        &self,
        master_data: &Arc<MasterData>,
        input: &ProgrammingInput,
        variant_hint: VariantHint,
        target: &mut AcquiredTarget,
        session: &mut ExecutionSession<'_>,
        access_options: &ManagementAccessOptions,
        observes_group_security: bool,
    ) -> Result<ProfileObservation> {
        let product = input.device.product();
        let bootstrap_mode_required = session.selected_credential() == ManagementCredential::Fdsk
            && match input.intent {
                CommissioningIntent::AssignAddressAndDownload(_) => true,
                CommissioningIntent::AssignAddress => {
                    !matches!(input.options.target, TargetSelection::KnownPreviousAddress(_))
                }
                CommissioningIntent::Download(_) | CommissioningIntent::Unload(_) => false,
            };
        let discovery = async {
            let dd0 = read_dd0(session).await?;
            let descriptor = if requires_management_descriptor_01(master_data, dd0)? {
                Some(read_management_descriptor_01(session).await?)
            } else {
                None
            };

            let base_discovery = ProfileDiscovery { dd0, management_descriptor_01: descriptor, management_style: None };

            // The replacement product selects the target BCU2 realization
            // without consulting the currently installed user-save pointer.
            // The selected application's load-procedure style owns the
            // replacement image's realization choice.
            // Observing the installed realization is deferred until the
            // compiled operation proves that it will reuse installed state.
            let selection = ProfileSelection { discovery: base_discovery, variant_hint };
            let profile = resolve_profile(master_data, Some(product), &selection)?;
            let access =
                resolve_profile_authorization(&profile, self.options.required_authorization_level, access_options)?;
            session.bind_access(access.clone(), self.bus.max_apdu());
            session.authorize().await?;

            let association_table_entry_size = if input.intent.download_mode().is_some() {
                observe_association_table_entry_size(session.connection_mut()?, &profile).await?
            } else {
                None
            };
            let profile = match association_table_entry_size {
                Some(width) => profile
                    .with_association_table_entry_size(width)
                    .map_err(crate::commissioning::error::CompileError::from)?,
                None => profile,
            };
            let target_max_apdu = read_target_max_apdu(session, self.bus.max_apdu()).await;
            session.bind_access(access, target_max_apdu);
            let serial_number = match target.serial_number {
                Some(serial_number) => Some(serial_number),
                None => read_profile_serial_number(session, &profile).await?,
            };

            let data_security =
                if (product.supports_data_secure() && observes_group_security) || bootstrap_mode_required {
                    read_data_security_mode(session).await?
                } else {
                    ObservedDataSecurity::Unknown
                };
            Ok::<_, Diagnostic>((profile, target_max_apdu, serial_number, data_security))
        }
        .await;
        let (profile, target_max_apdu, serial_number, data_security) = session.finish(discovery).await?;
        target.serial_number = serial_number;
        session.identify(serial_number);

        Ok(ProfileObservation { profile, target_max_apdu, data_security })
    }
}

pub(in crate::commissioning) async fn read_dd0(session: &mut ExecutionSession<'_>) -> Result<u16> {
    let descriptor = session.connection_mut()?.device_descriptor_read(0).await.map_err(|error| {
        Diagnostic::from(error).preparation_context(PreparationFailure::Communication, "reading DD0")
    })?;
    let [high, low, ..] = descriptor.as_slice() else {
        return Err(Diagnostic::preparation(
            PreparationFailure::InvalidResponse,
            "DD0 response is shorter than two octets",
        ));
    };

    Ok(u16::from_be_bytes([*high, *low]))
}

pub(in crate::commissioning) async fn read_management_descriptor_01(
    session: &mut ExecutionSession<'_>,
) -> Result<[u8; 10]> {
    let target = OperationTarget::Property {
        address: PropertyAddress::Indexed { object_index: 0, property_id: pid::device::MGT_DESCRIPTOR as u8 },
        start_element: 1,
    };
    let value = session.read(&target, OperationExtent::property(10, 1), TransferContext::Public).await?;
    value.try_into().map_err(|_| {
        Diagnostic::preparation(PreparationFailure::InvalidResponse, "Device Object PID 72 is not exactly ten octets")
    })
}

pub(in crate::commissioning) async fn read_profile_serial_number(
    session: &mut ExecutionSession<'_>,
    profile: &ResolvedProfile,
) -> Result<Option<[u8; 6]>> {
    let Some(resource) = profile
        .resource("DeviceSerialNumber")
        .map_err(|error| Diagnostic::preparation(PreparationFailure::Profile, error.to_string()))?
    else {
        return Ok(None);
    };
    if resource.length() != 6 {
        return Err(Diagnostic::preparation(
            PreparationFailure::Profile,
            format!("profile {} declares a {}-octet DeviceSerialNumber resource", profile.mask(), resource.length()),
        ));
    }

    match resource
        .property_location()
        .map_err(|error| Diagnostic::preparation(PreparationFailure::Profile, error.to_string()))?
    {
        Some((_, _, 0)) => {}
        location => {
            return Err(Diagnostic::preparation(
                PreparationFailure::Profile,
                format!("DeviceSerialNumber uses unsupported live location {location:?}"),
            ));
        }
    };
    let read = resource.read(StandardMemoryService::Classic)?;
    let value = session.read(&read.target, read.extent, TransferContext::Public).await?;
    let serial_number: [u8; 6] = value.try_into().map_err(|value: Vec<u8>| {
        Diagnostic::preparation(
            PreparationFailure::InvalidResponse,
            format!("PID_SERIAL_NUMBER returned {} octets", value.len()),
        )
    })?;

    Ok((serial_number != [0; 6]).then_some(serial_number))
}

pub(in crate::commissioning) async fn read_target_max_apdu(
    session: &mut ExecutionSession<'_>,
    interface_max: u16,
) -> u16 {
    match session.connection_mut() {
        Ok(connection) => connection.read_max_apdu(interface_max).await,
        Err(_) => STANDARD_APDU_LENGTH,
    }
}

pub(in crate::commissioning) async fn read_data_security_mode(
    session: &mut ExecutionSession<'_>,
) -> Result<ObservedDataSecurity> {
    let address = PropertyAddress::Extended {
        object_type: InterfaceObjectType::Security,
        object_instance: 1,
        property_id: pid::security::SECURITY_MODE,
    };
    let response = session.function_request(address, &[0, 0], false, &LoadEffect::None).await?;
    decode_data_security_mode(&response.data)
}

fn decode_data_security_mode(data: &[u8]) -> Result<ObservedDataSecurity> {
    match data {
        [0, 0] => Ok(ObservedDataSecurity::Disabled),
        [0, 1] => Ok(ObservedDataSecurity::Enabled),
        _ => Err(Diagnostic::preparation(
            PreparationFailure::InvalidResponse,
            "Security Mode response has an invalid service or mode value",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_observation_rejects_unknown_services_and_non_boolean_values() {
        assert_eq!(decode_data_security_mode(&[0, 0]).expect("disabled mode"), ObservedDataSecurity::Disabled);
        assert_eq!(decode_data_security_mode(&[0, 1]).expect("enabled mode"), ObservedDataSecurity::Enabled);
        for data in [vec![], vec![0], vec![1, 0], vec![0, 2], vec![0, 1, 0]] {
            assert!(decode_data_security_mode(&data).is_err());
        }
    }
}
