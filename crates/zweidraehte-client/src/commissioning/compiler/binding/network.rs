//! Lower network configuration into explicit, ordered execution phases.

use crate::bus::access::ManagementCredential;
use crate::commissioning::compiler::program::{CommissioningApduRequirements, CompiledProgram};
use crate::commissioning::error::CompileError;
use crate::commissioning::input::security::{DesiredDataSecurity, ObservedDataSecurity};
use crate::commissioning::input::{CommissioningIntent, TargetSelection, UnloadMode};
use crate::commissioning::procedure::RestartKind;

use zweidraehte_project::DomainAddress;
use zweidraehte_proto::messages::apdu::device::{
    DomainAddressSerialNumberWrite, DomainAddressWrite, IndividualAddressSerialNumberWrite, IndividualAddressWrite,
    OpenMediumDomainAddress,
};
use zweidraehte_proto::messages::apdu::property_ext::PropertyExtValueRequest;
use zweidraehte_proto::messages::knx::offsets;

use crate::commissioning::compiler::program::network::NetworkProgram;

pub(crate) fn compile(program: &CompiledProgram) -> NetworkProgram {
    let observed = program.observed_target();
    let address_change = program.intent.mutates_address() && observed.previous_address != program.individual_address;
    // The open-medium domain address is network configuration, loaded
    // together with the individual address. An application download never
    // assigns it, not even when its medium-configuration section is selected:
    // that section's option set excludes the domain-address load bit, which
    // only the network-configuration load (individual and domain address)
    // carries.
    let domain_configuration = program.intent.mutates_address() && program.topology.domain_address.is_some();
    let programming_button_cleanup = (program.intent.mutates_address() || domain_configuration)
        && matches!(program.target, TargetSelection::ProgrammingButton(_));
    let clear_programming_mode = (program.intent.mutates_address() || domain_configuration)
        && match program.target {
            TargetSelection::ProgrammingButton(_) => true,
            TargetSelection::KnownPreviousAddress(_) => address_change,
            TargetSelection::SerialNumber(_) | TargetSelection::ExistingAddress(_) => false,
        };
    let bootstrap = observed.credential == ManagementCredential::Fdsk
        && match program.intent {
            CommissioningIntent::AssignAddressAndDownload(_) => true,
            CommissioningIntent::AssignAddress => !matches!(program.target, TargetSelection::KnownPreviousAddress(_)),
            CommissioningIntent::Download(_) | CommissioningIntent::Unload(_) => false,
        };
    let advance_sending_sequence = observed.credential == ManagementCredential::ToolKey
        && !matches!(
            (&program.intent, &program.target),
            (CommissioningIntent::AssignAddress, TargetSelection::KnownPreviousAddress(_))
        );

    // Loading the Data Secure tables does not change the Security Mode. The
    // reference download reads the mode before every application download
    // and switches it only when it differs; the factory bootstrap enables it
    // separately above. A device observed with the mode already on needs no
    // session at all; any other observation is read again at execution.
    let enable_data_security_before_download = !bootstrap
        && program.intent.download_mode().is_some()
        && program.desired_data_security == DesiredDataSecurity::Enabled
        && program.facts.data_security != ObservedDataSecurity::Enabled
        && observed.credential == ManagementCredential::ToolKey;

    NetworkProgram {
        assign_domain: domain_configuration,
        assign_address: address_change,
        clear_programming_mode,
        enable_data_security: bootstrap
            && program.desired_data_security == DesiredDataSecurity::Enabled
            && program.facts.data_security == ObservedDataSecurity::Disabled,
        enable_data_security_before_download,
        bootstrap_tool_key: bootstrap,
        restart: !bootstrap && (domain_configuration || address_change || clear_programming_mode),
        advance_sending_sequence,
        programming_button_cleanup,
    }
}

pub(crate) fn required_apdu(
    network: &NetworkProgram,
    program: &CompiledProgram,
) -> Result<CommissioningApduRequirements, CompileError> {
    if program.observed_target().credential == ManagementCredential::Fdsk
        && matches!(
            program.intent,
            CommissioningIntent::Download(_) | CommissioningIntent::Unload(UnloadMode::Application)
        )
    {
        return Err(network_error("application-only commissioning cannot retain factory FDSK management"));
    }
    let mut requirements = CommissioningApduRequirements::default();
    if network.assign_address {
        requirements.address_assignment = Some(
            (match program.target {
                TargetSelection::SerialNumber(_) => IndividualAddressSerialNumberWrite::MSG_LEN,
                TargetSelection::ProgrammingButton(_) | TargetSelection::KnownPreviousAddress(_) => {
                    IndividualAddressWrite::MSG_LEN
                }
                TargetSelection::ExistingAddress(_) => {
                    return Err(network_error("ExistingAddress cannot assign a different project address"));
                }
            } - offsets::MSG_APCI) as u16,
        );
    }
    let mut required = 0;
    if network.assign_domain {
        let domain = match program.topology.domain_address {
            Some(DomainAddress::Rf(value)) if value != [0; 6] && value != [255; 6] => {
                OpenMediumDomainAddress::Rf(value)
            }
            Some(DomainAddress::Rf(_)) => return Err(network_error("RF domain is reserved as void or ex-factory")),
            _ => return Err(network_error("domain assignment requires an RF domain")),
        };
        required = match program.target {
            TargetSelection::SerialNumber(_) => DomainAddressSerialNumberWrite::msg_len(domain),
            TargetSelection::ProgrammingButton(_) if !program.management_secure() => {
                DomainAddressWrite::msg_len(domain)
            }
            _ => return Err(network_error("domain assignment requires serial identity or plain programming mode")),
        } as u16
            - offsets::MSG_APCI as u16;
    }
    if network.clear_programming_mode {
        let (read, _) =
            program.programming_mode.as_ref().ok_or_else(|| network_error("programming mode resource is absent"))?;
        required = required.max(read.minimum_apdu()?);
    }
    if network.enable_data_security || network.enable_data_security_before_download {
        required = required.max(9);
    }
    if network.bootstrap_tool_key {
        if program.facts.data_security == ObservedDataSecurity::Unknown {
            return Err(network_error("Tool-Key bootstrap requires an observed Security Mode"));
        }
        if program.desired_data_security == DesiredDataSecurity::Disabled
            && program.facts.data_security == ObservedDataSecurity::Enabled
        {
            return Err(network_error("disabling installed Data Security is not implemented"));
        }
        required = required.max((PropertyExtValueRequest::msg_len(16) - offsets::MSG_APCI) as u16);
    }
    if network.restart {
        required = required.max(if network.advance_sending_sequence {
            (PropertyExtValueRequest::msg_len(6) - offsets::MSG_APCI) as u16
        } else {
            match program.network_restart_kind {
                RestartKind::Basic => 1,
                RestartKind::Confirmed => 4,
            }
        });
    }
    requirements.network_configuration = (required != 0).then_some(required);
    Ok(requirements)
}

fn network_error(message: &str) -> CompileError {
    CompileError::invalid(message)
}
