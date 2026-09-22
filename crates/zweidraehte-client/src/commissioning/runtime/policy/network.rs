//! Network scope policy and explicit post-assignment address verification.

use super::identity::unique_target;
use crate::bus::KnxBus;
use crate::commissioning::compiler::program::CompiledProgram;
use crate::commissioning::error::Diagnostic;
use crate::commissioning::error::DiagnosticResult as Result;
use crate::commissioning::input::{CommissioningIntent, DownloadMode, ProgramSections};
use crate::commissioning::runtime::commissioner::OPEN_MEDIUM_COLLECTION_WINDOW;
use std::time::Duration;
use zweidraehte_project::DomainAddress;
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::apdu::device::OpenMediumDomainAddress;

pub(in crate::commissioning) fn requested_topology_network_configuration(
    intent: CommissioningIntent,
    automatic_sections: Option<ProgramSections>,
) -> bool {
    if intent.mutates_address() {
        return true;
    }

    match intent {
        CommissioningIntent::Download(DownloadMode::Full) => true,
        CommissioningIntent::Download(DownloadMode::Partial(sections)) => {
            sections.contains(ProgramSections::CONFIGURATION)
        }
        CommissioningIntent::Download(DownloadMode::Automatic) => {
            // Profile resolution may widen any automatic delta to a full
            // published procedure. Before that profile is known, an authored
            // open-medium domain must use the discovery path which remains
            // valid if CONFIGURATION is added by that widening.
            automatic_sections.is_some()
        }
        CommissioningIntent::AssignAddress
        | CommissioningIntent::AssignAddressAndDownload(_)
        | CommissioningIntent::Unload(_) => false,
    }
}

pub(in crate::commissioning) fn medium_configuration_requested(plan: &CompiledProgram) -> bool {
    plan.intent().download_mode().is_some()
        && plan.program_sections().is_some_and(|sections| sections.contains(ProgramSections::CONFIGURATION))
}

pub(in crate::commissioning) fn open_medium_domain(domain: DomainAddress) -> Result<OpenMediumDomainAddress> {
    match domain {
        DomainAddress::Rf(value) if value != [0; 6] && value != [u8::MAX; 6] => Ok(OpenMediumDomainAddress::Rf(value)),
        DomainAddress::Rf(value) => Err(Diagnostic::preparation(format!(
            "RF domain address {value:02x?} is reserved as a void or ex-factory value"
        ))),
        DomainAddress::Ip(_) => Err(Diagnostic::preparation(
            "KNX/IP multicast is compiled through the IP Parameter Object, never open-medium domain services",
        )),
    }
}

pub(in crate::commissioning) fn system_status_with_programming_mode(value: u8, enabled: bool) -> u8 {
    // BCU system status protects the byte with even parity in bit 7. Preserve
    // every unrelated status flag, replace only the programming-mode bit,
    // then recompute parity so real masks accept the write.
    let mut value = value & !(0x80 | 0x01);
    if enabled {
        value |= 0x01;
    }
    if !value.count_ones().is_multiple_of(2) {
        value |= 0x80;
    }

    value
}

// `NM_IndividualAddress_Write` has no response of its own. Its specified
// verification is another programming-mode address read: the response source
// is the persisted IA. Do not substitute a connectionless DD0 probe here;
// base BCU profiles expose DD0 only through connected management.
pub(in crate::commissioning) async fn verify_programming_mode_address(
    bus: &KnxBus,
    expected: IndividualAddress,
    window: Duration,
    open_medium: bool,
) -> Result<()> {
    let network = bus.network_management();
    let found = if open_medium {
        network.read_open_medium_individual_addresses(OPEN_MEDIUM_COLLECTION_WINDOW).await
    } else {
        network.read_individual_addresses(window).await
    }
    .map_err(|error| {
        Diagnostic::from(error).preparation_context("verifying the programming-mode individual address")
    })?;

    verify_programming_mode_address_responses(&found, expected)
}

pub(in crate::commissioning) fn verify_programming_mode_address_responses(
    found: &[IndividualAddress],
    expected: IndividualAddress,
) -> Result<()> {
    let actual = unique_target(found.to_vec(), "programming-mode address verification")?;
    if actual == expected {
        Ok(())
    } else {
        Err(Diagnostic::preparation(format!("programming-mode IA assignment produced {actual}, expected {expected}")))
    }
}

pub(in crate::commissioning) async fn verify_serial_address(
    bus: &KnxBus,
    serial_number: [u8; 6],
    expected: IndividualAddress,
    window: Duration,
) -> Result<()> {
    let found = bus
        .network_management()
        .read_individual_addresses_by_serial(&serial_number, window)
        .await
        .map_err(|error| Diagnostic::from(error).context("verifying the serial-number IA assignment"))?;
    match found.as_slice() {
        [actual] if *actual == expected => Ok(()),
        [actual] => Err(Diagnostic::new(format!("serial-number IA assignment produced {actual}, expected {expected}"))),
        [] => Err(Diagnostic::new("the serial-number target disappeared after IA assignment")),
        devices => Err(Diagnostic::new(format!("{} devices answered with the assigned serial number", devices.len()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commissioning::input::UnloadMode;
    use crate::commissioning::runtime::policy::requested_topology_network_configuration;

    #[test]
    fn open_medium_target_acquisition_is_limited_to_network_configuration() {
        assert!(requested_topology_network_configuration(CommissioningIntent::AssignAddress, None));
        assert!(requested_topology_network_configuration(CommissioningIntent::Download(DownloadMode::Full), None));
        assert!(requested_topology_network_configuration(
            CommissioningIntent::Download(DownloadMode::Partial(ProgramSections::CONFIGURATION)),
            None
        ));
        assert!(!requested_topology_network_configuration(
            CommissioningIntent::Download(DownloadMode::Partial(ProgramSections::PARAMETERS)),
            None
        ));
        let automatic_delta = ProgramSections::APPLICATION_PROGRAM_1.union(ProgramSections::PARAMETERS);
        assert!(requested_topology_network_configuration(
            CommissioningIntent::Download(DownloadMode::Automatic),
            Some(automatic_delta)
        ));
        assert!(!requested_topology_network_configuration(
            CommissioningIntent::Download(DownloadMode::Partial(automatic_delta)),
            None
        ));
        assert!(!requested_topology_network_configuration(CommissioningIntent::Unload(UnloadMode::Application), None));
    }
}
