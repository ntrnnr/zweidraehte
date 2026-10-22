//! Network scope policy and explicit post-assignment address verification.

use super::identity::unique_target;
use crate::AddressTarget;
use crate::bus::KnxBus;
use crate::commissioning::error::Diagnostic;
use crate::commissioning::error::DiagnosticResult as Result;
use crate::commissioning::error::PreparationFailure;
use crate::commissioning::input::CommissioningIntent;
use crate::commissioning::runtime::commissioner::OPEN_MEDIUM_COLLECTION_WINDOW;
use std::time::Duration;
use zweidraehte_project::DomainAddress;
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::apdu::device::OpenMediumDomainAddress;

/// Whether target acquisition must collect open-medium domain evidence.
///
/// The domain address is loaded only with the individual address, so an
/// application download never assigns it, whatever sections it selects.
pub(in crate::commissioning) fn requested_topology_network_configuration(intent: CommissioningIntent) -> bool {
    intent.mutates_address()
}

pub(in crate::commissioning) fn open_medium_domain(domain: DomainAddress) -> Result<OpenMediumDomainAddress> {
    match domain {
        DomainAddress::Rf(value) if value != [0; 6] && value != [u8::MAX; 6] => Ok(OpenMediumDomainAddress::Rf(value)),
        DomainAddress::Rf(value) => Err(Diagnostic::preparation(
            PreparationFailure::InvalidOptions,
            format!("RF domain address {value:02x?} is reserved as a void or ex-factory value"),
        )),
        DomainAddress::Ip(_) => Err(Diagnostic::preparation(
            PreparationFailure::InvalidOptions,
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
/// How physical programming mode is scanned: an open medium answers a KNX
/// system broadcast and needs the longer collection window.
pub(in crate::commissioning) fn programming_mode_scan(
    open_medium: bool,
    scan_window: Duration,
) -> (AddressTarget, Duration) {
    if open_medium {
        (AddressTarget::OpenMediumProgrammingMode, OPEN_MEDIUM_COLLECTION_WINDOW)
    } else {
        (AddressTarget::ProgrammingMode, scan_window)
    }
}

pub(in crate::commissioning) async fn verify_programming_mode_address(
    bus: &KnxBus,
    expected: IndividualAddress,
    window: Duration,
    open_medium: bool,
) -> Result<()> {
    let (target, window) = programming_mode_scan(open_medium, window);
    let found = bus.network_management().read_individual_addresses(target, window).await.map_err(|error| {
        Diagnostic::from(error)
            .preparation_context(PreparationFailure::Communication, "verifying the programming-mode individual address")
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
        Err(Diagnostic::preparation(
            PreparationFailure::InvalidResponse,
            format!("programming-mode IA assignment produced {actual}, expected {expected}"),
        ))
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
        .read_individual_addresses(AddressTarget::Serial(serial_number), window)
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
    use crate::commissioning::input::{DownloadMode, ProgramSections, UnloadMode};
    use crate::commissioning::runtime::policy::requested_topology_network_configuration;

    #[test]
    fn open_medium_target_acquisition_is_limited_to_address_programming() {
        assert!(requested_topology_network_configuration(CommissioningIntent::AssignAddress));
        assert!(requested_topology_network_configuration(CommissioningIntent::AssignAddressAndDownload(
            DownloadMode::Partial(ProgramSections::PARAMETERS)
        )));
        for mode in [
            DownloadMode::Full,
            DownloadMode::Automatic,
            DownloadMode::Partial(ProgramSections::CONFIGURATION),
            DownloadMode::Partial(ProgramSections::PARAMETERS),
        ] {
            assert!(!requested_topology_network_configuration(CommissioningIntent::Download(mode)));
        }
        assert!(!requested_topology_network_configuration(CommissioningIntent::Unload(UnloadMode::Application)));
    }
}
