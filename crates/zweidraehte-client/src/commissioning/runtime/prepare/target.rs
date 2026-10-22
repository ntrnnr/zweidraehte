//! Acquire one exact target through the selected discovery service.

use super::profile::AcquiredTarget;
use crate::AddressTarget;
use crate::commissioning::compiler::program::CompiledProgram;
use crate::commissioning::error::Diagnostic;
use crate::commissioning::error::DiagnosticResult as Result;
use crate::commissioning::error::PreparationFailure;
use crate::commissioning::input::{ProgrammingModePolling, TargetSelection};
use crate::commissioning::runtime::commissioner::{
    Commissioner, CommissioningObserver, DeviceObservation, OPEN_MEDIUM_COLLECTION_WINDOW,
};
use crate::commissioning::runtime::policy::{programming_mode_scan, unique_domain_target, unique_target};
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::apdu::device::OpenMediumDomainAddress;

impl Commissioner<'_> {
    pub(in crate::commissioning) async fn acquire_target(
        &self,
        selection: &TargetSelection,
        open_medium: bool,
        observer: &impl CommissioningObserver,
    ) -> Result<AcquiredTarget> {
        let network = self.bus.network_management();

        match selection {
            TargetSelection::SerialNumber(serial_number) => {
                let addresses = network
                    .read_individual_addresses(AddressTarget::Serial(*serial_number), self.options.scan_window)
                    .await
                    .map_err(|error| {
                        Diagnostic::from(error)
                            .preparation_context(PreparationFailure::Communication, "locating serial-number target")
                    })?;
                let address = unique_target(addresses, "serial number")?;

                Ok(AcquiredTarget { address, serial_number: Some(*serial_number) })
            }
            TargetSelection::ProgrammingButton(polling) => {
                let addresses = self.poll_programming_mode(*polling, open_medium, observer).await?;
                let address = unique_target(addresses, "physical programming mode")?;
                let devices =
                    network.read_programming_mode_devices(self.options.scan_window).await.map_err(|error| {
                        Diagnostic::from(error).preparation_context(
                            PreparationFailure::Communication,
                            "reading the programming-mode serial number",
                        )
                    })?;
                let serial_number = match devices.as_slice() {
                    [] => None,
                    [device] if device.address == address => Some(device.serial_number),
                    [device] => {
                        return Err(Diagnostic::preparation(
                            PreparationFailure::AmbiguousTarget,
                            format!("programming-mode address scans disagree ({address} and {})", device.address),
                        ));
                    }
                    devices => {
                        return Err(Diagnostic::preparation(
                            PreparationFailure::AmbiguousTarget,
                            format!("{} devices answered the programming-mode serial query", devices.len()),
                        ));
                    }
                };

                Ok(AcquiredTarget { address, serial_number })
            }
            TargetSelection::KnownPreviousAddress(address) | TargetSelection::ExistingAddress(address) => {
                Ok(AcquiredTarget { address: *address, serial_number: None })
            }
        }
    }

    pub(in crate::commissioning) async fn poll_programming_mode(
        &self,
        polling: ProgrammingModePolling,
        open_medium: bool,
        observer: &impl CommissioningObserver,
    ) -> Result<Vec<IndividualAddress>> {
        if polling.wait_when_none_found && polling.timeout.is_zero() {
            return Err(Diagnostic::preparation(
                PreparationFailure::InvalidOptions,
                "programming-mode polling timeout must not be zero",
            ));
        }
        if polling.wait_when_none_found && polling.poll_interval.is_zero() {
            return Err(Diagnostic::preparation(
                PreparationFailure::InvalidOptions,
                "programming-mode polling interval must not be zero",
            ));
        }

        let scan = async {
            loop {
                observer.checkpoint()?;
                let network = self.bus.network_management();
                let (target, window) = programming_mode_scan(open_medium, self.options.scan_window);
                let found = network.read_individual_addresses(target, window).await.map_err(|error| {
                    Diagnostic::from(error)
                        .preparation_context(PreparationFailure::Communication, "scanning physical programming mode")
                })?;
                if !found.is_empty() || !polling.wait_when_none_found {
                    return Ok(found);
                }

                tokio::time::sleep(polling.poll_interval).await;
            }
        };

        if polling.wait_when_none_found {
            tokio::time::timeout(polling.timeout, scan).await.map_err(|_| {
                Diagnostic::preparation(
                    PreparationFailure::TargetNotFound,
                    "physical programming-mode polling timed out",
                )
            })?
        } else {
            scan.await
        }
    }
}

impl Commissioner<'_> {
    pub(in crate::commissioning) async fn preflight_open_medium_domain(
        &self,
        plan: &CompiledProgram,
        expected_address: IndividualAddress,
        serial_number: Option<[u8; 6]>,
        desired: OpenMediumDomainAddress,
    ) -> Result<bool> {
        let network = self.bus.network_management();
        let (address, current) = if let Some(serial_number) = serial_number {
            let found = network
                .read_domain_addresses(AddressTarget::Serial(serial_number), OPEN_MEDIUM_COLLECTION_WINDOW)
                .await
                .map_err(|error| {
                    Diagnostic::from(error)
                        .preparation_context(PreparationFailure::Communication, "reading the serial-number RF domain")
                })?;
            unique_domain_target(found, "the prepared serial number")?
        } else {
            if !matches!(plan.target(), TargetSelection::ProgrammingButton(_)) {
                return Err(Diagnostic::preparation(
                    PreparationFailure::Unsupported,
                    "RF domain assignment without a serial number requires physical programming mode",
                ));
            }

            let found = network
                .read_domain_addresses(AddressTarget::OpenMediumProgrammingMode, OPEN_MEDIUM_COLLECTION_WINDOW)
                .await
                .map_err(|error| {
                    Diagnostic::from(error).preparation_context(
                        PreparationFailure::Communication,
                        "reading the programming-mode RF domain",
                    )
                })?;
            unique_domain_target(found, "physical programming mode")?
        };

        if address != expected_address {
            return Err(Diagnostic::preparation(
                PreparationFailure::AmbiguousTarget,
                format!("RF domain discovery selected {address}, but target discovery selected {expected_address}"),
            ));
        }
        if current.encoded_len() != desired.encoded_len() {
            return Err(Diagnostic::preparation(
                PreparationFailure::Capability,
                format!("the selected device reports a {current:?} domain, incompatible with desired {desired:?}"),
            ));
        }

        Ok(current != desired)
    }
}
