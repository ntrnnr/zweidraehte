//! Network provisioning in fixed phase order, with one cleanup path.
use crate::commissioning::runtime::TransferContext;

use crate::commissioning::compiler::program::CompiledProgram;
use crate::commissioning::error::classify_serial_domain_poll;
use crate::commissioning::error::{CleanupOperation, Diagnostic, DiagnosticResult as CommissioningResult};
use crate::commissioning::evidence::SerialDomainPoll;
use crate::commissioning::input::TargetSelection;
use crate::commissioning::procedure::WritePolicy;
use crate::commissioning::report::{AddressAssignment, CommissioningEvent, CommissioningStage};
use crate::commissioning::runtime::ExecutionSession;
use crate::commissioning::runtime::commissioner::{
    CommissioningObserver, DeviceObservation, OPEN_MEDIUM_COLLECTION_WINDOW, SERIAL_DOMAIN_READ_ATTEMPT_WINDOW,
    SERIAL_DOMAIN_WRITE_SETTLE,
};
use crate::commissioning::runtime::credentials::ManagementAccess;
use crate::commissioning::runtime::policy::{
    open_medium_domain, system_status_with_programming_mode, unique_domain_target, unique_target,
    verify_programming_mode_address, verify_serial_address,
};
use crate::commissioning::runtime::prepared::PreparedEvidence;
use zweidraehte_project::ProgrammingSection;
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::apdu::device::OpenMediumDomainAddress;

impl ExecutionSession<'_> {
    /// Switch the Security Mode on before an application download, in a
    /// management session of its own. The mode is read again first, as the
    /// reference download does; a device that already has it on receives
    /// nothing. The tables follow in the download, so a failure after the
    /// switch leaves group communication uncertain.
    pub(super) async fn execute_security_mode(
        &mut self,
        plan: &CompiledProgram,
        observer: &mut impl CommissioningObserver,
    ) -> CommissioningResult<()> {
        if !plan.network().enable_data_security_before_download {
            return Ok(());
        }
        observer.checkpoint()?;
        observer.emit(CommissioningEvent::Stage(CommissioningStage::BootstrappingSecurity));
        self.connect().await?;
        let result = async {
            let mode = crate::commissioning::runtime::prepare::profile::read_data_security_mode(self).await?;
            if mode != crate::commissioning::input::security::ObservedDataSecurity::Enabled {
                self.enable_data_security().await?;
                self.effects.record_sections([ProgrammingSection::GroupCommunication]);
                observer.emit(CommissioningEvent::ProgrammingSectionsMutated {
                    sections: vec![ProgrammingSection::GroupCommunication],
                });
            }
            Ok(())
        }
        .await;
        self.finish(result).await
    }

    pub(super) async fn execute_network(
        &mut self,
        plan: &CompiledProgram,
        evidence: &PreparedEvidence,
        observer: &mut impl CommissioningObserver,
    ) -> CommissioningResult<()> {
        let network = *plan.network();
        let target = plan.observed_target();
        let mut domain_configuration_changed = false;
        let mut cleanup_armed = false;
        let mut uncertain_section = None;
        let result = async {
            if network.assign_domain {
                observer.checkpoint()?;
                observer.emit(CommissioningEvent::Stage(CommissioningStage::ConfiguringNetwork));
                let serial = match plan.target() {
                    TargetSelection::SerialNumber(serial) => Some(*serial),
                    _ => None,
                };
                uncertain_section = Some(ProgrammingSection::Configuration);
                self.images.forget_device();
                domain_configuration_changed = self.configure_open_medium_domain(plan, serial).await?;
                if domain_configuration_changed {
                    self.effects.record_sections([ProgrammingSection::Configuration]);
                    observer.emit(CommissioningEvent::ProgrammingSectionsMutated {
                        sections: vec![ProgrammingSection::Configuration],
                    });
                }
                uncertain_section = None;
            }
            if network.assign_address {
                observer.checkpoint()?;
                observer.emit(CommissioningEvent::Stage(CommissioningStage::AssigningAddress));
                self.images.forget_device();
                let assignment = self.assign_address(plan, &mut cleanup_armed).await?;
                self.target = assignment.current;
                self.effects.confirm_address(assignment);
                observer.emit(CommissioningEvent::AddressAssigned {
                    previous: assignment.previous,
                    current: self.target,
                    serial_number: target.serial_number,
                });
                cleanup_armed |= network.clear_programming_mode;
                self.bus.move_device_security(target.previous_address, self.target).await.map_err(|error| {
                    Diagnostic::from(error).context("moving management credentials after address assignment")
                })?;
            }
            if network.clear_programming_mode {
                cleanup_armed = true;
                self.set_programming_mode(plan, self.target, false).await?;
                cleanup_armed = false;
            }
            self.effects.record_network_configuration(
                domain_configuration_changed
                    || self.effects.address_assignment().is_some()
                    || network.clear_programming_mode
                    || network.bootstrap_tool_key,
            );
            if !self.effects.network_configuration_performed() {
                return Ok(());
            }
            observer.checkpoint()?;
            self.connect().await?;
            if network.bootstrap_tool_key {
                observer.emit(CommissioningEvent::Stage(CommissioningStage::BootstrappingSecurity));
                uncertain_section = Some(ProgrammingSection::GroupCommunication);
                if network.enable_data_security {
                    self.enable_data_security().await?;
                    self.disconnect().await?;
                    self.connect().await?;
                }
                self.bootstrap_tool_key().await?;
                self.advance_sending_sequence(target.serial_number).await?;
                self.restart_device(plan.network_restart_kind()).await?;
                self.effects.record_sections([ProgrammingSection::GroupCommunication]);
                observer.emit(CommissioningEvent::ProgrammingSectionsMutated {
                    sections: vec![ProgrammingSection::GroupCommunication],
                });
                uncertain_section = None;
            } else {
                if !network.assign_domain {
                    observer.emit(CommissioningEvent::Stage(CommissioningStage::ConfiguringNetwork));
                }
                if network.advance_sending_sequence {
                    self.advance_sending_sequence(target.serial_number).await?;
                }
                self.restart_device(plan.network_restart_kind()).await?;
            }
            self.revalidate_binding(self.target, plan, evidence, false).await
        }
        .await;
        let result = self.finish(result).await;
        if let Err(error) = result {
            if self.mutated() {
                if let Some(section) = uncertain_section {
                    self.effects.record_sections([section]);
                    observer.emit(CommissioningEvent::ProgrammingSectionsMutated { sections: vec![section] });
                }
            }
            let cleanup = if cleanup_armed || (network.programming_button_cleanup && self.mutated()) {
                self.best_effort_disable_programming_mode(plan, [target.previous_address, plan.individual_address()])
                    .await
            } else {
                Vec::new()
            };
            return Err(error.with_cleanup_failures(CleanupOperation::DisableProgrammingMode, cleanup));
        }
        Ok(())
    }
}

impl ExecutionSession<'_> {
    pub(in crate::commissioning) async fn configure_open_medium_domain(
        &mut self,
        plan: &CompiledProgram,
        serial_number: Option<[u8; 6]>,
    ) -> Result<bool, Diagnostic> {
        let expected_address = self.target;
        let Some(domain) = plan.topology().domain_address else {
            return Ok(false);
        };
        let desired = open_medium_domain(domain)?;
        let network = self.bus.network_management();

        if let Some(serial_number) = serial_number {
            let found = network
                .read_domain_addresses_by_serial(&serial_number, OPEN_MEDIUM_COLLECTION_WINDOW)
                .await
                .map_err(|error| Diagnostic::from(error).context("revalidating the serial-number RF domain"))?;
            let (address, current) = unique_domain_target(found, "the prepared serial number")?;
            if address != expected_address {
                return Err(Diagnostic::new(format!(
                    "the serial-number RF target moved from {expected_address} to {address}"
                )));
            }
            if current == desired {
                return Ok(false);
            }

            let secure = self.access.credential().is_secure();
            self.write_serial_domain_once(serial_number, desired).await?;

            // 03/05/02 sections 2.12 and 2.13 start verification one second
            // after local send confirmation. Repeated serial IA reads prove
            // reachability through the new domain, but do not echo its bytes.
            tokio::time::sleep(SERIAL_DOMAIN_WRITE_SETTLE).await;
            let mut verified = self
                .poll_serial_domain_reachability(serial_number)
                .await
                .map_err(|error| Diagnostic::from(error).context("verifying reachability after the RF domain write"))?;

            if verified.is_none() {
                // The plain procedure repeats its write once. The secure
                // procedure repeats from its post-write timer/verification
                // phase, deliberately avoiding a second protected mutation.
                tokio::time::sleep(SERIAL_DOMAIN_WRITE_SETTLE).await;
                if !secure {
                    self.write_serial_domain_once(serial_number, desired).await?;
                }

                // This is the verification delay after the repeated plain
                // write, or after the secure procedure's repeated timer phase.
                tokio::time::sleep(SERIAL_DOMAIN_WRITE_SETTLE).await;
                verified = self.poll_serial_domain_reachability(serial_number).await.map_err(|error| {
                    Diagnostic::from(error).context("verifying reachability after the RF domain retry")
                })?;
            }

            let verified = verified.ok_or_else(|| {
                Diagnostic::new("the serial-number RF domain write remained unreachable after the specified retry")
            })?;
            if verified != expected_address {
                return Err(Diagnostic::new(format!(
                    "the RF-domain verification answered from {verified}, expected {expected_address}"
                )));
            }

            return Ok(true);
        }

        if self.access.credential().is_secure() {
            return Err(Diagnostic::new("protected RF domain assignment requires a serial-number identity"));
        }
        if !matches!(plan.target(), TargetSelection::ProgrammingButton(_)) {
            return Err(Diagnostic::new(
                "RF domain assignment without a serial number requires physical programming mode",
            ));
        }

        let found = network
            .read_programming_mode_domain_addresses(OPEN_MEDIUM_COLLECTION_WINDOW)
            .await
            .map_err(|error| Diagnostic::from(error).context("revalidating the programming-mode RF domain"))?;
        let (address, current) = unique_domain_target(found, "physical programming mode")?;
        if address != expected_address {
            return Err(Diagnostic::new("the programming-mode RF target changed after preparation"));
        }
        if current == desired {
            return Ok(false);
        }

        let written = network.write_programming_mode_domain_address(desired).await;
        self.network_write_result("writing the programming-mode RF domain", written)?;
        let verified = network
            .verify_programming_mode_domain_address(desired, OPEN_MEDIUM_COLLECTION_WINDOW)
            .await
            .map_err(|error| Diagnostic::from(error).context("verifying the programming-mode RF domain"))?;
        if verified != expected_address {
            return Err(Diagnostic::new(format!(
                "the RF-domain verification answered from {verified}, expected {expected_address}"
            )));
        }

        Ok(true)
    }

    pub(in crate::commissioning) async fn write_serial_domain_once(
        &mut self,
        serial_number: [u8; 6],
        desired: OpenMediumDomainAddress,
    ) -> Result<(), Diagnostic> {
        let network = self.bus.network_management();
        let result = match &self.access {
            ManagementAccess::ToolKey(key) | ManagementAccess::Fdsk(key) => {
                network
                    .write_domain_address_by_serial_secure(
                        &serial_number,
                        self.target,
                        desired,
                        key.key16().expect("selected management key width"),
                    )
                    .await
            }
            ManagementAccess::Plaintext => network.write_domain_address_by_serial(&serial_number, desired).await,
        };

        self.network_write_result("writing the serial-number RF domain", result)
    }

    fn network_write_result(&mut self, operation: &str, result: crate::bus::BusResult<()>) -> Result<(), Diagnostic> {
        result.map_err(|error| {
            let mut error = self.mutating_client_error(error);
            error.message = format!("{operation}: {}", error.message);
            error
        })?;
        self.record_mutation();
        Ok(())
    }

    pub(in crate::commissioning) async fn poll_serial_domain_reachability(
        &self,
        serial_number: [u8; 6],
    ) -> std::result::Result<Option<IndividualAddress>, crate::bus::BusError> {
        let deadline = tokio::time::Instant::now() + self.config.scan_window;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }

            let attempt_window = remaining.min(SERIAL_DOMAIN_READ_ATTEMPT_WINDOW);
            let result =
                self.bus.network_management().read_individual_addresses_by_serial(&serial_number, attempt_window).await;

            match classify_serial_domain_poll(result)? {
                SerialDomainPoll::Found(address) => return Ok(Some(address)),
                SerialDomainPoll::NoResponse => {}
                SerialDomainPoll::RejectedSend => {
                    // Some interfaces reject a broadcast before installing the
                    // scan window. Keep the specified repeated-read cadence;
                    // otherwise this retry loop can flood a faulty interface.
                    tokio::time::sleep(attempt_window).await;
                }
            }
        }
    }
}

impl ExecutionSession<'_> {
    pub(in crate::commissioning) async fn assign_address(
        &mut self,
        plan: &CompiledProgram,
        cleanup_armed: &mut bool,
    ) -> Result<AddressAssignment, Diagnostic> {
        let previous = self.target;
        let desired = plan.individual_address();
        let network = self.bus.network_management();

        // The desired-address collision check intentionally does not live in
        // this helper. Execution performs it immediately before any domain
        // write, as required by the combined open-medium procedure; repeating
        // it here could first change the domain and only then report a clash.
        let (open_medium, source) = match plan.target() {
            TargetSelection::SerialNumber(serial) => {
                let found = network
                    .read_individual_addresses_by_serial(serial, self.config.scan_window)
                    .await
                    .map_err(|error| Diagnostic::from(error).context("revalidating the serial-number target"))?;
                let found = unique_target(found, "the serial-number target")?;
                if found != previous {
                    return Err(Diagnostic::new(format!("the serial-number target moved from {previous} to {found}")));
                }

                let written = match &self.access {
                    ManagementAccess::ToolKey(key) | ManagementAccess::Fdsk(key) => {
                        network
                            .write_individual_address_by_serial_secure(
                                serial,
                                previous,
                                desired,
                                key.key16().expect("selected management key width"),
                            )
                            .await
                    }
                    ManagementAccess::Plaintext => network.write_individual_address_by_serial(serial, desired).await,
                };
                self.network_write_result("assigning the individual address by serial number", written)?;
                verify_serial_address(self.bus, *serial, desired, self.config.scan_window).await?;

                return Ok(AddressAssignment {
                    previous,
                    current: desired,
                    changed: true,
                    serial_number: self.serial_number,
                });
            }
            TargetSelection::ProgrammingButton(_) => {
                (plan.topology().domain_address.is_some(), "physical programming mode")
            }
            TargetSelection::KnownPreviousAddress(_) => {
                let enabled = self.set_programming_mode(plan, previous, true).await;
                // A successful enable owns cleanup even when the device was
                // already in that mode. Uncertain writes own it as well.
                *cleanup_armed = enabled.is_ok() || self.mutated();
                enabled?;
                (false, "remotely enabled programming mode")
            }
            TargetSelection::ExistingAddress(_) => {
                return Err(Diagnostic::new("ExistingAddress cannot assign a different project individual address"));
            }
        };
        let active = if open_medium {
            network.read_open_medium_individual_addresses(OPEN_MEDIUM_COLLECTION_WINDOW).await
        } else {
            network.read_individual_addresses(self.config.scan_window).await
        }
        .map_err(|error| Diagnostic::from(error).context(format!("revalidating {source}")))?;
        let active = unique_target(active, source)?;
        if active != previous {
            return Err(Diagnostic::new(format!("the {source} target changed before individual-address assignment")));
        }
        let write = if open_medium {
            network.write_open_medium_individual_address(desired).await
        } else {
            network.write_individual_address(desired).await
        };
        self.network_write_result("writing the programming-mode individual address", write)?;
        verify_programming_mode_address(self.bus, desired, self.config.scan_window, open_medium).await?;

        Ok(AddressAssignment { previous, current: desired, changed: true, serial_number: self.serial_number })
    }

    pub(in crate::commissioning) async fn best_effort_disable_programming_mode(
        &mut self,
        plan: &CompiledProgram,
        addresses: [IndividualAddress; 2],
    ) -> Vec<Diagnostic> {
        let previous = addresses[0];
        let mut failures = Vec::new();

        for (index, address) in addresses.into_iter().enumerate() {
            if index == 1 && address == previous {
                continue;
            }

            if let Err(mut error) = self.set_programming_mode(plan, address, false).await {
                error.message = format!("clearing programming mode at {address}: {}", error.message);
                failures.push(error);
            }
        }

        failures
    }
}

impl ExecutionSession<'_> {
    pub(super) async fn set_programming_mode(
        &mut self,
        plan: &CompiledProgram,
        address: IndividualAddress,
        enabled: bool,
    ) -> std::result::Result<bool, Diagnostic> {
        let (binding, legacy_status) =
            plan.programming_mode().ok_or_else(|| Diagnostic::new("programming mode has no prepared service"))?;
        self.connect_at(address).await?;
        let result = async {
            let current = self.read(&binding.target, binding.extent, TransferContext::Public).await?;
            let value = if *legacy_status {
                let [current] = current.as_slice() else {
                    return Err(Diagnostic::new("BCU programming-mode status is not one octet"));
                };
                vec![system_status_with_programming_mode(*current, enabled)]
            } else {
                vec![u8::from(enabled)]
            };
            if current == value {
                return Ok(false);
            }
            self.write(&binding.target, &value, binding.extent, WritePolicy::ReadBack, TransferContext::Public).await?;
            Ok(true)
        }
        .await;
        self.finish(result).await
    }
}

impl ExecutionSession<'_> {
    pub(in crate::commissioning) async fn finish_complete_unload(
        &mut self,
        plan: &CompiledProgram,
        observer: &mut impl CommissioningObserver,
    ) -> Result<(), Diagnostic> {
        let default_address = IndividualAddress::from([0xFF, 0xFF]);
        if !self.effects.cleared_sections().contains(&ProgrammingSection::Address) {
            let serial_number = plan
                .observed_target()
                .serial_number
                .ok_or_else(|| Diagnostic::new("legacy complete unload lost its preflight serial number"))?;
            let network = self.bus.network_management();
            let written = match &self.access {
                ManagementAccess::ToolKey(key) | ManagementAccess::Fdsk(key) => {
                    network
                        .write_individual_address_by_serial_secure(
                            &serial_number,
                            self.target,
                            default_address,
                            key.key16().expect("selected management key width"),
                        )
                        .await
                }
                ManagementAccess::Plaintext => {
                    network.write_individual_address_by_serial(&serial_number, default_address).await
                }
            };
            self.network_write_result("resetting the legacy device individual address", written)?;
            self.effects.record_sections([ProgrammingSection::Address, ProgrammingSection::Configuration]);
            observer.emit(CommissioningEvent::ProgrammingSectionsMutated {
                sections: vec![ProgrammingSection::Address, ProgrammingSection::Configuration],
            });
        }

        if let Some(serial_number) = plan.observed_target().serial_number {
            verify_serial_address(self.bus, serial_number, default_address, self.config.scan_window).await?;
        }
        self.effects.confirm_section_erasure(ProgrammingSection::Address);
        if self.effects.group_keys_erased() {
            self.bus.remove_device_security(self.target).await.map_err(|error| {
                Diagnostic::from(error).context("removing obsolete management security after complete unload")
            })?;
        }

        Ok(())
    }
}
