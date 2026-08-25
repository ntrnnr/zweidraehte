//! One commissioning pipeline shared by command-line, UI, and tests.
//!
//! Product interpretation and key resolution happen before this layer. The
//! programmer owns the ordering that matters on a live bus. It exposes ETS's
//! network-configuration and application-programming phases separately, plus
//! a combined operation: identify and compile against the real mask before a
//! move, choose management access without a plaintext downgrade, establish
//! secure management, execute the requested mask procedure, and verify state.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::device::{MaskFamily, MaskVersion};
use zweidraehte_proto::messages::apdu::load_control::{LoadEvent, LoadState, RunState};
use zweidraehte_proto::messages::apdu::restart::EraseCode;
use zweidraehte_proto::messages::apdu::secure;
use zweidraehte_proto::pid;

use crate::api::{DeviceConnection, KnxBus};
use crate::download::{
    CompiledDownload, DeviceConfiguration, DeviceImage, DownloadEvent, DownloadModel, Instruction, LoadControlPath,
    LsmTarget, MaskData, MaskDb, ProductData, load_control_path, select_download_mask,
};
use crate::error::{Error, Result};
use crate::security::{
    DeviceSecurityMode, KeyMetadata, KeyStoreError, ResolvedKeyMaterial, SecurityEntry, knx_sequence_timestamp_floor,
};

const SECURITY_IO: u16 = 0x0011;
const SECURITY_IO_OCCURRENCE: u16 = 1;

/// How the programmer locates and, if needed, addresses the target.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AddressingMode {
    /// Use serial-number addressing for BCU2/System 7/System B when a serial
    /// is available; otherwise expect the desired IA to be current already.
    #[default]
    Automatic,
    /// Locate the one device whose physical programming mode is active.
    ProgrammingButton,
    /// Do not discover or change the address.
    ExistingAddress,
}

/// Which ETS-style programming phase to execute.
///
/// Network configuration owns identity and secure-management bootstrap. The
/// application phase assumes that work has completed and never changes the
/// individual address or installs a Tool Key implicitly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProgrammingScope {
    /// Assign the individual address and establish secure management only.
    Address,
    /// Download application and Security IO tables at the configured address.
    Application,
    /// Commission the address when necessary, then download the application.
    #[default]
    AddressAndApplication,
}

impl ProgrammingScope {
    pub fn includes_address(self) -> bool {
        matches!(self, Self::Address | Self::AddressAndApplication)
    }

    pub fn includes_application(self) -> bool {
        matches!(self, Self::Application | Self::AddressAndApplication)
    }
}

#[derive(Debug, Clone)]
pub struct ProgrammingOptions {
    pub scope: ProgrammingScope,
    pub addressing: AddressingMode,
    pub scan_window: Duration,
    pub restart_delay: Duration,
    /// Permit plaintext only after configured tool-key and FDSK attempts.
    pub allow_plaintext_management: bool,
}

impl Default for ProgrammingOptions {
    fn default() -> Self {
        Self {
            scope: ProgrammingScope::AddressAndApplication,
            addressing: AddressingMode::Automatic,
            scan_window: Duration::from_secs(2),
            restart_delay: Duration::from_secs(3),
            allow_plaintext_management: true,
        }
    }
}

/// Durable destination for a generated tool key. Persistence happens before
/// the first bus operation, so a lost rotation acknowledgement is retryable.
pub trait GeneratedToolKeySink {
    fn persist_generated_tool_key(
        &mut self,
        serial: Option<[u8; 6]>,
        tool_key: [u8; 16],
    ) -> core::result::Result<(), KeyStoreError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgrammingStage {
    PersistingToolKey,
    DiscoveringDevice,
    ReadingDescriptor,
    Compiling,
    AssigningAddress,
    SelectingManagementAccess,
    EnablingSecurityMode,
    InstallingToolKey,
    RestartingSecurityBootstrap,
    SettingDeviceSequence,
    Downloading,
    RestartingDevice,
    WaitingForRestart,
    Verifying,
}

#[derive(Debug, Clone)]
pub enum ProgrammingEvent {
    Stage(ProgrammingStage),
    Download(DownloadEvent),
}

pub type ProgrammingProgress = Box<dyn FnMut(ProgrammingEvent) + Send>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementAccess {
    ToolKey,
    Fdsk,
    Plain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressAssignmentMethod {
    SerialNumber,
    ProgrammingButton,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressAssignmentReport {
    pub method: AddressAssignmentMethod,
    pub previous: IndividualAddress,
    pub current: IndividualAddress,
    pub changed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityVerification {
    pub security_mode: bool,
    pub group_key_entries: u16,
    pub sender_entries: u16,
    pub group_object_entries: u16,
}

#[derive(Debug, Clone)]
pub struct ProgrammingReport {
    pub individual_address: IndividualAddress,
    pub product_mask: MaskVersion,
    pub device_mask: MaskVersion,
    pub address_assignment: Option<AddressAssignmentReport>,
    /// Whether this invocation changed network configuration (IA, secure
    /// management state, or the device's outgoing sequence-number base).
    pub network_configuration_performed: bool,
    /// Whether the compiled application procedure was executed.
    pub application_downloaded: bool,
    pub management_access: ManagementAccess,
    pub max_apdu: u16,
    /// Non-secret mask-compiled memory image, useful for dry comparisons.
    pub programmed_image: DeviceImage,
    pub load_control_path: LoadControlPath,
    pub instruction_count: usize,
    pub load_states: Vec<(LsmTarget, LoadState)>,
    pub security: Option<SecurityVerification>,
    /// Non-secret origins and fingerprints of credentials used by the run.
    pub key_provenance: Vec<KeyMetadata>,
}

pub struct ProgrammingRequest<'a> {
    pub mask_db: &'a MaskDb,
    pub product: &'a ProductData,
    pub configuration: &'a DeviceConfiguration,
    pub key_material: ResolvedKeyMaterial,
    pub options: ProgrammingOptions,
}

/// Read-only result used to prove that every member of a batch is compatible
/// and compilable before the first device is changed.
pub struct ProgrammingPreflight {
    pub current_address: IndividualAddress,
    pub product_mask: MaskVersion,
    pub device_mask: MaskVersion,
    pub assignment_method: Option<AddressAssignmentMethod>,
    /// Present only when the selected scope includes application programming.
    pub compiled: Option<CompiledDownload>,
}

/// Stateless high-level commissioner. Mutable protocol and security state stays
/// in [`KnxBus`]; all per-run desired state is explicit in the request.
#[derive(Debug, Default)]
pub struct DeviceProgrammer;

impl DeviceProgrammer {
    pub fn new() -> Self {
        Self
    }

    /// Generate and durably store a missing tool key before any bus object is
    /// opened. Frontends call this after offline resolution; `program` calls
    /// it again defensively for library callers which already own a bus.
    ///
    /// Returns `true` when a key was generated during this call.
    pub fn materialize_tool_key(
        &self,
        key_material: &mut ResolvedKeyMaterial,
        generated_key_sink: Option<&mut dyn GeneratedToolKeySink>,
    ) -> Result<bool> {
        if !key_material.needs_tool_key_generation {
            return Ok(false);
        }
        let sink = generated_key_sink.ok_or(Error::GeneratedToolKeyRequiresStore)?;
        let mut tool_key = [0u8; 16];
        getrandom::fill(&mut tool_key).map_err(|error| {
            Error::KeyMaterial(KeyStoreError::Unavailable(format!("the OS random generator failed: {error}")))
        })?;
        sink.persist_generated_tool_key(key_material.serial_number, tool_key)?;
        key_material.tool_key = Some(tool_key);
        key_material.record_generated_tool_key(tool_key);
        key_material.needs_tool_key_generation = false;
        Ok(true)
    }

    /// Discover, authenticate, merge live SIAT replay floors, select the real
    /// device mask, and compile without writing device configuration. The
    /// key material is mutable because a live SIAT can only raise rows which
    /// the desired complete table already contains.
    pub async fn preflight(&self, bus: &KnxBus, request: &mut ProgrammingRequest<'_>) -> Result<ProgrammingPreflight> {
        validate_data_secure_selection(request)?;
        if request.options.scope == ProgrammingScope::Application && request.key_material.needs_tool_key_generation {
            return Err(Error::NetworkConfigurationRequired);
        }
        if request.key_material.needs_tool_key_generation {
            return Err(Error::GeneratedToolKeyRequiresStore);
        }
        let product_mask = request
            .product
            .mask_version
            .ok_or_else(|| Error::ProductData("the product names no mask version".to_string()))?;
        let desired = request.configuration.identity.desired_address;
        let (current_address, assignment_method) = if request.options.scope.includes_address() {
            discover_current_address(bus, product_mask, desired, request.key_material.serial_number, &request.options)
                .await?
        } else {
            (desired, None)
        };
        let (device_mask, mut retained, plain_descriptor_probe) = read_device_mask(
            bus,
            current_address,
            product_mask.family(),
            &request.key_material,
            request.options.allow_plaintext_management,
        )
        .await?;

        if request.options.scope == ProgrammingScope::Application
            && retained.as_ref().is_some_and(|(_, access)| *access == ManagementAccess::Fdsk)
        {
            if let Some((connection, _)) = retained.take() {
                let _ = connection.close().await;
            }
            return Err(Error::NetworkConfigurationRequired);
        }

        // Security IO may already contain higher replay floors than the
        // project snapshot or imported keyring. Read them before compiling
        // the replacement table, but never retain a row absent from desired
        // topology.
        if request.options.scope.includes_application()
            && request.configuration.data_secure_enabled
            && request.key_material.application_security.is_some()
        {
            let (mut connection, access) = match retained {
                Some(connection) => connection,
                None => {
                    connect_management_ordered(
                        bus,
                        current_address,
                        &request.key_material,
                        request.options.allow_plaintext_management,
                        plain_descriptor_probe,
                        false,
                    )
                    .await?
                }
            };
            if access == ManagementAccess::Plain {
                let _ = connection.close().await;
                return Err(Error::ManagementAccessUnavailable);
            }
            if request.options.scope == ProgrammingScope::Application && access == ManagementAccess::Fdsk {
                let _ = connection.close().await;
                return Err(Error::NetworkConfigurationRequired);
            }
            merge_live_siat(&mut connection, &mut request.key_material).await?;
            let _ = connection.close().await;
        } else if request.options.scope == ProgrammingScope::Application && retained.is_none() {
            let (connection, access) = connect_management_ordered(
                bus,
                current_address,
                &request.key_material,
                request.options.allow_plaintext_management,
                plain_descriptor_probe,
                false,
            )
            .await?;
            let _ = connection.close().await;
            if access == ManagementAccess::Fdsk {
                return Err(Error::NetworkConfigurationRequired);
            }
        } else if let Some((connection, _)) = retained {
            let _ = connection.close().await;
        }

        let mask = select_download_mask(request.mask_db, product_mask, device_mask)?;
        let compiled = if request.options.scope.includes_application() {
            let lowered = request.configuration.lower(request.key_material.application_security.clone())?;
            let mut product = request.product.clone();
            product.configured_com_objects = Some(lowered.com_objects);
            Some(crate::download::compile(&mask, &product, &lowered.project)?)
        } else {
            None
        };
        Ok(ProgrammingPreflight { current_address, product_mask, device_mask, assignment_method, compiled })
    }

    pub async fn program(
        &self,
        bus: &KnxBus,
        request: ProgrammingRequest<'_>,
        generated_key_sink: Option<&mut dyn GeneratedToolKeySink>,
    ) -> Result<ProgrammingReport> {
        self.program_with_progress(bus, request, generated_key_sink, Box::new(|_| {})).await
    }

    pub async fn program_with_progress(
        &self,
        bus: &KnxBus,
        mut request: ProgrammingRequest<'_>,
        generated_key_sink: Option<&mut dyn GeneratedToolKeySink>,
        progress: ProgrammingProgress,
    ) -> Result<ProgrammingReport> {
        let progress = Arc::new(Mutex::new(progress));

        // This check precedes even generated-key persistence. Capability and
        // enablement mismatches are project errors and must be side-effect
        // free, including for direct `DeviceProgrammer` callers.
        validate_data_secure_selection(&request)?;

        // A tool key is never first used until its authoritative source can
        // reproduce it. This ordering is what makes an interrupted key change
        // recoverable on the next invocation.
        if request.options.scope == ProgrammingScope::Application && request.key_material.needs_tool_key_generation {
            return Err(Error::NetworkConfigurationRequired);
        }
        if request.key_material.needs_tool_key_generation {
            emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::PersistingToolKey));
            self.materialize_tool_key(&mut request.key_material, generated_key_sink)?;
        }

        let product_mask = request
            .product
            .mask_version
            .ok_or_else(|| Error::ProductData("the product names no mask version".to_string()))?;
        let desired = request.configuration.identity.desired_address;

        let (current, assignment_method) = if request.options.scope.includes_address() {
            emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::DiscoveringDevice));
            discover_current_address(bus, product_mask, desired, request.key_material.serial_number, &request.options)
                .await?
        } else {
            (desired, None)
        };

        // Read DD0 before an address write so compilation can fail without
        // altering the installation. Legacy masks may require a connected
        // request; `read_device_mask` retains that session for the download.
        emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::ReadingDescriptor));
        let (device_mask, mut preflight_connection, plain_descriptor_probe) = read_device_mask(
            bus,
            current,
            product_mask.family(),
            &request.key_material,
            request.options.allow_plaintext_management,
        )
        .await?;
        let mask = select_download_mask(request.mask_db, product_mask, device_mask)?;

        // `program` is also a standalone public entry point, not merely the
        // execution half of `ProjectProgrammer::preflight_batch`. Preserve
        // live replay floors here as well so a direct caller cannot replace a
        // receiver's SIAT with an older desired snapshot.
        if request.options.scope == ProgrammingScope::Application
            && preflight_connection.as_ref().is_some_and(|(_, access)| *access == ManagementAccess::Fdsk)
        {
            if let Some((connection, _)) = preflight_connection.take() {
                let _ = connection.close().await;
            }
            return Err(Error::NetworkConfigurationRequired);
        }

        if request.options.scope.includes_application()
            && request.configuration.data_secure_enabled
            && request.key_material.application_security.is_some()
        {
            if preflight_connection.is_none() {
                preflight_connection = Some(
                    connect_management_ordered(
                        bus,
                        current,
                        &request.key_material,
                        request.options.allow_plaintext_management,
                        plain_descriptor_probe,
                        false,
                    )
                    .await?,
                );
            }
            if preflight_connection.as_ref().expect("secure management connection exists").1 == ManagementAccess::Plain
            {
                let (connection, _) = preflight_connection.take().expect("connection checked above");
                let _ = connection.close().await;
                return Err(Error::ManagementAccessUnavailable);
            }
            if request.options.scope == ProgrammingScope::Application
                && preflight_connection.as_ref().expect("secure management connection exists").1
                    == ManagementAccess::Fdsk
            {
                let (connection, _) = preflight_connection.take().expect("connection checked above");
                let _ = connection.close().await;
                return Err(Error::NetworkConfigurationRequired);
            }
            merge_live_siat(
                &mut preflight_connection.as_mut().expect("secure management connection exists").0,
                &mut request.key_material,
            )
            .await?;
        }

        let compiled = if request.options.scope.includes_application() {
            emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::Compiling));
            let lowered = request.configuration.lower(request.key_material.application_security.clone())?;
            let mut product = request.product.clone();
            product.configured_com_objects = Some(lowered.com_objects);
            Some(crate::download::compile(&mask, &product, &lowered.project)?)
        } else {
            None
        };
        let selected_load_path = match compiled.as_ref() {
            Some(compiled) => compiled.path(),
            None => load_control_path(&mask)?,
        };

        // A connected session is addressed to the IA it opened on. Keep it
        // for the common no-op assignment case, but close it before an actual
        // move. Merely finding the configured IA is not an address write.
        let serial_assignment_key = match preflight_connection.as_ref().map(|(_, access)| *access) {
            Some(ManagementAccess::Fdsk) => request.key_material.fdsk,
            Some(ManagementAccess::ToolKey) => request.key_material.tool_key,
            Some(ManagementAccess::Plain) => None,
            // A factory device may expose DD0 connectionlessly, so no
            // retained session exists to tell us that its serial write still
            // requires the FDSK. A commissioned secure device normally hides
            // DD0 from plaintext and therefore takes the retained Tool-Key
            // branch above.
            None => request.key_material.fdsk.or(request.key_material.tool_key),
        };
        if current != desired
            && let Some((connection, _)) = preflight_connection.take()
        {
            let _ = connection.close().await;
        }
        let address_assignment = match (assignment_method, current != desired) {
            (Some(method), true) => {
                emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::AssigningAddress));
                Some(
                    assign_address(
                        bus,
                        method,
                        current,
                        desired,
                        request.key_material.serial_number,
                        request.options.scan_window,
                        serial_assignment_key,
                    )
                    .await?,
                )
            }
            _ => None,
        };
        let address_changed = address_assignment.is_some_and(|assignment| assignment.changed);
        if address_changed {
            bus.move_device_security(current, desired).await?;
        }

        emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::SelectingManagementAccess));
        let (mut connection, mut management_access) = if let Some(connection) = preflight_connection {
            connection
        } else {
            connect_management_ordered(
                bus,
                desired,
                &request.key_material,
                request.options.allow_plaintext_management,
                plain_descriptor_probe,
                false,
            )
            .await?
        };
        if request.configuration.data_secure_enabled && management_access == ManagementAccess::Plain {
            let _ = connection.close().await;
            return Err(Error::ManagementAccessUnavailable);
        }
        if request.options.scope == ProgrammingScope::Application && management_access == ManagementAccess::Fdsk {
            let _ = connection.close().await;
            return Err(Error::NetworkConfigurationRequired);
        }

        let programming_mode_cleared = request.options.scope.includes_address()
            && assignment_method == Some(AddressAssignmentMethod::ProgrammingButton);
        if programming_mode_cleared {
            disable_programming_mode(&mut connection, &mask).await?;
        }

        let security_bootstrap = management_access == ManagementAccess::Fdsk;
        if management_access == ManagementAccess::Fdsk {
            emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::EnablingSecurityMode));
            enable_security_mode(&mut connection).await?;
            let tool_key = request.key_material.tool_key.ok_or(Error::GeneratedToolKeyRequiresStore)?;
            emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::InstallingToolKey));
            connection.write_tool_key(tool_key).await?;
            management_access = ManagementAccess::ToolKey;
        }
        let secure_management = management_access != ManagementAccess::Plain;

        let model = DownloadModel::for_management_model(mask.management_model());
        let max_apdu = negotiate_max_apdu(&mut connection, bus.max_apdu(), request.configuration.max_apdu, model).await;

        // ETS treats PID 59 as part of LoadNetworkConfiguration: it is set
        // after installing the Tool Key and before the phase's confirmed
        // restart. Re-downloading an application therefore does not rewrite
        // the device's outgoing sequence-number base.
        let network_configuration_performed = needs_network_configuration(
            request.options.scope,
            address_changed,
            programming_mode_cleared,
            security_bootstrap,
        );
        if network_configuration_performed && secure_management {
            emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::SettingDeviceSequence));
            advance_device_sending_sequence(bus, &mut connection, request.key_material.serial_number).await?;
        }

        if network_configuration_performed {
            emit(
                &progress,
                ProgrammingEvent::Stage(if security_bootstrap {
                    ProgrammingStage::RestartingSecurityBootstrap
                } else {
                    ProgrammingStage::RestartingDevice
                }),
            );
            let restart_wait = if device_mask.family() == MaskFamily::Bcu1 {
                match connection.restart().await {
                    Ok(()) | Err(Error::TransportClosed) => {}
                    Err(error) => {
                        let _ = connection.close().await;
                        return Err(error);
                    }
                }
                request.options.restart_delay
            } else {
                match connection.master_reset(EraseCode::Confirmed, 0).await {
                    Ok(restart) => restart.process_time.max(request.options.restart_delay),
                    Err(error) => {
                        let _ = connection.close().await;
                        return Err(error);
                    }
                }
            };
            let _ = connection.close().await;
            emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::WaitingForRestart));
            tokio::time::sleep(restart_wait).await;

            if !request.options.scope.includes_application() {
                emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::Verifying));
                let security = verify_network_configuration(bus, desired, device_mask, secure_management).await?;
                return Ok(ProgrammingReport {
                    individual_address: desired,
                    product_mask,
                    device_mask,
                    address_assignment,
                    network_configuration_performed,
                    application_downloaded: false,
                    management_access,
                    max_apdu,
                    programmed_image: DeviceImage::new(),
                    load_control_path: selected_load_path,
                    instruction_count: 0,
                    load_states: Vec::new(),
                    security,
                    key_provenance: request.key_material.provenance,
                });
            }

            emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::SelectingManagementAccess));
            let reconnected = connect_management_ordered(
                bus,
                desired,
                &request.key_material,
                request.options.allow_plaintext_management,
                false,
                false,
            )
            .await?;
            if secure_management && reconnected.1 != ManagementAccess::ToolKey {
                let _ = reconnected.0.close().await;
                return Err(Error::ManagementAccessUnavailable);
            }
            connection = reconnected.0;
            management_access = reconnected.1;
        }

        // With no network change there was no restart, so close the retained
        // preflight connection before verifying the address-only operation.
        if !request.options.scope.includes_application() {
            let _ = connection.close().await;
            emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::Verifying));
            let security = verify_network_configuration(bus, desired, device_mask, secure_management).await?;
            return Ok(ProgrammingReport {
                individual_address: desired,
                product_mask,
                device_mask,
                address_assignment,
                network_configuration_performed,
                application_downloaded: false,
                management_access,
                max_apdu,
                programmed_image: DeviceImage::new(),
                load_control_path: selected_load_path,
                instruction_count: 0,
                load_states: Vec::new(),
                security,
                key_provenance: request.key_material.provenance,
            });
        }

        let compiled = compiled.expect("application scope compiles a download");
        let download_apdu = download_plaintext_apdu(max_apdu, management_access);
        log::debug!(
            "using max APDU {max_apdu} on the wire and {download_apdu} for {} download APDUs",
            if management_access == ManagementAccess::Plain { "plain" } else { "secure" }
        );

        emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::Downloading));
        let nested_progress = Arc::clone(&progress);
        let procedure_restarts_device = compiled
            .instructions
            .iter()
            .any(|step| matches!(step, Instruction::Restart | Instruction::ConfirmedRestart));
        let result = compiled
            .execute_with_progress_outcome(
                &mut connection,
                download_apdu,
                Box::new(move |event| emit(&nested_progress, ProgrammingEvent::Download(event))),
            )
            .await;
        let download_outcome = match result {
            Ok(outcome) => outcome,
            Err(error) => {
                let _ = connection.close().await;
                return Err(error);
            }
        };

        // BCU1's memory procedure carries its own basic restart. The later
        // management models normally end their product procedure with only
        // `LdCtrlDisconnect`; ETS then issues ConfirmedRestart as the commit
        // boundary for the completed load machines and Security IO. Merely
        // dropping the transport connection leaves real devices loaded but
        // not restarted, which also makes immediate verification observe the
        // pre-commit runtime state.
        let restart_wait = if procedure_restarts_device {
            download_outcome
                .confirmed_restart_process_time()
                .unwrap_or(request.options.restart_delay)
                .max(request.options.restart_delay)
        } else if device_mask.family() == MaskFamily::Bcu1 {
            emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::RestartingDevice));
            match connection.restart().await {
                Ok(()) | Err(Error::TransportClosed) => {}
                Err(error) => {
                    let _ = connection.close().await;
                    return Err(error);
                }
            }
            request.options.restart_delay
        } else {
            emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::RestartingDevice));
            match connection.master_reset(EraseCode::Confirmed, 0).await {
                Ok(restart) => restart.process_time.max(request.options.restart_delay),
                Err(error) => {
                    let _ = connection.close().await;
                    return Err(error);
                }
            }
        };
        let _ = connection.close().await;

        emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::WaitingForRestart));
        tokio::time::sleep(restart_wait).await;

        emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::Verifying));
        let (load_states, security) =
            verify_download(bus, desired, device_mask, &compiled, request.configuration.data_secure_enabled).await?;

        for &(group, key) in request
            .key_material
            .application_security
            .as_ref()
            .map(|security| security.group_keys.as_slice())
            .unwrap_or_default()
        {
            bus.set_group_key(group, key).await?;
        }

        Ok(ProgrammingReport {
            individual_address: desired,
            product_mask,
            device_mask,
            address_assignment,
            network_configuration_performed,
            application_downloaded: true,
            management_access,
            max_apdu,
            programmed_image: compiled.image.clone(),
            load_control_path: compiled.path(),
            instruction_count: compiled.instructions.len(),
            load_states,
            security,
            key_provenance: request.key_material.provenance,
        })
    }
}

fn validate_data_secure_selection(request: &ProgrammingRequest<'_>) -> Result<()> {
    let enabled = request.configuration.data_secure_enabled;
    if enabled && !request.product.supports_data_secure {
        return Err(Error::DeviceConfiguration(format!(
            "product `{}` does not support Data Secure",
            request.product.id
        )));
    }
    if !request.options.scope.includes_application() {
        if request.key_material.fdsk.is_some() && request.key_material.fdsk == request.key_material.tool_key {
            return Err(Error::DeviceConfiguration("the Tool Key must differ from the FDSK".to_string()));
        }
        return Ok(());
    }
    match (enabled, request.key_material.application_security.is_some()) {
        (true, false) => {
            return Err(Error::DeviceConfiguration(
                "Data Secure is enabled but no application-security configuration was resolved".to_string(),
            ));
        }
        (false, true) => {
            return Err(Error::DeviceConfiguration(
                "application-security configuration was supplied while Data Secure is disabled".to_string(),
            ));
        }
        _ => {}
    }
    if request.key_material.fdsk.is_some() && request.key_material.fdsk == request.key_material.tool_key {
        return Err(Error::DeviceConfiguration("the Tool Key must differ from the FDSK".to_string()));
    }
    Ok(())
}

fn needs_network_configuration(
    scope: ProgrammingScope,
    address_changed: bool,
    programming_mode_cleared: bool,
    security_bootstrap: bool,
) -> bool {
    scope.includes_address() && (address_changed || programming_mode_cleared || security_bootstrap)
}

async fn merge_live_siat(connection: &mut DeviceConnection, keys: &mut ResolvedKeyMaterial) -> Result<()> {
    let Some(security) = keys.application_security.as_mut() else { return Ok(()) };
    let count = connection
        .property_ext_read(SECURITY_IO, SECURITY_IO_OCCURRENCE, pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, 0, 1)
        .await?;
    let count: [u8; 2] = count
        .as_slice()
        .try_into()
        .map_err(|_| Error::ProgrammingVerification("Security IO SIAT count is not a 16-bit value".to_string()))?;
    let mut desired: BTreeMap<IndividualAddress, u64> = security.siat.iter().copied().collect();
    for index in 1..=u16::from_be_bytes(count) {
        let row = connection
            .property_ext_read(
                SECURITY_IO,
                SECURITY_IO_OCCURRENCE,
                pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE,
                index,
                1,
            )
            .await?;
        if row.len() != 8 {
            return Err(Error::ProgrammingVerification(format!(
                "Security IO SIAT row {index} is {} octets instead of eight",
                row.len()
            )));
        }
        let address = IndividualAddress::from_bytes(&row[..2]);
        if let Some(last_valid) = desired.get_mut(&address) {
            *last_valid = (*last_valid).max(decode_u48(&row[2..])?);
        }
    }
    security.siat = desired.into_iter().collect();
    Ok(())
}

/// Activate the secure-management policy before replacing the factory key.
/// The command itself is protected with the FDSK; after it succeeds every
/// management operation remains secure, and the following Tool Key write is
/// confirmed under the newly installed key.
async fn enable_security_mode(connection: &mut DeviceConnection) -> Result<()> {
    let result = connection
        .function_property_ext_command(SECURITY_IO, SECURITY_IO_OCCURRENCE, pid::security::SECURITY_MODE, &[0, 0, 1])
        .await?;
    if result.return_code != 0 {
        return Err(Error::DeviceError(result.return_code));
    }
    Ok(())
}

async fn advance_device_sending_sequence(
    bus: &KnxBus,
    connection: &mut DeviceConnection,
    serial: Option<[u8; 6]>,
) -> Result<u64> {
    let reported = connection
        .property_ext_read(SECURITY_IO, SECURITY_IO_OCCURRENCE, pid::security::SEQUENCE_NUMBER_SENDING, 1, 1)
        .await?;
    let reported = decode_u48(&reported)?;
    let stored = match serial {
        Some(serial) => bus.device_sequence_floor(serial).await?,
        None => 1,
    };
    let selected = reported.max(stored).max(knx_sequence_timestamp_floor()).max(1);
    let encoded = encode_u48(selected)?;
    connection
        .property_ext_write(SECURITY_IO, SECURITY_IO_OCCURRENCE, pid::security::SEQUENCE_NUMBER_SENDING, 1, 1, &encoded)
        .await?;
    Ok(selected)
}

fn decode_u48(bytes: &[u8]) -> Result<u64> {
    let bytes: [u8; 6] = bytes.try_into().map_err(|_| Error::Parse("PID 59 is not a six-octet value"))?;
    Ok(u64::from_be_bytes([0, 0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]]))
}

fn encode_u48(value: u64) -> Result<[u8; 6]> {
    if value == 0 || value > 0xFFFF_FFFF_FFFF {
        return Err(Error::ProgrammingVerification(format!("PID 59 value {value} is outside the KNX 48-bit range")));
    }
    let bytes = value.to_be_bytes();
    Ok(bytes[2..].try_into().expect("six-byte suffix"))
}

fn emit(progress: &Arc<Mutex<ProgrammingProgress>>, event: ProgrammingEvent) {
    if let Ok(mut progress) = progress.lock() {
        progress(event);
    }
}

async fn discover_current_address(
    bus: &KnxBus,
    product_mask: MaskVersion,
    desired: IndividualAddress,
    serial: Option<[u8; 6]>,
    options: &ProgrammingOptions,
) -> Result<(IndividualAddress, Option<AddressAssignmentMethod>)> {
    match options.addressing {
        AddressingMode::ExistingAddress => Ok((desired, None)),
        AddressingMode::ProgrammingButton => {
            let found = bus.network_management().read_individual_addresses(options.scan_window).await?;
            match found.as_slice() {
                [address] => Ok((*address, Some(AddressAssignmentMethod::ProgrammingButton))),
                [] => Err(Error::ProgrammingDeviceNotFound),
                _ => Err(Error::MultipleProgrammingDevices(found.len())),
            }
        }
        AddressingMode::Automatic if product_mask.family() != MaskFamily::Bcu1 => {
            let Some(serial) = serial else { return Ok((desired, None)) };
            let found =
                bus.network_management().read_individual_addresses_by_serial(&serial, options.scan_window).await?;
            match found.as_slice() {
                [address] => Ok((*address, Some(AddressAssignmentMethod::SerialNumber))),
                [] => Err(Error::SerialDeviceNotFound),
                _ => Err(Error::DuplicateSerialNumber(found.len())),
            }
        }
        AddressingMode::Automatic => Ok((desired, None)),
    }
}

async fn assign_address(
    bus: &KnxBus,
    method: AddressAssignmentMethod,
    previous: IndividualAddress,
    desired: IndividualAddress,
    serial: Option<[u8; 6]>,
    scan_window: Duration,
    secure_key: Option<[u8; 16]>,
) -> Result<AddressAssignmentReport> {
    if previous == desired {
        return Ok(AddressAssignmentReport { method, previous, current: previous, changed: false });
    }

    match method {
        AddressAssignmentMethod::SerialNumber => {
            let serial = serial.expect("serial addressing is selected only with a serial");
            let management = bus.network_management();
            let result = match secure_key {
                Some(key) => {
                    management.assign_individual_address_by_serial_secure(&serial, desired, scan_window, key).await?
                }
                None => management.assign_individual_address_by_serial(&serial, desired, scan_window).await?,
            };
            Ok(AddressAssignmentReport {
                method,
                previous: result.previous,
                current: result.current,
                changed: result.changed,
            })
        }
        AddressAssignmentMethod::ProgrammingButton => {
            let nm = bus.network_management();
            if nm.is_device_present(desired, scan_window).await? {
                return Err(Error::IndividualAddressOccupied(desired));
            }
            nm.write_individual_address(desired).await?;
            let found = nm.read_individual_addresses(scan_window).await?;
            if found.as_slice() != [desired] {
                return Err(Error::ProgrammingAddressVerification(desired));
            }
            Ok(AddressAssignmentReport { method, previous, current: desired, changed: true })
        }
    }
}

async fn read_device_mask(
    bus: &KnxBus,
    address: IndividualAddress,
    family: MaskFamily,
    keys: &ResolvedKeyMaterial,
    allow_plaintext: bool,
) -> Result<(MaskVersion, Option<(DeviceConnection, ManagementAccess)>, bool)> {
    // Connectionless DD0 is optional on System 1. BCU1 still supports the
    // connected service. Some BCU2 implementations make the same choice,
    // while a commissioned secure device intentionally answers an unsecured
    // connectionless probe with FFFFh. Try the cheap form first, then retain
    // one authenticated connected session for compilation/download.
    if family != MaskFamily::Bcu1
        && let Ok(descriptor) = bus.network_management().device_descriptor_read(address, 0).await
        && descriptor.as_slice() != [0xFF, 0xFF]
    {
        return Ok((parse_device_mask(&descriptor)?, None, true));
    }

    let (mut connection, access) = connect_management(bus, address, keys, allow_plaintext).await?;
    let descriptor = connection.device_descriptor_read(0).await?;
    let mask = parse_device_mask(&descriptor)?;
    Ok((mask, Some((connection, access)), false))
}

fn parse_device_mask(descriptor: &[u8]) -> Result<MaskVersion> {
    let [high, low] = descriptor else {
        return Err(Error::ProgrammingVerification(format!("DD0 answered {} octets instead of two", descriptor.len())));
    };
    Ok(MaskVersion::from(u16::from_be_bytes([*high, *low])))
}

/// Open a management session using the same conservative credential order as
/// full programming. Read and unload frontends use this without gaining any
/// implicit address-changing behavior.
pub async fn connect_management(
    bus: &KnxBus,
    address: IndividualAddress,
    keys: &ResolvedKeyMaterial,
    allow_plaintext: bool,
) -> Result<(DeviceConnection, ManagementAccess)> {
    connect_management_ordered(bus, address, keys, allow_plaintext, false, false).await
}

/// Open management access while explicitly synchronizing every secure
/// credential attempted. Used by `sync`/state-recovery commands; normal
/// programming calls [`connect_management`] and reuses known counters first.
pub async fn connect_management_synchronized(
    bus: &KnxBus,
    address: IndividualAddress,
    keys: &ResolvedKeyMaterial,
    allow_plaintext: bool,
) -> Result<(DeviceConnection, ManagementAccess)> {
    connect_management_ordered(bus, address, keys, allow_plaintext, false, true).await
}

async fn connect_management_ordered(
    bus: &KnxBus,
    address: IndividualAddress,
    keys: &ResolvedKeyMaterial,
    allow_plaintext: bool,
    prefer_fdsk: bool,
    force_sync: bool,
) -> Result<(DeviceConnection, ManagementAccess)> {
    // A usable plaintext DD0 is the factory/off-mode signal. In that case an
    // FDSK bootstrap is expected and avoids waiting for a generated Tool Key
    // which cannot be active yet. Otherwise retain Tool-Key-first ordering so
    // a retry after a lost key-rotation acknowledgement recovers safely.
    let credentials = if prefer_fdsk {
        [(ManagementAccess::Fdsk, keys.fdsk), (ManagementAccess::ToolKey, keys.tool_key)]
    } else {
        [(ManagementAccess::ToolKey, keys.tool_key), (ManagementAccess::Fdsk, keys.fdsk)]
    };
    for (access, key) in credentials {
        let Some(key) = key else { continue };
        let entry = match access {
            ManagementAccess::ToolKey => SecurityEntry {
                mode: DeviceSecurityMode::Secure,
                tool_key: Some(key),
                fdsk: keys.fdsk,
                serial: keys.serial_number,
            },
            ManagementAccess::Fdsk => SecurityEntry {
                mode: DeviceSecurityMode::Secure,
                tool_key: None,
                fdsk: Some(key),
                serial: keys.serial_number,
            },
            ManagementAccess::Plain => unreachable!(),
        };
        bus.set_device_security(address, entry).await?;
        let opened =
            if force_sync { bus.connect_device_synchronized(address).await } else { bus.connect_device(address).await };
        match opened {
            Ok(mut connection) => match connection.validate_security().await {
                // Unknown state and FDSK access were already proven by sync.
                // A known Tool-Key session instead proves its persisted
                // counters with one protected DD0 exchange; FFFF is still a
                // valid authenticated response and is cached for the caller.
                Ok(()) => return Ok((connection, access)),
                Err(error) => {
                    log::debug!("{access:?} management access failed: {error}");
                    let _ = connection.close().await;
                }
            },
            Err(error) => log::debug!("{access:?} management access failed: {error}"),
        }
    }

    if allow_plaintext {
        bus.remove_device_security(address).await?;
        if let Ok(mut connection) = bus.connect_device(address).await {
            if connection.device_descriptor_read(0).await.is_ok_and(|descriptor| descriptor.as_slice() != [0xFF, 0xFF])
            {
                return Ok((connection, ManagementAccess::Plain));
            }
            let _ = connection.close().await;
        }
    }
    Err(Error::ManagementAccessUnavailable)
}

async fn disable_programming_mode(connection: &mut DeviceConnection, mask: &MaskData<'_>) -> Result<()> {
    if let Some(address) = mask.standard_memory_address("ProgrammingMode") {
        let bytes = connection.memory_read(address, 1).await?;
        let byte = *bytes.first().ok_or(Error::Parse("programming-mode read returned no byte"))?;
        if byte & 1 != 0 {
            // BCU system status guards the byte with even parity in bit 7.
            // Clearing only bit 0 turns 81h into the invalid 80h, which real
            // masks reject. Recalculate the parity bit with the new mode.
            connection.memory_write_verify(address, &[system_status_with_programming_mode(byte, false)]).await?;
        }
    } else {
        connection.property_write(0, pid::device::PROGMODE, 1, 1, &[0]).await?;
    }
    Ok(())
}

fn system_status_with_programming_mode(value: u8, enabled: bool) -> u8 {
    let mut value = value & !(0x80 | 0x01);
    if enabled {
        value |= 0x01;
    }
    if !value.count_ones().is_multiple_of(2) {
        value |= 0x80;
    }
    value
}

async fn negotiate_max_apdu(
    connection: &mut DeviceConnection,
    interface_max: u16,
    configured: Option<u16>,
    model: Option<&DownloadModel>,
) -> u16 {
    // 03/05/02 §2.6 only probes the target when the local interface can
    // forward extended frames. A property-less target, an unreadable PID 56,
    // or an invalid value all select the standard-frame APDU of 15.
    let fallback = model.map_or(15, |model| model.default_max_apdu);
    if let Some(model) = model
        && !model.has_properties
    {
        return select_max_apdu(None, interface_max, configured, fallback);
    }
    if interface_max <= 15 {
        return 15;
    }

    let reported = match connection.property_read(0, pid::device::MAX_APDU_LENGTH, 1, 1).await {
        Ok(bytes) if bytes.len() == 2 => {
            let value = u16::from_be_bytes([bytes[0], bytes[1]]);
            if (15..=254).contains(&value) {
                log::debug!("target reports PID_MAX_APDU_LENGTH={value}");
                Some(value)
            } else {
                log::warn!("target reported invalid PID_MAX_APDU_LENGTH={value}; using standard frames");
                None
            }
        }
        Ok(bytes) => {
            log::warn!("target returned {} bytes for PID_MAX_APDU_LENGTH; using standard frames", bytes.len());
            None
        }
        Err(error) => {
            log::debug!("target has no readable PID_MAX_APDU_LENGTH ({error}); using standard frames");
            None
        }
    };
    select_max_apdu(reported, interface_max, configured, fallback)
}

fn select_max_apdu(reported: Option<u16>, interface_max: u16, configured: Option<u16>, fallback: u16) -> u16 {
    let target_max = reported.unwrap_or(fallback);
    let configured_cap = configured.unwrap_or(u16::MAX);
    target_max.min(interface_max).min(configured_cap).max(15)
}

/// PID 56 limits the complete APDU on the wire. Secure management puts the
/// original management APDU inside an S-A_Data envelope, so the downloader's
/// chunker receives only the remaining plaintext budget.
fn download_plaintext_apdu(wire_max_apdu: u16, access: ManagementAccess) -> u16 {
    if access == ManagementAccess::Plain {
        wire_max_apdu
    } else {
        wire_max_apdu.saturating_sub(secure::OVERHEAD as u16)
    }
}

async fn verify_network_configuration(
    bus: &KnxBus,
    address: IndividualAddress,
    expected_mask: MaskVersion,
    secure_management: bool,
) -> Result<Option<SecurityVerification>> {
    let mut connection = bus
        .connect_device(address)
        .await
        .map_err(|error| Error::ProgrammingVerification(format!("could not reconnect after restart: {error}")))?;
    let result = async {
        let descriptor = connection
            .device_descriptor_read(0)
            .await
            .map_err(|error| Error::ProgrammingVerification(format!("could not read DD0 after restart: {error}")))?;
        if descriptor != expected_mask.to_bytes() {
            return Err(Error::ProgrammingVerification(format!(
                "DD0 returned {descriptor:02X?}, expected {:02X?}",
                expected_mask.to_bytes()
            )));
        }
        if !secure_management {
            return Ok(None);
        }

        let mode = connection
            .function_property_ext_state_read(SECURITY_IO, SECURITY_IO_OCCURRENCE, pid::security::SECURITY_MODE, &[
                0, 0,
            ])
            .await
            .map_err(|error| {
                Error::ProgrammingVerification(format!("could not read Security Mode after restart: {error}"))
            })?;
        let security_mode = mode.return_code == 0 && mode.data == [0, 1];
        if !security_mode {
            return Err(Error::ProgrammingVerification(format!(
                "Security Mode returned code {:#04X}, data {:02X?}",
                mode.return_code, mode.data
            )));
        }
        Ok(Some(SecurityVerification {
            security_mode,
            group_key_entries: read_table_count(&mut connection, pid::security::GROUP_KEY_TABLE).await?,
            sender_entries: read_table_count(&mut connection, pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE).await?,
            group_object_entries: read_table_count(&mut connection, pid::security::GO_SECURITY_FLAGS).await?,
        }))
    }
    .await;
    let _ = connection.close().await;
    result
}

async fn verify_download(
    bus: &KnxBus,
    address: IndividualAddress,
    expected_mask: MaskVersion,
    compiled: &CompiledDownload,
    secure_product: bool,
) -> Result<(Vec<(LsmTarget, LoadState)>, Option<SecurityVerification>)> {
    let mut connection = bus
        .connect_device(address)
        .await
        .map_err(|error| Error::ProgrammingVerification(format!("could not reconnect after restart: {error}")))?;
    let result = async {
        let descriptor = connection
            .device_descriptor_read(0)
            .await
            .map_err(|error| Error::ProgrammingVerification(format!("could not read DD0 after restart: {error}")))?;
        if descriptor != expected_mask.to_bytes() {
            return Err(Error::ProgrammingVerification(format!(
                "DD0 returned {descriptor:02X?}, expected {:02X?}",
                expected_mask.to_bytes()
            )));
        }

        let completed: BTreeSet<_> = compiled
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instruction::LsmEvent { lsm, event: LoadEvent::LoadCompleted } => Some(*lsm),
                _ => None,
            })
            .collect();
        let mut load_states = Vec::with_capacity(completed.len());
        for target in completed {
            let bytes = read_load_state(&mut connection, compiled.path(), target).await.map_err(|error| {
                Error::ProgrammingVerification(format!("could not read load machine {target} after restart: {error}"))
            })?;
            let value = *bytes.first().ok_or(Error::Parse("load-state read returned no byte"))?;
            let state = LoadState::try_from(value).map_err(|_| {
                Error::ProgrammingVerification(format!("load machine {target} returned unknown state {value:#04X}"))
            })?;
            if state != LoadState::Loaded {
                return Err(Error::ProgrammingVerification(format!(
                    "load machine {target} returned {state}, expected Loaded"
                )));
            }
            load_states.push((target, state));
        }

        if let Some((object, property)) = compiled.application_run_state_property() {
            let bytes = connection.property_read(object, property, 1, 1).await.map_err(|error| {
                Error::ProgrammingVerification(format!(
                    "could not read application run state on object {object} after restart: {error}"
                ))
            })?;
            let value = *bytes.first().ok_or(Error::Parse("run-state read returned no byte"))?;
            let state = RunState::try_from(value).map_err(|_| {
                Error::ProgrammingVerification(format!("application returned unknown run state {value:#04X}"))
            })?;
            if state != RunState::Running {
                return Err(Error::ProgrammingVerification(format!("application returned {state}, expected Running")));
            }
        }

        let security = if secure_product { Some(verify_security(&mut connection, compiled).await?) } else { None };
        Ok((load_states, security))
    }
    .await;
    let _ = connection.close().await;
    result
}

async fn read_load_state(
    connection: &mut DeviceConnection,
    path: LoadControlPath,
    target: LsmTarget,
) -> Result<Vec<u8>> {
    match (path, target) {
        (LoadControlPath::Property, LsmTarget::Index(index)) => {
            connection.property_read(index, pid::LOAD_STATE_CONTROL, 1, 1).await
        }
        (LoadControlPath::Property, LsmTarget::ObjectType { object_type, occurrence }) => {
            connection.property_ext_read(object_type, occurrence, pid::LOAD_STATE_CONTROL, 1, 1).await
        }
        (LoadControlPath::Memory(resources), LsmTarget::Index(index)) => {
            let offset = index.checked_sub(1).ok_or(Error::Parse("load machine zero is invalid"))?;
            connection.memory_read(resources.load_status_addr + u16::from(offset), 1).await
        }
        (LoadControlPath::Memory(_), LsmTarget::ObjectType { .. }) => {
            Err(Error::UnsupportedInstruction("memory load control cannot address an object type"))
        }
        (LoadControlPath::Direct, _) => Err(Error::UnsupportedInstruction("direct downloads have no load states")),
    }
}

async fn verify_security(
    connection: &mut DeviceConnection,
    compiled: &CompiledDownload,
) -> Result<SecurityVerification> {
    let expected = expected_security_table_counts(compiled)?;
    let group_key_entries = read_table_count(connection, pid::security::GROUP_KEY_TABLE).await?;
    let sender_entries = read_table_count(connection, pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE).await?;
    let group_object_entries = read_table_count(connection, pid::security::GO_SECURITY_FLAGS).await?;
    for (name, actual, expected) in [
        ("group-key table", group_key_entries, expected[&pid::security::GROUP_KEY_TABLE]),
        ("SIAT", sender_entries, expected[&pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE]),
        ("GO-security table", group_object_entries, expected[&pid::security::GO_SECURITY_FLAGS]),
    ] {
        if actual != expected {
            return Err(Error::ProgrammingVerification(format!(
                "{name} contains {actual} entries, expected {expected}"
            )));
        }
    }

    let mode = connection
        .function_property_ext_state_read(SECURITY_IO, SECURITY_IO_OCCURRENCE, pid::security::SECURITY_MODE, &[0, 0])
        .await
        .map_err(|error| {
            Error::ProgrammingVerification(format!("could not read Security Mode after restart: {error}"))
        })?;
    let security_mode = mode.return_code == 0 && mode.data == [0, 1];
    if !security_mode {
        return Err(Error::ProgrammingVerification(format!(
            "Security Mode returned code {:#04X}, data {:02X?}",
            mode.return_code, mode.data
        )));
    }
    Ok(SecurityVerification { security_mode, group_key_entries, sender_entries, group_object_entries })
}

fn expected_security_table_counts(compiled: &CompiledDownload) -> Result<BTreeMap<u16, u16>> {
    expected_security_table_counts_from_instructions(&compiled.instructions)
}

fn expected_security_table_counts_from_instructions(instructions: &[Instruction]) -> Result<BTreeMap<u16, u16>> {
    let counted_tables = [pid::security::GROUP_KEY_TABLE, pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE];
    // PID 61 is fixed by the Group Object Table. Unlike PID 53/54 it must
    // not be resized through element zero, so derive its expected size from
    // the dense 1..N writes produced by the compiler.
    let mut result = BTreeMap::from([(pid::security::GO_SECURITY_FLAGS, 0)]);
    for instruction in instructions {
        let Instruction::WritePropertyExt {
            object_type: SECURITY_IO,
            occurrence: SECURITY_IO_OCCURRENCE,
            prop_id,
            start_idx,
            count,
            data,
            ..
        } = instruction
        else {
            continue;
        };
        if counted_tables.contains(prop_id) && *start_idx == 0 && *count == 1 {
            let bytes: [u8; 2] = data.as_slice().try_into().map_err(|_| {
                Error::ProgrammingVerification("security table count is not a 16-bit value".to_string())
            })?;
            result.insert(*prop_id, u16::from_be_bytes(bytes));
        } else if *prop_id == pid::security::GO_SECURITY_FLAGS && *start_idx != 0 && *count == 1 {
            let expected = result.entry(pid::security::GO_SECURITY_FLAGS).or_default();
            *expected = (*expected).max(*start_idx);
        }
    }
    if counted_tables.iter().any(|property| !result.contains_key(property)) {
        return Err(Error::ProgrammingVerification(
            "compiled secure download does not initialize every variable-length security table".to_string(),
        ));
    }
    Ok(result)
}

async fn read_table_count(connection: &mut DeviceConnection, property: u16) -> Result<u16> {
    let bytes =
        connection.property_ext_read(SECURITY_IO, SECURITY_IO_OCCURRENCE, property, 0, 1).await.map_err(|error| {
            Error::ProgrammingVerification(format!(
                "could not read security property {property} after restart: {error}"
            ))
        })?;
    let bytes: [u8; 2] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::ProgrammingVerification(format!("security property {property} has no 16-bit count")))?;
    Ok(u16::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingSink(Option<([u8; 6], [u8; 16])>);

    impl GeneratedToolKeySink for RecordingSink {
        fn persist_generated_tool_key(
            &mut self,
            serial: Option<[u8; 6]>,
            tool_key: [u8; 16],
        ) -> core::result::Result<(), KeyStoreError> {
            self.0 = Some((serial.expect("fixture has a serial"), tool_key));
            Ok(())
        }
    }

    #[test]
    fn programming_mode_updates_system_status_parity() {
        assert_eq!(system_status_with_programming_mode(0x81, false), 0x00);
        assert_eq!(system_status_with_programming_mode(0x00, true), 0x81);
        assert_eq!(system_status_with_programming_mode(0x12, true), 0x93);
        assert!(system_status_with_programming_mode(0x12, true).count_ones().is_multiple_of(2));
    }

    #[test]
    fn programming_scopes_keep_network_and_application_phases_separate() {
        assert!(ProgrammingScope::Address.includes_address());
        assert!(!ProgrammingScope::Address.includes_application());
        assert!(!ProgrammingScope::Application.includes_address());
        assert!(ProgrammingScope::Application.includes_application());
        assert!(ProgrammingScope::AddressAndApplication.includes_address());
        assert!(ProgrammingScope::AddressAndApplication.includes_application());

        assert!(!needs_network_configuration(ProgrammingScope::AddressAndApplication, false, false, false,));
        assert!(needs_network_configuration(ProgrammingScope::AddressAndApplication, true, false, false,));
        assert!(needs_network_configuration(ProgrammingScope::Address, false, false, true,));
        assert!(!needs_network_configuration(ProgrammingScope::Application, true, true, true,));
    }

    #[test]
    fn max_apdu_override_caps_the_detected_target_value() {
        assert_eq!(select_max_apdu(Some(40), 254, None, 15), 40);
        assert_eq!(select_max_apdu(Some(40), 254, Some(32), 15), 32);
        assert_eq!(select_max_apdu(None, 254, Some(40), 15), 15, "an override cannot invent long-frame support");
        assert_eq!(select_max_apdu(Some(254), 55, None, 15), 55, "the local interface remains the upper bound");
    }

    #[test]
    fn secure_download_reserves_the_data_secure_envelope() {
        assert_eq!(download_plaintext_apdu(40, ManagementAccess::Plain), 40);
        assert_eq!(download_plaintext_apdu(40, ManagementAccess::Fdsk), 27);
        assert_eq!(download_plaintext_apdu(40, ManagementAccess::ToolKey), 27);
    }

    #[test]
    fn security_verification_derives_fixed_go_table_size_without_element_zero() {
        let mut instructions = vec![
            Instruction::WritePropertyExt {
                object_type: SECURITY_IO,
                occurrence: SECURITY_IO_OCCURRENCE,
                prop_id: pid::security::GROUP_KEY_TABLE,
                start_idx: 0,
                count: 1,
                data: 2_u16.to_be_bytes().to_vec(),
                verify: false,
            },
            Instruction::WritePropertyExt {
                object_type: SECURITY_IO,
                occurrence: SECURITY_IO_OCCURRENCE,
                prop_id: pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE,
                start_idx: 0,
                count: 1,
                data: 1_u16.to_be_bytes().to_vec(),
                verify: false,
            },
        ];
        for index in 1..=4 {
            instructions.push(Instruction::WritePropertyExt {
                object_type: SECURITY_IO,
                occurrence: SECURITY_IO_OCCURRENCE,
                prop_id: pid::security::GO_SECURITY_FLAGS,
                start_idx: index,
                count: 1,
                data: vec![0],
                verify: false,
            });
        }

        let counts =
            expected_security_table_counts_from_instructions(&instructions).expect("security table layout is valid");
        assert_eq!(counts[&pid::security::GROUP_KEY_TABLE], 2);
        assert_eq!(counts[&pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE], 1);
        assert_eq!(counts[&pid::security::GO_SECURITY_FLAGS], 4);
    }

    #[test]
    fn tool_key_is_persisted_before_becoming_usable() {
        let serial = [0x00, 0xFA, 1, 2, 3, 4];
        let mut material = ResolvedKeyMaterial {
            serial_number: Some(serial),
            fdsk: Some([0x11; 16]),
            tool_key: None,
            application_security: None,
            secured_groups: BTreeMap::new(),
            needs_tool_key_generation: true,
            provenance: Vec::new(),
        };
        let mut sink = RecordingSink::default();

        assert!(DeviceProgrammer::new().materialize_tool_key(&mut material, Some(&mut sink)).expect("key generates"));
        let (_, persisted) = sink.0.expect("sink observes key before return");
        assert_eq!(material.tool_key, Some(persisted));
        assert!(!material.needs_tool_key_generation);
        assert!(material.provenance.iter().any(|metadata| metadata.origin == crate::security::KeyOrigin::Generated));
    }
}
