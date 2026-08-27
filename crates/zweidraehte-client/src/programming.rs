//! One commissioning pipeline shared by command-line, UI, and tests.
//!
//! Product interpretation and key resolution happen before this layer. The
//! programmer owns the ordering that matters on a live bus. It exposes ETS's
//! network-configuration and application-programming phases separately, plus
//! a combined operation: identify and compile against the real mask before a
//! move, choose management access without a plaintext downgrade, establish
//! secure management, execute the requested mask procedure, and verify state.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use zweidraehte_project::McbSnapshot;
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::device::{MaskFamily, MaskVersion};
use zweidraehte_proto::dpt::InterfaceObjectType;
use zweidraehte_proto::messages::apdu::load_control::{LoadEvent, LoadState, RunState};
use zweidraehte_proto::messages::apdu::restart::EraseCode;
use zweidraehte_proto::pid;

use crate::api::{DeviceConnection, KnxBus};
use crate::download::{
    CompiledDownload, DeviceConfiguration, DeviceImage, DownloadEvent, DownloadModel, DownloadScope, Instruction,
    LoadControlPath, LsmTarget, MachineRole, MaskData, MaskDb, ProductData, compile_scoped, load_control_path,
    select_download_mask,
};
use crate::error::{Error, Result};
use crate::security::{
    DeviceSecurityMode, KeyMetadata, KeyStoreError, ResolvedKeyMaterial, SecurityEntry, knx_sequence_timestamp_floor,
};

const SECURITY_IO: InterfaceObjectType = InterfaceObjectType::Security;
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
    /// Reach the device at a known previous address, enable its programming
    /// mode remotely, and replace that address.
    KnownAddress(IndividualAddress),
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
    /// A partial procedure failed and the precompiled full procedure is about
    /// to run. Keep the cause visible: silently widening here makes a broken
    /// partial implementation look merely slow.
    FallingBackToFullDownload {
        reason: String,
    },
}

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
    KnownAddress,
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
    pub download_scope: DownloadScope,
    pub load_states: Vec<(LsmTarget, LoadState)>,
    pub security: Option<SecurityVerification>,
    /// Device-generated PID 27 values captured after `LoadCompleted`.
    /// Project callers persist these as the integrity gate for the next
    /// differential download.
    pub mcb_snapshots: Vec<McbSnapshot>,
    /// Non-secret origins and fingerprints of credentials used by the run.
    pub key_provenance: Vec<KeyMetadata>,
}

pub struct ProgrammingRequest {
    product: ProductData,
    configuration: DeviceConfiguration,
    key_material: ResolvedKeyMaterial,
    /// Desired application scope. Direct library callers select
    /// [`DownloadScope::Full`] for the complete flow; project callers derive
    /// the smallest safe scope from durable deployment state.
    download_scope: DownloadScope,
    /// PID 27 values captured after the previous successful deployment.
    /// Empty state makes an MCB-backed differential procedure ineligible.
    previous_mcb: Vec<McbSnapshot>,
    options: ProgrammingOptions,
}

impl ProgrammingRequest {
    pub fn new(product: ProductData, configuration: DeviceConfiguration, key_material: ResolvedKeyMaterial) -> Self {
        Self {
            product,
            configuration,
            key_material,
            download_scope: DownloadScope::Full,
            previous_mcb: Vec::new(),
            options: ProgrammingOptions::default(),
        }
    }

    pub fn with_download_scope(mut self, scope: DownloadScope) -> Self {
        self.download_scope = scope;
        self
    }

    pub fn with_previous_mcb(mut self, previous_mcb: Vec<McbSnapshot>) -> Self {
        self.previous_mcb = previous_mcb;
        self
    }

    pub fn with_options(mut self, options: ProgrammingOptions) -> Self {
        self.options = options;
        self
    }

    pub fn key_material(&self) -> &ResolvedKeyMaterial {
        &self.key_material
    }
}

/// A read-only preparation result which owns every value execution needs.
/// Consuming this value prevents a caller from combining live discovery with
/// different product data or programming options.
pub struct PreparedProgramming {
    request: ProgrammingRequest,
    current_address: IndividualAddress,
    product_mask: MaskVersion,
    device_mask: MaskVersion,
    assignment_method: Option<AddressAssignmentMethod>,
    descriptor_access: Option<ManagementAccess>,
    plain_descriptor_probe: bool,
    programming_mode_address: Option<u16>,
    download_model: Option<&'static DownloadModel>,
    selected_load_path: LoadControlPath,
    compiled: Option<CompiledDownload>,
    /// Precompiled before mutation so a failed partial run can recover with
    /// the ordinary full flow without discovering a late compiler error.
    full_fallback: Option<CompiledDownload>,
    /// Why preflight widened a requested partial operation to full.
    partial_fallback_reason: Option<String>,
}

impl PreparedProgramming {
    pub fn current_address(&self) -> IndividualAddress {
        self.current_address
    }

    pub fn product_mask(&self) -> MaskVersion {
        self.product_mask
    }

    pub fn device_mask(&self) -> MaskVersion {
        self.device_mask
    }

    pub fn assignment_method(&self) -> Option<AddressAssignmentMethod> {
        self.assignment_method
    }

    pub fn compiled(&self) -> Option<&CompiledDownload> {
        self.compiled.as_ref()
    }

    pub fn partial_fallback_reason(&self) -> Option<&str> {
        self.partial_fallback_reason.as_deref()
    }

    pub fn key_material(&self) -> &ResolvedKeyMaterial {
        &self.request.key_material
    }

    pub(crate) fn apply_authenticated_siat_sequences(
        &mut self,
        mask_db: &MaskDb,
        remote_next_sequences: &BTreeMap<IndividualAddress, u64>,
    ) -> Result<()> {
        if !raise_siat_rows(&mut self.request.key_material, remote_next_sequences) {
            return Ok(());
        }

        let mask = select_download_mask(mask_db, self.product_mask, self.device_mask)?;
        let requested_scope =
            if self.partial_fallback_reason.is_some() { DownloadScope::Full } else { self.request.download_scope };
        let (compiled, full_fallback) = compile_application_downloads_for_scope(&mask, &self.request, requested_scope)?;
        self.compiled = Some(compiled);
        self.full_fallback = full_fallback;

        Ok(())
    }
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
        if !key_material.needs_tool_key_generation() {
            return Ok(false);
        }
        let sink = generated_key_sink.ok_or(Error::GeneratedToolKeyRequiresStore)?;
        let mut tool_key = [0u8; 16];
        getrandom::fill(&mut tool_key).map_err(|error| {
            Error::KeyMaterial(KeyStoreError::Unavailable(format!("the OS random generator failed: {error}")))
        })?;
        sink.persist_generated_tool_key(key_material.serial_number(), tool_key)?;
        key_material.install_generated_tool_key(tool_key);
        Ok(true)
    }

    /// Discover, authenticate, merge live SIAT replay floors, select the real
    /// device mask, and compile without writing device configuration.
    pub async fn prepare(
        &self,
        bus: &KnxBus,
        mask_db: &MaskDb,
        request: ProgrammingRequest,
    ) -> Result<PreparedProgramming> {
        self.prepare_with_progress(bus, mask_db, request, &mut |_| {}).await
    }

    async fn prepare_with_progress<F>(
        &self,
        bus: &KnxBus,
        mask_db: &MaskDb,
        mut request: ProgrammingRequest,
        progress: &mut F,
    ) -> Result<PreparedProgramming>
    where
        F: FnMut(ProgrammingEvent) + Send,
    {
        validate_data_secure_selection(&request)?;
        if request.options.scope == ProgrammingScope::Application && request.key_material.needs_tool_key_generation() {
            return Err(Error::NetworkConfigurationRequired);
        }
        if request.key_material.needs_tool_key_generation() && !preserves_security_configuration(&request.options) {
            return Err(Error::GeneratedToolKeyRequiresStore);
        }
        let product_mask = request
            .product
            .mask_version()
            .ok_or_else(|| Error::ProductData("the product names no mask version".to_string()))?;
        let desired = request.configuration.identity.desired_address;
        let (current_address, assignment_method) = if request.options.scope.includes_address() {
            emit(progress, ProgrammingEvent::Stage(ProgrammingStage::DiscoveringDevice));
            discover_current_address(bus, product_mask, desired, request.key_material.serial_number(), &request.options)
                .await?
        } else {
            (desired, None)
        };
        emit(progress, ProgrammingEvent::Stage(ProgrammingStage::ReadingDescriptor));
        let (device_mask, mut retained, plain_descriptor_probe) = read_device_mask(
            bus,
            current_address,
            product_mask.family(),
            &request.key_material,
            request.options.allow_plaintext_management,
        )
        .await?;
        let descriptor_access = retained.as_ref().map(|(_, access)| *access);

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
            && request.key_material.application_security().is_some()
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

        let mask = select_download_mask(mask_db, product_mask, device_mask)?;
        let (mut compiled, mut full_fallback) = if request.options.scope.includes_application() {
            emit(progress, ProgrammingEvent::Stage(ProgrammingStage::Compiling));
            let (compiled, full_fallback) = compile_application_downloads(&mask, &request)?;
            (Some(compiled), full_fallback)
        } else {
            (None, None)
        };
        let mut partial_fallback_reason = None;
        if compiled.as_ref().is_some_and(|compiled| compiled.scope() != DownloadScope::Full) {
            let (mut connection, _) = connect_management_ordered(
                bus,
                current_address,
                &request.key_material,
                request.options.allow_plaintext_management,
                false,
                false,
            )
            .await?;
            if let Err(error) = validate_partial_download_state(
                &mut connection,
                &mask,
                &request.product,
                compiled.as_ref().expect("partial download checked above"),
                &request.previous_mcb,
            )
            .await
            {
                let reason = error.to_string();
                log::warn!("partial download preflight failed: {reason}; falling back to full");
                compiled = full_fallback.take().map(Some).expect("partial downloads precompile a full fallback");
                partial_fallback_reason = Some(reason);
            }
            let _ = connection.close().await;
        }
        let selected_load_path = match compiled.as_ref() {
            Some(compiled) => compiled.path(),
            None => load_control_path(&mask)?,
        };
        Ok(PreparedProgramming {
            request,
            current_address,
            product_mask,
            device_mask,
            assignment_method,
            descriptor_access,
            plain_descriptor_probe,
            programming_mode_address: mask.standard_memory_address("ProgrammingMode"),
            download_model: DownloadModel::for_management_model(mask.management_model()),
            selected_load_path,
            compiled,
            full_fallback,
            partial_fallback_reason,
        })
    }

    pub async fn program(
        &self,
        bus: &KnxBus,
        mask_db: &MaskDb,
        request: ProgrammingRequest,
        generated_key_sink: Option<&mut dyn GeneratedToolKeySink>,
    ) -> Result<ProgrammingReport> {
        self.program_with_progress(bus, mask_db, request, generated_key_sink, &mut |_| {}).await
    }

    pub async fn program_with_progress<F>(
        &self,
        bus: &KnxBus,
        mask_db: &MaskDb,
        mut request: ProgrammingRequest,
        generated_key_sink: Option<&mut dyn GeneratedToolKeySink>,
        progress: &mut F,
    ) -> Result<ProgrammingReport>
    where
        F: FnMut(ProgrammingEvent) + Send,
    {
        // This check precedes even generated-key persistence. Capability and
        // enablement mismatches are project errors and must be side-effect
        // free, including for direct `DeviceProgrammer` callers.
        validate_data_secure_selection(&request)?;

        // A tool key is never first used until its authoritative source can
        // reproduce it. This ordering is what makes an interrupted key change
        // recoverable on the next invocation.
        if request.options.scope == ProgrammingScope::Application && request.key_material.needs_tool_key_generation() {
            return Err(Error::NetworkConfigurationRequired);
        }
        if request.key_material.needs_tool_key_generation() && !preserves_security_configuration(&request.options) {
            emit(progress, ProgrammingEvent::Stage(ProgrammingStage::PersistingToolKey));
            self.materialize_tool_key(&mut request.key_material, generated_key_sink)?;
        }

        let prepared = self.prepare_with_progress(bus, mask_db, request, progress).await?;
        self.execute_with_progress(bus, prepared, progress).await
    }

    pub async fn execute(&self, bus: &KnxBus, prepared: PreparedProgramming) -> Result<ProgrammingReport> {
        self.execute_with_progress(bus, prepared, &mut |_| {}).await
    }

    pub async fn execute_with_progress<F>(
        &self,
        bus: &KnxBus,
        prepared: PreparedProgramming,
        progress: &mut F,
    ) -> Result<ProgrammingReport>
    where
        F: FnMut(ProgrammingEvent) + Send,
    {
        let PreparedProgramming {
            mut request,
            current_address: current,
            product_mask,
            device_mask,
            assignment_method,
            descriptor_access,
            plain_descriptor_probe,
            programming_mode_address,
            download_model,
            selected_load_path,
            compiled,
            full_fallback,
            partial_fallback_reason: _,
        } = prepared;
        let compiled = compiled;
        let mut full_fallback = full_fallback;
        let desired = request.configuration.identity.desired_address;
        let preserve_security_configuration = preserves_security_configuration(&request.options);

        let serial_assignment_key = match descriptor_access {
            Some(ManagementAccess::Fdsk) => request.key_material.fdsk().copied(),
            Some(ManagementAccess::ToolKey) => request.key_material.tool_key().copied(),
            Some(ManagementAccess::Plain) => None,
            // A factory device may expose DD0 connectionlessly, so no
            // retained session exists to tell us that its serial write still
            // requires the FDSK. A commissioned secure device normally hides
            // DD0 from plaintext and therefore takes the retained Tool-Key
            // branch above.
            None => request.key_material.fdsk().or_else(|| request.key_material.tool_key()).copied(),
        };

        if assignment_method == Some(AddressAssignmentMethod::KnownAddress) && current != desired {
            enable_known_address_programming_mode(
                bus,
                current,
                desired,
                &request,
                plain_descriptor_probe,
                programming_mode_address,
            )
            .await?;
        }

        let address_assignment = match (assignment_method, current != desired) {
            (Some(method), true) => {
                emit(progress, ProgrammingEvent::Stage(ProgrammingStage::AssigningAddress));
                Some(
                    assign_address(
                        bus,
                        method,
                        current,
                        desired,
                        request.key_material.serial_number(),
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

        emit(progress, ProgrammingEvent::Stage(ProgrammingStage::SelectingManagementAccess));
        let (mut connection, mut management_access) = connect_management_ordered(
            bus,
            desired,
            &request.key_material,
            request.options.allow_plaintext_management,
            plain_descriptor_probe,
            false,
        )
        .await?;
        if request.configuration.data_secure_enabled && management_access == ManagementAccess::Plain {
            let _ = connection.close().await;
            return Err(Error::ManagementAccessUnavailable);
        }
        if request.options.scope == ProgrammingScope::Application && management_access == ManagementAccess::Fdsk {
            let _ = connection.close().await;
            return Err(Error::NetworkConfigurationRequired);
        }

        let programming_mode_cleared = request.options.scope.includes_address()
            && matches!(
                assignment_method,
                Some(AddressAssignmentMethod::ProgrammingButton | AddressAssignmentMethod::KnownAddress)
            );
        if programming_mode_cleared {
            disable_programming_mode(&mut connection, programming_mode_address).await?;
        }

        let security_bootstrap = management_access == ManagementAccess::Fdsk && !preserve_security_configuration;
        if security_bootstrap {
            emit(progress, ProgrammingEvent::Stage(ProgrammingStage::EnablingSecurityMode));
            connection.enable_security_mode().await?;
            let tool_key = request.key_material.tool_key().copied().ok_or(Error::GeneratedToolKeyRequiresStore)?;
            emit(progress, ProgrammingEvent::Stage(ProgrammingStage::InstallingToolKey));
            connection.write_tool_key(tool_key).await?;
            management_access = ManagementAccess::ToolKey;
        }
        let secure_management = management_access != ManagementAccess::Plain;

        let max_apdu =
            negotiate_max_apdu(&mut connection, bus.max_apdu(), request.configuration.max_apdu, download_model).await;

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
        if network_configuration_performed && secure_management && !preserve_security_configuration {
            emit(progress, ProgrammingEvent::Stage(ProgrammingStage::SettingDeviceSequence));
            advance_device_sending_sequence(bus, &mut connection, request.key_material.serial_number()).await?;
        }

        if network_configuration_performed {
            emit(
                progress,
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
            emit(progress, ProgrammingEvent::Stage(ProgrammingStage::WaitingForRestart));
            tokio::time::sleep(restart_wait).await;

            if !request.options.scope.includes_application() {
                emit(progress, ProgrammingEvent::Stage(ProgrammingStage::Verifying));
                let security = verify_network_configuration(
                    bus,
                    desired,
                    device_mask,
                    management_access == ManagementAccess::ToolKey,
                )
                .await?;
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
                    download_scope: DownloadScope::Full,
                    load_states: Vec::new(),
                    security,
                    mcb_snapshots: Vec::new(),
                    key_provenance: request.key_material.take_provenance(),
                });
            }

            emit(progress, ProgrammingEvent::Stage(ProgrammingStage::SelectingManagementAccess));
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
            emit(progress, ProgrammingEvent::Stage(ProgrammingStage::Verifying));
            let security =
                verify_network_configuration(bus, desired, device_mask, management_access == ManagementAccess::ToolKey)
                    .await?;
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
                download_scope: DownloadScope::Full,
                load_states: Vec::new(),
                security,
                mcb_snapshots: Vec::new(),
                key_provenance: request.key_material.take_provenance(),
            });
        }

        let mut compiled = compiled.expect("application scope compiles a download");
        let download_apdu = download_plaintext_apdu(max_apdu, management_access);
        log::debug!(
            "using max APDU {max_apdu} on the wire and {download_apdu} for {} download APDUs",
            if management_access == ManagementAccess::Plain { "plain" } else { "secure" }
        );

        emit(progress, ProgrammingEvent::Stage(ProgrammingStage::Downloading));
        let mut nested_progress = |event| emit(progress, ProgrammingEvent::Download(event));
        let result = compiled.execute_with_progress_outcome(&mut connection, download_apdu, &mut nested_progress).await;
        let download_outcome = match result {
            Ok(outcome) => outcome,
            Err(partial_error) if full_fallback.is_some() => {
                let _ = connection.close().await;
                emit(progress, ProgrammingEvent::FallingBackToFullDownload { reason: partial_error.to_string() });

                // A partial procedure may have failed immediately after a
                // restart or disconnect. Wait through the normal restart
                // window, then establish a fresh session rather than making
                // assumptions about the device's transport state.
                tokio::time::sleep(request.options.restart_delay).await;
                let reconnected = connect_management_ordered(
                    bus,
                    desired,
                    &request.key_material,
                    request.options.allow_plaintext_management,
                    false,
                    false,
                )
                .await;
                let (reconnected, reconnected_access) = match reconnected {
                    Ok(connection) => connection,
                    Err(full_error) => {
                        return Err(Error::PartialDownloadFallback {
                            partial: Box::new(partial_error),
                            full: Box::new(full_error),
                        });
                    }
                };
                if secure_management && reconnected_access != ManagementAccess::ToolKey {
                    let _ = reconnected.close().await;
                    return Err(Error::PartialDownloadFallback {
                        partial: Box::new(partial_error),
                        full: Box::new(Error::ManagementAccessUnavailable),
                    });
                }
                connection = reconnected;
                management_access = reconnected_access;

                let fallback = full_fallback.take().expect("guard checks full fallback");
                let mut nested_progress = |event| emit(progress, ProgrammingEvent::Download(event));
                let result = fallback
                    .execute_with_progress_outcome(
                        &mut connection,
                        download_plaintext_apdu(max_apdu, management_access),
                        &mut nested_progress,
                    )
                    .await;
                match result {
                    Ok(outcome) => {
                        compiled = fallback;
                        outcome
                    }
                    Err(full_error) => {
                        let _ = connection.close().await;
                        return Err(Error::PartialDownloadFallback {
                            partial: Box::new(partial_error),
                            full: Box::new(full_error),
                        });
                    }
                }
            }
            Err(error) => {
                let _ = connection.close().await;
                return Err(error);
            }
        };

        let procedure_restarts_device = compiled
            .instructions
            .iter()
            .any(|step| matches!(step, Instruction::Restart | Instruction::ConfirmedRestart));

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
            emit(progress, ProgrammingEvent::Stage(ProgrammingStage::RestartingDevice));
            match connection.restart().await {
                Ok(()) | Err(Error::TransportClosed) => {}
                Err(error) => {
                    let _ = connection.close().await;
                    return Err(error);
                }
            }
            request.options.restart_delay
        } else {
            emit(progress, ProgrammingEvent::Stage(ProgrammingStage::RestartingDevice));
            match connection.master_reset(EraseCode::Confirmed, 0).await {
                Ok(restart) => restart.process_time.max(request.options.restart_delay),
                Err(error) => {
                    let _ = connection.close().await;
                    return Err(error);
                }
            }
        };
        let _ = connection.close().await;

        emit(progress, ProgrammingEvent::Stage(ProgrammingStage::WaitingForRestart));
        tokio::time::sleep(restart_wait).await;

        emit(progress, ProgrammingEvent::Stage(ProgrammingStage::Verifying));
        // A partial procedure intentionally omits unchanged Security IO
        // writes. Verify its completed load machines, but derive the expected
        // final security-table shape from the precompiled full desired state.
        let desired_download = full_fallback.as_ref().unwrap_or(&compiled);
        let (load_states, security) = verify_download(
            bus,
            desired,
            device_mask,
            &compiled,
            desired_download,
            request.configuration.data_secure_enabled,
        )
        .await?;
        let mcb_snapshots = download_outcome
            .loaded_properties()
            .iter()
            .filter(|property| property.prop_id == pid::MCB_TABLE)
            .map(mcb_snapshot_from_property)
            .collect::<Result<Vec<_>>>()?;

        if let Some(security) = request.key_material.application_security() {
            for (group, key) in security.group_keys() {
                bus.set_group_key(group, *key).await?;
            }
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
            download_scope: compiled.scope(),
            load_states,
            security,
            mcb_snapshots,
            key_provenance: request.key_material.take_provenance(),
        })
    }
}

/// Compile the selected procedure and, when it is genuinely partial, its
/// recovery procedure. Both are built before the first configuration write so
/// runtime fallback cannot expose a product or master-data compiler failure
/// after leaving the device half-loaded.
fn compile_application_downloads(
    mask: &MaskData<'_>,
    request: &ProgrammingRequest,
) -> Result<(CompiledDownload, Option<CompiledDownload>)> {
    compile_application_downloads_for_scope(mask, request, request.download_scope)
}

fn compile_application_downloads_for_scope(
    mask: &MaskData<'_>,
    request: &ProgrammingRequest,
    requested_scope: DownloadScope,
) -> Result<(CompiledDownload, Option<CompiledDownload>)> {
    let lowered = request.configuration.lower(request.key_material.application_security().cloned())?;
    let compiled = compile_scoped(mask, &request.product, &lowered, requested_scope)?;
    let full_fallback = if compiled.scope() == DownloadScope::Full {
        None
    } else {
        Some(compile_scoped(mask, &request.product, &lowered, DownloadScope::Full)?)
    };
    Ok((compiled, full_fallback))
}

/// Prove that an in-place procedure is targeting the application recorded by
/// the project. Master data describes which machine owns the application, so
/// this gate remains independent of BCU family and load-control realization.
async fn validate_partial_download_state(
    connection: &mut DeviceConnection,
    mask: &MaskData<'_>,
    product: &ProductData,
    compiled: &CompiledDownload,
    previous_mcb: &[McbSnapshot],
) -> Result<()> {
    let application = mask
        .lsm_model()
        .index_of(MachineRole::Application)
        .ok_or_else(|| Error::ProgrammingVerification("the mask declares no application load machine".to_string()))?;
    let bytes = read_load_state(connection, compiled.path(), LsmTarget::Index(application)).await?;
    let value = *bytes.first().ok_or(Error::Parse("load-state read returned no byte"))?;
    let state = LoadState::try_from(value).map_err(|_| {
        Error::ProgrammingVerification(format!("application load machine returned unknown state {value:#04X}"))
    })?;
    if state != LoadState::Loaded {
        return Err(Error::ProgrammingVerification(format!(
            "application load machine returned {state}, expected Loaded for a partial download"
        )));
    }

    let version = connection.property_read(application, pid::PROGRAM_VERSION, 1, 1).await?;
    if version.as_slice() != product.application_identity().application_id {
        return Err(Error::ProgrammingVerification(format!(
            "application program identity is {:02X?}, expected {:02X?}",
            version,
            product.application_identity().application_id
        )));
    }
    validate_mcb_state(connection, compiled, previous_mcb).await?;
    Ok(())
}

/// ETS retains the device-generated CRCs read by the product's final
/// `LdCtrlLoadImageProp PID_MCB_TABLE` controls. Before an in-place load it
/// compares those values with the live device. Mutable MCB segments (CRC
/// control bit 0 set) are intentionally excluded because the application is
/// allowed to change their contents between downloads.
async fn validate_mcb_state(
    connection: &mut DeviceConnection,
    compiled: &CompiledDownload,
    previous: &[McbSnapshot],
) -> Result<()> {
    // The CRC stamp protects parameter-only reuse of application memory.
    // Group Communication reloads its tables completely; §3.9.3.5 therefore
    // requires the application identity check but no CRC precondition.
    let changes_parameters =
        matches!(compiled.scope(), DownloadScope::Parameters | DownloadScope::ParametersAndGroupCommunication);
    let requires_mcb = changes_parameters
        && compiled.instructions.iter().any(
            |instruction| matches!(instruction, Instruction::LoadImageProperty { prop_id, .. } if *prop_id == pid::MCB_TABLE),
        );
    if !requires_mcb {
        return Ok(());
    }
    if previous.is_empty() {
        return Err(Error::ProgrammingVerification(
            "no PID 27 CRC snapshot exists from a previous successful download".to_string(),
        ));
    }

    for expected in previous {
        let count = u16::try_from(expected.segment_crc.len()).map_err(|_| {
            Error::ProgrammingVerification(format!(
                "object {} PID 27 snapshot exceeds the property count field",
                expected.object_index
            ))
        })?;
        if count == 0 {
            return Err(Error::ProgrammingVerification(format!(
                "object {} PID 27 snapshot contains no elements",
                expected.object_index
            )));
        }
        let live = connection.property_read(expected.object_index, pid::MCB_TABLE, expected.start_index, count).await?;
        compare_mcb_crc(expected, &live)?;
    }
    Ok(())
}

fn compare_mcb_crc(expected: &McbSnapshot, live: &[u8]) -> Result<()> {
    let expected_len = expected.segment_crc.len() * 8;
    if live.len() != expected_len {
        return Err(Error::ProgrammingVerification(format!(
            "object {} PID 27 returned malformed MCB data (live {}, expected {})",
            expected.object_index,
            live.len(),
            expected_len
        )));
    }
    for (offset, (&stored_crc, current)) in expected.segment_crc.iter().zip(live.chunks_exact(8)).enumerate() {
        let current_crc = (current[4] & 1 == 0).then(|| u16::from_be_bytes([current[6], current[7]]));
        let element = usize::from(expected.start_index) + offset;
        if stored_crc.is_some() != current_crc.is_some() {
            return Err(Error::ProgrammingVerification(format!(
                "object {} PID 27 element {element} changed its CRC-control mode",
                expected.object_index
            )));
        }
        if stored_crc != current_crc {
            return Err(Error::ProgrammingVerification(format!(
                "object {} PID 27 element {element} CRC changed from {:04X} to {:04X}",
                expected.object_index,
                stored_crc.expect("CRC mode equality proves both values exist"),
                current_crc.expect("CRC mode equality proves both values exist")
            )));
        }
    }
    Ok(())
}

fn mcb_snapshot_from_property(property: &crate::download::LoadedProperty) -> Result<McbSnapshot> {
    let expected_len = usize::from(property.count) * 8;
    if property.data.len() != expected_len {
        return Err(Error::ProgrammingVerification(format!(
            "object {} PID 27 post-download read returned {} bytes, expected {expected_len}",
            property.obj_idx,
            property.data.len()
        )));
    }
    let segment_crc = property
        .data
        .chunks_exact(8)
        .map(|row| (row[4] & 1 == 0).then(|| u16::from_be_bytes([row[6], row[7]])))
        .collect();
    Ok(McbSnapshot { object_index: property.obj_idx, start_index: property.start_idx, segment_crc })
}

fn validate_data_secure_selection(request: &ProgrammingRequest) -> Result<()> {
    let enabled = request.configuration.data_secure_enabled;
    if enabled && !request.product.supports_data_secure() {
        return Err(Error::DeviceConfiguration(format!(
            "product `{}` does not support Data Secure",
            request.product.id()
        )));
    }
    if !request.options.scope.includes_application() {
        if request.key_material.fdsk().is_some() && request.key_material.fdsk() == request.key_material.tool_key() {
            return Err(Error::DeviceConfiguration("the Tool Key must differ from the FDSK".to_string()));
        }
        return Ok(());
    }
    match (enabled, request.key_material.application_security().is_some()) {
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
    if request.key_material.fdsk().is_some() && request.key_material.fdsk() == request.key_material.tool_key() {
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

/// ETS's overwrite operation changes only the physical address. It may use
/// either the current Tool Key or FDSK to reach the old address, but it does
/// not bootstrap Security Mode, replace the Tool Key, or reseed PID 59.
fn preserves_security_configuration(options: &ProgrammingOptions) -> bool {
    options.scope == ProgrammingScope::Address && matches!(options.addressing, AddressingMode::KnownAddress(_))
}

async fn merge_live_siat(connection: &mut DeviceConnection, keys: &mut ResolvedKeyMaterial) -> Result<()> {
    let Some(security) = keys.application_security_mut() else { return Ok(()) };
    let count = connection
        .property_ext_read(SECURITY_IO, SECURITY_IO_OCCURRENCE, pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, 0, 1)
        .await?;
    let count: [u8; 2] = count
        .as_slice()
        .try_into()
        .map_err(|_| Error::ProgrammingVerification("Security IO SIAT count is not a 16-bit value".to_string()))?;
    let mut desired: BTreeMap<IndividualAddress, u64> = security.siat().iter().copied().collect();
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
    security.replace_siat(desired.into_iter().collect());
    Ok(())
}

fn raise_siat_rows(keys: &mut ResolvedKeyMaterial, remote_next_sequences: &BTreeMap<IndividualAddress, u64>) -> bool {
    let Some(security) = keys.application_security_mut() else {
        return false;
    };

    let mut rows: BTreeMap<IndividualAddress, u64> = security.siat().iter().copied().collect();
    let mut changed = false;

    for (address, last_valid) in &mut rows {
        let Some(remote_next_sequence) = remote_next_sequences.get(address) else {
            continue;
        };

        // Do not subtract one here. Project SIAT generation stores the raw
        // `SeqNrremote` returned by sync.
        if *last_valid < *remote_next_sequence {
            *last_valid = *remote_next_sequence;
            changed = true;
        }
    }

    if changed {
        security.replace_siat(rows.into_iter().collect());
    }

    changed
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

fn emit(progress: &mut (impl FnMut(ProgrammingEvent) + ?Sized), event: ProgrammingEvent) {
    progress(event);
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
        AddressingMode::KnownAddress(previous) => Ok((previous, Some(AddressAssignmentMethod::KnownAddress))),
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
        AddressAssignmentMethod::ProgrammingButton | AddressAssignmentMethod::KnownAddress => {
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

async fn enable_known_address_programming_mode(
    bus: &KnxBus,
    address: IndividualAddress,
    desired: IndividualAddress,
    request: &ProgrammingRequest,
    plain_descriptor_probe: bool,
    memory_address: Option<u16>,
) -> Result<()> {
    if bus.network_management().is_device_present(desired, request.options.scan_window).await? {
        return Err(Error::IndividualAddressOccupied(desired));
    }

    let (mut connection, _) = connect_management_ordered(
        bus,
        address,
        &request.key_material,
        request.options.allow_plaintext_management,
        plain_descriptor_probe,
        false,
    )
    .await?;

    set_programming_mode(&mut connection, memory_address, true).await?;

    let found = bus.network_management().read_individual_addresses(request.options.scan_window).await?;
    if found.as_slice() != [address] {
        let _ = set_programming_mode(&mut connection, memory_address, false).await;
        let _ = connection.close().await;

        return match found.len() {
            0 => Err(Error::ProgrammingDeviceNotFound),
            1 => Err(Error::ProgrammingAddressVerification(address)),
            count => Err(Error::MultipleProgrammingDevices(count)),
        };
    }

    connection.close().await
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
/// credential attempted. Normal programming may reuse only a synchronization
/// performed with the same credential during the preceding two seconds.
/// The returned connection exposes the authenticated `SeqNrremote` through
/// [`DeviceConnection::last_security_sync_remote_sequence`].
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
        [(ManagementAccess::Fdsk, keys.fdsk()), (ManagementAccess::ToolKey, keys.tool_key())]
    } else {
        [(ManagementAccess::ToolKey, keys.tool_key()), (ManagementAccess::Fdsk, keys.fdsk())]
    };
    for (access, key) in credentials {
        let Some(key) = key else { continue };
        let entry = match access {
            ManagementAccess::ToolKey => SecurityEntry::with_credentials(
                DeviceSecurityMode::Secure,
                Some(*key),
                keys.fdsk().copied(),
                keys.serial_number(),
            )
            .expect("the selected tool key is present"),
            ManagementAccess::Fdsk => {
                SecurityEntry::with_credentials(DeviceSecurityMode::Secure, None, Some(*key), keys.serial_number())
                    .expect("the selected FDSK is present")
            }
            ManagementAccess::Plain => unreachable!(),
        };
        bus.set_device_security(address, entry).await?;
        let opened =
            if force_sync { bus.connect_device_synchronized(address).await } else { bus.connect_device(address).await };
        match opened {
            Ok(connection) => return Ok((connection, access)),
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

async fn disable_programming_mode(connection: &mut DeviceConnection, memory_address: Option<u16>) -> Result<()> {
    set_programming_mode(connection, memory_address, false).await
}

async fn set_programming_mode(
    connection: &mut DeviceConnection,
    memory_address: Option<u16>,
    enabled: bool,
) -> Result<()> {
    if let Some(address) = memory_address {
        let bytes = connection.memory_read(address, 1).await?;
        let byte = *bytes.first().ok_or(Error::Parse("programming-mode read returned no byte"))?;
        if (byte & 1 != 0) != enabled {
            // BCU system status guards the byte with even parity in bit 7.
            // Changing only bit 0 can produce an invalid byte, which real
            // masks reject. Recalculate the parity bit with the new mode.
            connection.memory_write_verify(address, &[system_status_with_programming_mode(byte, enabled)]).await?;
        }
    } else {
        connection.property_write(0, pid::device::PROGMODE, 1, 1, &[u8::from(enabled)]).await?;
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
    crate::download::management_plaintext_apdu_budget(wire_max_apdu, access != ManagementAccess::Plain)
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
    executed: &CompiledDownload,
    desired: &CompiledDownload,
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

        let completed: BTreeSet<_> = executed
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instruction::LsmEvent { lsm, event: LoadEvent::LoadCompleted } => Some(*lsm),
                _ => None,
            })
            .collect();
        let mut load_states = Vec::with_capacity(completed.len());
        for target in completed {
            let bytes = read_load_state(&mut connection, executed.path(), target).await.map_err(|error| {
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

        if let Some((object, property)) = executed.application_run_state_property() {
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

        let security = if secure_product { Some(verify_security(&mut connection, desired).await?) } else { None };
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
        } else if *prop_id == pid::security::GO_SECURITY_FLAGS && *start_idx != 0 && *count != 0 {
            if data.len() != usize::from(*count) {
                return Err(Error::ProgrammingVerification(
                    "compiled GO-security range does not contain one byte per element".to_string(),
                ));
            }
            let last = start_idx.checked_add(*count - 1).ok_or_else(|| {
                Error::ProgrammingVerification("compiled GO-security range exceeds 16 bits".to_string())
            })?;
            let expected = result.entry(pid::security::GO_SECURITY_FLAGS).or_default();
            *expected = (*expected).max(last);
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
    fn only_address_overwrite_preserves_security_configuration() {
        let overwrite = ProgrammingOptions {
            scope: ProgrammingScope::Address,
            addressing: AddressingMode::KnownAddress(IndividualAddress::new(1, 1, 1)),
            ..ProgrammingOptions::default()
        };
        assert!(preserves_security_configuration(&overwrite));

        let combined = ProgrammingOptions { scope: ProgrammingScope::AddressAndApplication, ..overwrite.clone() };
        assert!(!preserves_security_configuration(&combined));

        let ordinary = ProgrammingOptions { addressing: AddressingMode::Automatic, ..overwrite };
        assert!(!preserves_security_configuration(&ordinary));
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
                data: 2_u16.to_be_bytes().to_vec().into(),
                verify: false,
            },
            Instruction::WritePropertyExt {
                object_type: SECURITY_IO,
                occurrence: SECURITY_IO_OCCURRENCE,
                prop_id: pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE,
                start_idx: 0,
                count: 1,
                data: 1_u16.to_be_bytes().to_vec().into(),
                verify: false,
            },
        ];
        instructions.push(Instruction::WritePropertyExt {
            object_type: SECURITY_IO,
            occurrence: SECURITY_IO_OCCURRENCE,
            prop_id: pid::security::GO_SECURITY_FLAGS,
            start_idx: 1,
            count: 4,
            data: vec![0; 4].into(),
            verify: false,
        });

        let counts =
            expected_security_table_counts_from_instructions(&instructions).expect("security table layout is valid");
        assert_eq!(counts[&pid::security::GROUP_KEY_TABLE], 2);
        assert_eq!(counts[&pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE], 1);
        assert_eq!(counts[&pid::security::GO_SECURITY_FLAGS], 4);
    }

    #[test]
    fn partial_crc_gate_checks_only_immutable_mcb_segments() {
        let expected = McbSnapshot { object_index: 4, start_index: 1, segment_crc: vec![Some(0x1234), None] };
        let mut live = vec![
            0, 0, 0, 32, 0, 0x32, 0x12, 0x34, // immutable
            0, 0, 0, 16, 1, 0x32, 0x56, 0x78, // application-mutable
        ];
        live[14..16].copy_from_slice(&[0x9A, 0xBC]);
        compare_mcb_crc(&expected, &live).expect("mutable CRC changes are valid");

        live[6..8].copy_from_slice(&[0xDE, 0xAD]);
        let error = compare_mcb_crc(&expected, &live).expect_err("immutable CRC changes reject partial loads");
        assert!(error.to_string().contains("CRC changed"));
    }

    #[test]
    fn partial_crc_gate_rejects_changed_control_and_malformed_rows() {
        let expected = McbSnapshot { object_index: 4, start_index: 3, segment_crc: vec![Some(0x1234)] };
        let mut live = vec![0, 0, 0, 32, 0, 0x32, 0x12, 0x34];
        live[4] = 1;
        assert!(
            compare_mcb_crc(&expected, &live)
                .expect_err("control changes reject partial loads")
                .to_string()
                .contains("CRC-control")
        );
        assert!(
            compare_mcb_crc(&expected, &live[..7])
                .expect_err("short rows reject partial loads")
                .to_string()
                .contains("malformed")
        );
    }

    #[test]
    fn partial_download_precompiles_its_full_fallback() {
        let product =
            ProductData::from_mtxml_str(crate::download::SYSTEM_B_PRODUCT_XML).expect("product fixture parses");
        let configuration = DeviceConfiguration {
            identity: crate::download::DeviceIdentity {
                desired_address: IndividualAddress::new(1, 1, 42),
                serial_number: None,
            },
            data_secure_enabled: false,
            parameters: Vec::new(),
            object_memberships: vec![crate::download::ObjectMembership {
                group_address: zweidraehte_proto::address::GroupAddress::from_three_level(1, 0, 1),
                com_object: 1,
                role: crate::download::MembershipRole::Primary,
            }],
            objects: product.com_objects().to_vec(),
            net_security: BTreeMap::new(),
            max_apdu: None,
        };
        let request = ProgrammingRequest::new(product, configuration, ResolvedKeyMaterial::new(None))
            .with_download_scope(DownloadScope::Parameters);
        let partial_mask_xml = crate::download::SYSTEM_B_MASK_XML.replace(
            "</Procedures>",
            r#"<Procedure ProcedureType="Load" ProcedureSubType="par" Access="remote">
              <LdCtrlConnect />
              <LdCtrlWriteRelMem ObjIdx="4" Offset="0" Size="1048576" Verify="true" />
              <LdCtrlRestart />
            </Procedure>
          </Procedures>"#,
        );
        let db = MaskDb::from_xml_str(&partial_mask_xml).expect("mask fixture parses");
        let mask = db.mask(MaskVersion::SystemBTp1).expect("System B mask exists");

        let (partial, fallback) = compile_application_downloads(&mask, &request).expect("both procedures compile");
        assert_ne!(partial.scope(), DownloadScope::Full);
        assert_eq!(fallback.expect("partial procedures retain a fallback").scope(), DownloadScope::Full);
    }

    #[test]
    fn authenticated_sender_sequences_advance_existing_siat_rows() {
        let first = IndividualAddress::new(1, 1, 1);
        let second = IndividualAddress::new(1, 1, 2);
        let absent = IndividualAddress::new(1, 1, 3);
        let security = crate::download::SecurityConfig::new(Vec::new(), vec![(first, 0), (second, 50)], Vec::new());
        let mut material = ResolvedKeyMaterial::new(None).with_application_security(Some(security));
        let remote_next_sequences = BTreeMap::from([(first, 123), (second, 40), (absent, 999)]);

        assert!(raise_siat_rows(&mut material, &remote_next_sequences));
        assert_eq!(material.application_security().expect("security remains").siat(), [(first, 123), (second, 50)]);
        assert!(!raise_siat_rows(&mut material, &remote_next_sequences), "an unchanged refresh avoids recompilation");
    }

    #[test]
    fn tool_key_is_persisted_before_becoming_usable() {
        let serial = [0x00, 0xFA, 1, 2, 3, 4];
        let mut material =
            ResolvedKeyMaterial::new(Some(serial)).with_fdsk(Some([0x11; 16])).requiring_tool_key_generation();
        let mut sink = RecordingSink::default();

        assert!(DeviceProgrammer::new().materialize_tool_key(&mut material, Some(&mut sink)).expect("key generates"));
        let (_, persisted) = sink.0.expect("sink observes key before return");
        assert_eq!(material.tool_key(), Some(&persisted));
        assert!(!material.needs_tool_key_generation());
        assert!(material.provenance().iter().any(|metadata| metadata.origin == crate::security::KeyOrigin::Generated));
    }
}
