//! One commissioning pipeline shared by command-line, UI, and tests.
//!
//! Product interpretation and key resolution happen before this layer. The
//! programmer owns the ordering that matters on a live bus: identify and
//! compile against the real mask before moving the address, choose the
//! management credential without a plaintext downgrade, rotate the tool key,
//! execute the mask procedure, and verify the resulting state.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::device::{MaskFamily, MaskVersion};
use zweidraehte_proto::messages::apdu::load_control::{LoadEvent, LoadState};
use zweidraehte_proto::pid;

use crate::api::{DeviceConnection, KnxBus};
use crate::download::{
    CompiledDownload, DeviceConfiguration, DeviceImage, DownloadEvent, DownloadModel, Instruction, LoadControlPath,
    LsmTarget, MaskData, MaskDb, ProductData, select_download_mask,
};
use crate::error::{Error, Result};
use crate::security::{DeviceSecurityMode, KeyMetadata, KeyStoreError, ResolvedKeyMaterial, SecurityEntry};

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

#[derive(Debug, Clone)]
pub struct ProgrammingOptions {
    pub addressing: AddressingMode,
    pub scan_window: Duration,
    pub restart_delay: Duration,
    /// Permit plaintext only after configured tool-key and FDSK attempts.
    pub allow_plaintext_management: bool,
}

impl Default for ProgrammingOptions {
    fn default() -> Self {
        Self {
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
    InstallingToolKey,
    Downloading,
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

        // A tool key is never first used until its authoritative source can
        // reproduce it. This ordering is what makes an interrupted key change
        // recoverable on the next invocation.
        if request.key_material.needs_tool_key_generation {
            emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::PersistingToolKey));
            self.materialize_tool_key(&mut request.key_material, generated_key_sink)?;
        }

        let product_mask = request
            .product
            .mask_version
            .ok_or_else(|| Error::ProductData("the product names no mask version".to_string()))?;
        let desired = request.configuration.identity.desired_address;

        emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::DiscoveringDevice));
        let (current, assignment_method) =
            discover_current_address(bus, product_mask, desired, request.key_material.serial_number, &request.options)
                .await?;

        // Read DD0 before an address write so compilation can fail without
        // altering the installation. Legacy masks may require a connected
        // request; `read_device_mask` retains that session for the download.
        emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::ReadingDescriptor));
        let (device_mask, mut preflight_connection) = read_device_mask(
            bus,
            current,
            product_mask.family(),
            &request.key_material,
            request.options.allow_plaintext_management,
        )
        .await?;
        let mask = select_download_mask(request.mask_db, product_mask, device_mask)?;

        emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::Compiling));
        let lowered = request.configuration.lower(request.key_material.application_security.clone())?;
        let mut product = request.product.clone();
        product.com_objects = lowered.com_objects;
        let compiled = crate::download::compile(&mask, &product, &lowered.project)?;

        // A connected session is addressed to the IA it opened on. Keep it
        // for the common no-op assignment case (notably a repeat secure
        // download, avoiding a second SyncReq inside the rate-limit window),
        // but close it before an actual move.
        if current != desired
            && let Some((connection, _)) = preflight_connection.take()
        {
            let _ = connection.close().await;
        }
        let address_assignment = match assignment_method {
            Some(method) => {
                emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::AssigningAddress));
                Some(
                    assign_address(
                        bus,
                        method,
                        current,
                        desired,
                        request.key_material.serial_number,
                        request.options.scan_window,
                    )
                    .await?,
                )
            }
            None => None,
        };
        if current != desired {
            bus.move_device_security(current, desired).await?;
        }

        emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::SelectingManagementAccess));
        let (mut connection, mut management_access) = if let Some(connection) = preflight_connection {
            connection
        } else {
            connect_management(bus, desired, &request.key_material, request.options.allow_plaintext_management).await?
        };
        if product.is_secure_enabled && management_access == ManagementAccess::Plain {
            let _ = connection.close().await;
            return Err(Error::ManagementAccessUnavailable);
        }

        if assignment_method == Some(AddressAssignmentMethod::ProgrammingButton) {
            disable_programming_mode(&mut connection, &mask).await?;
        }

        let model = DownloadModel::for_management_model(mask.management_model());
        let max_apdu = negotiate_max_apdu(&mut connection, bus.max_apdu(), request.configuration.max_apdu, model).await;

        if management_access == ManagementAccess::Fdsk {
            let tool_key = request.key_material.tool_key.ok_or(Error::GeneratedToolKeyRequiresStore)?;
            if request.key_material.fdsk != Some(tool_key) {
                emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::InstallingToolKey));
                connection.write_tool_key(tool_key).await?;
            }
            management_access = ManagementAccess::ToolKey;
        }

        emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::Downloading));
        let nested_progress = Arc::clone(&progress);
        let result = compiled
            .execute_with_progress(
                &mut connection,
                max_apdu,
                Box::new(move |event| emit(&nested_progress, ProgrammingEvent::Download(event))),
            )
            .await;
        let _ = connection.close().await;
        result?;

        emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::WaitingForRestart));
        tokio::time::sleep(request.options.restart_delay).await;

        emit(&progress, ProgrammingEvent::Stage(ProgrammingStage::Verifying));
        let (load_states, security) =
            verify_download(bus, desired, device_mask, &compiled, product.is_secure_enabled).await?;

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
) -> Result<AddressAssignmentReport> {
    if previous == desired {
        return Ok(AddressAssignmentReport { method, previous, current: previous, changed: false });
    }

    match method {
        AddressAssignmentMethod::SerialNumber => {
            let serial = serial.expect("serial addressing is selected only with a serial");
            let result =
                bus.network_management().assign_individual_address_by_serial(&serial, desired, scan_window).await?;
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
) -> Result<(MaskVersion, Option<(DeviceConnection, ManagementAccess)>)> {
    // Connectionless DD0 is optional on System 1. BCU1 still supports the
    // connected service. Some BCU2 implementations make the same choice,
    // while a commissioned secure device intentionally answers an unsecured
    // connectionless probe with FFFFh. Try the cheap form first, then retain
    // one authenticated connected session for compilation/download.
    if family != MaskFamily::Bcu1
        && let Ok(descriptor) = bus.network_management().device_descriptor_read(address, 0).await
        && descriptor.as_slice() != [0xFF, 0xFF]
    {
        return Ok((parse_device_mask(&descriptor)?, None));
    }

    let (mut connection, access) = connect_management(bus, address, keys, allow_plaintext).await?;
    let descriptor = connection.device_descriptor_read(0).await?;
    let mask = parse_device_mask(&descriptor)?;
    Ok((mask, Some((connection, access))))
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
    for (access, key) in [(ManagementAccess::ToolKey, keys.tool_key), (ManagementAccess::Fdsk, keys.fdsk)] {
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
        if let Ok(mut connection) = bus.connect_device(address).await {
            if connection.device_descriptor_read(0).await.is_ok() {
                return Ok((connection, access));
            }
            let _ = connection.close().await;
        }
    }

    if allow_plaintext {
        bus.remove_device_security(address).await?;
        if let Ok(mut connection) = bus.connect_device(address).await {
            if connection.device_descriptor_read(0).await.is_ok() {
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
    if let Some(configured) = configured {
        return configured.min(interface_max).max(15);
    }
    if let Some(model) = model
        && !model.has_properties
    {
        return model.default_max_apdu.min(interface_max).max(15);
    }
    match connection.property_read(0, pid::device::MAX_APDU_LENGTH, 1, 1).await {
        Ok(bytes) => bytes.iter().fold(0u16, |value, byte| (value << 8) | u16::from(*byte)).min(interface_max).max(15),
        Err(_) => 15.min(interface_max),
    }
}

async fn verify_download(
    bus: &KnxBus,
    address: IndividualAddress,
    expected_mask: MaskVersion,
    compiled: &CompiledDownload,
    secure_product: bool,
) -> Result<(Vec<(LsmTarget, LoadState)>, Option<SecurityVerification>)> {
    let mut connection = bus.connect_device(address).await?;
    let result = async {
        let descriptor = connection.device_descriptor_read(0).await?;
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
            let bytes = read_load_state(&mut connection, compiled.path(), target).await?;
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
        .await?;
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
    let wanted = [
        pid::security::GROUP_KEY_TABLE,
        pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE,
        pid::security::GO_SECURITY_FLAGS,
    ];
    let mut result = BTreeMap::new();
    for instruction in &compiled.instructions {
        let Instruction::WritePropertyExt {
            object_type: SECURITY_IO,
            occurrence: SECURITY_IO_OCCURRENCE,
            prop_id,
            start_idx: 0,
            count: 1,
            data,
            ..
        } = instruction
        else {
            continue;
        };
        if wanted.contains(prop_id) {
            let bytes: [u8; 2] = data.as_slice().try_into().map_err(|_| {
                Error::ProgrammingVerification("security table count is not a 16-bit value".to_string())
            })?;
            result.insert(*prop_id, u16::from_be_bytes(bytes));
        }
    }
    if wanted.iter().any(|property| !result.contains_key(property)) {
        return Err(Error::ProgrammingVerification(
            "compiled secure download does not initialize every security table".to_string(),
        ));
    }
    Ok(result)
}

async fn read_table_count(connection: &mut DeviceConnection, property: u16) -> Result<u16> {
    let bytes = connection.property_ext_read(SECURITY_IO, SECURITY_IO_OCCURRENCE, property, 0, 1).await?;
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
