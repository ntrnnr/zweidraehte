//! Management access depends on identity and credentials, not desired images.

use super::inputs::{CatalogAcquisition, ProductInputs, ProjectResourceCache};
use super::keys::resolve_management_keys;
use super::revision::FileRevision;
use super::{
    ProjectCommissioningSession, ProjectFinalizationFailure, ProjectOperation, ProjectSetupRequirement,
    SerialAddressingSupport,
};
use crate::bus::access::{ManagementCredential, ManagementCredentials};
use crate::configuration::ResolvedKeyMaterial;
use crate::project::error::{Error, Result};
use crate::security::Keyring;
use crate::security::channel::seq_from_bytes;
use crate::{BusError, DeviceConnection, IndividualAddress, InterfaceObjectType, KnxBus};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;
use zweidraehte_project::{
    AuthoredProject, KeyMaterialSource, ProjectDevice, ProjectDeviceId, ProjectStore, SenderIdentity, format_serial,
};
use zweidraehte_proto::pid;

/// A management target resolved without evaluating parameters, object links,
/// group keys or desired IP security. Credential conflicts remain errors.
#[derive(Debug, Clone)]
pub struct ProjectManagementTarget {
    id: ProjectDeviceId,
    address: IndividualAddress,
    serial_addressing: SerialAddressingSupport,
    keys: ResolvedKeyMaterial,
}

impl ProjectManagementTarget {
    pub fn resolve(
        device: &ProjectDevice,
        keys: &dyn KeyMaterialSource,
        keyring: Option<&Keyring>,
        serial_addressing: SerialAddressingSupport,
    ) -> Result<Self> {
        let (keys, _) = resolve_management_keys(device.serial, device.address, &device.id.0, keys, keyring)?;
        Ok(Self { id: device.id.clone(), address: device.address, serial_addressing, keys })
    }

    pub fn id(&self) -> &ProjectDeviceId {
        &self.id
    }
    pub fn address(&self) -> IndividualAddress {
        self.address
    }
    pub fn serial_number(&self) -> Option<[u8; 6]> {
        self.keys.serial_number()
    }
    pub fn credentials(&self) -> ManagementCredentials<'_> {
        self.keys.management_credentials()
    }
    pub fn has_credentials(&self) -> bool {
        self.keys.tool_key().is_some() || self.keys.fdsk().is_some()
    }

    /// Locate a supported serial, preserving the known address when no device
    /// answers. Duplicate answers are ambiguous and never select a device.
    pub async fn locate(&self, bus: &KnxBus) -> Result<IndividualAddress> {
        let Some(serial) = self.serial_addressing.serial_target(self.serial_number()) else {
            return Ok(self.address);
        };
        let found =
            bus.network_management().read_individual_addresses_by_serial(&serial, Duration::from_secs(2)).await?;
        match found.as_slice() {
            [address] => Ok(*address),
            [] => Ok(self.address),
            _ => Err(BusError::DuplicateSerialNumber(found.len()).into()),
        }
    }
}

/// Recovery completes only after all managed secure receivers are observed,
/// unless the caller supplies an explicit client sequence floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectSynchronization {
    Synchronize,
    Recover { client_floor: Option<u64> },
}

#[derive(Debug, Default)]
pub struct ProjectSynchronizationReport {
    pub devices: Vec<ProjectDeviceSynchronization>,
}

/// Observations survive failures later in the device or project operation.
#[derive(Debug)]
pub struct ProjectDeviceSynchronization {
    pub device: ProjectDeviceId,
    pub complete: bool,
    pub address: Option<IndividualAddress>,
    pub access: Option<ManagementCredential>,
    pub outgoing_next: Option<u64>,
    pub siat_rows: u16,
    pub unavailable: Option<Error>,
}

#[derive(Debug)]
pub struct ProjectMemoryReadout {
    pub address: u16,
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct ProjectMemoryReadReport {
    pub device: ProjectDeviceId,
    pub address: Option<IndividualAddress>,
    pub access: Option<ManagementCredential>,
    pub target_max_apdu: Option<u16>,
    pub segments: Vec<ProjectMemoryReadout>,
}

/// The primary error, partial observations and all cleanup errors remain
/// inspectable independently. No application programming report is fabricated.
#[derive(Debug, thiserror::Error)]
#[error("project management failed: {}", management_failure_message(.source, .finalization))]
pub struct ProjectManagementFailure<T: std::fmt::Debug> {
    pub report: T,
    #[source]
    pub source: Option<Error>,
    pub finalization: Vec<ProjectFinalizationFailure>,
}

pub type ProjectManagementResult<T> = std::result::Result<T, ProjectManagementFailure<T>>;

impl ProjectOperation {
    /// Synchronize every active managed secure receiver. The session must be
    /// opened with `begin_recovery` for `Recover`. Static products supply only
    /// addressing evidence; desired application edits are not evaluated.
    pub async fn synchronize(
        self,
        keyring: Option<&Keyring>,
        master_data: Option<&Path>,
        mode: ProjectSynchronization,
    ) -> ProjectManagementResult<ProjectSynchronizationReport> {
        let mut report = ProjectSynchronizationReport::default();
        let result = async {
            let (project, _, targets) = management_inputs(self.session(), None, keyring, master_data)?;
            self.synchronize_targets(&project, &targets, mode, &mut report).await
        }
        .await;
        self.finish_management(report, result, matches!(mode, ProjectSynchronization::Recover { .. })).await
    }

    async fn synchronize_targets(
        &self,
        project: &AuthoredProject,
        targets: &[ProjectManagementTarget],
        mode: ProjectSynchronization,
        report: &mut ProjectSynchronizationReport,
    ) -> Result<()> {
        if let ProjectSynchronization::Recover { client_floor: Some(floor) } = mode {
            self.session().advance_client_sequence(floor)?;
        }
        for target in targets {
            report.devices.push(ProjectDeviceSynchronization {
                device: target.id.clone(),
                complete: false,
                address: None,
                access: None,
                outgoing_next: None,
                siat_rows: 0,
                unavailable: None,
            });
            let observed = report.devices.last_mut().expect("device report just inserted");
            let connection = async {
                if !target.has_credentials() {
                    return Err(ProjectSetupRequirement::ManagementCredential { device: target.id.clone() }.into());
                }
                let address = target.locate(self.bus()).await?;
                observed.address = Some(address);
                let (connection, access) =
                    self.bus().connect_management_synchronized(address, target.credentials(), false).await?;
                observed.access = Some(access);
                Ok::<_, Error>(connection)
            }
            .await;
            let mut connection = match connection {
                Ok(connection) => connection,
                Err(
                    error @ (Error::ProjectSetup(_) | Error::Bus(BusError::DuplicateSerialNumber(_) | BusError::Io(_))),
                ) => return Err(error),
                Err(error) => {
                    observed.unavailable = Some(error);
                    continue;
                }
            };
            let result = if matches!(mode, ProjectSynchronization::Recover { .. }) {
                recover_device_state(
                    self.session(),
                    project,
                    target,
                    &mut connection,
                    self.bus().assigned_address(),
                    observed,
                )
                .await
            } else {
                Ok(())
            };
            // Closing the device connection is separate from closing the bus.
            // Preserve both errors if observation/persistence and close fail.
            finish_connection(result, connection.close().await)?;
            observed.complete = true;
        }
        let unavailable = report
            .devices
            .iter()
            .filter(|device| device.unavailable.is_some())
            .map(|device| device.device.clone())
            .collect::<Vec<_>>();
        if !unavailable.is_empty() && mode == (ProjectSynchronization::Recover { client_floor: None }) {
            return Err(Error::RecoveryIncomplete { unavailable });
        }
        Ok(())
    }

    /// Inspect a product's absolute memory segments without compiling its
    /// desired configuration. The caller owns blob naming and file output.
    pub async fn read_device_memory(
        self,
        device: &ProjectDeviceId,
        keyring: Option<&Keyring>,
        master_data: Option<&Path>,
        allow_plaintext: bool,
    ) -> ProjectManagementResult<ProjectMemoryReadReport> {
        let mut report = ProjectMemoryReadReport {
            device: device.clone(),
            address: None,
            access: None,
            target_max_apdu: None,
            segments: Vec::new(),
        };
        let result = async {
            let (_, resources, targets) = management_inputs(self.session(), Some(device), keyring, master_data)?;
            let target = targets.first().expect("selected target resolved");
            let ranges = resources.products[device]
                .product()
                .segments()
                .iter()
                .filter_map(|segment| segment.address.map(|address| (address, segment.size)))
                .map(|(address, size)| {
                    let start = u16::try_from(address).map_err(|_| {
                        Error::DeviceConfiguration("diagnostic segment address exceeds classic memory".into())
                    })?;
                    if u64::from(address) + u64::from(size) > 0x1_0000 {
                        return Err(Error::DeviceConfiguration("diagnostic segment exceeds classic memory".into()));
                    }
                    Ok((start, size as usize))
                })
                .collect::<Result<Vec<_>>>()?;
            if ranges.is_empty() {
                return Err(Error::DeviceConfiguration("product has no absolute memory segments to read".into()));
            }
            let address = target.locate(self.bus()).await?;
            report.address = Some(address);
            let (mut connection, access) =
                self.bus().connect_management(address, target.credentials(), allow_plaintext).await?;
            report.access = Some(access);
            let target_max = connection.read_max_apdu(self.bus().max_apdu()).await;
            report.target_max_apdu = Some(target_max);
            let result = async {
                for (address, length) in ranges {
                    let bytes =
                        connection.read_memory_range(address, length, self.bus().max_apdu(), target_max).await?;
                    report.segments.push(ProjectMemoryReadout { address, bytes });
                }
                Ok(())
            }
            .await;
            finish_connection(result, connection.close().await)
        }
        .await;
        self.finish_management(report, result, false).await
    }

    async fn finish_management<T: std::fmt::Debug>(
        self,
        report: T,
        result: Result<()>,
        recovery: bool,
    ) -> ProjectManagementResult<T> {
        let finalization = self.close(recovery && result.is_ok()).await;
        if result.is_ok() && finalization.is_empty() {
            return Ok(report);
        }
        Err(ProjectManagementFailure { report, source: result.err(), finalization })
    }
}

/// Keep static resource selection shared with programming/status, but stop at
/// product metadata. Evaluating the desired application here would make broken
/// edits prevent the management operation needed to diagnose them.
fn management_inputs(
    session: &ProjectCommissioningSession,
    selected: Option<&ProjectDeviceId>,
    keyring: Option<&Keyring>,
    master_data: Option<&Path>,
) -> Result<(AuthoredProject, ProductInputs, Vec<ProjectManagementTarget>)> {
    session.inspect(|store| {
        let project = store.authored();
        let scope: BTreeSet<_> = match selected {
            Some(id) => [id.clone()].into(),
            None => project.devices.values().filter(|device| device.active).map(|device| device.id.clone()).collect(),
        };
        let mut files = FileRevision::capture(ProjectStore::input_files(store.project_path()))?;
        let keys = store.keys().ok_or(zweidraehte_project::ProjectStoreError::NotInitialized)?;
        let mut targets = scope
            .iter()
            .map(|id| {
                let device = project
                    .devices
                    .get(id)
                    .ok_or_else(|| Error::DeviceConfiguration(format!("project has no device `{id}`")))?;
                ProjectManagementTarget::resolve(device, keys, keyring, SerialAddressingSupport::Unknown)
            })
            .collect::<Result<Vec<_>>>()?;
        // Synchronization concerns secure receivers. An unrelated plain
        // device's product must not block recovery of those receivers.
        if selected.is_none() {
            targets.retain(|target| target.has_credentials() || project.devices[target.id()].data_secure.is_enabled());
        }
        let scope = targets.iter().map(|target| target.id.clone()).collect();
        let resources = ProjectResourceCache::default().load(
            project,
            &scope,
            master_data,
            CatalogAcquisition::SuppliedOnly,
            &mut files,
            |_, _, _| {},
        )?;
        for target in &mut targets {
            let product = resources.products[&target.id].product();
            // Missing programming metadata is not a reason to withhold
            // management access. Unknown support uses the known address.
            target.serial_addressing = match resources.master_data.for_product(product) {
                Ok(catalog) => SerialAddressingSupport::for_product(product, &catalog),
                Err(Error::MissingCatalog { .. }) => SerialAddressingSupport::Unknown,
                Err(error) => return Err(error),
            };
        }
        files.verify(|| Error::OperationInputsChanged)?;
        Ok((project.clone(), resources, targets))
    })?
}

async fn recover_device_state(
    session: &ProjectCommissioningSession,
    project: &AuthoredProject,
    target: &ProjectManagementTarget,
    connection: &mut DeviceConnection,
    client_address: IndividualAddress,
    observed: &mut ProjectDeviceSynchronization,
) -> Result<()> {
    let serial =
        target.serial_number().ok_or_else(|| ProjectSetupRequirement::DeviceSerial { device: target.id.clone() })?;
    let serial = format_serial(&serial);
    let bytes = connection
        .property_ext_read(InterfaceObjectType::Security, 1, pid::security::SEQUENCE_NUMBER_SENDING, 1, 1)
        .await?;
    let next = decode_u48(&bytes)?;
    observed.outgoing_next = Some(next);
    session.observe_device_outgoing(serial.clone(), next)?;
    let count = connection
        .property_ext_read(InterfaceObjectType::Security, 1, pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE, 0, 1)
        .await?;
    let count = u16::from_be_bytes(count.try_into().map_err(|_| BusError::Parse("SIAT count is not two octets"))?);
    for index in 1..=count {
        let row = connection
            .property_ext_read(
                InterfaceObjectType::Security,
                1,
                pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE,
                index,
                1,
            )
            .await?;
        if row.len() != 8 {
            return Err(BusError::Parse("SIAT row is not eight octets").into());
        }
        let address = IndividualAddress::from_bytes(&row[..2]);
        let last_valid = decode_u48(&row[2..])?;
        if address == client_address {
            session.advance_client_sequence(last_valid + 1)?;
        }
        let sender = project
            .devices
            .values()
            .find(|device| device.address == address)
            .and_then(|device| device.serial)
            .map(|serial| SenderIdentity::ManagedSerial(format_serial(&serial)))
            .unwrap_or_else(|| SenderIdentity::UnmanagedAddress(address.to_string()));
        session.observe_device_siat(serial.clone(), sender, last_valid)?;
        observed.siat_rows += 1;
    }
    Ok(())
}

fn decode_u48(bytes: &[u8]) -> Result<u64> {
    let bytes: [u8; 6] = bytes.try_into().map_err(|_| BusError::Parse("expected a six-octet sequence number"))?;
    Ok(seq_from_bytes(&bytes))
}

fn finish_connection(result: Result<()>, close: crate::BusResult<()>) -> Result<()> {
    match (result, close.map_err(Error::from)) {
        (Err(source), Err(cleanup)) => {
            Err(Error::ManagementCleanup { source: Box::new(source), cleanup: Box::new(cleanup) })
        }
        (Err(error), _) | (_, Err(error)) => Err(error),
        _ => Ok(()),
    }
}

fn management_failure_message(source: &Option<Error>, finalization: &[ProjectFinalizationFailure]) -> String {
    source
        .iter()
        .map(ToString::to_string)
        .chain(finalization.iter().map(ToString::to_string))
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests;
