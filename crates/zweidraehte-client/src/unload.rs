//! ETS-style application and complete device unload flows.

use core::time::Duration;

use crate::download::{
    DeviceImage, DownloadEvent, DownloadModel, Downloader, MaskDb, ProcedureKind, assemble, load_control_path,
    select_download_mask,
};
use crate::programming::{ManagementAccess, ProgrammingOptions, connect_management};
use crate::project::PlannedProjectDevice;
use crate::{DeviceConnection, EraseCode, Error, IndividualAddress, KnxBus, MaskFamily, MaskVersion, Result};
use zweidraehte_project::{ProjectDeviceId, ProjectEvent};

/// The two unload operations exposed by ETS.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UnloadScope {
    /// Remove the application while retaining the IA and secure-management
    /// configuration.
    #[default]
    Application,
    /// Return the complete device to factory state, including its IA and
    /// secure-management configuration.
    All,
}

impl UnloadScope {
    const fn erase_code(self) -> EraseCode {
        match self {
            Self::Application => EraseCode::FactoryResetKeepIA,
            Self::All => EraseCode::FactoryReset,
        }
    }
}

/// Timing used by an unload operation.
#[derive(Debug, Clone)]
pub struct UnloadOptions {
    pub scope: UnloadScope,
    pub scan_window: Duration,
    pub restart_delay: Duration,
}

impl Default for UnloadOptions {
    fn default() -> Self {
        let programming = ProgrammingOptions::default();

        Self {
            scope: UnloadScope::default(),
            scan_window: programming.scan_window,
            restart_delay: programming.restart_delay,
        }
    }
}

/// Coarse unload phases suitable for CLI and TUI progress displays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnloadStage {
    SelectingManagementAccess,
    ReadingDescriptor,
    UnloadingApplication,
    FactoryResettingApplication,
    FactoryResettingDevice,
    ResettingIndividualAddress,
    WaitingForRestart,
    Verifying,
}

/// Progress emitted while unloading one device.
#[derive(Debug, Clone)]
pub enum UnloadEvent {
    Stage(UnloadStage),
    Download(DownloadEvent),
}

/// Successful unload details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnloadReport {
    pub previous_address: IndividualAddress,
    pub device_mask: MaskVersion,
    pub scope: UnloadScope,
}

/// An unload error plus whether the device may already have been changed.
///
/// Once a reset or legacy unload procedure starts, a later error cannot prove
/// which parts remain. Frontends use this flag to discard optimistic project
/// status rather than showing stale green programming indicators.
#[derive(Debug, thiserror::Error)]
#[error("{source}")]
pub struct UnloadFailure {
    #[source]
    source: Error,
    device_may_have_changed: bool,
}

impl UnloadFailure {
    pub fn device_may_have_changed(&self) -> bool {
        self.device_may_have_changed
    }

    pub fn into_source(self) -> Error {
        self.source
    }
}

/// Translate a physical unload result into the durable project-state changes
/// it proves. A complete reset invalidates every downloaded SIAT that names
/// this device because the sender will receive a new security sequence base
/// when it is commissioned again.
pub fn project_unload_state_events(
    planned: &PlannedProjectDevice,
    scope: UnloadScope,
    result: &core::result::Result<UnloadReport, UnloadFailure>,
) -> Vec<ProjectEvent> {
    unload_state_events(
        &planned.id,
        &planned.siat_consumers,
        scope,
        result.is_ok(),
        result.as_ref().is_err_and(UnloadFailure::device_may_have_changed),
    )
}

fn unload_state_events(
    device: &ProjectDeviceId,
    siat_consumers: &[ProjectDeviceId],
    scope: UnloadScope,
    succeeded: bool,
    device_may_have_changed: bool,
) -> Vec<ProjectEvent> {
    let mut events = Vec::new();

    if succeeded {
        events.push(ProjectEvent::RecordUnload {
            device: device.to_string(),
            preserve_network_configuration: scope == UnloadScope::Application,
        });
    } else if device_may_have_changed {
        events.push(ProjectEvent::MarkInconsistent { devices: vec![device.to_string()] });
    } else {
        return events;
    }

    if scope == UnloadScope::All && !siat_consumers.is_empty() {
        events.push(ProjectEvent::MarkGroupCommunicationStale {
            devices: siat_consumers.iter().map(ToString::to_string).collect(),
        });
    }

    events
}

/// Unload one planned project device using its live mask and management model.
pub async fn unload_project_device<F>(
    bus: &KnxBus,
    mask_db: &MaskDb,
    planned: &PlannedProjectDevice,
    options: UnloadOptions,
    progress: &mut F,
) -> core::result::Result<UnloadReport, UnloadFailure>
where
    F: FnMut(UnloadEvent) + Send,
{
    let mut changed = false;
    let result = unload_project_device_inner(bus, mask_db, planned, &options, progress, &mut changed).await;

    result.map_err(|source| UnloadFailure { source, device_may_have_changed: changed })
}

async fn unload_project_device_inner<F>(
    bus: &KnxBus,
    mask_db: &MaskDb,
    planned: &PlannedProjectDevice,
    options: &UnloadOptions,
    progress: &mut F,
    changed: &mut bool,
) -> Result<UnloadReport>
where
    F: FnMut(UnloadEvent) + Send,
{
    let desired = planned.configuration.identity.desired_address;
    let current = locate_current_address(bus, planned, desired, options.scan_window).await?;

    emit(progress, UnloadEvent::Stage(UnloadStage::SelectingManagementAccess));
    let (mut connection, access) = connect_management(bus, current, &planned.key_material, true).await?;

    emit(progress, UnloadEvent::Stage(UnloadStage::ReadingDescriptor));
    let descriptor = connection.device_descriptor_read(0).await?;
    let [high, low] = descriptor.as_slice() else {
        let _ = connection.close().await;

        return Err(Error::ProgrammingVerification("DD0 did not return two octets".into()));
    };
    let device_mask = MaskVersion::from(u16::from_be_bytes([*high, *low]));

    if device_mask.family() == MaskFamily::Bcu1 {
        unload_legacy_device(
            bus,
            mask_db,
            planned,
            current,
            device_mask,
            access,
            options,
            progress,
            changed,
            connection,
        )
        .await?;
    } else {
        unload_modern_device(bus, planned, current, options, progress, changed, connection).await?;
    }

    Ok(UnloadReport { previous_address: current, device_mask, scope: options.scope })
}

#[allow(clippy::too_many_arguments)]
async fn unload_legacy_device<F>(
    bus: &KnxBus,
    mask_db: &MaskDb,
    planned: &PlannedProjectDevice,
    current: IndividualAddress,
    device_mask: MaskVersion,
    access: ManagementAccess,
    options: &UnloadOptions,
    progress: &mut F,
    changed: &mut bool,
    mut connection: DeviceConnection,
) -> Result<()>
where
    F: FnMut(UnloadEvent) + Send,
{
    if options.scope == UnloadScope::All && planned.key_material.serial_number().is_none() {
        let _ = connection.close().await;

        // A serial-less BCU1 can only reset its IA through a programming-mode
        // broadcast. That needs a separate physical-confirmation flow so an
        // unload cannot reset every BCU1 on a populated bus.
        return Err(Error::DeviceConfiguration(
            "the BCU1 device has no KNX serial number; refusing an unscoped individual-address reset".into(),
        ));
    }

    let product_mask =
        planned.product.mask_version().ok_or_else(|| Error::ProductData("the product names no mask version".into()))?;
    let mask = select_download_mask(mask_db, product_mask, device_mask)?;
    let instructions = assemble(&mask, &planned.product, ProcedureKind::UnloadAll)?;
    let model = DownloadModel::for_management_model(mask.management_model());
    let path = load_control_path(&mask)?;
    let max_apdu = planned.configuration.max_apdu.unwrap_or(bus.max_apdu()).min(bus.max_apdu()).max(15);

    emit(progress, UnloadEvent::Stage(UnloadStage::UnloadingApplication));
    let mut report_download = |event| emit(progress, UnloadEvent::Download(event));
    let mut downloader = Downloader::with_path(&mut connection, path, max_apdu).with_progress(&mut report_download);
    if let Some(model) = model {
        if !model.authorize_on_connect {
            downloader = downloader.without_authorize();
        }
        if model.diff_writes {
            downloader = downloader.with_diffed_writes();
        }
    }

    // The first instruction may mutate a load machine before any later
    // failure is returned, so uncertainty begins at procedure entry.
    *changed = true;
    let result = downloader.run(&instructions, &DeviceImage::new()).await;
    drop(downloader);
    result?;

    connection.close().await?;

    if options.scope == UnloadScope::All {
        reset_legacy_individual_address(bus, current, access, planned, options.scan_window, progress).await?;
    }

    Ok(())
}

async fn unload_modern_device<F>(
    bus: &KnxBus,
    planned: &PlannedProjectDevice,
    current: IndividualAddress,
    options: &UnloadOptions,
    progress: &mut F,
    changed: &mut bool,
    mut connection: DeviceConnection,
) -> Result<()>
where
    F: FnMut(UnloadEvent) + Send,
{
    let stage = match options.scope {
        UnloadScope::Application => UnloadStage::FactoryResettingApplication,
        UnloadScope::All => UnloadStage::FactoryResettingDevice,
    };
    emit(progress, UnloadEvent::Stage(stage));

    // Confirmed restart code 07h preserves IA, Security Mode and Tool Key.
    // Code 02h also resets the IA, disables Security Mode and restores FDSK
    // access, matching ETS's two unload operations.
    *changed = true;
    let restart = connection.master_reset(options.scope.erase_code(), 0).await?;
    let _ = connection.close().await;

    emit(progress, UnloadEvent::Stage(UnloadStage::WaitingForRestart));
    tokio::time::sleep(restart.process_time.max(options.restart_delay)).await;

    if options.scope == UnloadScope::All {
        finish_factory_reset(bus, current, planned, options.scan_window, progress).await?;
    }

    Ok(())
}

async fn reset_legacy_individual_address<F>(
    bus: &KnxBus,
    current: IndividualAddress,
    access: ManagementAccess,
    planned: &PlannedProjectDevice,
    scan_window: Duration,
    progress: &mut F,
) -> Result<()>
where
    F: FnMut(UnloadEvent) + Send,
{
    let serial = planned.key_material.serial_number().expect("complete BCU1 unload validates the serial first");
    let default_address = IndividualAddress::from([0xFF, 0xFF]);
    emit(progress, UnloadEvent::Stage(UnloadStage::ResettingIndividualAddress));

    // 03/05/03 §3.5.4 places this serial-addressed write after the application
    // unload. Secure profiles cannot implement the ResetIA master-reset code.
    match access {
        ManagementAccess::Plain => {
            bus.network_management().write_individual_address_by_serial(&serial, default_address).await?;
        }
        ManagementAccess::ToolKey => {
            let key = planned
                .key_material
                .tool_key()
                .copied()
                .ok_or_else(|| Error::DeviceConfiguration("Tool-Key access has no Tool Key".into()))?;
            bus.network_management()
                .write_individual_address_by_serial_secure(&serial, current, default_address, key)
                .await?;
        }
        ManagementAccess::Fdsk => {
            let key = planned
                .key_material
                .fdsk()
                .copied()
                .ok_or_else(|| Error::DeviceConfiguration("FDSK access has no FDSK".into()))?;
            bus.network_management()
                .write_individual_address_by_serial_secure(&serial, current, default_address, key)
                .await?;
        }
    }

    verify_factory_address(bus, serial, default_address, scan_window).await?;
    bus.remove_device_security(current).await?;

    Ok(())
}

async fn finish_factory_reset<F>(
    bus: &KnxBus,
    current: IndividualAddress,
    planned: &PlannedProjectDevice,
    scan_window: Duration,
    progress: &mut F,
) -> Result<()>
where
    F: FnMut(UnloadEvent) + Send,
{
    emit(progress, UnloadEvent::Stage(UnloadStage::Verifying));

    if let Some(serial) = planned.key_material.serial_number() {
        verify_factory_address(bus, serial, IndividualAddress::from([0xFF, 0xFF]), scan_window).await?;
    }

    // Security Mode is now off and the FDSK is active. Retaining the old
    // address entry would make the next connection try an obsolete Tool Key.
    bus.remove_device_security(current).await?;

    Ok(())
}

async fn verify_factory_address(
    bus: &KnxBus,
    serial: [u8; 6],
    expected: IndividualAddress,
    scan_window: Duration,
) -> Result<()> {
    let found = bus.network_management().read_individual_addresses_by_serial(&serial, scan_window).await?;
    match found.as_slice() {
        [address] if *address == expected => Ok(()),
        [address] => {
            Err(Error::ProgrammingVerification(format!("factory reset returned {address}, expected {expected}")))
        }
        [] => Err(Error::ProgrammingVerification("device did not answer after factory reset".into())),
        _ => Err(Error::DuplicateSerialNumber(found.len())),
    }
}

async fn locate_current_address(
    bus: &KnxBus,
    planned: &PlannedProjectDevice,
    desired: IndividualAddress,
    scan_window: Duration,
) -> Result<IndividualAddress> {
    let Some(serial) = planned.key_material.serial_number() else { return Ok(desired) };
    let found = bus.network_management().read_individual_addresses_by_serial(&serial, scan_window).await?;

    match found.as_slice() {
        [address] => Ok(*address),
        [] => Ok(desired),
        _ => Err(Error::DuplicateSerialNumber(found.len())),
    }
}

fn emit(progress: &mut (impl FnMut(UnloadEvent) + ?Sized), event: UnloadEvent) {
    progress(event);
}

#[cfg(test)]
mod tests {
    use super::{UnloadScope, unload_state_events};
    use crate::EraseCode;
    use zweidraehte_project::{ProjectDeviceId, ProjectEvent};

    fn successful_unload(device: &ProjectDeviceId, preserve_network_configuration: bool) -> ProjectEvent {
        let device = device.to_string();

        ProjectEvent::RecordUnload { device, preserve_network_configuration }
    }

    #[test]
    fn unload_scopes_select_the_standard_factory_reset_codes() {
        assert_eq!(UnloadScope::Application.erase_code(), EraseCode::FactoryResetKeepIA);
        assert_eq!(UnloadScope::All.erase_code(), EraseCode::FactoryReset);
    }

    #[test]
    fn complete_unload_invalidates_siat_consumers() {
        let device = ProjectDeviceId("sender".into());
        let consumer = ProjectDeviceId("consumer".into());
        let events = unload_state_events(&device, std::slice::from_ref(&consumer), UnloadScope::All, true, false);
        let unloaded = successful_unload(&device, false);
        let consumer_stale = ProjectEvent::MarkGroupCommunicationStale { devices: vec![consumer.to_string()] };

        assert_eq!(events, vec![unloaded, consumer_stale]);
    }

    #[test]
    fn application_unload_preserves_other_devices_group_state() {
        let device = ProjectDeviceId("sender".into());
        let consumer = ProjectDeviceId("consumer".into());
        let events = unload_state_events(&device, &[consumer], UnloadScope::Application, true, false);
        let unloaded = successful_unload(&device, true);

        assert_eq!(events, vec![unloaded]);
    }

    #[test]
    fn failed_complete_unload_conservatively_invalidates_consumers_after_mutation() {
        let device = ProjectDeviceId("sender".into());
        let consumer = ProjectDeviceId("consumer".into());
        let events = unload_state_events(&device, std::slice::from_ref(&consumer), UnloadScope::All, false, true);
        let inconsistent = ProjectEvent::MarkInconsistent { devices: vec![device.to_string()] };
        let consumer_stale = ProjectEvent::MarkGroupCommunicationStale { devices: vec![consumer.to_string()] };

        assert_eq!(events, vec![inconsistent, consumer_stale]);
        assert!(unload_state_events(&device, &[consumer], UnloadScope::All, false, false).is_empty());
    }
}
