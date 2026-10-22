//! Persist execution evidence and reconstruct verified deployment history.

use crate::commissioning::AssociationTableEntrySize;
use crate::commissioning::input::security::{DesiredDataSecurity, ObservedDataSecurity};
use crate::commissioning::{
    CommissioningIntent, CommissioningSectionOutcome, DeploymentRecord, DeviceStamp, DifferentialPolicy, DownloadMode,
    ExecutionReport, ImageLocation, ImageSegment, ImageSpace, ProfileVariant, SparseDeviceImage, UnloadMode,
};
use crate::project::error::{Error, Result};
use crate::security::{Keyring, KeyringDevice};
use std::collections::{BTreeMap, BTreeSet};
use zweidraehte_ets_files::keyring::KeyringBackbone;
use zweidraehte_project::{
    AuthoredProject, COMMISSIONING_DEPLOYMENT_RECORD_VERSION, CommissioningAssociationEntrySize,
    CommissioningDeploymentRecord as ProjectCommissioningDeploymentRecord,
    CommissioningImageSegment as ProjectCommissioningImageSegment, CommissioningOutcome,
    CommissioningProfileVariant as ProjectProfileVariant, CredentialCommitment, DomainAddress, KeyId, KeyKind,
    KeyMaterialSource, KeyScope, KeyStoreError, MutableProjectState, ObservedPropertyType, ProgrammingManifest,
    ProgrammingSection, ProjectEvent, SenderIdentity, format_serial,
};
use zweidraehte_proto::address::GroupAddress;

use super::session::LockedProjectStore;
use super::{PlannedProjectDevice, credential_commitments, set_credential_commitments};
use crate::configuration::ErrorDetail;
/// Header of an exported ETS keyring.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeyringExport {
    pub project_name: String,
    /// The exporting tool and its version.
    pub created_by: String,
    /// Written with whole-second precision. The keyring derives its
    /// encryption IV from this text, so the format is fixed here.
    pub created: time::OffsetDateTime,
}

impl KeyringExport {
    pub fn new(project_name: impl Into<String>, created_by: impl Into<String>, created: time::OffsetDateTime) -> Self {
        Self { project_name: project_name.into(), created_by: created_by.into(), created }
    }
}

/// Build the ETS keyring representation of a project's active security
/// material and forward-only device sequence observations.
///
/// Historical group-key epochs and the commissioning client's own sending
/// counter cannot be represented by the `.knxkeys` schema. The active epoch
/// for every logical net is exported; `client_next` remains authoritative in
/// the project state.
pub fn build_project_keyring(
    project: &AuthoredProject,
    state: &MutableProjectState,
    keys: &dyn KeyMaterialSource,
    export: KeyringExport,
) -> Result<Keyring> {
    let KeyringExport { project_name, created_by, created } = export;
    let created = created
        .replace_nanosecond(0)
        .expect("zero nanoseconds are always in range")
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| {
            Error::KeyringExport(ErrorDetail::new(format!("keyring creation time is not RFC 3339: {error}")))
        })?;

    // A live SIAT read may be newer than the direct observation of its
    // sender. ETS has one sequence value per device, so export the greatest
    // last-valid value learned through any project-state path.
    let mut sender_last_valid = state.sender_floors.clone();
    for (serial, observation) in &state.devices {
        let identity = SenderIdentity::ManagedSerial(serial.clone());
        let direct = observation.outgoing_next.saturating_sub(1);
        sender_last_valid.entry(identity).and_modify(|old| *old = (*old).max(direct)).or_insert(direct);
        for (sender, &last_valid) in &observation.siat_last_valid {
            sender_last_valid
                .entry(sender.clone())
                .and_modify(|old| *old = (*old).max(last_valid))
                .or_insert(last_valid);
        }
    }

    let mut group_keys = BTreeMap::new();
    for net in project.nets.values() {
        let id = KeyId { scope: KeyScope::Group(net.id.0.clone()), kind: KeyKind::GroupKey };
        let Some(record) = keys.read(&id, None)? else { continue };
        let address = u16::from_be_bytes(net.address.0);
        let key = record.value.key16().map_err(KeyStoreError::from)?;
        if let Some(previous) = group_keys.insert(address, key)
            && previous != key
        {
            return Err(Error::KeyringExport(ErrorDetail::new(format!(
                "multiple project nets assign different keys to group address {}",
                net.address
            ))));
        }
    }

    let backbone_record = keys.read(&KeyId { scope: KeyScope::IpBackbone, kind: KeyKind::BackboneKey }, None)?;
    let backbone = backbone_record
        .map(|record| {
            let key = record.value.key16().map_err(KeyStoreError::from)?;
            let authored: BTreeSet<_> = project
                .topology_lines()
                .filter_map(|line| {
                    let DomainAddress::Ip(address) = line.domain? else { return None };
                    let multicast_address =
                        Some(format!("{}.{}.{}.{}", address[0], address[1], address[2], address[3]));
                    let latency_ms =
                        line.ip.and_then(|configuration| configuration.multicast_latency_tolerance_ms).map(u32::from);
                    Some((multicast_address, latency_ms))
                })
                .collect();
            let (multicast_address, latency_ms) = match authored.len() {
                0 => (None, None),
                1 => authored.into_iter().next().expect("one authored IP backbone exists"),
                _ => {
                    return Err(Error::KeyringExport(ErrorDetail::new(
                        "the ETS keyring format cannot represent multiple authored KNX/IP backbones",
                    )));
                }
            };
            Ok(KeyringBackbone::new(multicast_address, latency_ms).with_key(Some(key)))
        })
        .transpose()?;

    let mut devices = Vec::new();
    let mut occupied_addresses = BTreeSet::new();
    for device in project.devices.values().filter(|device| device.active) {
        let scope = KeyScope::Device(device.id.to_string());
        let fdsk = keys.read(&KeyId { scope: scope.clone(), kind: KeyKind::Fdsk }, None)?;
        let tool_key = keys.read(&KeyId { scope, kind: KeyKind::ToolKey }, None)?;
        let mut serial = device.serial;
        if let Some(embedded) = fdsk.as_ref().and_then(|record| record.embedded_serial) {
            if serial.is_some_and(|configured| configured != embedded) {
                return Err(Error::KeyringExport(ErrorDetail::new(format!(
                    "device `{}` serial disagrees with its FDSK certificate",
                    device.id
                ))));
            }
            serial = serial.or(Some(embedded));
        }
        let sequence_number = serial
            .as_ref()
            .and_then(|serial| sender_last_valid.get(&SenderIdentity::ManagedSerial(format_serial(serial))))
            .copied()
            .unwrap_or(0);
        let fdsk = fdsk.map(|record| record.value.key16()).transpose().map_err(KeyStoreError::from)?;
        let tool_key = tool_key.map(|record| record.value.key16()).transpose().map_err(KeyStoreError::from)?;

        // Plain, unobserved devices with no credentials add no information to
        // a security keyring. Data-Secure devices stay visible even while
        // incompletely provisioned so the export exposes that condition.
        if fdsk.is_none() && tool_key.is_none() && sequence_number == 0 && !device.data_secure.is_enabled() {
            continue;
        }
        if !occupied_addresses.insert(device.address) {
            return Err(Error::KeyringExport(ErrorDetail::new(format!(
                "multiple keyring devices use individual address {}",
                device.address
            ))));
        }
        // The IP records in keys.toml are already one-way DAC/password
        // derivations. `.knxkeys` stores the originating plaintext strings,
        // so they cannot be reconstructed and are intentionally not exported
        // as device or tunnelling-interface password fields.
        devices.push(
            KeyringDevice::new(device.address)
                .with_tool_key(tool_key)
                .with_fdsk(fdsk)
                .with_serial(serial)
                .with_sequence_number(sequence_number),
        );
    }

    // Unmanaged secure senders have no project key slot, but their observed
    // last-valid number is useful to a later import and to SIAT derivation.
    for sender in project.external_senders.values() {
        let identity = SenderIdentity::UnmanagedAddress(sender.address.to_string());
        let sequence_number = sender_last_valid.get(&identity).copied().unwrap_or(0);
        if sequence_number == 0 {
            continue;
        }
        if !occupied_addresses.insert(sender.address) {
            return Err(Error::KeyringExport(ErrorDetail::new(format!(
                "managed and external keyring devices share individual address {}",
                sender.address
            ))));
        }
        devices.push(KeyringDevice::new(sender.address).with_sequence_number(sequence_number));
    }
    devices.sort_by_key(|device| u16::from_be_bytes(device.individual_address.0));

    Ok(Keyring::new(project_name, created_by, created)
        .with_backbone(backbone)
        .with_group_keys(group_keys)
        .with_devices(devices))
}

fn commissioning_downloaded_application(report: &ExecutionReport) -> bool {
    report.sections.iter().any(|(section, outcome)| {
        *section != ProgrammingSection::Address && *outcome == CommissioningSectionOutcome::Programmed
    })
}

pub(super) fn intent_with_baseline(
    intent: CommissioningIntent,
    differential: DifferentialPolicy,
    baseline: bool,
) -> Result<CommissioningIntent> {
    if baseline {
        return Ok(intent);
    }
    let Some(mode) = intent.download_mode() else { return Ok(intent) };
    if matches!(mode, DownloadMode::Partial(_)) || differential == DifferentialPolicy::RequireVerified {
        return Err(Error::StateEvidence(ErrorDetail::new(
            "partial and verified differential downloads require a current full-download baseline",
        )));
    }
    // All section bits do not mean Full: native load controls distinguish the
    // intent itself, so a baseline reset must select the actual full procedure.
    Ok(match intent {
        CommissioningIntent::Download(_) => CommissioningIntent::Download(DownloadMode::Full),
        CommissioningIntent::AssignAddressAndDownload(_) => {
            CommissioningIntent::AssignAddressAndDownload(DownloadMode::Full)
        }
        _ => intent,
    })
}

pub(super) fn commissioning_deployment_from_project(
    record: &ProjectCommissioningDeploymentRecord,
) -> core::result::Result<DeploymentRecord, String> {
    if record.version != COMMISSIONING_DEPLOYMENT_RECORD_VERSION {
        return Err(format!(
            "unsupported deployment evidence version {} (expected {})",
            record.version, COMMISSIONING_DEPLOYMENT_RECORD_VERSION
        ));
    }
    if record.mask.full_id.is_empty() {
        return Err("deployment mask ID is empty".into());
    }

    let image = sparse_image_from_project(&record.image_segments)?;
    let actual_fingerprint = crate::commissioning::image::fingerprint_image(&image);
    if actual_fingerprint != record.image_fingerprint {
        return Err("persisted image does not match its fingerprint".into());
    }

    let source_index = usize::try_from(record.variant.source_index)
        .map_err(|_| "deployment variant source index does not fit this host".to_string())?;
    validate_device_stamps(&record.device_stamps)?;

    Ok(DeploymentRecord {
        mask: record.mask.clone(),
        variant: ProfileVariant {
            source_index,
            legacy_version: record.variant.legacy_version,
            ets3_system_plugin: record.variant.ets3_system_plugin.clone(),
        },
        master_data_fingerprint: record.master_data_fingerprint,
        product_fingerprint: record.product_fingerprint,
        image_fingerprint: record.image_fingerprint,
        image,
        device_stamps: record.device_stamps.clone(),
    })
}

pub(crate) fn project_deployment_from_report(
    report: &ExecutionReport,
) -> core::result::Result<Option<ProjectCommissioningDeploymentRecord>, String> {
    if report.plan.program_sections().is_none() {
        return Ok(None);
    }

    // The session has already tracked fills, compound transfers, ignored
    // failures and restart effects. Borrow its confirmed public image; the
    // loaded/caller-supplied baseline is validated separately at its boundary.
    let profile = report.plan.profile();
    let variant = profile.variant();
    let source_index = u32::try_from(variant.source_index)
        .map_err(|_| "deployment variant source index exceeds the project format".to_string())?;
    validate_device_stamps(&report.device_stamps)?;
    let data_security_enabled = match report.plan.desired_data_security() {
        DesiredDataSecurity::Enabled => Some(true),
        DesiredDataSecurity::Disabled => Some(false),
        DesiredDataSecurity::Preserve => match report.plan.observed_data_security() {
            ObservedDataSecurity::Enabled => Some(true),
            ObservedDataSecurity::Disabled => Some(false),
            ObservedDataSecurity::Unknown => None,
        },
    };
    Ok(Some(ProjectCommissioningDeploymentRecord {
        version: COMMISSIONING_DEPLOYMENT_RECORD_VERSION,
        mask: profile.mask().clone(),
        variant: ProjectProfileVariant {
            source_index,
            legacy_version: variant.legacy_version,
            ets3_system_plugin: variant.ets3_system_plugin.clone(),
        },
        master_data_fingerprint: profile.master_data_fingerprint(),
        product_fingerprint: report.plan.product_fingerprint(),
        image_fingerprint: crate::commissioning::image::fingerprint_image(&report.programmed_image),
        image_segments: project_image_segments(&report.programmed_image),
        device_stamps: report.device_stamps.clone(),
        association_table_entry_size: profile.association_entry_size.map(|size| match size {
            AssociationTableEntrySize::TwoBytes => CommissioningAssociationEntrySize::TwoBytes,
            AssociationTableEntrySize::FourBytes => CommissioningAssociationEntrySize::FourBytes,
        }),
        observed_property_types: profile
            .observed_property_types
            .iter()
            .map(|((object, property_id), pdt)| ObservedPropertyType {
                object: object.clone(),
                property_id: *property_id,
                pdt: *pdt,
            })
            .collect(),
        data_security_enabled,
    }))
}

fn sparse_image_from_project(
    segments: &[ProjectCommissioningImageSegment],
) -> core::result::Result<SparseDeviceImage, String> {
    let mut image = SparseDeviceImage::new();

    for stored in segments {
        if matches!(&stored.space, ImageSpace::Pointer { resource_id } if resource_id.0.is_empty()) {
            return Err("persisted pointer resource ID is empty".into());
        }
        let location = ImageLocation { space: stored.space.clone(), offset: stored.offset };
        let segment = ImageSegment::new(location, stored.data.clone(), stored.mask.clone())
            .map_err(|error| format!("invalid persisted image segment: {error}"))?;

        image.apply(&segment);
    }

    // Applying overlapping ranges, zero masks, or out-of-mask data would
    // otherwise normalize corrupted input silently. Only the exact canonical
    // representation emitted by this client is eligible for differential use.
    if project_image_segments(&image) != segments {
        return Err("persisted sparse image is not canonical".into());
    }

    Ok(image)
}

fn project_image_segments(image: &SparseDeviceImage) -> Vec<ProjectCommissioningImageSegment> {
    image
        .segments()
        .into_iter()
        .map(|segment| ProjectCommissioningImageSegment {
            space: segment.location().space.clone(),
            offset: segment.location().offset,
            data: segment.data().to_vec(),
            mask: segment.mask().to_vec(),
        })
        .collect()
}

fn validate_device_stamps(stamps: &[DeviceStamp]) -> core::result::Result<(), String> {
    let mut resources = BTreeSet::new();

    for stamp in stamps {
        if stamp.resource.0.is_empty() {
            return Err("device-stamp resource ID is empty".into());
        }
        if !resources.insert(stamp.resource.0.as_str()) {
            return Err(format!("device stamp `{}` is duplicated", stamp.resource));
        }
    }

    Ok(())
}

pub(super) fn programming_invalidation_event(
    device: &str,
    sections: BTreeSet<ProgrammingSection>,
    exposed_group_keys: Vec<CredentialCommitment>,
) -> Option<ProjectEvent> {
    (!sections.is_empty() || !exposed_group_keys.is_empty()).then(|| ProjectEvent::RecordCommissioningOutcome {
        device: device.to_owned(),
        outcome: CommissioningOutcome::Indeterminate { sections: sections.into_iter().collect(), exposed_group_keys },
    })
}

pub(super) fn record_programming_failure(
    shared: &LockedProjectStore,
    planned: &PlannedProjectDevice,
    mut sections: BTreeSet<ProgrammingSection>,
    source: &crate::commissioning::CommissioningError,
) -> Vec<Error> {
    let address = source.effects().address_assignment().filter(|assignment| {
        assignment.current == planned.device.individual_address()
            && !source.effects().cleared_sections().contains(&ProgrammingSection::Address)
    });
    if address.is_some() {
        sections.remove(&ProgrammingSection::Address);
    }
    let exposures = group_key_exposure_manifest(
        &credential_commitments(planned.device.key_material()),
        &planned.net_ids,
        source.effects().group_key_exposures(),
    )
    .map(|manifest| manifest.credentials);
    let (proofs, evidence_error) = match exposures {
        Ok(proofs) => (proofs, None),
        Err(error) => (Vec::new(), Some(error)),
    };
    let recovery = programming_invalidation_event(planned.id.as_str(), sections, proofs);
    let mut state_errors: Vec<_> =
        evidence_error.into_iter().chain(record_recovery_event(shared, recovery.as_ref())).collect();
    if address.is_some() {
        let event = ProjectEvent::RecordCommissioningOutcome {
            device: planned.id.to_string(),
            outcome: CommissioningOutcome::Programmed {
                established: planned.desired_manifest.retain_sections([ProgrammingSection::Address]),
                commissioning: None,
                fully_verified: false,
            },
        };
        state_errors.extend(record_recovery_event(shared, Some(&event)));
    }
    state_errors
}

fn record_recovery_event(shared: &LockedProjectStore, recovery: Option<&ProjectEvent>) -> Option<Error> {
    let recovery = recovery?.clone();
    shared
        .lock()
        .map_err(|_| Error::ProjectStorePoisoned)
        .and_then(|mut store| store.record(recovery).map_err(Error::from))
        .err()
}

#[derive(Debug)]
pub(super) struct PostExecutionPersistenceFailure {
    pub(super) source: Error,
    pub(super) state_errors: Vec<Error>,
}

/// Persist one logically related group of post-execution events without
/// pretending that the journal has transactions. Each event keeps the
/// existing append/fsync/apply boundary. If any event fails, the remaining
/// success events are abandoned and the physically established sections are
/// invalidated while the same project-store guard is still held.
fn persist_post_execution_events(
    shared: &LockedProjectStore,
    events: Result<Vec<ProjectEvent>>,
    recovery: Option<ProjectEvent>,
) -> core::result::Result<(), PostExecutionPersistenceFailure> {
    let mut store = match shared.lock() {
        Ok(store) => store,
        Err(poisoned) => {
            // PoisonError retains the acquired mutex guard. Release it before
            // attempting the recovery journal, which takes the same lock.
            drop(poisoned);
            let source = Error::ProjectStorePoisoned;
            let state_errors = record_recovery_event(shared, recovery.as_ref()).into_iter().collect();
            return Err(PostExecutionPersistenceFailure { source, state_errors });
        }
    };

    persist_post_execution_events_with(events, recovery, |event| store.record(event).map_err(Error::from))
}

pub(super) fn persist_post_execution_events_with<F>(
    events: Result<Vec<ProjectEvent>>,
    recovery: Option<ProjectEvent>,
    mut record: F,
) -> core::result::Result<(), PostExecutionPersistenceFailure>
where
    F: FnMut(ProjectEvent) -> Result<()>,
{
    let source = match events {
        Ok(events) => {
            let mut failure = None;
            for event in events {
                if let Err(error) = record(event) {
                    failure = Some(error);
                    break;
                }
            }

            let Some(source) = failure else { return Ok(()) };
            source
        }
        Err(source) => source,
    };
    let state_errors = recovery.and_then(|event| record(event).err()).into_iter().collect();

    Err(PostExecutionPersistenceFailure { source, state_errors })
}

pub(super) fn record_success(
    shared: &LockedProjectStore,
    planned: &PlannedProjectDevice,
    report: &ExecutionReport,
    confirmed_mutations: &BTreeSet<ProgrammingSection>,
) -> core::result::Result<(), PostExecutionPersistenceFailure> {
    let credentials = ExecutionCredentials::from_report(planned, report);
    let mut recovery_sections: BTreeSet<_> = report.sections.keys().copied().collect();
    // Address and configuration have independent physical operations. A
    // semantically broad procedure may advertise them without reaching the
    // corresponding mutation before persistence fails.
    recovery_sections.remove(&ProgrammingSection::Address);
    recovery_sections.remove(&ProgrammingSection::Configuration);
    recovery_sections.extend(confirmed_mutations);
    let recovery = programming_invalidation_event(
        planned.id.as_str(),
        recovery_sections,
        credentials.as_ref().map(|evidence| evidence.exposed.clone()).unwrap_or_default(),
    );
    let events = credentials.and_then(|credentials| success_events(planned, report, credentials));
    persist_post_execution_events(shared, events, recovery)
}

/// Proofs are hashed once, then shared by success and journal-failure recovery.
pub(super) struct ExecutionCredentials {
    all: Vec<CredentialCommitment>,
    exposed: Vec<CredentialCommitment>,
}

impl ExecutionCredentials {
    pub(super) fn from_report(planned: &PlannedProjectDevice, report: &ExecutionReport) -> Result<Self> {
        let all = credential_commitments(planned.device.key_material());
        let exposed =
            group_key_exposure_manifest(&all, &planned.net_ids, report.effects().group_key_exposures())?.credentials;
        Ok(Self { all, exposed })
    }
}

pub(super) fn success_events(
    planned: &PlannedProjectDevice,
    report: &ExecutionReport,
    credentials: ExecutionCredentials,
) -> Result<Vec<ProjectEvent>> {
    let ExecutionCredentials { all, exposed: exposed_group_keys } = credentials;
    if let CommissioningIntent::Unload(mode) = report.plan.intent() {
        if !report.effects().group_keys_erased()
            || report.sections.values().any(|outcome| *outcome != CommissioningSectionOutcome::Cleared)
        {
            return Ok(programming_invalidation_event(
                planned.id.as_str(),
                report.effects().affected_sections().clone(),
                exposed_group_keys,
            )
            .into_iter()
            .collect());
        }
        return Ok(vec![ProjectEvent::RecordCommissioningOutcome {
            device: planned.id.to_string(),
            outcome: CommissioningOutcome::Unloaded {
                preserve_network_configuration: mode == UnloadMode::Application,
                serial: report.discovered.serial_number.as_ref().map(format_serial),
            },
        }]);
    }

    let established_sections: Vec<_> = report
        .sections
        .iter()
        .filter_map(|(section, outcome)| (*outcome == CommissioningSectionOutcome::Programmed).then_some(*section))
        .collect();
    // Discovery may complete an image which the offline project view could
    // only mark pending. Successful evidence comes from the executed program.
    let mut executed_manifest = report.plan.manifest().clone();
    set_credential_commitments(&mut executed_manifest, all)?;
    let mut established = executed_manifest.retain_sections(established_sections);
    // Desired group metadata can exist even when Preserve omits the GKT.
    // Only dispatched rows establish new deployed-key guards.
    established.credentials.retain(|proof| proof.id.kind != KeyKind::GroupKey);
    established.credentials.extend(exposed_group_keys.iter().cloned());
    let application_downloaded = commissioning_downloaded_application(report);
    let commissioning_deployment = application_downloaded
        .then(|| project_deployment_from_report(report))
        .transpose()
        .map_err(|error| {
            Error::StateEvidence(ErrorDetail::new(format!("could not persist commissioning evidence: {error}")))
        })?
        .flatten();
    let fully_verified = report.plan.is_full_program_scope()
        && (report.section(ProgrammingSection::Address) == CommissioningSectionOutcome::Programmed
            || planned.status.individual_address)
        && [
            ProgrammingSection::ApplicationProgram1,
            ProgrammingSection::Parameters,
            ProgrammingSection::GroupCommunication,
            ProgrammingSection::Configuration,
        ]
        .into_iter()
        .all(|section| report.section(section) == CommissioningSectionOutcome::Programmed);

    let mut events: Vec<_> = programming_invalidation_event(
        planned.id.as_str(),
        report
            .sections
            .iter()
            .filter_map(|(section, outcome)| (*outcome == CommissioningSectionOutcome::Unverified).then_some(*section))
            .collect(),
        exposed_group_keys,
    )
    .into_iter()
    .collect();
    events.push(ProjectEvent::RecordCommissioningOutcome {
        device: planned.id.to_string(),
        outcome: CommissioningOutcome::Programmed {
            established,
            commissioning: commissioning_deployment.map(Box::new),
            fully_verified,
        },
    });
    Ok(events)
}

pub(super) fn group_key_exposure_manifest(
    commitments: &[CredentialCommitment],
    net_ids: &BTreeMap<GroupAddress, String>,
    addresses: &BTreeSet<GroupAddress>,
) -> Result<ProgrammingManifest> {
    let mut manifest = ProgrammingManifest::default();
    for address in addresses {
        let net = net_ids.get(address).ok_or_else(|| {
            Error::StateEvidence(ErrorDetail::new(format!(
                "exposed group key for {address} has no planned net identity"
            )))
        })?;
        let id = KeyId { scope: KeyScope::Group(net.clone()), kind: KeyKind::GroupKey };
        let proofs: Vec<_> = commitments.iter().filter(|proof| proof.id == id).cloned().collect();
        if proofs.is_empty() {
            return Err(Error::StateEvidence(ErrorDetail::new(format!(
                "exposed group key for net `{net}` lacks credential evidence"
            ))));
        }
        manifest.credentials.extend(proofs);
    }
    manifest.credentials.sort_by(|a, b| a.id.cmp(&b.id));
    manifest.credentials.dedup();
    manifest.validate().map_err(|detail| Error::StateEvidence(ErrorDetail::new(detail)))?;
    Ok(manifest)
}

#[cfg(test)]
pub(in crate::project) mod tests;
