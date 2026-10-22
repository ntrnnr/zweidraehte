use super::*;
use crate::commissioning::catalog_testing::*;
use crate::commissioning::{
    CommissioningIntent, CommissioningSectionOutcome, DifferentialPolicy, DownloadMode, ExecutionReport,
    MutationStatus, ProgramSections, ProgrammingInput, TargetSelection, UnloadMode,
};
use crate::configuration::ResolvedKeyMaterial;
use crate::project::PlannedProjectDevice;
use crate::project::error::Error;
use crate::project::persistence::{
    group_key_exposure_manifest, intent_with_baseline, persist_post_execution_events_with,
    programming_invalidation_event, record_programming_failure, success_events,
};
use crate::project::session::{ProjectCommissioningSession, ProjectDeviceCommissioningOptions};
use crate::project::{CompileOptions, persistence};
use std::collections::{BTreeMap, BTreeSet};
use zweidraehte_ets_files::product::ProductData;
use zweidraehte_project::{
    CommissioningOutcome, CredentialCommitment, DeviceProgrammingStatus, KeyEpoch, KeyId, KeyKind, KeyMetadata,
    KeyScope, ProgrammingManifest, ProgrammingSection, ProjectDeviceId, ProjectEvent, ProjectStore,
};
use zweidraehte_proto::address::GroupAddress;

#[test]
fn only_exposed_group_rows_enter_atomic_failure_recovery() {
    use zweidraehte_project::{KeyEncoding, KeyOrigin, KeyState};
    let address = GroupAddress::from_three_level(1, 0, 1);
    let unsent = GroupAddress::from_three_level(1, 0, 2);
    let metadata = KeyMetadata {
        id: KeyId { kind: KeyKind::GroupKey, scope: KeyScope::Group("floor:room".into()) },
        epoch: Some(KeyEpoch(7)),
        origin: KeyOrigin::Generated,
        encoding: KeyEncoding::Hex,
        state: KeyState::Active,
        fingerprint: [9; 32],
    };
    let mut other = metadata.clone();
    other.id.scope = KeyScope::Group("unsent".into());
    let material = ResolvedKeyMaterial::default().with_provenance(vec![metadata.clone(), other]);
    let nets = BTreeMap::from([(address, "floor:room".into()), (unsent, "unsent".into())]);
    assert!(
        group_key_exposure_manifest(&credential_commitments(&material), &nets, &BTreeSet::new())
            .expect("no dispatched keys")
            .credentials
            .is_empty()
    );
    let exposed = group_key_exposure_manifest(&credential_commitments(&material), &nets, &BTreeSet::from([address]))
        .expect("known row identity");
    assert_eq!(exposed.credentials, [CredentialCommitment::from_metadata(&metadata).expect("group commitment")]);
    assert!(
        group_key_exposure_manifest(&credential_commitments(&material), &BTreeMap::new(), &BTreeSet::from([address]))
            .is_err()
    );
    let missing = ResolvedKeyMaterial::default();
    assert!(group_key_exposure_manifest(&credential_commitments(&missing), &nets, &BTreeSet::from([address])).is_err());
    let mut conflicting = metadata.clone();
    conflicting.fingerprint = [10; 32];
    let conflicting = ResolvedKeyMaterial::default().with_provenance(vec![metadata, conflicting]);
    assert!(
        group_key_exposure_manifest(&credential_commitments(&conflicting), &nets, &BTreeSet::from([address])).is_err()
    );

    let recovery = programming_invalidation_event(
        "receiver",
        BTreeSet::from([ProgrammingSection::Parameters]),
        exposed.credentials.clone(),
    )
    .expect("physical evidence requires a journal event");
    let mut written = Vec::new();
    persist_post_execution_events_with(
        Err(Error::DeviceConfiguration("success serialization failed".into())),
        Some(recovery.clone()),
        |event| {
            written.push(event);
            Ok(())
        },
    )
    .expect_err("success failure remains visible after recovery");
    assert_eq!(written, [recovery]);
    assert!(matches!(&written[0], ProjectEvent::RecordCommissioningOutcome {
        outcome: CommissioningOutcome::Indeterminate { sections, exposed_group_keys }, ..
    } if sections == &[ProgrammingSection::Parameters] && exposed_group_keys == &exposed.credentials));
}

#[test]
fn unknown_image_history_uses_full_intent_and_refuses_explicit_partial_or_diff() {
    for assign in [false, true] {
        let wrap = |mode| {
            if assign {
                CommissioningIntent::AssignAddressAndDownload(mode)
            } else {
                CommissioningIntent::Download(mode)
            }
        };
        assert_eq!(
            intent_with_baseline(wrap(DownloadMode::Automatic), DifferentialPolicy::FallBackToUndifferenced, false)
                .expect("automatic bootstraps"),
            wrap(DownloadMode::Full)
        );
        assert!(
            intent_with_baseline(
                wrap(DownloadMode::Partial(ProgramSections::PARAMETERS)),
                DifferentialPolicy::Disabled,
                false
            )
            .is_err()
        );
        assert!(intent_with_baseline(wrap(DownloadMode::Full), DifferentialPolicy::RequireVerified, false).is_err());
        let partial = wrap(DownloadMode::Partial(ProgramSections::PARAMETERS));
        assert_eq!(
            intent_with_baseline(partial, DifferentialPolicy::Disabled, true).expect("current baseline"),
            partial
        );
    }
}

#[test]
fn failed_execution_invalidates_only_affected_sections_without_progress_events() {
    let mut effects = crate::commissioning::ExecutionEffects::with_status(MutationStatus::PartiallyApplied);
    effects.record_sections([ProgrammingSection::Parameters]);
    let error = crate::commissioning::CommissioningError::after_execution(
        crate::commissioning::Diagnostic::new("write reply is lost"),
        effects,
    );
    let event = programming_invalidation_event("button", error.effects().affected_sections().clone(), Vec::new())
        .expect("uncertain dispatched write needs recovery");
    assert!(matches!(event, ProjectEvent::RecordCommissioningOutcome {
        outcome: CommissioningOutcome::Indeterminate { sections, .. }, ..
    } if sections == [ProgrammingSection::Parameters]));
    assert!(programming_invalidation_event("button", BTreeSet::new(), Vec::new()).is_none());
}

#[test]
fn confirmed_address_assignment_survives_a_later_application_failure() {
    let (planned, _) = persistence_fixture(CommissioningIntent::AssignAddress);
    let directory = tempfile::tempdir().expect("temporary project");
    let path = directory.path().join("project.knx");
    std::fs::write(
        &path,
        concat!(
            "area 1 ground { line 1 lighting { medium tp1 device button { ",
            "product package:\"sha256:0000000000000000000000000000000000000000000000000000000000000000\" ",
            "catalog_item \"M-00FA_H-1_P-1_CI-1\" address 1.1.23 } } }\n",
        ),
    )
    .expect("authored project");
    let mut store = ProjectStore::open(&path).expect("project opens");
    store = store.initialize().expect("journal initializes");
    let session = ProjectCommissioningSession::begin(store).expect("locked session");
    let mut effects = crate::commissioning::ExecutionEffects::with_status(MutationStatus::PartiallyApplied);
    effects.confirm_address(crate::commissioning::AddressAssignment {
        serial_number: None,
        previous: zweidraehte_proto::address::IndividualAddress::new(15, 15, 255),
        current: planned.device.individual_address(),
        changed: true,
    });
    effects.record_sections([ProgrammingSection::Address, ProgrammingSection::Parameters]);
    let error = crate::commissioning::CommissioningError::after_execution(
        crate::commissioning::Diagnostic::new("application write times out"),
        effects,
    );
    assert!(
        record_programming_failure(&session.store, &planned, error.effects().affected_sections().clone(), &error,)
            .is_empty()
    );
    session.finish().expect("journal compacts");

    // No progress event was emitted. Reopening proves the result itself
    // supplied enough information for durable address recovery.
    let reopened = ProjectStore::open(&path).expect("project reopens");
    let deployment = reopened.state().expect("persisted state").deployment(&planned.id.0).expect("device evidence");
    assert_eq!(
        deployment.manifest.section(ProgrammingSection::Address),
        planned.desired_manifest.section(ProgrammingSection::Address),
    );
    assert!(deployment.manifest.section(ProgrammingSection::Parameters).is_none());
}

#[test]
fn broad_failed_procedure_preserves_untouched_address_and_configuration() {
    let affected = BTreeSet::from([
        ProgrammingSection::ApplicationProgram1,
        ProgrammingSection::Parameters,
        ProgrammingSection::GroupCommunication,
    ]);
    let event = programming_invalidation_event("button", affected.clone(), Vec::new())
        .expect("affected application needs recovery");
    assert!(matches!(event, ProjectEvent::RecordCommissioningOutcome {
        outcome: CommissioningOutcome::Indeterminate { sections, .. }, ..
    } if sections.iter().copied().collect::<BTreeSet<_>>() == affected));
}

#[test]
fn persisted_report_keeps_sparse_evidence_and_rejects_corrupt_baselines() {
    use crate::commissioning::{DeviceStamp, ImageLocation, ImageSegment};
    use crate::project::persistence::{commissioning_deployment_from_project, project_deployment_from_report};
    use zweidraehte_project::ResourceId;

    let (_, mut report) = persistence_fixture(CommissioningIntent::Download(DownloadMode::Full));
    report.programmed_image.apply(
        &ImageSegment::new(ImageLocation::standard_memory(7), vec![0x0C, 0], vec![0x0F, 0]).expect("partial ownership"),
    );
    report.programmed_image.apply_owned(ImageLocation::standard_memory(10), vec![0xA5]).expect("separate range");
    report.device_stamps.push(DeviceStamp { resource: ResourceId("ProgramStamp".into()), value: vec![1, 2] });
    let before = report.programmed_image.clone();
    let record = project_deployment_from_report(&report).expect("report serializes").expect("download record");
    assert_eq!(report.programmed_image, before, "persistence only borrows report evidence");
    let restored = commissioning_deployment_from_project(&record).expect("canonical record validates");
    assert_eq!(restored.image, before);
    assert_eq!(restored.device_stamps, report.device_stamps);
    assert_eq!(record.image_segments.len(), 2, "unowned hole stays absent");

    for damage in 0..4 {
        let mut corrupt = record.clone();
        match damage {
            0 => corrupt.image_segments[0].data[0] ^= 1,
            1 => corrupt.image_segments.push(corrupt.image_segments[0].clone()),
            2 => corrupt.device_stamps.push(corrupt.device_stamps[0].clone()),
            _ => corrupt.image_fingerprint[0] ^= 1,
        }
        assert!(commissioning_deployment_from_project(&corrupt).is_err(), "corruption case {damage}");
    }
}

#[test]
fn old_product_fingerprints_reopen_without_image_baselines_or_lost_credentials() {
    use crate::project::persistence::project_deployment_from_report;

    let (_, report) = persistence_fixture(CommissioningIntent::Download(DownloadMode::Full));
    let current = project_deployment_from_report(&report).expect("current record").expect("download evidence");
    let proof = CredentialCommitment {
        id: KeyId { scope: KeyScope::Group("room-light".into()), kind: KeyKind::GroupKey },
        epoch: Some(KeyEpoch(7)),
        commitment: [0x55; 32],
    };
    for snapshot in [false, true] {
        let directory = tempfile::tempdir().expect("temporary project");
        let path = directory.path().join("project.knx");
        std::fs::write(&path, "").expect("empty authored project");
        let mut store = ProjectStore::open(&path).expect("project opens");
        store = store.initialize().expect("state initializes");
        let mut store = store.into_writer().expect("exclusive old writer");
        store.begin_mutation().expect("old journal opens");
        let mut old = current.clone();
        old.version = 2;
        old.product_fingerprint = [0x22; 32]; // Opaque Debug-era identity.
        let established = ProgrammingManifest {
            sections: BTreeMap::from([(ProgrammingSection::Parameters, [3; 32])]),
            credentials: vec![proof.clone()],
        };
        store.record(ProjectEvent::AdvanceClient { next: 500 }).expect("durable sending counter");
        store
            .record(ProjectEvent::ObserveDeviceOutgoing { serial: "00FA:00000001".into(), next: 300 })
            .expect("durable device counter");
        store
            .record(ProjectEvent::RecordCommissioningOutcome {
                device: "button".into(),
                outcome: CommissioningOutcome::Programmed {
                    established: established.clone(),
                    commissioning: Some(Box::new(old)),
                    fully_verified: true,
                },
            })
            .expect("old evidence journal");
        if snapshot {
            store.compact().expect("old snapshot");
        }
        drop(store);

        let reopened = ProjectStore::open(&path).expect("old snapshot or journal reopens");
        let state = reopened.state().expect("durable state");
        let deployment = state.deployment("button").expect("physical evidence retained");
        assert_eq!(deployment.manifest, established);
        assert_eq!(state.client_next, 500);
        assert_eq!(state.devices["00FA:00000001"].outgoing_next, 300);
        assert!(deployment.commissioning.is_none(), "old digest never proves the new format");
        let baseline = deployment.commissioning.is_some();
        assert_eq!(
            intent_with_baseline(
                CommissioningIntent::Download(DownloadMode::Automatic),
                DifferentialPolicy::FallBackToUndifferenced,
                baseline
            )
            .expect("full fallback"),
            CommissioningIntent::Download(DownloadMode::Full)
        );
        assert!(
            intent_with_baseline(
                CommissioningIntent::Download(DownloadMode::Partial(ProgramSections::PARAMETERS)),
                DifferentialPolicy::FallBackToUndifferenced,
                baseline
            )
            .is_err()
        );
        assert!(
            intent_with_baseline(
                CommissioningIntent::Download(DownloadMode::Automatic),
                DifferentialPolicy::RequireVerified,
                baseline
            )
            .is_err()
        );
    }
}

#[test]
fn unload_persistence_requires_confirmed_erasure_without_progress_events() {
    let (planned, mut report) = persistence_fixture(CommissioningIntent::Unload(UnloadMode::Application));
    report.effects.record_sections([ProgrammingSection::ApplicationProgram1]);
    for keys_erased in [false, true] {
        for cleared in [false, true] {
            report.effects = crate::commissioning::ExecutionEffects::with_status(MutationStatus::Complete);
            report.effects.record_sections([ProgrammingSection::ApplicationProgram1]);
            if keys_erased {
                report
                    .effects
                    .confirm_reset(zweidraehte_proto::messages::apdu::restart::EraseCode::FactoryResetKeepIA, 0);
            }
            report.sections = BTreeMap::from([(
                ProgrammingSection::ApplicationProgram1,
                if cleared { CommissioningSectionOutcome::Cleared } else { CommissioningSectionOutcome::Unverified },
            )]);
            let credentials =
                persistence::ExecutionCredentials::from_report(&planned, &report).expect("credential evidence");
            let events = success_events(&planned, &report, credentials).expect("execution effects serialize");
            let unloaded = events.iter().any(|event| {
                matches!(event, ProjectEvent::RecordCommissioningOutcome {
                    outcome: CommissioningOutcome::Unloaded { .. },
                    ..
                })
            });
            assert_eq!(unloaded, keys_erased && cleared);
        }
    }
}

pub(in crate::project) const PERSISTENCE_PRODUCT_XML: &str = r#"
        <KNX xmlns="http://knx.org/xml/project/23"><ManufacturerData><Manufacturer RefId="M-00FA">
        <ApplicationPrograms><ApplicationProgram Id="M-00FA_A-0001-01-0000" ApplicationNumber="1"
        ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-0012" Name="Button"
        LoadProcedureStyle="DefaultProcedure" PeiType="0" DefaultLanguage="en-US"
        DynamicTableManagement="false" Linkable="false"><Static/></ApplicationProgram>
        </ApplicationPrograms></Manufacturer></ManufacturerData></KNX>"#;

pub(in crate::project) fn persistence_fixture(intent: CommissioningIntent) -> (PlannedProjectDevice, ExecutionReport) {
    use crate::commissioning::DiscoveredDevice;
    use crate::configuration::MaterializedDevice;
    let catalog = parse_master_data(
        r#"
        <KNX xmlns="http://knx.org/xml/project/23"><MasterData Id="MD" Version="1"><MaskVersions>
        <MaskVersion Id="MV-0012" MaskVersion="18" Name="BCU1" ManagementModel="Bcu1" MediumTypeRefId="MT-0">
        <HawkConfigurationData><Procedures><Procedure ProcedureType="Load" ProcedureSubType="all">
        <LdCtrlConnect/><LdCtrlDisconnect/>
        </Procedure><Procedure ProcedureType="Unload" ProcedureSubType="all"><LdCtrlConnect/><LdCtrlDisconnect/></Procedure></Procedures></HawkConfigurationData></MaskVersion>
        </MaskVersions></MasterData></KNX>"#,
    )
    .expect("fixture catalog");
    let product = ProductData::from_mtxml_str(PERSISTENCE_PRODUCT_XML).expect("fixture product");
    let address = zweidraehte_proto::address::IndividualAddress::new(1, 1, 23);
    let device = MaterializedDevice::fixture(address, Some(15))
        .with_product(product.bind_master_data(std::sync::Arc::clone(&catalog)).expect("catalog binds"))
        .with_key_material(ResolvedKeyMaterial::default());
    let target = TargetSelection::ExistingAddress(address);
    let plan = ProgrammingInput::new(device.clone(), intent, CompileOptions {
        target: target.clone(),
        automatic_sections: None,
        progress_messages_by_reference: BTreeMap::new(),
        progress_messages_by_id: BTreeMap::new(),
    })
    .facts(crate::commissioning::ProgrammingFacts::new(crate::commissioning::ObservedTarget {
        previous_address: address,
        serial_number: None,
        credential: crate::commissioning::ManagementCredential::Plaintext,
    }))
    .compile_selection(&ProfileSelection::discovered(0x0012))
    .expect("persistence fixture compiles");
    let planned = PlannedProjectDevice {
        serial_addressing: super::super::SerialAddressingSupport::Unknown,
        id: ProjectDeviceId("button".into()),
        device,
        evaluated_intent: intent,
        target_override: None,
        commissioning: ProjectDeviceCommissioningOptions {
            intent,
            target,
            allow_plaintext: true,
            differential_policy: DifferentialPolicy::Disabled,
        },
        supports_data_secure: false,
        data_secure_enabled: false,
        desired_manifest: plan.manifest().clone(),
        image_requirements: Vec::new(),
        status: DeviceProgrammingStatus::NONE,
        automatic_sections: ProgramSections::all(),
        net_ids: BTreeMap::new(),
        previous_commissioning: None,
        warnings: Vec::new(),
    };
    let report = ExecutionReport {
        execution_address: plan.individual_address(),
        differential: crate::commissioning::DifferentialDecision::Undifferenced,
        discovered: DiscoveredDevice {
            address: Some(address),
            serial_number: None,
            mask: plan.profile().mask().clone(),
            interface_max_apdu: 15,
            target_max_apdu: 15,
            secure_management: false,
            observed_management_style: None,
        },
        plan,
        programmed_image: Default::default(),

        procedure: None,

        device_stamps: Vec::new(),
        sections: BTreeMap::new(),

        effects: crate::commissioning::ExecutionEffects::with_status(MutationStatus::Complete),
    };
    (planned, report)
}

#[test]
fn poisoned_store_recovery_releases_the_failed_lock_before_retrying() {
    let directory = tempfile::tempdir().expect("temporary project");
    let path = directory.path().join("project.knx");
    std::fs::write(&path, "").expect("empty project source");
    let mut store = zweidraehte_project::ProjectStore::open(path).expect("project opens");
    store = store.initialize().expect("state initializes");
    let session = crate::project::session::ProjectCommissioningSession::begin(store).expect("locked writer");
    let owner = session.store.clone();
    let _ = std::thread::spawn(move || {
        let _guard = owner.lock().expect("initially healthy mutex");
        panic!("injected writer failure");
    })
    .join();

    let error = persist_post_execution_events(
        &session.store,
        Ok(Vec::new()),
        Some(ProjectEvent::ObserveDeviceOutgoing { serial: "00FA:00000001".into(), next: 2 }),
    )
    .expect_err("poison and recovery failure are reported");
    assert!(matches!(error.source, Error::ProjectStorePoisoned));
    assert!(!error.state_errors.is_empty());
}
