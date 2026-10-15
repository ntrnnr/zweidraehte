//! Preserve behavioral regressions from the former management simulator.
use super::*;
use crate::commissioning::runtime::TransferContext;

#[tokio::test]
async fn memory_image_load_skips_owned_windows_and_preserves_desired_bits_in_later_writes() {
    for (mask, observed, expected) in
        [(vec![0, 255, 0], None, 0xa5), (vec![255, 15, 255], Some(0xf0), 0xf5), (vec![255, 0, 255], Some(0xf0), 0xf0)]
    {
        let (bus, rx) = bus();
        let mut session =
            ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
        session.begin_execution();
        let mut image = SparseDeviceImage::new();
        image.apply_section(
            zweidraehte_project::ProgrammingSection::Parameters,
            &crate::commissioning::image::ImageSegment::new(location(0x100), vec![0x11, 0xa5, 0x33], mask)
                .expect("masked image"),
        );
        let controls = procedure(vec![
            ProcedureOperation::Connect,
            ProcedureOperation::LoadImage {
                target: memory(0x101),
                image_location: location(0x101),
                extent: OperationExtent::bytes(1),
                alignment: 1,
            },
            write(memory(0x101), OperationData::Buffer { location: location(0x101), length: 1, fallback: None }, 1),
            ProcedureOperation::Disconnect,
        ]);
        controls.validate().expect("absolute memory load has valid service and byte geometry");
        let mut script = vec![Wire::Open(false)];
        if let Some(value) = observed {
            script.push(Wire::Memory { address: 0x101, count: 1, write: None, reply: Ok(vec![value]) });
        }
        // A wholly unowned read already proves the destination byte equal.
        // Desired owned bits in the other cases still require the write.
        if observed != Some(expected) {
            script.push(mem_write(0x101, &[expected]));
        }
        script.push(Wire::Close(Ok(())));
        let regions = vec![native(location(0x100), 3)];
        let (result, ()) = tokio::join!(
            ProcedureRunner::new(&mut session).execute(&image, &regions, &controls, || false, |_| {}),
            peer(rx, script)
        );
        result.expect("selected memory read and subsequent merged payload follow the wire script");
        assert_eq!(session.images.working_byte(&location(0x101)), Some((expected, 255)));
    }
}

#[tokio::test]
async fn restart_closure_restores_mode_and_invalidates_knowledge_before_secure_reconnect() {
    let (bus, rx) = KnxBus::scripted(ConnectorInfo { assigned_address: IndividualAddress::new(1, 1, 1), max_apdu: 64 });
    let mut options = config(true);
    options.target_max_apdu = 64;
    let mut session =
        ExecutionSession::new(&bus, address(), options, ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let mut image = SparseDeviceImage::new();
    image.apply_owned(location(0x100), vec![7]).expect("valid image");
    let mut controls = procedure(vec![
        ProcedureOperation::Connect,
        ProcedureOperation::Restart { kind: RestartKind::Basic },
        ProcedureOperation::Disconnect,
        ProcedureOperation::Connect,
        write(memory(0x100), OperationData::Image { location: location(0x100), length: 1 }, 1),
        ProcedureOperation::Disconnect,
    ]);
    controls.initial_state.memory_auto_verify = Some(true);
    controls.steps[2].secure_only = true;
    controls.steps[3].secure_only = true;
    session.images.known = image.clone();
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(true),
            prop_read(pid::DEVICE_CONTROL, 1, 1, &[0]),
            prop_write(pid::DEVICE_CONTROL, 4),
            prop_write(pid::DEVICE_CONTROL, 0),
            Wire::Restart(Err(Error::TransportClosed)),
            Wire::Close(Err(Error::TransportClosed)),
            Wire::Open(true),
            prop_read(pid::DEVICE_CONTROL, 1, 1, &[0]),
            prop_write(pid::DEVICE_CONTROL, 4),
            // The explicit NoVerification transfer overrides the initial
            // automatic-verify setting before sending its memory write.
            prop_write(pid::DEVICE_CONTROL, 0),
            mem_write(0x100, &[7]),
            Wire::Close(Ok(())),
        ])
    );
    assert_eq!(result.expect("restart closes its transport").steps_completed, 6);
    assert!(session.connection.is_none());
}
use crate::commissioning::error::{CleanupOperation, TransportCause};
use crate::commissioning::image::ImageSegment;
use std::cell::Cell;

fn observation_catalog(resources: &str) -> crate::commissioning::catalog::ProgrammingCatalog {
    crate::commissioning::catalog::ProgrammingCatalog::from_xml(&format!(r#"
      <KNX xmlns="http://knx.org/xml/project/20"><MasterData Id="MD" Version="1"><MaskVersions>
        <MaskVersion Id="MV-0012" MaskVersion="18" Name="BCU1" ManagementModel="Bcu1" MediumTypeRefId="MT-0">
          <HawkConfigurationData><Features><Feature Name="AuthorizeLevels" Value="16"/></Features>
            <Resources>{resources}</Resources><Procedures><Procedure ProcedureType="Load" ProcedureSubType="all"/></Procedures>
          </HawkConfigurationData>
        </MaskVersion>
      </MaskVersions></MasterData></KNX>"#)).expect("observation fixture parses")
}

#[tokio::test]
async fn discovery_reads_identity_before_authorization_and_failed_serial_reads_do_not_publish_facts() {
    use crate::commissioning::catalog::profile::VariantHint;
    use crate::commissioning::input::CompileOptions;
    use crate::commissioning::input::{CommissioningIntent, ProgrammingInput, TargetSelection};
    use crate::commissioning::runtime::commissioner::Commissioner;
    use crate::commissioning::runtime::credentials::ManagementAccessOptions;
    use crate::commissioning::runtime::prepare::profile::AcquiredTarget;
    use crate::configuration::ResolvedKeyMaterial;
    use crate::configuration::{LoweredDeviceConfiguration, MaterializedDevice};
    use zweidraehte_ets_files::product::ProductData;

    for succeeds in [false, true] {
        let (bus, rx) = bus();
        let commissioner = Commissioner::new(&bus);
        let catalog = observation_catalog(
            r#"<Resource Name="DeviceSerialNumber" Access="remote">
          <Location AddressSpace="SystemProperty" InterfaceObjectRef="3" PropertyID="11" StartAddress="0"/>
          <ResourceType Length="6"/></Resource>"#,
        );
        let input = ProgrammingInput::new(
            MaterializedDevice::new(
                ProductData::default().with_fixture_mask_version_id("MV-0012"),
                LoweredDeviceConfiguration::new(address(), Some(15)),
                Vec::new(),
                ResolvedKeyMaterial::new(None),
            ),
            CommissioningIntent::AssignAddress,
            CompileOptions {
                target: TargetSelection::ExistingAddress(address()),
                automatic_sections: None,
                progress_messages_by_reference: Default::default(),
                progress_messages_by_id: Default::default(),
            },
        );
        let mut target = AcquiredTarget { address: address(), serial_number: None };
        let mut session =
            ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("session");
        let access = ManagementAccessOptions::new().with_access_key([1, 2, 3, 4]);
        let serial = [1, 2, 3, 4, 5, 6];
        let (result, ()) = tokio::join!(
            async {
                session.connect_without_authorization_at(target.address).await?;
                commissioner
                    .observe_profile(
                        &catalog,
                        &input,
                        VariantHint::Automatic,
                        &mut target,
                        &mut session,
                        &access,
                        false,
                    )
                    .await
            },
            peer(rx, vec![
                Wire::Open(false),
                Wire::Descriptor(0x0012),
                Wire::Authorize,
                Wire::Property {
                    start: 1,
                    count: 1,
                    pid: pid::SERIAL_NUMBER,
                    write: None,
                    reply: if succeeds { Ok(serial.to_vec()) } else { Err(Error::Timeout) }
                },
                Wire::Close(Ok(()))
            ]),
        );
        assert_eq!(result.is_ok(), succeeds, "{:?}", result.as_ref().map(|_| ()));
        assert_eq!(target.serial_number, succeeds.then_some(serial));
        assert_eq!(
            result.as_ref().ok().map(|_| session.config.authorization.clone()),
            succeeds.then_some(AuthorizationPolicy::LegacyKey { key: [1, 2, 3, 4].into(), required_level: 3 })
        );
        assert!(session.connection.is_none());
        assert_eq!(session.mutation_status(), MutationStatus::NotStarted);
        if !succeeds {
            assert!(session.images.known.segments().is_empty());
        }
    }
}

#[tokio::test]
async fn serial_resources_use_the_same_zero_based_occurrence_binding_as_control_properties() {
    use crate::commissioning::catalog::profile::{ProfileDiscovery, ProfileRequest, VariantHint};
    use crate::commissioning::runtime::prepare::profile::read_profile_serial_number;

    for (occurrence, instance) in [("", 1), (r#"Occurrence="0""#, 1), (r#"Occurrence="1""#, 2)] {
        let profile = observation_catalog(&format!(
            r#"<Resource Name="DeviceSerialNumber" Access="remote">
          <Location AddressSpace="Property" InterfaceObjectRef="0" PropertyID="11" StartAddress="0" {occurrence}/>
          <ResourceType Length="6"/></Resource>"#
        ))
        .resolve(ProfileRequest {
            discovery: ProfileDiscovery { dd0: 0x0012, management_descriptor_01: None, management_style: None },
            product: None,
            variant_hint: VariantHint::Automatic,
        })
        .expect("serial resource profile");
        let (bus, rx) = bus();
        let mut session =
            ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("session");
        session.begin_execution();
        let client = async {
            session.connect_without_authorization_at(address()).await.expect("open");
            let result = read_profile_serial_number(&mut session, &profile).await;
            session.finish(result).await
        };
        let serial = vec![1, 2, 3, 4, 5, 6];
        let (result, ()) = tokio::join!(
            client,
            peer(rx, vec![Wire::Open(false), Wire::Serial { instance, value: serial }, Wire::Close(Ok(()))])
        );
        assert_eq!(result.expect("correct object instance"), Some([1, 2, 3, 4, 5, 6]));
    }
}

#[tokio::test]
async fn preparation_close_keeps_compilation_diagnostics_and_reports_cleanup_failure() {
    use crate::commissioning::error::CompileError;
    for primary in [false, true] {
        for close_fails in [false, true] {
            let (bus, rx) = bus();
            let mut session =
                ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("session");
            let client = async {
                session.connect_without_authorization_at(address()).await.expect("open");
                session
                    .finish(if primary {
                        Err(CompileError::invalid("selected profile is invalid").into())
                    } else {
                        Ok(())
                    })
                    .await
            };
            let (result, ()) = tokio::join!(
                client,
                peer(rx, vec![
                    Wire::Open(false),
                    Wire::Close(if close_fails { Err(Error::AckTimeout) } else { Ok(()) })
                ])
            );
            match (result, primary, close_fails) {
                (Ok(()), false, false) => {}
                (Err(error), true, false) => assert_eq!(
                    error.kind(),
                    crate::commissioning::DiagnosticKind::Compilation(
                        crate::commissioning::CompileErrorKind::InvalidInput
                    )
                ),
                (Err(error), _, true) => {
                    assert_eq!(session.effects.mutation_status(), MutationStatus::NotStarted);
                    assert_eq!(error.cleanup_failures.len(), usize::from(primary));
                    if !primary {
                        assert_eq!(error.transport, Some(TransportCause::Timeout));
                    }
                }
                (result, _, _) => panic!("unexpected preparation result: {result:?}"),
            }
        }
    }
}

#[tokio::test]
async fn post_restart_close_failure_cannot_be_reported_as_success() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("session");
    session.begin_execution();
    let client = async {
        session.connect().await.expect("open");
        session.restart_device(RestartKind::Basic).await
    };
    let (result, ()) = tokio::join!(
        client,
        peer(rx, vec![Wire::Open(false), Wire::Restart(Ok(())), Wire::Close(Err(Error::AckTimeout))])
    );
    let error = result.expect_err("failed close follows confirmed restart");
    assert_eq!(session.effects.mutation_status(), MutationStatus::PartiallyApplied);
    assert_eq!(error.transport, Some(TransportCause::Timeout));
}

#[tokio::test]
async fn published_image_uses_confirmed_compound_ranges_and_retains_unrequested_previous_values() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("session");
    session.begin_execution();
    let mut desired = SparseDeviceImage::new();
    for (offset, value) in [(0x200, 7), (0x204, 9), (0x208, 8), (0x300, 6)] {
        desired.apply_section(
            zweidraehte_project::ProgrammingSection::Parameters,
            &ImageSegment::owned(location(offset), vec![value]).expect("desired byte"),
        );
        session.images.known.apply_owned(location(offset), vec![1]).expect("verified previous byte");
    }
    let mut controls = procedure(vec![
        ProcedureOperation::Connect,
        ProcedureOperation::AbsoluteSegment {
            record: LoadRecord {
                write: ServiceRead { target: memory(0x100), extent: OperationExtent::bytes(1) },
                bytes: vec![1],
                poll: None,
                effect: LoadEffect::None,
            },
            transfers: [0x200, 0x204, 0x208]
                .map(|offset| MemoryTransfer {
                    target: memory(offset),
                    data: OperationData::ImageWindow { location: location(offset), maximum: 1 },
                    extent: OperationExtent::bytes(1),
                    policy: WriteIntent::AbsoluteSegment,
                })
                .to_vec(),
        },
        ProcedureOperation::Restart { kind: RestartKind::Basic },
    ]);
    controls.steps[1]
        .on_error
        .push(ErrorHandler { cause: LoadControlCause::DeviceReturnCode(2), action: ErrorAction::Ignore });
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&desired, &[], &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            mem_write(0x100, &[1]),
            Wire::Memory { address: 0x200, count: 1, write: None, reply: Ok(vec![1]) },
            mem_write(0x200, &[7]),
            Wire::Memory { address: 0x204, count: 1, write: None, reply: Err(Error::DeviceError(2)) },
            Wire::Restart(Ok(())),
            Wire::Close(Ok(())),
        ])
    );
    result.expect("ignored failure skips the remaining compound transfer");
    assert!(session.images.known.is_empty(), "restart invalidates comparison knowledge");
    let programmed_image = session.images.take_programmed_image();
    assert_eq!(programmed_image.byte(&location(0x200)), Some((7, 255)));
    assert_eq!(programmed_image.byte(&location(0x204)), None);
    assert_eq!(programmed_image.byte(&location(0x208)), Some((1, 255)));
    assert_eq!(programmed_image.byte(&location(0x300)), Some((1, 255)));
    assert_eq!(programmed_image.byte(&location(0x100)), None, "load-record bytes are not public image data");
    assert_eq!(programmed_image.ownership().len(), 3, "only the confirmed owned ranges survive");
}

#[tokio::test]
async fn writes_after_restart_discard_the_earlier_publication_snapshot() {
    for uncertain in [false, true] {
        let (bus, rx) = bus();
        let mut session =
            ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("session");
        session.begin_execution();
        let mut desired = SparseDeviceImage::new();
        desired.apply_owned(location(0x200), vec![7, 9]).expect("desired");
        let mut controls = procedure(vec![
            ProcedureOperation::Connect,
            write(memory(0x200), OperationData::Inline(vec![7]), 1),
            ProcedureOperation::Restart { kind: RestartKind::Basic },
            ProcedureOperation::Connect,
            ProcedureOperation::Write {
                target: memory(0x201),
                data: OperationData::Inline(vec![9]),
                extent: OperationExtent::bytes(1),
                policy: WriteIntent::Explicit(if uncertain {
                    WritePolicy::ReadBack
                } else {
                    WritePolicy::NoVerification
                }),
            },
            ProcedureOperation::Disconnect,
        ]);
        controls.steps[4]
            .on_error
            .push(ErrorHandler { cause: LoadControlCause::CompareMismatch, action: ErrorAction::Ignore });
        let mut script = vec![
            Wire::Open(false),
            mem_write(0x200, &[7]),
            Wire::Restart(Ok(())),
            Wire::Close(Ok(())),
            Wire::Open(false),
            mem_write(0x201, &[9]),
        ];
        if uncertain {
            script.push(Wire::Memory { address: 0x201, count: 1, write: None, reply: Ok(vec![8]) });
        }
        script.push(Wire::Close(Ok(())));
        let (result, ()) = tokio::join!(
            ProcedureRunner::new(&mut session).execute(&desired, &[], &controls, || false, |_| {}),
            peer(rx, script)
        );
        result.expect("late comparison failure is authored as ignorable");
        let programmed_image = session.images.take_programmed_image();
        assert_eq!(programmed_image.byte(&location(0x200)), None);
        assert_eq!(programmed_image.byte(&location(0x201)), (!uncertain).then_some((9, 255)));
    }
}

#[tokio::test]
async fn rejected_writes_and_allocations_cannot_restore_invalidated_bytes_from_a_restart_snapshot() {
    for allocation in [false, true] {
        let (bus, rx) = bus();
        let mut session =
            ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("session");
        session.begin_execution();
        let mut desired = SparseDeviceImage::new();
        desired.apply_owned(location(0x200), vec![7, 9]).expect("desired");
        session.images.known = desired.clone();
        let rejected = if allocation {
            ProcedureOperation::LoadRecord(LoadRecord {
                write: ServiceRead { target: memory(0x100), extent: OperationExtent::bytes(1) },
                bytes: vec![1],
                poll: None,
                effect: LoadEffect::Invalidate { location: location(0x201), length: 1 },
            })
        } else {
            write(memory(0x201), OperationData::Inline(vec![8]), 1)
        };
        let mut controls = procedure(vec![
            ProcedureOperation::Connect,
            ProcedureOperation::Restart { kind: RestartKind::Basic },
            ProcedureOperation::Connect,
            rejected,
            ProcedureOperation::Disconnect,
        ]);
        controls.steps[3]
            .on_error
            .push(ErrorHandler { cause: LoadControlCause::DeviceReturnCode(2), action: ErrorAction::Ignore });
        let (result, ()) = tokio::join!(
            ProcedureRunner::new(&mut session).execute(&desired, &[], &controls, || false, |_| {}),
            peer(rx, vec![
                Wire::Open(false),
                Wire::Restart(Ok(())),
                Wire::Close(Ok(())),
                Wire::Open(false),
                Wire::Memory {
                    address: if allocation { 0x100 } else { 0x201 },
                    count: 1,
                    write: Some(vec![if allocation { 1 } else { 8 }]),
                    reply: Err(Error::DeviceError(2))
                },
                Wire::Close(Ok(())),
            ])
        );
        result.expect("explicit rejection is ignored");
        let programmed_image = session.images.take_programmed_image();
        assert_eq!(programmed_image.byte(&location(0x200)), Some((7, 255)));
        assert_eq!(programmed_image.byte(&location(0x201)), None);
    }
}

#[tokio::test]
async fn published_image_excludes_secret_targets_and_unowned_readback_bits() {
    for failed_private_write in [false, true] {
        let (bus, rx) = bus();
        let mut session =
            ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("session");
        session.begin_execution();
        let mut desired = SparseDeviceImage::new();
        desired
            .apply_owned(property_location(0), vec![0])
            .expect("public placeholder must never reveal replacement key");
        let public = ImageLocation {
            space: crate::commissioning::image::ImageSpace::Property {
                object: crate::commissioning::catalog::profile::ObjectSelector::Index { index: 3 },
                property_id: 28,
            },
            offset: 0,
        };
        desired.apply(&ImageSegment::new(public.clone(), vec![3], vec![0x0F]).expect("partial ownership"));
        let secret = session.secret_payload.insert_for_test(vec![0xA7].into());
        let mut controls = procedure(vec![
            ProcedureOperation::Connect,
            ProcedureOperation::Write {
                target: property(1),
                data: OperationData::Secret(secret),
                extent: OperationExtent::property(1, 1),
                policy: WriteIntent::Explicit(WritePolicy::ReadBack),
            },
            ProcedureOperation::ReadIntoImage {
                target: property(1),
                image_location: property_location(0),
                extent: OperationExtent::property(1, 1),
                cache: CachePolicy::Bypass,
                capture_as: None,
            },
            ProcedureOperation::ReadIntoImage {
                target: OperationTarget::Property {
                    address: PropertyAddress::Indexed { object_index: 3, property_id: 28 },
                    start_element: 1,
                },
                image_location: public.clone(),
                extent: OperationExtent::property(1, 1),
                cache: CachePolicy::Bypass,
                capture_as: None,
            },
            ProcedureOperation::Disconnect,
        ]);
        if failed_private_write {
            controls.steps[1]
                .on_error
                .push(ErrorHandler { cause: LoadControlCause::DeviceReturnCode(2), action: ErrorAction::Ignore });
        }
        let mut wire = vec![Wire::Open(false)];
        if failed_private_write {
            wire.push(Wire::Property {
                start: 1,
                count: 1,
                pid: 27,
                write: Some(vec![0xA7]),
                reply: Err(Error::DeviceError(2)),
            });
        } else {
            wire.push(prop_write(27, 0xA7));
            wire.push(prop_read(27, 1, 1, &[0xA7]));
        }
        wire.extend([prop_read(27, 1, 1, &[0xA7]), prop_read(28, 1, 1, &[0xA5]), Wire::Close(Ok(()))]);
        let (result, ()) = tokio::join!(
            ProcedureRunner::new(&mut session).execute(&desired, &[], &controls, || false, |_| {}),
            peer(rx, wire)
        );
        result.expect("private write and later reads complete");
        let programmed_image = session.images.take_programmed_image();
        assert_eq!(programmed_image.byte(&property_location(0)), None);
        assert_eq!(programmed_image.byte(&public), Some((5, 0x0F)));
    }
}

#[tokio::test]
async fn function_commands_send_bound_bytes_and_state_reads_remain_real_wire_operations() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let address = PropertyAddress::Indexed { object_index: 3, property_id: 42 };
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        ProcedureOperation::FunctionProperty(FunctionPropertyOperation::Invoke {
            address,
            data: vec![0, 0xA5, 4],
            effect: LoadEffect::InvalidateAll,
        }),
        ProcedureOperation::FunctionProperty(FunctionPropertyOperation::ReadResult { address }),
        ProcedureOperation::Disconnect,
    ]);
    assert_eq!(
        crate::commissioning::procedure::operands::required_plaintext_apdu(&controls, false).expect("bounded requests"),
        Some(6)
    );
    let image = SparseDeviceImage::new();
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            Wire::Function { command: true, data: vec![0, 0xA5, 4] },
            Wire::Function { command: false, data: Vec::new() },
            Wire::Close(Ok(())),
        ])
    );
    result.expect("both function operations complete");
}

#[tokio::test]
async fn load_record_without_room_for_an_extended_frame_uses_the_located_object_index() {
    use zweidraehte_proto::dpt::InterfaceObjectType;

    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let mut load = vec![0; 10];
    load[0] = 1;
    let record = LoadRecord {
        write: ServiceRead {
            target: OperationTarget::Property {
                address: PropertyAddress::Extended {
                    object_type: InterfaceObjectType::Router,
                    object_instance: 1,
                    property_id: pid::LOAD_STATE_CONTROL,
                },
                start_element: 1,
            },
            extent: OperationExtent::property(10, 1),
        },
        bytes: load.clone(),
        poll: None,
        effect: LoadEffect::None,
    };
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        ProcedureOperation::LoadRecord(record.clone()),
        ProcedureOperation::LoadRecord(record),
        ProcedureOperation::Disconnect,
    ]);

    // An extended frame needs 9 + 10 octets; the indexed one fits exactly.
    assert_eq!(
        crate::commissioning::procedure::operands::required_plaintext_apdu(&controls, false).expect("bounded requests"),
        Some(15)
    );

    let object_type = |index, object_type: u16| Wire::ObjectProperty {
        object_index: index,
        pid: pid::OBJECT_TYPE,
        write: None,
        reply: Ok(object_type.to_be_bytes().to_vec()),
    };
    let image = SparseDeviceImage::new();
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            object_type(0, 0),
            object_type(1, 6),
            Wire::ObjectProperty {
                object_index: 1,
                pid: pid::LOAD_STATE_CONTROL,
                write: Some(load.clone()),
                reply: Ok(load.clone()),
            },
            // The located index is reused without walking the objects again.
            Wire::ObjectProperty {
                object_index: 1,
                pid: pid::LOAD_STATE_CONTROL,
                write: Some(load.clone()),
                reply: Ok(load),
            },
            Wire::Close(Ok(())),
        ])
    );
    result.expect("both records fit the standard frame");
}

#[tokio::test]
async fn object_lookup_stops_at_the_first_absent_index() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();

    let client = async {
        session.connect().await.expect("connection opens");
        let error = session.locate_object(6, 2).await.expect_err("only one router object exists");
        assert!(error.to_string().contains("instance 2"), "{error}");
        session.locate_object(6, 2).await.expect_err("the end of the list is remembered");
    };
    tokio::join!(
        client,
        peer(rx, vec![
            Wire::Open(false),
            Wire::ObjectProperty { object_index: 0, pid: pid::OBJECT_TYPE, write: None, reply: Ok(vec![0, 6]) },
            Wire::ObjectProperty {
                object_index: 1,
                pid: pid::OBJECT_TYPE,
                write: None,
                reply: Err(Error::PropertyValueUnavailable { object_index: 1, property_id: pid::OBJECT_TYPE }),
            },
        ])
    );
}

#[tokio::test]
async fn direct_pointer_write_rejects_final_range_before_mutating_state() {
    use crate::commissioning::procedure::operands::PointerEncoding;

    for (service, base, space) in [
        (MemoryService::Extended, 0x00ff_ffffu32, ImageSpace::StandardMemory),
        (MemoryService::User, 0x000f_ffffu32, ImageSpace::UserMemory),
    ] {
        let (bus, rx) = bus();
        let mut session = ExecutionSession::new(&bus, address(), config(true), ManagementAccess::Plaintext)
            .expect("valid configuration");
        let last_byte = ImageLocation { space, offset: base };
        session.images.known.apply_owned(last_byte.clone(), vec![7]).expect("known boundary byte");
        let target = OperationTarget::Memory {
            service,
            address: MemoryAddress::Pointer {
                read: Box::new(ServiceRead {
                    target: OperationTarget::Constant(base.to_be_bytes().to_vec()),
                    extent: OperationExtent::bytes(4),
                }),
                space: ImageSpace::RelativeMemory { object: ObjectSelector::Index { index: 3 } },
                offset: 0,
                encoding: PointerEncoding::Absolute,
            },
        };
        // Exercise the low-level helper directly. Ordinary procedure transfers
        // resolve their pointer before calling it and already validate the range.
        let client = async {
            session.connect().await.expect("connection opens");
            let error = session
                .write(
                    &target,
                    &[1, 2],
                    OperationExtent::bytes(2),
                    WritePolicy::DeviceAutoVerify,
                    TransferContext::Public,
                )
                .await
                .expect_err("resolved range exceeds its service");
            assert!(error.message.contains("range exceeds"), "{error}");
            assert_eq!(session.images.known.byte(&last_byte), Some((7, 255)));
            assert!(session.current_device_control.is_none(), "mode was not read or changed");
            session.disconnect().await.expect("connection closes");
        };
        tokio::join!(client, peer(rx, vec![Wire::Open(false), Wire::Close(Ok(()))]));
    }
}

#[tokio::test]
async fn wide_pointer_service_follows_each_observed_range_without_downgrading_secure_memory() {
    use crate::commissioning::procedure::operands::{PointerEncoding, StandardMemoryService};

    for secure in [false, true] {
        let (bus, rx) =
            KnxBus::scripted(ConnectorInfo { assigned_address: IndividualAddress::new(1, 1, 1), max_apdu: 64 });
        let mut options = config(false);
        options.target_max_apdu = 64;
        let mut session =
            ExecutionSession::new(&bus, address(), options, ManagementAccess::Plaintext).expect("valid config");
        session.begin_execution();
        let minimum = if secure { StandardMemoryService::Extended } else { StandardMemoryService::Classic };
        let service = minimum.for_pointer(4, 3, 1);
        assert_eq!(service.overhead(), 5);
        let target = OperationTarget::Memory {
            service,
            address: MemoryAddress::Pointer {
                space: ImageSpace::RelativeMemory { object: ObjectSelector::Index { index: 3 } },
                read: Box::new(ServiceRead { target: property(1), extent: OperationExtent::property(4, 1) }),
                offset: 3,
                encoding: PointerEncoding::Absolute,
            },
        };
        // The deferred target retains the conservative extended-memory header,
        // even when the device subsequently returns a low classic address.
        assert_eq!(target.minimum_apdu(OperationExtent::bytes(1)).expect("bounded pointer"), 9);
        let mut operations = vec![ProcedureOperation::Connect];
        let mut script = vec![Wire::Open(secure)];
        for (base, value) in [(0x200u32, 7), (0xFFFC, 8), (0x10200, 9)] {
            operations.push(write(target.clone(), OperationData::Inline(vec![value]), 1));
            script.push(prop_read(27, 1, 1, &base.to_be_bytes()));
            script.push(if secure || base + 3 > u32::from(u16::MAX) {
                Wire::ExtendedMemory { address: base + 3, count: 1, write: Some(vec![value]), reply: Ok(Vec::new()) }
            } else {
                mem_write((base + 3) as u16, &[value])
            });
        }
        operations.push(ProcedureOperation::Disconnect);
        script.push(Wire::Close(Ok(())));
        let controls = procedure(operations);
        let destination = ImageLocation {
            space: ImageSpace::RelativeMemory { object: ObjectSelector::Index { index: 3 } },
            offset: 3,
        };
        let mut image = SparseDeviceImage::new();
        image.apply_section(
            zweidraehte_project::ProgrammingSection::Parameters,
            &ImageSegment::owned(destination.clone(), vec![9]).expect("one byte"),
        );
        let (result, ()) = tokio::join!(
            ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
            peer(rx, script)
        );
        result.expect("current pointer range selects the service");
        let programmed_image = session.images.take_programmed_image();
        assert_eq!(programmed_image.byte(&destination), Some((9, 255)));
        assert_eq!(programmed_image.manifest(), image.manifest());
    }
}

#[tokio::test]
async fn image_window_combines_read_ownership_with_desired_bytes_and_preserves_inline_write_source() {
    let (bus, rx) = bus();
    let mut session = ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).unwrap();
    session.begin_execution();
    let mut desired = SparseDeviceImage::new();
    desired.apply_owned(location(0x101), vec![0x22]).unwrap();
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        ProcedureOperation::LoadImage {
            target: memory(0x100),
            image_location: location(0x100),
            extent: OperationExtent::bytes(1),
            alignment: 1,
        },
        write(memory(0x100), OperationData::Inline(vec![0x77]), 1),
        ProcedureOperation::Write {
            target: memory(0x100),
            data: OperationData::ImageWindow { location: location(0x100), maximum: 3 },
            extent: OperationExtent::bytes(3),
            policy: WriteIntent::Explicit(WritePolicy::NoVerification),
        },
        ProcedureOperation::Disconnect,
    ]);
    let script = vec![
        Wire::Open(false),
        Wire::Memory { address: 0x100, count: 1, write: None, reply: Ok(vec![0xa0]) },
        mem_write(0x100, &[0x77]),
        mem_write(0x100, &[0xa0, 0x22]),
        Wire::Close(Ok(())),
    ];
    let regions = [native(location(0x100), 3)];
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&desired, &regions, &controls, || false, |_| {}),
        peer(rx, script)
    );
    result.unwrap();
    assert_eq!(desired.byte(&location(0x100)), None);
    assert_eq!(session.images.working_byte(&location(0x100)), Some((0xa0, 255)));
    assert_eq!(session.images.working_byte(&location(0x102)), None);
}

#[tokio::test]
async fn absolute_transfers_follow_native_capacity_including_regions_loaded_earlier() {
    for case in ["missing start", "unowned prefix", "adjacent allocations", "earlier load"] {
        let (bus, rx) = bus();
        let mut session =
            ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
        session.begin_execution();
        let mut image = SparseDeviceImage::new();
        image.apply_owned(location(0x202), vec![7, 8]).expect("desired bytes");
        let regions = match case {
            "unowned prefix" => vec![native(location(0x200), 8)],
            "adjacent allocations" => {
                image.apply_owned(location(0x204), vec![9, 10]).expect("adjacent bytes");
                vec![native(location(0x200), 4), native(location(0x204), 4)]
            }
            _ => Vec::new(),
        };
        let mut operations = vec![ProcedureOperation::Connect];
        let mut script = vec![Wire::Open(false)];
        if case == "earlier load" {
            operations.push(ProcedureOperation::LoadImage {
                target: memory(0x200),
                image_location: location(0x200),
                extent: OperationExtent::bytes(8),
                alignment: 1,
            });
            script.push(Wire::Memory {
                address: 0x200,
                count: 8,
                write: None,
                reply: Ok(vec![1, 2, 3, 4, 5, 6, 7, 8]),
            });
        }
        operations.push(ProcedureOperation::AbsoluteSegment {
            record: LoadRecord {
                write: ServiceRead { target: memory(0x100), extent: OperationExtent::bytes(1) },
                bytes: vec![1],
                poll: None,
                effect: LoadEffect::Invalidate { location: location(0x200), length: 8 },
            },
            transfers: vec![MemoryTransfer {
                target: memory(0x200),
                data: OperationData::ImageWindow { location: location(0x200), maximum: 8 },
                extent: OperationExtent::bytes(8),
                policy: WriteIntent::AbsoluteSegment,
            }],
        });
        // The declaration always runs, even when no native allocation contains
        // its start. Owned bytes in an adjacent allocation remain untouched.
        script.push(mem_write(0x100, &[1]));
        if case == "earlier load" {
            // Successful LoadImage owns the entire observed allocation. Desired
            // bytes override the corresponding observations in the payload.
            script.push(Wire::Memory { address: 0x200, count: 8, write: None, reply: Ok(vec![0; 8]) });
            script.push(mem_write(0x200, &[1, 2, 7, 8, 5, 6, 7, 8]));
        } else if case != "missing start" {
            // Default segment policy compares current bytes optimistically,
            // then writes only the differing run without a second read.
            script.push(Wire::Memory { address: 0x202, count: 2, write: None, reply: Ok(vec![0, 0]) });
            script.push(mem_write(0x202, &[7, 8]));
        }
        operations.push(ProcedureOperation::Disconnect);
        script.push(Wire::Close(Ok(())));
        let controls = procedure(operations);
        let (result, ()) = tokio::join!(
            ProcedureRunner::new(&mut session).execute(&image, &regions, &controls, || false, |_| {}),
            peer(rx, script)
        );
        result.unwrap_or_else(|error| panic!("native allocation case {case}: {error}"));
    }
}

#[tokio::test]
async fn network_restart_cannot_resurrect_the_prepared_baseline_when_controls_start() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let mut image = SparseDeviceImage::new();
    image.apply_owned(location(0x100), vec![7]).expect("image");
    session.images.known = image.clone();
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        write(memory(0x100), OperationData::Image { location: location(0x100), length: 1 }, 1),
        ProcedureOperation::Disconnect,
    ]);
    let client = async {
        session.connect().await?;
        session.restart_device(RestartKind::Basic).await?;
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}).await
    };
    let (result, ()) = tokio::join!(
        client,
        peer(rx, vec![
            Wire::Open(false),
            Wire::Restart(Ok(())),
            Wire::Close(Ok(())),
            Wire::Open(false),
            mem_write(0x100, &[7]),
            Wire::Close(Ok(())),
        ])
    );
    result.expect("the post-restart write is required even when the original baseline matched");
}

#[tokio::test]
async fn network_bootstrap_commits_only_confirmed_keys_and_retains_them_after_later_failure() {
    use crate::bus::access::ManagementCredential;
    use zweidraehte_proto::messages::apdu::property_ext::PropertyExtValueRequest;

    for confirmed in [false, true] {
        let (bus, mut channel) =
            KnxBus::scripted(ConnectorInfo { assigned_address: IndividualAddress::new(1, 1, 1), max_apdu: 64 });
        let mut options = config(false);
        options.target_max_apdu = 64;
        let mut session =
            ExecutionSession::new(&bus, address(), options, ManagementAccess::Plaintext).expect("valid config");
        session.begin_execution();
        session.access = ManagementAccess::Fdsk([0xF0; 16].into());
        session.replacement_tool_key = Some([0xA7; 16].into());
        let client = async {
            session.connect().await.expect("session opens");
            let result = async {
                session.bootstrap_tool_key().await?;
                session.advance_sending_sequence(None).await
            }
            .await;
            session.finish(result).await
        };
        let wire = async {
            let BusCommand::SetDeviceSecurity { tx, .. } = channel.recv().await.expect("install FDSK") else {
                panic!("expected selected credential installation");
            };
            tx.send(()).expect("credential installed");
            let BusCommand::TlOpen { tx, .. } = channel.recv().await.expect("open") else {
                panic!("expected open");
            };
            assert!(
                tx.send(Ok(TlOpenResult {
                    connection: crate::bus::driver::ConnectionId::TEST,
                    secure_management: true,
                    remote_next_sequence: None
                }))
                .is_ok()
            );
            let BusCommand::TlToolKeyWrite { frame, new_key, tx, .. } = channel.recv().await.expect("key write") else {
                panic!("expected key write");
            };
            let request = KnxMessageBuffer::from_buffer(frame);
            assert_eq!(request.get_apci_code(), ApciCode::PropertyExtValueWriteCon);
            assert_eq!(new_key, [0xA7; 16]);
            let response = if confirmed {
                Ok(frames::build_individual_frame(
                    address(),
                    IndividualAddress::new(1, 1, 1),
                    Tpci::DataConnected(0),
                    ApciCode::PropertyExtValueWriteConRes,
                    PropertyExtValueRequest::msg_len(1),
                    |buf| PropertyExtValueRequest::write(buf, 17, 1, pid::security::TOOL_KEY, 1, 1, &[0]),
                ))
            } else {
                Err(Error::DeviceError(5))
            };
            tx.send(response).expect("key result");
            if confirmed {
                let BusCommand::TlRequest { frame, tx, .. } = channel.recv().await.expect("sequence read") else {
                    panic!("expected sequence read");
                };
                assert_eq!(KnxMessageBuffer::from_buffer(frame).get_apci_code(), ApciCode::PropertyExtValueRead);
                tx.send(Err(Error::Timeout)).expect("sequence failure");
            }
            let BusCommand::TlClose { tx, .. } = channel.recv().await.expect("mandatory close") else {
                panic!("expected close");
            };
            tx.send(Err(Error::AckTimeout)).expect("close failure");
        };
        let (result, ()) = tokio::join!(client, wire);
        let error = result.expect_err("primary and close fail");
        assert_eq!(error.cleanup_failures.len(), 1);
        assert_eq!(error.cleanup_failures[0].operation, CleanupOperation::Disconnect);
        assert!(session.connection.is_none());
        assert_eq!(session.mutated(), confirmed);
        assert_eq!(
            session.access.credential(),
            if confirmed { ManagementCredential::ToolKey } else { ManagementCredential::Fdsk },
        );
        assert_eq!(
            session.effects.credential_transitions(),
            if confirmed { vec![CredentialTransition::ToolKey] } else { vec![] }
        );

        let (reopened, ()) = tokio::join!(session.connect(), async {
            let BusCommand::SetDeviceSecurity { entry, tx, .. } = channel.recv().await.expect("reconnect credential")
            else {
                panic!("reconnect installs the committed key");
            };
            assert_eq!(entry.tool_key().copied(), confirmed.then_some([0xA7; 16]));
            assert_eq!(entry.fdsk().copied(), (!confirmed).then_some([0xF0; 16]));
            tx.send(()).expect("credential installed");
            let BusCommand::TlOpen { tx, .. } = channel.recv().await.expect("reopen") else {
                panic!("open");
            };
            assert!(
                tx.send(Ok(TlOpenResult {
                    connection: crate::bus::driver::ConnectionId::TEST,
                    secure_management: true,
                    remote_next_sequence: None
                }))
                .is_ok()
            );
        });
        reopened.expect("reconnect uses the confirmed credential");
        let (outcome, ()) = tokio::join!(session.finalize::<()>(Err(error)), async {
            let BusCommand::TlClose { tx, .. } = channel.recv().await.expect("final cleanup") else {
                panic!("close");
            };
            tx.send(Ok(())).expect("cleanup completes");
        });
        let error = outcome.expect_err("original failure remains");
        assert_eq!(
            error.effects().credential_transitions(),
            if confirmed { vec![CredentialTransition::ToolKey] } else { vec![] }
        );
        assert_eq!(error.diagnostic().cleanup_failures.len(), 1);
        assert_eq!(error.diagnostic().cleanup_failures[0].error.transport, Some(TransportCause::Timeout));
    }
}

#[tokio::test]
async fn ignored_factory_reset_failure_and_address_reset_do_not_prove_application_or_key_erasure() {
    use zweidraehte_project::ProgrammingSection;
    for (code, error) in [(2, 2), (3, 0), (2, 0)] {
        let (bus, rx) = bus();
        let mut session =
            ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("session");
        let desired = SparseDeviceImage::new();
        let mut controls = procedure(vec![
            ProcedureOperation::Connect,
            ProcedureOperation::MasterReset { erase_code: code, channel: 0 },
            ProcedureOperation::Disconnect,
        ]);
        controls.steps[1].sections.insert(ProgrammingSection::ApplicationProgram1);
        controls.steps[1]
            .on_error
            .push(ErrorHandler { cause: LoadControlCause::DeviceReturnCode(2), action: ErrorAction::Ignore });
        let (result, ()) = tokio::join!(
            ProcedureRunner::new(&mut session).unloading(true).execute(&desired, &[], &controls, || false, |_| {}),
            peer(rx, vec![Wire::Open(false), Wire::Reset { code, error }, Wire::Close(Ok(()))])
        );
        result.expect("authored failure handler completes the procedure");
        assert_eq!(session.effects.group_keys_erased(), code == 2 && error == 0);
        assert_eq!(
            session.effects.cleared_sections().contains(&ProgrammingSection::ApplicationProgram1),
            code == 2 && error == 0
        );
    }
}

#[tokio::test]
async fn local_property_rejection_preserves_observations_and_cached_reads() {
    for writable in [false, true] {
        let (bus, rx) = bus();
        let mut session =
            ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("session");
        session.images.known.apply_owned(property_location(0), vec![7]).expect("known byte");
        session.images.cache_read(property(1), OperationExtent::property(1, 1), Some(property_location(0)), vec![7]);
        session.property_descriptors.insert(
            PropertyAddress::Indexed { object_index: 3, property_id: 27 },
            PropertyDescriptor {
                property_data_type: "property".into(),
                maximum_elements: if writable { 0 } else { 1 },
                read_access: 0,
                write_access: 0,
                writable,
            },
        );
        let client = async {
            session.connect().await.expect("open");
            let error = session
                .write(
                    &property(1),
                    &[9],
                    OperationExtent::property(1, 1),
                    WritePolicy::NoVerification,
                    TransferContext::Public,
                )
                .await
                .expect_err("locally rejected");
            assert!(error.message.contains(if writable { "maximum" } else { "writable" }));
            session.disconnect().await.expect("close");
        };
        tokio::join!(client, peer(rx, vec![Wire::Open(false), Wire::Close(Ok(()))]));
        assert_eq!(session.images.known.byte(&property_location(0)), Some((7, 255)));
        assert_eq!(session.images.cached(&property(1), OperationExtent::property(1, 1)), Some(vec![7]));
    }
}

#[tokio::test]
async fn final_evidence_requires_a_bound_read_and_survives_an_unobserved_progress_stream() {
    use zweidraehte_project::ProgrammingSection;
    for bound in [false, true] {
        let (bus, rx) = bus();
        let mut session =
            ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("session");
        let mut desired = SparseDeviceImage::new();
        desired.apply_owned(location(0x200), vec![7, 8]).expect("image");
        let mut controls = procedure(vec![
            ProcedureOperation::Connect,
            write(memory(0x200), OperationData::Inline(vec![7]), 1),
            ProcedureOperation::Disconnect,
        ]);
        controls.steps[1].sections.insert(ProgrammingSection::Parameters);
        let reads = [(location(0x200), ServiceRead { target: memory(0x200), extent: OperationExtent::bytes(2) })];
        let mut script = vec![Wire::Open(false), mem_write(0x200, &[7])];
        if bound {
            script.push(Wire::Memory { address: 0x201, count: 1, write: None, reply: Ok(vec![8]) });
        }
        script.push(Wire::Close(Ok(())));
        let (result, ()) = tokio::join!(
            ProcedureRunner::new(&mut session).with_verification_reads(if bound { &reads } else { &[] }).execute(
                &desired,
                &[],
                &controls,
                || false,
                |_| {}
            ),
            peer(rx, script),
        );
        result.expect("procedure finishes");
        let programmed_image = session.images.take_programmed_image();
        assert_eq!(programmed_image.byte(&location(0x201)), bound.then_some((8, 255)));
        assert_eq!(
            *session.effects.affected_sections(),
            std::collections::BTreeSet::from([ProgrammingSection::Parameters])
        );
    }
}

#[tokio::test]
async fn verified_no_write_control_does_not_report_sections_as_mutated() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let mut image = SparseDeviceImage::new();
    image.apply_owned(location(0x200), vec![9]).expect("desired");
    let mut controls = procedure(vec![
        ProcedureOperation::Connect,
        write(memory(0x200), OperationData::Image { location: location(0x200), length: 1 }, 1),
        ProcedureOperation::Disconnect,
    ]);
    controls.steps[1].sections.insert(zweidraehte_project::ProgrammingSection::Parameters);
    let mut events = Vec::new();
    session.images.known = image.clone();
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |event| events.push(event)),
        peer(rx, vec![Wire::Open(false), Wire::Close(Ok(()))])
    );
    result.expect("verified destination needs no write");
    assert!(!events.iter().any(|event| matches!(event, CommissioningEvent::ProgrammingSectionsMutated { .. })));
    assert!(!session.mutated());
}

#[tokio::test]
async fn differential_property_never_splits_changed_elements() {
    let (bus, rx) = bus();
    let mut options = config(false);
    options.minimum_equal_run = 4;
    let mut session =
        ExecutionSession::new(&bus, address(), options, ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let mut image = SparseDeviceImage::new();
    image.apply_owned(property_location(3), vec![1, 9, 1, 2, 2, 2, 3, 3, 3]).expect("desired");
    let mut baseline = SparseDeviceImage::new();
    baseline.apply_owned(property_location(3), vec![1, 1, 1, 2, 2, 2, 3, 3, 3]).expect("baseline");
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        ProcedureOperation::Write {
            target: property(2),
            data: OperationData::Image { location: property_location(3), length: 9 },
            extent: OperationExtent::property(9, 3),
            policy: WriteIntent::Explicit(WritePolicy::NoVerification),
        },
        ProcedureOperation::Disconnect,
    ]);
    session.images.known = baseline;
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            Wire::Property { pid: 27, start: 2, count: 1, write: Some(vec![1, 9, 1]), reply: Ok(vec![1, 9, 1]) },
            Wire::Close(Ok(())),
        ])
    );
    result.expect("one changed byte transfers its complete three-byte element");
}

#[tokio::test]
async fn property_writes_preserve_unrelated_differences_and_forget_possible_object_aliases() {
    use crate::commissioning::catalog::profile::{ObjectSelector, Occurrence};
    use crate::commissioning::image::ImageSpace;

    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let other = ImageLocation {
        space: ImageSpace::Property { object: ObjectSelector::Index { index: 3 }, property_id: 28 },
        offset: 0,
    };
    let alias = ImageLocation {
        space: ImageSpace::Property {
            object: ObjectSelector::Type { object_type: 6, occurrence: Occurrence::Zero },
            property_id: 27,
        },
        offset: 0,
    };
    let mut image = SparseDeviceImage::new();
    image.apply_owned(property_location(0), vec![9, 2, 3]).expect("desired table");
    image.apply_owned(other.clone(), vec![7]).expect("other property");
    session.images.known = image.clone();
    session.images.known.apply_owned(property_location(0), vec![1]).expect("changed first element");
    session.images.known.apply_owned(alias.clone(), vec![1, 2, 3]).expect("possible indexed object alias");
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        ProcedureOperation::Write {
            target: property(1),
            data: OperationData::Image { location: property_location(0), length: 1 },
            extent: OperationExtent::property(1, 1),
            policy: WriteIntent::Explicit(WritePolicy::NoVerification),
        },
        ProcedureOperation::Write {
            target: property(2),
            data: OperationData::Image { location: property_location(1), length: 2 },
            extent: OperationExtent::property(2, 2),
            policy: WriteIntent::Explicit(WritePolicy::NoVerification),
        },
        ProcedureOperation::Write {
            target: OperationTarget::Property {
                address: PropertyAddress::Indexed { object_index: 3, property_id: 28 },
                start_element: 1,
            },
            data: OperationData::Image { location: other.clone(), length: 1 },
            extent: OperationExtent::property(1, 1),
            policy: WriteIntent::Explicit(WritePolicy::NoVerification),
        },
        ProcedureOperation::Disconnect,
    ]);
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![Wire::Open(false), prop_write(27, 9), Wire::Close(Ok(()))])
    );
    result.expect("only the changed element requires a telegram");
    assert_eq!(session.images.known.byte(&alias), None);
    assert_eq!(session.images.known.byte(&property_location(0)), Some((9, 255)));
    assert_eq!(session.images.known.byte(&property_location(1)), Some((2, 255)));
    assert_eq!(session.images.known.byte(&other), Some((7, 255)));
}

#[tokio::test]
async fn final_stamp_width_failure_keeps_confirmed_credential_transition() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let key = session
        .secret_payload
        .insert_with_transitions([7; 16].into(), vec![CredentialTransition::ToolKey])
        .expect("key");
    let mut controls = procedure(vec![
        ProcedureOperation::Connect,
        write(memory(0x200), OperationData::Secret(key), 16),
        ProcedureOperation::ReadIntoImage {
            target: property(1),
            image_location: property_location(0),
            extent: OperationExtent::property(4, 1),
            cache: CachePolicy::Bypass,
            capture_as: None,
        },
        ProcedureOperation::Disconnect,
    ]);
    controls.stamp_output = DownloadStampOutput::ImageProperties(vec![StampDescriptor {
        id: ResourceId("stamp".into()),
        image_location: property_location(0),
        read: ServiceRead { target: property(1), extent: OperationExtent::property(5, 1) },
        optional: false,
    }]);
    let image = SparseDeviceImage::new();
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            mem_write(0x200, &[7; 12]),
            mem_write(0x20c, &[7; 4]),
            prop_read(27, 1, 1, &[9; 4]),
            Wire::Close(Ok(())),
        ])
    );
    result.expect("procedure completes before publication validation");
    let stamp_result = session.images.completed_stamps().map_err(Diagnostic::from);
    let error = stamp_result.expect_err("stamp publication cannot truncate a declared width");
    assert!(error.message.contains("byte length"));
    assert_eq!(session.effects.credential_transitions(), vec![CredentialTransition::ToolKey]);
    assert_eq!(session.effects.mutation_status(), MutationStatus::PartiallyApplied);
}

#[tokio::test]
async fn differential_user_memory_keeps_short_equal_runs_and_twenty_bit_offsets() {
    use crate::commissioning::image::ImageSpace;
    let (bus, rx) = bus();
    let mut options = config(false);
    options.minimum_equal_run = 4;
    let mut session =
        ExecutionSession::new(&bus, address(), options, ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let location = ImageLocation { space: ImageSpace::UserMemory, offset: 0x8fffc };
    let mut image = SparseDeviceImage::new();
    image.apply_owned(location.clone(), vec![1, 1, 9, 1, 1, 1, 1, 8, 1]).expect("desired");
    let mut baseline = SparseDeviceImage::new();
    baseline.apply_owned(location.clone(), vec![1; 9]).expect("baseline");
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        write(
            OperationTarget::Memory { service: MemoryService::User, address: MemoryAddress::Fixed(0x8fffc) },
            OperationData::Image { location, length: 9 },
            9,
        ),
        ProcedureOperation::Disconnect,
    ]);
    session.images.known = baseline;
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            Wire::UserWrite { address: 0x8fffc, data: vec![1, 1, 9] },
            Wire::UserWrite { address: 0x90003, data: vec![8, 1] },
            Wire::Close(Ok(())),
        ])
    );
    result.expect("long equal run skipped without truncating address extension");
}

#[tokio::test]
async fn ignored_readback_mismatch_does_not_reestablish_the_old_differential_base() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let mut image = SparseDeviceImage::new();
    image.apply_owned(location(0x200), vec![9]).expect("desired");
    let mut controls = procedure(vec![
        ProcedureOperation::Connect,
        ProcedureOperation::Write {
            target: memory(0x200),
            data: OperationData::Inline(vec![9]),
            extent: OperationExtent::bytes(1),
            policy: WriteIntent::Explicit(WritePolicy::ReadBack),
        },
        write(memory(0x200), OperationData::Image { location: location(0x200), length: 1 }, 1),
        ProcedureOperation::Disconnect,
    ]);
    controls.steps[1]
        .on_error
        .push(ErrorHandler { cause: LoadControlCause::CompareMismatch, action: ErrorAction::Ignore });
    session.images.known = image.clone();
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            mem_write(0x200, &[9]),
            Wire::Memory { address: 0x200, count: 1, write: None, reply: Ok(vec![8]) },
            mem_write(0x200, &[9]),
            Wire::Close(Ok(())),
        ])
    );
    result.expect("unverified destination is transferred again");
}

#[tokio::test]
async fn error_mapping_matches_exact_code_and_source_control() {
    for (source, code, handled) in [(0x41, 0xf5, true), (0x42, 0xf5, false), (0x41, 0xf4, false)] {
        let (bus, rx) = bus();
        let mut session =
            ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
        session.begin_execution();
        let mut controls = procedure(vec![
            ProcedureOperation::Connect,
            ProcedureOperation::MapError { filter: Some(0x41), original: 0xf5, mapped: 0 },
            write(memory(0x200), OperationData::Inline(vec![1]), 1),
            ProcedureOperation::Disconnect,
        ]);
        controls.steps[2].source_control_code = Some(source);
        let image = SparseDeviceImage::new();
        let (result, ()) = tokio::join!(
            ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
            peer(rx, vec![
                Wire::Open(false),
                Wire::Memory { address: 0x200, count: 1, write: Some(vec![1]), reply: Err(Error::DeviceError(code)) },
                Wire::Close(Ok(())),
            ])
        );
        if handled {
            assert_eq!(result.expect("matching error mapped").mapped_errors, vec![(0xf5, 0)]);
        } else {
            assert_eq!(result.expect_err("another source or code is not mapped").device_return_code(), Some(code));
        }
    }
}

fn compare(target: OperationTarget) -> ProcedureOperation {
    ProcedureOperation::Compare {
        target,
        comparison: Comparison::Exact {
            data: OperationData::Inline(vec![1]),
            mask: None,
            padding: ComparisonPadding::None,
        },
        extent: OperationExtent::bytes(1),
        cache: CachePolicy::Bypass,
        invert: false,
        retry_interval_milliseconds: Some(0),
        timeout_milliseconds: Some(60_000),
    }
}

#[tokio::test]
async fn zero_mask_comparisons_skip_source_resolution_and_device_reads_even_when_inverted() {
    for target in [memory(0x200), OperationTarget::Memory {
        service: MemoryService::Classic,
        address: MemoryAddress::Pointer {
            read: Box::new(ServiceRead {
                target: OperationTarget::Property {
                    address: PropertyAddress::Indexed { object_index: 4, property_id: 7 },
                    start_element: 1,
                },
                extent: OperationExtent::property(4, 1),
            }),
            space: ImageSpace::RelativeMemory { object: ObjectSelector::Index { index: 4 } },
            offset: 0,
            encoding: crate::commissioning::procedure::operands::PointerEncoding::Absolute,
        },
    }] {
        for invert in [false, true] {
            for data in [OperationData::Inline(vec![0xa0]), OperationData::Buffer {
                location: location(0x200),
                length: 1,
                fallback: None,
            }] {
                let (bus, rx) = bus();
                let mut session = ExecutionSession::new(&bus, address(), config(true), ManagementAccess::Plaintext)
                    .expect("valid config");
                let image = SparseDeviceImage::new();
                let controls = procedure(vec![
                    ProcedureOperation::Connect,
                    ProcedureOperation::Compare {
                        target: target.clone(),
                        comparison: Comparison::Exact { data, mask: Some(vec![0]), padding: ComparisonPadding::None },
                        extent: OperationExtent::bytes(1),
                        cache: CachePolicy::UseAndPopulate,
                        invert,
                        retry_interval_milliseconds: Some(1),
                        timeout_milliseconds: Some(1000),
                    },
                    ProcedureOperation::Disconnect,
                ]);
                let (result, ()) = tokio::join!(
                    ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
                    peer(rx, vec![Wire::Open(false), Wire::Close(Ok(()))])
                );
                result.expect("zero selected bits complete without comparing or resolving missing image data");
                assert!(session.images.working.is_empty());
                assert!(session.current_device_control.is_none(), "no verify-mode change");
            }
        }
    }
}

#[tokio::test]
async fn image_only_comparisons_do_not_fill_reference_bits_from_the_device() {
    for property_target in [false, true] {
        for authored in [None, Some(vec![255; 3]), Some(vec![15; 3])] {
            let (bus, rx) = bus();
            let mut session =
                ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).unwrap();
            let at = if property_target { property_location(0) } else { location(0x100) };
            let target = if property_target { property(1) } else { memory(0x100) };
            let extent = if property_target { OperationExtent::property(3, 1) } else { OperationExtent::bytes(3) };
            let mut image = SparseDeviceImage::new();
            image.apply(
                &crate::commissioning::image::ImageSegment::new(at.clone(), vec![0x40, 0x41, 0x42], vec![15; 3])
                    .unwrap(),
            );
            let before = image.clone();
            let compare = |cache| ProcedureOperation::Compare {
                target: target.clone(),
                comparison: Comparison::ImageExact { location: at.clone(), length: 3, mask: authored.clone() },
                extent,
                cache,
                invert: false,
                retry_interval_milliseconds: None,
                timeout_milliseconds: None,
            };
            let controls = procedure(vec![
                ProcedureOperation::Connect,
                compare(CachePolicy::Populate),
                compare(CachePolicy::UseAndPopulate),
                ProcedureOperation::Disconnect,
            ]);
            let read = if property_target {
                Wire::Property { start: 1, count: 1, pid: 27, write: None, reply: Ok(vec![0xa0, 0xa1, 0xa2]) }
            } else {
                Wire::Memory { address: 0x100, count: 3, write: None, reply: Ok(vec![0xa0, 0xa1, 0xa2]) }
            };
            let (result, ()) = tokio::join!(
                ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
                peer(rx, vec![Wire::Open(false), read, Wire::Close(Ok(()))])
            );
            result.expect("only one value read, with image-owned low bits compared; the second compare is cached");
            assert_eq!(image, before);
            assert!(session.images.working.is_empty(), "comparison is read-only");
        }
    }
}

#[tokio::test]
async fn image_reference_ownership_changes_after_a_successful_image_load() {
    let (bus, rx) = bus();
    let mut session = ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).unwrap();
    let mut image = SparseDeviceImage::new();
    image.apply(
        &crate::commissioning::image::ImageSegment::new(location(0x100), vec![0x40, 0x41, 0x42], vec![15; 3]).unwrap(),
    );
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        ProcedureOperation::LoadImage {
            target: memory(0x100),
            image_location: location(0x100),
            extent: OperationExtent::bytes(3),
            alignment: 1,
        },
        ProcedureOperation::Compare {
            target: memory(0x100),
            comparison: Comparison::ImageExact { location: location(0x100), length: 3, mask: None },
            extent: OperationExtent::bytes(3),
            cache: CachePolicy::Populate,
            invert: true,
            retry_interval_milliseconds: None,
            timeout_milliseconds: None,
        },
        ProcedureOperation::Disconnect,
    ]);
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            Wire::Memory { address: 0x100, count: 3, write: None, reply: Ok(vec![0xa0, 0xa1, 0xa2]) },
            Wire::Memory { address: 0x100, count: 3, write: None, reply: Ok(vec![0xb0, 0xb1, 0xb2]) },
            Wire::Close(Ok(()))
        ])
    );
    result.expect("LoadImage makes observed high bits part of the later comparison");
    assert_eq!(session.images.complete_working(&location(0x100), 3), Some(vec![0xa0, 0xa1, 0xa2]));
}

#[tokio::test]
async fn empty_image_comparison_selection_skips_memory_reads_and_inversion() {
    for authored in [None, Some(vec![255; 3]), Some(vec![0; 3])] {
        let (bus, rx) = bus();
        let mut session = ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).unwrap();
        let image = SparseDeviceImage::new();
        let regions = [crate::commissioning::image::NativeImageRegion {
            source_id: None,
            memory_type: None,
            seed: vec![0x40; 3],
            location: location(0x100),
            length: 3,
        }];
        let controls = procedure(vec![
            ProcedureOperation::Connect,
            ProcedureOperation::Compare {
                target: memory(0x100),
                comparison: Comparison::ImageExact { location: location(0x100), length: 3, mask: authored },
                extent: OperationExtent::bytes(3),
                cache: CachePolicy::UseAndPopulate,
                invert: true,
                retry_interval_milliseconds: Some(1),
                timeout_milliseconds: Some(1000),
            },
            ProcedureOperation::Disconnect,
        ]);
        let (result, ()) = tokio::join!(
            ProcedureRunner::new(&mut session).execute(&image, &regions, &controls, || false, |_| {}),
            peer(rx, vec![Wire::Open(false), Wire::Close(Ok(()))])
        );
        result.expect("an empty image mask selects no comparison bits");
    }
}

#[tokio::test]
async fn property_comparison_uses_loaded_ownership_before_inline_fallback_and_keeps_cache_separate() {
    for missing in [false, true] {
        let count = if missing { 2 } else { 1 };
        let length = 3 * u32::from(count);
        let start = if missing { 3 } else { 1 };
        let loaded: Vec<_> = (0xa0..0xa0 + length as u8).collect();
        let compared: Vec<_> = (0xb1..0xb1 + length as u8).collect();
        for fallback in [None, Some(vec![0xc0; length as usize])] {
            let (bus, rx) = bus();
            let mut session =
                ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).unwrap();
            let at = property_location(if missing { 6 } else { 0 });
            let mut image = SparseDeviceImage::new();
            if !missing {
                image.apply(
                    &crate::commissioning::image::ImageSegment::new(
                        at.clone(),
                        (0x40..0x40 + length as u8).collect(),
                        vec![15; length as usize],
                    )
                    .unwrap(),
                );
            }
            let comparison = match fallback {
                None => Comparison::ImageExact { location: at.clone(), length, mask: Some(vec![15; length as usize]) },
                Some(bytes) => Comparison::Exact {
                    data: OperationData::Buffer { location: at.clone(), length, fallback: Some(bytes) },
                    mask: Some(vec![15; length as usize]),
                    padding: ComparisonPadding::None,
                },
            };
            let compare = |cache| ProcedureOperation::Compare {
                target: property(start),
                comparison: comparison.clone(),
                extent: OperationExtent::property(length, count),
                cache,
                invert: true,
                retry_interval_milliseconds: None,
                timeout_milliseconds: None,
            };
            let controls = procedure(vec![
                ProcedureOperation::Connect,
                ProcedureOperation::LoadImage {
                    target: property(start),
                    image_location: at.clone(),
                    extent: OperationExtent::property(length, count),
                    alignment: 3,
                },
                compare(CachePolicy::Populate),
                compare(CachePolicy::UseAndPopulate),
                ProcedureOperation::Disconnect,
            ]);
            let (result, ()) = tokio::join!(
                ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
                peer(rx, vec![
                    Wire::Open(false),
                    Wire::Property { start, count, pid: 27, write: None, reply: Ok(loaded.clone()) },
                    Wire::Property { start, count, pid: 27, write: None, reply: Ok(compared.clone()) },
                    Wire::Close(Ok(()))
                ])
            );
            result.expect("LoadImage is not a comparison cache entry; both later comparisons use the loaded reference");
            assert_eq!(session.images.complete_working(&at, length), Some(loaded.clone()));
        }
    }
}

#[tokio::test]
async fn compare_observations_are_cached_without_changing_the_working_image() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    let image = SparseDeviceImage::new();
    let make_compare = |cache| ProcedureOperation::Compare {
        target: memory(0x100),
        comparison: Comparison::Exact {
            data: OperationData::Inline(vec![0xa0]),
            mask: None,
            padding: ComparisonPadding::None,
        },
        extent: OperationExtent::bytes(1),
        cache,
        invert: false,
        retry_interval_milliseconds: None,
        timeout_milliseconds: None,
    };
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        make_compare(CachePolicy::Populate),
        make_compare(CachePolicy::UseAndPopulate),
        ProcedureOperation::Disconnect,
    ]);
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            Wire::Memory { address: 0x100, count: 1, write: None, reply: Ok(vec![0xa0]) },
            Wire::Close(Ok(()))
        ])
    );
    result.expect("the second comparison uses the first observation without another read");
    assert!(session.images.working.is_empty());
}

#[tokio::test]
async fn property_chunks_keep_complete_elements_and_original_start() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let bytes = (1..=18).collect::<Vec<_>>();
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        ProcedureOperation::Write {
            target: property(2),
            data: OperationData::Inline(bytes.clone()),
            extent: OperationExtent::property(18, 6),
            policy: WriteIntent::Explicit(WritePolicy::NoVerification),
        },
        ProcedureOperation::Disconnect,
    ]);
    let image = SparseDeviceImage::new();
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            Wire::Property {
                pid: 27,
                start: 2,
                count: 3,
                write: Some(bytes[..9].to_vec()),
                reply: Ok(bytes[..9].to_vec())
            },
            Wire::Property {
                pid: 27,
                start: 5,
                count: 3,
                write: Some(bytes[9..].to_vec()),
                reply: Ok(bytes[9..].to_vec())
            },
            Wire::Close(Ok(())),
        ])
    );
    result.expect("two complete three-element writes");
}

#[tokio::test]
async fn masked_memory_write_preserves_unowned_device_bits() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let mut image = SparseDeviceImage::new();
    image.apply(&ImageSegment::new(location(0x200), vec![5, 6], vec![15, 15]).expect("masked range"));
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        write(memory(0x200), OperationData::Image { location: location(0x200), length: 2 }, 2),
        ProcedureOperation::Disconnect,
    ]);
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            Wire::Memory { address: 0x200, count: 2, write: None, reply: Ok(vec![0xa0, 0xb0]) },
            mem_write(0x200, &[0xa5, 0xb6]),
            Wire::Close(Ok(())),
        ])
    );
    result.expect("masked bits merge from a successful read");
    assert_eq!(image.range(&location(0x200), 2).expect("desired range").data(), &[5, 6]);
}

#[tokio::test]
async fn repeated_masked_writes_preserve_fresh_unowned_device_bits() {
    for data in [
        OperationData::Image { location: location(0x200), length: 2 },
        OperationData::Buffer { location: location(0x200), length: 2, fallback: None },
        OperationData::ImageWindow { location: location(0x200), maximum: 2 },
    ] {
        let (bus, rx) = bus();
        let mut options = config(false);
        // Match the public commissioning default: a two-byte equal run remains
        // part of a transfer. Otherwise skipping the whole write hides stale bits.
        options.minimum_equal_run = 4;
        let mut session =
            ExecutionSession::new(&bus, address(), options, ManagementAccess::Plaintext).expect("valid config");
        session.begin_execution();
        let mut image = SparseDeviceImage::new();
        image.apply(&ImageSegment::new(location(0x200), vec![5, 6], vec![15, 15]).expect("masked range"));
        let controls = procedure(vec![
            ProcedureOperation::Connect,
            write(memory(0x200), data.clone(), 2),
            write(memory(0x200), data, 2),
            ProcedureOperation::Disconnect,
        ]);
        let (result, ()) = tokio::join!(
            ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
            peer(rx, vec![
                Wire::Open(false),
                Wire::Memory { address: 0x200, count: 2, write: None, reply: Ok(vec![0xa0, 0xa0]) },
                mem_write(0x200, &[0xa5, 0xa6]),
                // Firmware changes only the unowned high bits between transfers.
                // Hawk reads again and writes B5/B6, keeping desired ownership 0F.
                Wire::Memory { address: 0x200, count: 2, write: None, reply: Ok(vec![0xb5, 0xb6]) },
                mem_write(0x200, &[0xb5, 0xb6]),
                Wire::Close(Ok(())),
            ])
        );
        result.expect("each masked write merges fresh unowned device bits");
        assert!(session.images.working.is_empty(), "device writes leave the source image unchanged");
        let desired = image.range(&location(0x200), 2).expect("desired range");
        assert_eq!(desired.data(), &[5, 6]);
        assert_eq!(desired.mask(), &[15, 15]);
    }
}

#[tokio::test]
async fn buffered_fallback_write_preserves_later_desired_source() {
    let (bus, rx) = bus();
    let mut options = config(false);
    options.minimum_equal_run = 4;
    let mut session =
        ExecutionSession::new(&bus, address(), options, ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let mut image = SparseDeviceImage::new();
    image.apply_owned(location(0x200), vec![5, 6]).expect("complete desired source");

    // A bound fallback can differ from desired data. Writing it to a device
    // must not replace the source used by a later image-backed operation.
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        write(
            memory(0x200),
            OperationData::Buffer { location: location(0x200), length: 2, fallback: Some(vec![7, 8]) },
            2,
        ),
        write(memory(0x200), OperationData::Image { location: location(0x200), length: 2 }, 2),
        ProcedureOperation::Disconnect,
    ]);
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![Wire::Open(false), mem_write(0x200, &[7, 8]), mem_write(0x200, &[5, 6]), Wire::Close(Ok(()))])
    );
    result.expect("the second write uses the original desired bytes");
    assert!(session.images.working.is_empty(), "a fallback write does not create working source bytes");
}

#[tokio::test]
async fn copying_working_data_compares_destination_knowledge_only() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let image = SparseDeviceImage::new();
    let regions = vec![native(property_location(0), 2)];
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        load(0, 2, 1),
        write(memory(0x200), OperationData::Image { location: property_location(0), length: 2 }, 2),
        write(memory(0x200), OperationData::Image { location: property_location(0), length: 2 }, 2),
        ProcedureOperation::Disconnect,
    ]);
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &regions, &controls, || false, |_| {}),
        peer(
            rx,
            vec![Wire::Open(false), prop_read(27, 1, 2, &[8, 9]), mem_write(0x200, &[8, 9]), Wire::Close(Ok(())),]
        )
    );
    result.expect("first destination copy writes; confirmed second copy skips");
}

#[tokio::test]
async fn loaded_buffer_survives_cache_clear_and_later_device_write() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let mut image = SparseDeviceImage::new();
    image.apply(&ImageSegment::new(property_location(0), vec![5; 8], vec![15; 8]).expect("masked range"));
    let controls = procedure(vec![
        ProcedureOperation::Connect,
        load(0, 8, 8),
        ProcedureOperation::Write {
            target: property(1),
            data: OperationData::Inline(vec![255; 8]),
            extent: OperationExtent::property(8, 1),
            policy: WriteIntent::Explicit(WritePolicy::NoVerification),
        },
        ProcedureOperation::ClearCache,
        load(0, 8, 8),
        write(memory(0x200), OperationData::Image { location: property_location(0), length: 8 }, 8),
        ProcedureOperation::Disconnect,
    ]);
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            prop_read(27, 1, 1, &[0xa0; 8]),
            Wire::Property { pid: 27, start: 1, count: 1, write: Some(vec![255; 8]), reply: Ok(vec![255; 8]) },
            mem_write(0x200, &[0xa5; 8]),
            Wire::Close(Ok(())),
        ])
    );
    result.expect("loaded tool buffer outlives read cache and device changes");
}

#[tokio::test]
async fn cancellation_stops_comparison_retry_and_restores_device_mode() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(true), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let mut controls =
        procedure(vec![ProcedureOperation::Connect, compare(memory(0x200)), ProcedureOperation::Disconnect]);
    controls.initial_state.memory_auto_verify = Some(true);
    controls.steps[1]
        .on_error
        .push(ErrorHandler { cause: LoadControlCause::CompareMismatch, action: ErrorAction::Ignore });
    let calls = Cell::new(0);
    let cancel = || {
        let count = calls.get() + 1;
        calls.set(count);
        count >= 5
    };
    let image = SparseDeviceImage::new();
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, cancel, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            prop_read(pid::DEVICE_CONTROL, 1, 1, &[0]),
            prop_write(pid::DEVICE_CONTROL, 4),
            Wire::Memory { address: 0x200, count: 1, write: None, reply: Ok(vec![0]) },
            prop_write(pid::DEVICE_CONTROL, 0),
            Wire::Close(Ok(())),
        ])
    );
    let error = result.expect_err("authored handler cannot suppress cancellation");
    assert!(error.message.contains("cancelled"));
    assert_eq!(session.effects.mutation_status(), MutationStatus::PartiallyApplied);
}

#[tokio::test]
async fn failed_restore_and_disconnect_both_survive_primary_comparison_error() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(true), ManagementAccess::Plaintext).expect("valid config");
    session.begin_execution();
    let mut comparison = compare(memory(0x200));
    if let ProcedureOperation::Compare { timeout_milliseconds, .. } = &mut comparison {
        *timeout_milliseconds = None;
    }
    let mut controls = procedure(vec![ProcedureOperation::Connect, comparison, ProcedureOperation::Disconnect]);
    controls.initial_state.memory_auto_verify = Some(true);
    let image = SparseDeviceImage::new();
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            prop_read(pid::DEVICE_CONTROL, 1, 1, &[0]),
            prop_write(pid::DEVICE_CONTROL, 4),
            Wire::Memory { address: 0x200, count: 1, write: None, reply: Ok(vec![0]) },
            Wire::Property {
                pid: pid::DEVICE_CONTROL,
                start: 1,
                count: 1,
                write: Some(vec![0]),
                reply: Err(Error::Timeout)
            },
            Wire::Close(Err(Error::Disconnected)),
        ])
    );
    let error = result.expect_err("read mismatch and both cleanup failures retained");
    assert_eq!(error.load_control_cause, Some(LoadControlCause::CompareMismatch));
    let cleanup = &error.cleanup_failures[0].error;
    assert!(cleanup.cleanup_failures.iter().any(|failure| failure.operation == CleanupOperation::RestoreDeviceState
        && failure.error.transport == Some(TransportCause::Timeout)));
    assert!(cleanup.cleanup_failures.iter().any(|failure| failure.operation == CleanupOperation::Disconnect
        && failure.error.transport == Some(TransportCause::ConnectionClosed)));
}
#[tokio::test]
async fn split_group_key_writes_report_only_successful_or_uncertain_rows() {
    use zweidraehte_proto::address::GroupAddress;

    for (failed_row, uncertain, ignored) in [
        (Some(0), false, false),
        (Some(1), false, false),
        (Some(1), true, false),
        (Some(1), false, true),
        (None, false, false),
    ] {
        let (bus, rx) = KnxBus::scripted(ConnectorInfo { assigned_address: address(), max_apdu: 23 });
        let mut config = config(false);
        config.target_max_apdu = 23;
        let mut session = ExecutionSession::new(&bus, address(), config, ManagementAccess::Plaintext)
            .expect("one complete key row fits");
        session.begin_execution();
        let groups = (1..=3).map(|number| GroupAddress::from_three_level(1, 1, number)).collect::<Vec<_>>();
        let bytes = (1..=3).flat_map(|number| [number; 18]).collect::<Vec<_>>();
        let secret = session.secret_payload.insert_group_keys(bytes.into(), groups.clone()).expect("three key rows");
        let mut controls = procedure(vec![
            ProcedureOperation::Connect,
            ProcedureOperation::Write {
                target: property(1),
                data: OperationData::Secret(secret),
                extent: OperationExtent::property(54, 3),
                policy: WriteIntent::Explicit(WritePolicy::NoVerification),
            },
            ProcedureOperation::Disconnect,
        ]);
        if ignored {
            controls.steps[1]
                .on_error
                .push(ErrorHandler { cause: LoadControlCause::DeviceReturnCode(2), action: ErrorAction::Ignore });
        }
        let mut wire = vec![Wire::Open(false)];
        for row in 0..3 {
            let failed = failed_row == Some(row);
            wire.push(Wire::Property {
                start: row as u16 + 1,
                count: 1,
                pid: 27,
                write: Some(vec![row as u8 + 1; 18]),
                reply: if failed {
                    Err(if uncertain { Error::Timeout } else { Error::DeviceError(2) })
                } else {
                    // A classic property confirmation carries complete values,
                    // even when the private write does not request readback.
                    Ok(vec![row as u8 + 1; 18])
                },
            });
            if failed {
                break;
            }
        }
        wire.push(Wire::Close(Ok(())));
        let image = SparseDeviceImage::new();
        let (result, ()) = tokio::join!(
            ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
            peer(rx, wire)
        );
        let exposed = failed_row.map_or(3, |row| row + usize::from(uncertain));
        let expected = groups[..exposed].iter().copied().collect::<BTreeSet<_>>();
        if failed_row.is_some() && !ignored {
            result.expect_err("split table fails at the scripted row");
            assert_eq!(*session.effects.group_key_exposures(), expected);
            assert!(session.effects.credential_transitions().is_empty());
        } else {
            result.expect("successful or explicitly ignored table control");
        }
        assert_eq!(*session.effects.group_key_exposures(), expected);
        assert!(session.effects.credential_transitions().is_empty());
        assert_eq!(session.secret_payload.resolve(secret).expect("payload restored after every result").len(), 54);
    }
}
#[test]
fn differential_and_optimistic_ranges_keep_their_distinct_equal_edge_policies() {
    use super::super::super::data::changed_ranges;

    let equal = [true, false, true, true, true, false, true];
    assert_eq!(changed_ranges(7, 4, false, |index| equal[index]), [0..7]);
    assert_eq!(changed_ranges(7, 4, true, |index| equal[index]), [1..6]);
    assert_eq!(changed_ranges(7, 3, false, |index| equal[index]), [0..2, 5..7]);
    assert_eq!(changed_ranges(7, 3, true, |index| equal[index]), [1..2, 5..6]);
    assert_eq!(changed_ranges(2, 3, false, |_| true), [0..2]);
    assert!(changed_ranges(2, 3, true, |_| true).is_empty());
    assert!(changed_ranges(0, 3, false, |_| false).is_empty());
}
#[tokio::test]
async fn address_write_status_survives_failed_verification_and_cleanup_tries_both_addresses() {
    use crate::bus::access::ManagementCredential;
    use crate::commissioning::catalog::profile::{ProfileDiscovery, ProfileRequest, VariantHint};
    use crate::commissioning::compiler::compile_fixture;
    use crate::commissioning::input::CompileOptions;
    use crate::commissioning::input::facts::{ObservedTarget, ProgrammingFacts};
    use crate::commissioning::input::{CommissioningIntent, ProgrammingInput, TargetSelection};
    use crate::configuration::ResolvedKeyMaterial;
    use crate::configuration::{LoweredDeviceConfiguration, MaterializedDevice};
    use zweidraehte_ets_files::product::ProductData;

    let desired = IndividualAddress::new(1, 1, 11);
    let catalog = observation_catalog(
        r#"<Resource Name="ProgrammingMode" Access="remote">
        <Location AddressSpace="SystemProperty" InterfaceObjectRef="3" PropertyID="54" StartAddress="0"/>
        <ResourceType Length="1"/></Resource>"#,
    );
    let profile = catalog
        .resolve(ProfileRequest {
            discovery: ProfileDiscovery { dd0: 0x0012, management_descriptor_01: None, management_style: None },
            product: None,
            variant_hint: VariantHint::Automatic,
        })
        .expect("addressing profile");
    let mut input = ProgrammingInput::new(
        MaterializedDevice::new(
            ProductData::default().with_fixture_mask_version_id("MV-0012"),
            LoweredDeviceConfiguration::new(desired, Some(15)),
            Vec::new(),
            ResolvedKeyMaterial::new(None),
        ),
        CommissioningIntent::AssignAddress,
        CompileOptions {
            target: TargetSelection::KnownPreviousAddress(address()),
            automatic_sections: None,
            progress_messages_by_reference: Default::default(),
            progress_messages_by_id: Default::default(),
        },
    );
    input.facts = ProgrammingFacts::new(ObservedTarget {
        previous_address: address(),
        serial_number: None,
        credential: ManagementCredential::Plaintext,
    });
    let plan = compile_fixture(input, profile).expect("ordinary address assignment compiles");

    for confirmed_send in [false, true] {
        let (bus, rx) = bus();
        let mut session =
            ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("session");
        session.begin_execution();
        let mut script = vec![
            Wire::Open(false),
            prop_read(54, 1, 1, &[1]),
            Wire::Close(Ok(())),
            Wire::AddressScan(Ok(vec![address()])),
            Wire::AddressWrite {
                address: desired,
                result: if confirmed_send { Ok(()) } else { Err(Error::NegativeConfirmation) },
            },
        ];
        if confirmed_send {
            script.push(Wire::AddressScan(Err(Error::Timeout)));
        }
        for candidate in [address(), desired] {
            script.extend([
                Wire::OpenAt(candidate),
                prop_read(54, 1, 1, &[1]),
                prop_write(54, 0),
                prop_read(54, 1, 1, &[0]),
                Wire::Close(Ok(())),
            ]);
        }
        let ((_error, cleanup), ()) = tokio::join!(
            async {
                let mut cleanup_armed = false;
                let error =
                    session.assign_address(&plan, &mut cleanup_armed).await.expect_err("assignment is unverified");
                assert!(cleanup_armed, "an already enabled mode still creates a restoration obligation");
                let expected =
                    if confirmed_send { MutationStatus::PartiallyApplied } else { MutationStatus::NoConfirmedMutation };
                assert_eq!(session.effects.mutation_status(), expected);
                assert_eq!(session.mutation_status(), expected);
                let cleanup = session.best_effort_disable_programming_mode(&plan, [address(), desired]).await;
                (error, cleanup)
            },
            peer(rx, script)
        );
        assert!(cleanup.is_empty(), "both possible addresses are restored");
        assert!(session.connection.is_none());
        assert!(session.mutated(), "cleanup writes are physical mutations too");
        assert_eq!(session.effects.mutation_status(), MutationStatus::PartiallyApplied);
    }
}

#[tokio::test]
async fn discovery_tries_tool_key_then_fdsk_then_permitted_plaintext() {
    use crate::bus::access::ManagementCredential;
    use crate::commissioning::runtime::commissioner::Commissioner;
    use crate::commissioning::runtime::credentials::ManagementAccessOptions;
    use crate::commissioning::runtime::prepare::profile::AcquiredTarget;
    use crate::configuration::ResolvedKeyMaterial;
    use crate::security::DeviceSecurityMode;

    for allow_plaintext in [false, true] {
        for accepted in [Some(0), Some(1), Some(2), None] {
            let (bus, mut channel) =
                KnxBus::scripted(ConnectorInfo { assigned_address: IndividualAddress::new(1, 1, 1), max_apdu: 64 });
            let commissioner = Commissioner::new(&bus);
            let serial = [1, 2, 3, 4, 5, 6];
            let material =
                ResolvedKeyMaterial::new(Some(serial)).with_tool_key(Some([0xA7; 16])).with_fdsk(Some([0xF0; 16]));
            let policy = ManagementAccessOptions::new().allow_plaintext(allow_plaintext);
            let expected = accepted.filter(|index| *index < 2 || allow_plaintext);
            let client = async {
                let mut session = commissioner
                    .select_management_session(
                        AcquiredTarget { address: address(), serial_number: Some(serial) },
                        &material,
                        &policy,
                    )
                    .await?;
                let credential = session.selected_credential();
                session.disconnect().await?;
                Ok::<_, crate::commissioning::Diagnostic>(credential)
            };
            let wire = async {
                for index in 0..if allow_plaintext { 3 } else { 2 } {
                    if index == 2 {
                        let BusCommand::RemoveDeviceSecurity { tx, .. } =
                            channel.recv().await.expect("plaintext candidate")
                        else {
                            panic!("plaintext clears secure credentials")
                        };
                        tx.send(()).expect("plaintext selected");
                    } else {
                        let BusCommand::SetDeviceSecurity { entry, tx, .. } = channel.recv().await.expect("candidate")
                        else {
                            panic!("credential")
                        };
                        assert_eq!(entry.serial(), Some(serial));
                        assert_eq!(entry.mode(), DeviceSecurityMode::Secure);
                        assert_eq!(entry.tool_key().copied(), (index == 0).then_some([0xA7; 16]));
                        assert_eq!(entry.fdsk().copied(), Some([0xF0; 16]));
                        tx.send(()).expect("candidate installed");
                    }
                    let BusCommand::TlOpen { tx, .. } = channel.recv().await.expect("candidate open") else {
                        panic!("open");
                    };
                    if expected == Some(index) {
                        assert!(
                            tx.send(Ok(TlOpenResult {
                                connection: crate::bus::driver::ConnectionId::TEST,
                                secure_management: index != 2,
                                remote_next_sequence: None
                            }))
                            .is_ok()
                        );
                        let BusCommand::TlClose { tx, .. } = channel.recv().await.expect("close selected session")
                        else {
                            panic!("close");
                        };
                        tx.send(Ok(())).expect("closed");
                        break;
                    }
                    assert!(tx.send(Err(Error::Timeout)).is_ok());
                }
                assert!(channel.try_recv().is_err(), "no additional credential attempt");
            };
            let (result, ()) = tokio::join!(client, wire);
            assert_eq!(result.is_ok(), expected.is_some());
            if let Some(index) = expected {
                assert_eq!(
                    result.expect("selected candidate"),
                    [ManagementCredential::ToolKey, ManagementCredential::Fdsk, ManagementCredential::Plaintext][index]
                );
            }
        }
    }
}

#[tokio::test]
async fn finalization_publishes_effects_after_success_or_primary_and_cleanup_failure() {
    use crate::commissioning::AddressAssignment;
    use zweidraehte_project::ProgrammingSection;
    for fails in [false, true] {
        let (bus, rx) = bus();
        let mut session =
            ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("session");
        session.begin_execution();
        let assigned = AddressAssignment {
            previous: IndividualAddress::new(1, 1, 2),
            current: address(),
            serial_number: Some([1, 2, 3, 4, 5, 6]),
            changed: true,
        };
        // The application phase inherits a confirmed network assignment.
        session.effects.confirm_address(assigned);
        let client = async {
            session.connect().await.expect("connection");
            let result = session
                .write(
                    &memory(0x200),
                    &[7],
                    OperationExtent::bytes(1),
                    WritePolicy::NoVerification,
                    TransferContext::Public,
                )
                .await;
            session.effects.record_sections([ProgrammingSection::Parameters]);
            session.finalize(result).await
        };
        let wire = peer(rx, vec![
            Wire::Open(false),
            Wire::Memory {
                address: 0x200,
                count: 1,
                write: Some(vec![7]),
                reply: if fails { Err(Error::Timeout) } else { Ok(Vec::new()) },
            },
            Wire::Close(if fails { Err(Error::AckTimeout) } else { Ok(()) }),
        ]);
        let (outcome, ()) = tokio::join!(client, wire);
        let effects = if fails {
            let error = outcome.expect_err("primary and cleanup fail");
            assert_eq!(error.diagnostic().cleanup_failures.len(), 1);
            assert_eq!(error.diagnostic().cleanup_failures[0].error.transport, Some(TransportCause::Timeout));
            assert_eq!(error.effects().mutation_status(), MutationStatus::PartiallyApplied);
            error.effects().clone()
        } else {
            let (_, _, effects) = outcome.expect("successful finalization");
            assert_eq!(effects.mutation_status(), MutationStatus::Complete);
            effects
        };
        assert_eq!(effects.address_assignment(), Some(assigned));
        assert_eq!(effects.learned_target().expect("recoverable identity").serial_number, assigned.serial_number);
        assert_eq!(
            effects.affected_sections(),
            &BTreeSet::from([ProgrammingSection::Address, ProgrammingSection::Parameters])
        );
    }
}

// A program-version (PID 13) mismatch carries no error cause, so a
// CompareMismatch handler that applies to any other property comparison
// does not catch it.
#[tokio::test]
async fn program_version_mismatch_escapes_its_compare_mismatch_handler() {
    let (bus, rx) = bus();
    let mut session =
        ExecutionSession::new(&bus, address(), config(false), ManagementAccess::Plaintext).expect("valid config");
    let compare = |property_id| ProcedureOperation::Compare {
        target: OperationTarget::Property {
            address: PropertyAddress::Indexed { object_index: 3, property_id },
            start_element: 1,
        },
        comparison: Comparison::Exact {
            data: OperationData::Inline(vec![5]),
            mask: None,
            padding: ComparisonPadding::None,
        },
        extent: OperationExtent::property(1, 1),
        cache: CachePolicy::Bypass,
        invert: false,
        retry_interval_milliseconds: None,
        timeout_milliseconds: None,
    };
    let mut controls =
        procedure(vec![ProcedureOperation::Connect, compare(27), compare(13), ProcedureOperation::Disconnect]);
    for step in [1, 2] {
        controls.steps[step]
            .on_error
            .push(ErrorHandler { cause: LoadControlCause::CompareMismatch, action: ErrorAction::Ignore });
    }

    let image = SparseDeviceImage::new();
    let (result, ()) = tokio::join!(
        ProcedureRunner::new(&mut session).execute(&image, &[], &controls, || false, |_| {}),
        peer(rx, vec![
            Wire::Open(false),
            prop_read(27, 1, 1, &[4]),
            prop_read(pid::PROGRAM_VERSION, 1, 1, &[4]),
            Wire::Close(Ok(())),
        ])
    );

    let error = result.expect_err("the program-version mismatch is not handled");
    assert_eq!(error.load_control_cause, None);
}
