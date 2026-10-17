use super::*;
use crate::commissioning::catalog::ProgrammingCatalog;
use crate::commissioning::catalog::profile::{ProfileDiscovery, ProfileRequest, ResourceManagementStyle, VariantHint};
use crate::commissioning::image::ImageLocation;
use crate::commissioning::procedure::operands::{MemoryAddress, StandardMemoryService, required_plaintext_apdu};
use crate::commissioning::procedure::{CachePolicy, OperationExtent, OperationTarget, ProcedureOperation};
use crate::commissioning::test_support::preflight::{procedure, profile};
use zweidraehte_proto::messages::apdu::load_control::LoadState;

fn legacy_system_b_profile(status_offset: u32) -> crate::commissioning::catalog::profile::ResolvedProfile {
    let resources = [(1, 1, "GroupAddressTable"), (2, 2, "GroupAssociationTable"),
        (3, 4, "Application"), (4, 5, "Peiprog")]
        .into_iter()
        .map(|(image_index, device_index, prefix)| format!(
            r#"<Resource Name="{prefix}LoadControl" Access="remote">
                <Location AddressSpace="SystemProperty" InterfaceObjectRef="{device_index}" PropertyID="5" StartAddress="0"/>
                <ImgLocation AddressSpace="SystemProperty" InterfaceObjectRef="{image_index}" PropertyID="5" StartAddress="0"/>
                <ResourceType Length="10" Flavour="LoadControl_Bcu2"/>
            </Resource>
            <Resource Name="{prefix}LoadStatus" Access="remote">
                <Location AddressSpace="SystemProperty" InterfaceObjectRef="{device_index}" PropertyID="5" StartAddress="{status_offset}"/>
                <ResourceType Length="1" Flavour="LoadControl_Bcu2"/>
            </Resource>"#,
        ))
        .collect::<String>();

    crate::commissioning::catalog::profile::testing::fixture_profile(
        "MV-17B0",
        "SystemB",
        "MT-1",
        &format!(
            r#"<Features><Feature Name="PropertyMappedLsms" Value="0"/></Features><Resources>{resources}</Resources>"#
        ),
    )
}

#[test]
fn legacy_system_b_memory_controls_poll_device_property_status() {
    let profile = legacy_system_b_profile(0);

    for (index, device_index, expected_machine) in [
        (1, 1, LsmMachine::AddressTable),
        (2, 2, LsmMachine::AssociationTable),
        (3, 4, LsmMachine::ApplicationProgram),
        (4, 5, LsmMachine::PeiProgram),
    ] {
        let (control, status, machine) =
            load_endpoint(&profile, &LoadMachineTarget::Index(index), StandardMemoryService::Classic)
                .expect("hybrid legacy endpoints");

        assert_eq!(control.target, OperationTarget::Memory {
            service: MemoryService::Classic,
            address: MemoryAddress::Fixed(0x104),
        });
        assert_eq!(control.extent, OperationExtent::bytes(11));
        assert_eq!(status.target, OperationTarget::Property {
            address: PropertyAddress::Indexed { object_index: device_index, property_id: 5 },
            start_element: 1,
        });
        assert_eq!(status.extent, OperationExtent::property(1, 1));
        assert_eq!(machine, Some(expected_machine));
    }
}

#[test]
fn legacy_system_b_compiles_memory_frames_with_property_polling() {
    use crate::commissioning::compiler::binding::procedure::test_support::compile_fixture_with_profile;
    use crate::commissioning::image::SparseDeviceImage;
    use zweidraehte_ets_files::schema::{LdCtrlLoad, LdCtrlLoadCompleted, LdCtrlUnload, LoadControl, LoadProcedure};

    let compiled = compile_fixture_with_profile(
        legacy_system_b_profile(0),
        LoadProcedure {
            merge_id: None,
            controls: vec![
                LoadControl::LdCtrlUnload(LdCtrlUnload { lsm_idx: Some(3), ..Default::default() }),
                LoadControl::LdCtrlLoad(LdCtrlLoad { lsm_idx: Some(3), ..Default::default() }),
                LoadControl::LdCtrlLoadCompleted(LdCtrlLoadCompleted { lsm_idx: Some(3), ..Default::default() }),
            ],
        },
        Vec::new(),
        SparseDeviceImage::new(),
    )
    .expect("legacy procedure compiles");

    for (step, tag, state) in
        [(0, 0x34, LoadState::Unloaded), (1, 0x31, LoadState::Loading), (2, 0x32, LoadState::Loaded)]
    {
        let ProcedureOperation::LoadRecord(record) = &compiled.steps[step].operation else { panic!("load record") };
        let mut expected = vec![0; 11];
        expected[0] = tag;
        assert_eq!(record.bytes, expected);
        assert_eq!(record.write.target, OperationTarget::Memory {
            service: MemoryService::Classic,
            address: MemoryAddress::Fixed(0x104),
        });
        let (status, expected_state) = record.poll.as_ref().expect("status poll");
        assert_eq!(*expected_state, state);
        assert_eq!(status.target, OperationTarget::Property {
            address: PropertyAddress::Indexed { object_index: 4, property_id: 5 },
            start_element: 1,
        });
    }
}

#[test]
fn legacy_system_b_rejects_unbound_status_or_unknown_machine() {
    assert!(
        load_endpoint(&legacy_system_b_profile(2), &LoadMachineTarget::Index(3), StandardMemoryService::Classic)
            .is_err()
    );
    assert!(
        load_endpoint(&legacy_system_b_profile(0), &LoadMachineTarget::Index(5), StandardMemoryService::Classic)
            .is_err()
    );
}

#[test]
fn deferred_pointer_requires_a_canonical_destination_space() {
    let read = Box::new(ServiceRead {
        target: OperationTarget::Property {
            address: PropertyAddress::Indexed { object_index: 3, property_id: 7 },
            start_element: 1,
        },
        extent: OperationExtent::property(4, 1),
    });
    let target = |space| OperationTarget::Memory {
        service: MemoryService::Standard,
        address: MemoryAddress::Pointer { read: read.clone(), space, offset: 0, encoding: PointerEncoding::Absolute },
    };
    for space in [ImageSpace::RelativeMemory { object: ObjectSelector::Index { index: 3 } }, ImageSpace::Pointer {
        resource_id: crate::commissioning::catalog::profile::ResourceId("ApplicationDataPtr".into()),
    }] {
        assert_eq!(target(space).minimum_apdu(OperationExtent::bytes(8)).expect("bound destination"), 9);
    }
    let error = target(ImageSpace::StandardMemory)
        .minimum_apdu(OperationExtent::bytes(8))
        .expect_err("a deferred base cannot claim a fixed address space");
    assert!(error.to_string().contains("pointer operand has no relative destination space"));
}

#[test]
fn load_endpoint_ignores_unselected_conflicting_resources() {
    let mut profile = crate::commissioning::catalog::profile::testing::association_profile_xml(
        r#"<Resource Name="ApplicationLoadControl" Access="remote">
          <Location AddressSpace="SystemProperty" InterfaceObjectRef="3" PropertyID="5" StartAddress="0"/>
          <ResourceType Length="10" Flavour="LoadControl_Bcu2"/>
        </Resource>
        <Resource Name="ApplicationLoadStatus" Access="remote">
          <Location AddressSpace="SystemProperty" InterfaceObjectRef="3" PropertyID="5" StartAddress="0"/>
          <ResourceType Length="1" Flavour="LoadControl_Bcu2"/>
        </Resource>
        <Resource Name="UnusedLoadControl" Access="remote">
          <Location AddressSpace="SystemProperty" InterfaceObjectRef="9" PropertyID="5" StartAddress="0"/>
          <ResourceType Length="10" Flavour="LoadControl_Bcu2"/>
        </Resource>
        <Resource Name="UnusedLoadControl" Access="remote">
          <Location AddressSpace="SystemProperty" InterfaceObjectRef="9" PropertyID="8" StartAddress="0"/>
          <ResourceType Length="10" Flavour="LoadControl_Bcu2"/>
        </Resource>"#,
    );
    let target = LoadMachineTarget::Index(3);
    let expected = PropertyAddress::Indexed { object_index: 3, property_id: 5 };
    assert_eq!(
        load_endpoint(&profile, &target, StandardMemoryService::Classic).expect("only the selected machine binds"),
        (
            ServiceRead {
                target: OperationTarget::Property { address: expected, start_element: 1 },
                extent: OperationExtent::property(10, 1),
            },
            ServiceRead {
                target: OperationTarget::Property { address: expected, start_element: 1 },
                extent: OperationExtent::property(1, 1),
            },
            None,
        )
    );
    assert!(
        load_endpoint(&profile, &LoadMachineTarget::Index(9), StandardMemoryService::Classic).is_err(),
        "selected conflicts still fail preparation"
    );

    crate::commissioning::catalog::profile::testing::append_xml(
        &mut profile,
        "Resources",
        r#"<Resource Name="ApplicationLoadControl" Access="remote">
          <Location AddressSpace="SystemProperty" InterfaceObjectRef="3" PropertyID="8" StartAddress="0"/>
          <ResourceType Length="10" Flavour="LoadControl_Bcu2"/>
        </Resource>"#,
    );
    assert!(
        load_endpoint(&profile, &target, StandardMemoryService::Classic).is_err(),
        "selected ambiguity is never discarded"
    );
}

#[test]
fn system7_property_mapped_lsms_override_legacy_memory_resources() {
    for enabled in [false, true] {
        let xml = format!(
            r#"<KNX xmlns="http://knx.org/xml/project/23">
          <MasterData Id="MD" Version="1"><MaskVersions>
            <MaskVersion Id="MV-0705" MaskVersion="1797" Name="System 7" ManagementModel="BimM112">
              <HawkConfigurationData>
                <Features><Feature Name="PropertyMappedLsms" Value="{}" /></Features>
                <Resources>
                  <Resource Name="GroupAddressTableLoadControl" Access="remote">
                    <Location AddressSpace="StandardMemory" StartAddress="260" />
                    <ResourceType Length="12" Flavour="LoadControl_M112" />
                  </Resource>
                  <Resource Name="GroupAddressTableLoadStatus" Access="remote">
                    <Location AddressSpace="StandardMemory" StartAddress="46826" />
                    <ResourceType Length="1" Flavour="LoadControl_M112" />
                  </Resource>
                </Resources>
              </HawkConfigurationData>
            </MaskVersion>
          </MaskVersions></MasterData>
        </KNX>"#,
            u8::from(enabled)
        );
        let profile = ProgrammingCatalog::from_xml(&xml)
            .expect("synthetic catalog")
            .resolve(ProfileRequest {
                discovery: ProfileDiscovery {
                    dd0: 0x0705,
                    management_descriptor_01: None,
                    management_style: Some(ResourceManagementStyle::LoadStateMachine),
                },
                product: None,
                variant_hint: VariantHint::Automatic,
            })
            .expect("exact System 7 profile");
        let (control, status, machine) =
            load_endpoint(&profile, &LoadMachineTarget::Index(1), StandardMemoryService::Classic)
                .expect("load endpoint resolves");
        if enabled {
            let address = PropertyAddress::Indexed { object_index: 1, property_id: 5 };
            assert_eq!(control.target, OperationTarget::Property { address, start_element: 1 });
            assert_eq!(control.extent, OperationExtent::property(10, 1));
            assert_eq!(status.target, control.target);
            assert_eq!(status.extent, OperationExtent::property(1, 1));
            assert_eq!(machine, None);
            for object_type in [9, 60001] {
                let selector = ObjectSelector::Type { object_type, occurrence: Occurrence::Zero };
                let (typed_control, typed_status, typed_machine) = load_endpoint(
                    &profile,
                    &LoadMachineTarget::Object(selector.clone()),
                    StandardMemoryService::Classic,
                )
                .expect("property-mapped typed load machine needs no memory-machine definition");
                let address =
                    pure_property_address(&selector, pid::LOAD_STATE_CONTROL).expect("typed property address");
                assert_eq!(typed_control.target, OperationTarget::Property { address, start_element: 1 });
                assert_eq!(typed_control.extent, OperationExtent::property(10, 1));
                assert_eq!(typed_status.target, typed_control.target);
                assert_eq!(typed_status.extent, OperationExtent::property(1, 1));
                assert!(typed_machine.is_none());
            }
        } else {
            assert_eq!(control.target, OperationTarget::Memory {
                service: MemoryService::Classic,
                address: MemoryAddress::Fixed(0x0104),
            });
            assert_eq!(control.extent, OperationExtent::bytes(12));
            assert_eq!(status.target, OperationTarget::Memory {
                service: MemoryService::Classic,
                address: MemoryAddress::Fixed(0xb6ea),
            });
            assert_eq!(status.extent, OperationExtent::bytes(1));
            assert_eq!(machine, Some(LsmMachine::AddressTable));
        }
    }
}

#[test]
fn production_preflight_resolves_every_supported_resource_location() {
    let resources = [
        ("standard", "AddressSpace=\"StandardMemory\" StartAddress=\"256\"", 2, ""),
        ("user", "AddressSpace=\"UserMemory\" StartAddress=\"512\"", 2, ""),
        ("system-property", "AddressSpace=\"SystemProperty\" InterfaceObjectRef=\"1\" PropertyID=\"10\" StartAddress=\"0\"", 1, ""),
        ("application-property", "AddressSpace=\"AppProperty\" InterfaceObjectRef=\"3\" PropertyID=\"10\" StartAddress=\"0\"", 2, ""),
        ("property-zero", "AddressSpace=\"Property\" InterfaceObjectRef=\"3\" PropertyID=\"300\" Occurrence=\"0\" StartAddress=\"0\"", 2, ""),
        ("property-absent", "AddressSpace=\"Property\" InterfaceObjectRef=\"3\" PropertyID=\"301\" StartAddress=\"0\"", 1, ""),
        ("relative-index", "AddressSpace=\"RelativeMemory\" InterfaceObjectRef=\"2\" PropertyID=\"20\" StartAddress=\"4\"", 2, ""),
        ("relative-type", "AddressSpace=\"RelativeMemoryByObjectType\" InterfaceObjectRef=\"4\" PropertyID=\"21\" Occurrence=\"1\" StartAddress=\"8\"", 2, ""),
        ("PointerSource", "AddressSpace=\"StandardMemory\" StartAddress=\"48\"", 2, "Flavour=\"Ptr_StandardMemory\""),
        ("pointer-target", "AddressSpace=\"Pointer\" PtrResource=\"PointerSource\"", 2, ""),
        ("constant", "AddressSpace=\"Constant\" StartAddress=\"4660\"", 2, ""),
        ("adc", "AddressSpace=\"ADC\" StartAddress=\"7\"", 2, ""),
        ("filter", "AddressSpace=\"LcFilterMemory\" StartAddress=\"5\"", 2, ""),
        ("slave", "AddressSpace=\"LcSlaveMemory\" StartAddress=\"6\"", 2, ""),
    ].into_iter().map(|(name, location, length, flavour)| format!(
        "<Resource Name=\"{name}\" Access=\"remote\"><Location {location}/><ResourceType Length=\"{length}\" {flavour}/></Resource>"
    )).collect::<String>();
    let profile = profile(&resources);
    let mut operations =
        vec![ProcedureOperation::Connect, ProcedureOperation::ClearLineCouplerFilter { address: None }];
    for name in profile.resource_names() {
        let read = profile
            .resource(name)
            .expect("exact selection")
            .expect("declared resource")
            .read(StandardMemoryService::Classic)
            .expect("concrete operand");
        if name == "relative-type" {
            let OperationTarget::Memory { address: MemoryAddress::Pointer { read, offset: 8, .. }, .. } = &read.target
            else {
                panic!("relative memory retains its pointer");
            };
            assert_eq!(read.extent, OperationExtent::property(2, 1), "second raw occurrence supplies its width");
        }
        if name == "constant" {
            assert_eq!(read.target, OperationTarget::Constant(vec![0x12, 0x34]));
        }
        operations.push(ProcedureOperation::ReadIntoImage {
            target: read.target,
            image_location: ImageLocation::standard_memory(0),
            extent: read.extent,
            cache: CachePolicy::Bypass,
            capture_as: None,
        });
    }
    operations.push(ProcedureOperation::Disconnect);
    // Extended property overhead plus one complete two-byte element.
    assert_eq!(required_plaintext_apdu(&procedure(operations), false).expect("valid services"), Some(11));
}

#[test]
fn locations_without_an_online_service_fail_during_preflight() {
    let profile = profile(
        r#"<Resource Name="none" Access="remote"><Location AddressSpace="None"/><ResourceType Length="1"/></Resource>"#,
    );
    let error = profile
        .resource("none")
        .expect("exact selection")
        .expect("declared resource")
        .read(StandardMemoryService::Classic)
        .expect_err("unreadable location fails before execution");
    assert!(error.to_string().contains("has no online location"));
}

#[test]
fn balanced_semantic_procedure_may_have_no_apdu_requirement() {
    let required =
        required_plaintext_apdu(&procedure(vec![ProcedureOperation::Connect, ProcedureOperation::Disconnect]), false)
            .expect("a balanced no-op procedure is structurally valid");

    assert_eq!(required, None);
}
