use super::*;
use crate::commissioning::catalog::profile::ResourceId;
use crate::commissioning::image::{ImageLocation, ImageSpace};
use crate::commissioning::procedure::operands::{MemoryAddress, MemoryService, OperationTarget, StandardMemoryService};
use zweidraehte_ets_files::schema::{LdCtrlChoose, LdCtrlCompareProp, LdCtrlLoadImageProp, LdCtrlWhen};

#[test]
fn demanded_resources_select_all_alternatives_and_preserve_consumer_order() {
    use crate::commissioning::catalog::ResourceOrder;

    let profile = crate::commissioning::catalog::profile::testing::fixture_profile(
        "MV-07B0",
        "SystemB",
        "MT-0",
        r#"<Resources>
          <Resource Name="First" Access="local1"><ResourceType Length="1"/></Resource>
          <Resource Name="Second" Access="remote"><ResourceType Length="1"/></Resource>
          <Resource Name="First" Access="remote"><ResourceType Length="2"/></Resource>
          <Resource Name="Ambiguous" Access="remote"><ResourceType Length="3"/></Resource>
          <Resource Name="Ambiguous" Access="remote"><ResourceType Length="4"/></Resource>
        </Resources>"#,
    );
    let relevant = |resource: &zweidraehte_ets_files::schema::master_data::Resource| resource.name != "Ambiguous";
    let selected = profile
        .selected_resources_matching(ResourceOrder::SelectedDeclaration, relevant)
        .expect("unused ambiguous names remain irrelevant");
    assert_eq!(selected.iter().map(|resource| resource.name()).collect::<Vec<_>>(), ["Second", "First"]);
    let selected = profile
        .selected_resources_matching(ResourceOrder::FirstDemandedName, relevant)
        .expect("stamp order follows first demanded name");
    assert_eq!(selected.iter().map(|resource| resource.name()).collect::<Vec<_>>(), ["First", "Second"]);
    assert_eq!(selected[0].length(), 2);

    let selected = profile
        .selected_resources_matching(ResourceOrder::SelectedDeclaration, |resource| {
            resource.name == "First" && resource.resource_type.as_ref().is_some_and(|kind| kind.length == 1)
        })
        .expect("a local candidate cannot override the remote winner");
    assert!(selected.is_empty());
    assert!(
        profile
            .selected_resources_matching(ResourceOrder::SelectedDeclaration, |resource| {
                resource.name == "Ambiguous" && resource.resource_type.as_ref().is_some_and(|kind| kind.length == 3)
            })
            .is_err(),
        "filtering demand must not hide an ambiguous alternative of the same name"
    );
}

#[test]
fn property_geometry_ignores_unselected_realizations_before_parsing_locations() {
    for (access, style) in [("local1", "lsm"), ("remote", "simple")] {
        let mut profile = crate::commissioning::catalog::profile::testing::fixture_profile(
            "MV-07B0",
            "SystemB",
            "MT-0",
            &format!(
                r#"<Resources>
                  <Resource Name="Selected" Access="remote" MgmtStyle="lsm">
                    <Location AddressSpace="SystemProperty" InterfaceObjectRef="3" PropertyID="78" StartAddress="0"/>
                    <ResourceType Length="6"/>
                  </Resource>
                  <Resource Name="Selected" Access="{access}" MgmtStyle="{style}">
                    <Location AddressSpace="SystemProperty" InterfaceObjectRef="3" PropertyID="78" StartAddress="0" Occurrence="1"/>
                    <ResourceType Length="6"/>
                  </Resource>
                </Resources>"#,
            ),
        );
        let selected = super::super::property_resources(&profile, &ObjectSelector::Index { index: 3 }, 78)
            .expect("unused realizations do not supply property geometry");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].1, Some(0));
        assert_eq!(selected[0].0.length(), 6);

        if access == "remote" {
            profile.management_style = Some(ResourceManagementStyle::Simple);
            let error = super::super::property_resources(&profile, &ObjectSelector::Index { index: 3 }, 78)
                .expect_err("the selected indexed occurrence remains invalid");
            assert!(error.message.contains("indexed property unexpectedly declares occurrence 1"));
        }
    }
}

#[test]
fn resource_memory_service_uses_selected_ranges_and_authentication() {
    for (address, length, expected) in [
        (0x100, 1, MemoryService::Classic),
        (0xffff, 1, MemoryService::Classic),
        (0xfffe, 2, MemoryService::Classic),
        (0xffff, 2, MemoryService::Extended),
        (0x10000, 1, MemoryService::Extended),
    ] {
        let profile = crate::commissioning::catalog::profile::testing::association_profile_xml(&format!(
            r#"<Resource Name="Selected"><Location AddressSpace="StandardMemory" StartAddress="{address}"/>
              <ResourceType Length="{length}"/></Resource>"#
        ));
        let resource = profile.resource("Selected").expect("unambiguous resource").expect("declared resource");
        for minimum in [StandardMemoryService::Classic, StandardMemoryService::Extended] {
            let read = resource.read(minimum).expect("selected extent fits its bound service");
            assert_eq!(read.target, OperationTarget::Memory {
                service: if minimum == StandardMemoryService::Extended { MemoryService::Extended } else { expected },
                address: MemoryAddress::Fixed(address),
            });
            assert_eq!(read.extent, crate::commissioning::procedure::OperationExtent::bytes(length));
        }
    }
}

#[test]
fn pointer_services_keep_legacy_widths_and_defer_the_base_read() {
    use crate::commissioning::procedure::OperationExtent;
    use crate::commissioning::procedure::operands::PointerEncoding;
    for (flavour, width, encoding) in [
        ("Ptr_StandardMemory100", 1, PointerEncoding::PageOne),
        ("Ptr_StandardMemory", 1, PointerEncoding::Absolute),
        ("Ptr_StandardMemory", 2, PointerEncoding::Absolute),
        ("Ptr_StandardMemory", 3, PointerEncoding::Absolute),
        ("Ptr_StandardMemory", 4, PointerEncoding::Absolute),
    ] {
        let profile = crate::commissioning::catalog::profile::testing::association_profile_xml(&format!(
            r#"<Resource Name="Base"><Location AddressSpace="StandardMemory" StartAddress="256"/>
              <ResourceType Length="{width}" Flavour="{flavour}"/></Resource>
            <Resource Name="Selected"><Location AddressSpace="Pointer" PtrResource="Base"/>
              <ResourceType Length="8"/></Resource>"#
        ));
        for minimum in [StandardMemoryService::Classic, StandardMemoryService::Extended] {
            let read = profile
                .resource("Selected")
                .expect("resource resolves")
                .expect("resource exists")
                .read(minimum)
                .expect("deferred pointer binds without an observed value");
            let OperationTarget::Memory {
                service,
                address: MemoryAddress::Pointer { space, read: pointer, offset: 0, encoding: actual_encoding },
            } = read.target
            else {
                panic!("pointer reads must remain deferred")
            };
            let secured = minimum == StandardMemoryService::Extended;
            assert_eq!(space, ImageSpace::Pointer { resource_id: ResourceId("Base".into()) });
            assert_eq!(
                service,
                if secured {
                    MemoryService::Extended
                } else if width > 2 {
                    MemoryService::Standard
                } else {
                    MemoryService::Classic
                }
            );
            assert_eq!(service.at(0x100, 8), if secured { MemoryService::Extended } else { MemoryService::Classic });
            if width > 2 {
                assert_eq!(
                    service.at(0xffff, 1),
                    if secured { MemoryService::Extended } else { MemoryService::Classic }
                );
                assert_eq!(service.at(0xffff, 2), MemoryService::Extended);
                assert_eq!(service.at(0x10000, 8), MemoryService::Extended);
                assert_eq!(service.overhead(), 5, "unknown pointers reserve the larger APDU header");
            }
            assert_eq!(actual_encoding, encoding);
            assert_eq!(pointer.extent, OperationExtent::bytes(width));
            assert_eq!(
                pointer.target,
                OperationTarget::Memory {
                    service: if secured { MemoryService::Extended } else { MemoryService::Classic },
                    address: MemoryAddress::Fixed(256),
                },
                "the pointer read binds from its own low-memory extent"
            );
        }
    }
}

#[test]
fn authored_pointer_resource_supplies_width_without_interface_property_metadata() {
    use crate::commissioning::procedure::operands::{PointerEncoding, PropertyAddress};
    let profile = crate::commissioning::catalog::profile::testing::association_profile_xml(
        r#"<Resource Name="ApplicationDataPtr" Access="remote">
          <Location AddressSpace="SystemProperty" InterfaceObjectRef="3" PropertyID="7" StartAddress="0"/>
          <ResourceType Length="4" Flavour="Ptr_StandardMemory"/>
          <AccessRights Read="Runtime" Write="Configuration"/>
        </Resource>
        <Resource Name="UnusedFeature" Access="remote">
          <Location AddressSpace="SystemProperty" InterfaceObjectRef="3" PropertyID="99" StartAddress="0"/>
          <ResourceType Length="4" Flavour="FutureFeature"/>
        </Resource>"#,
    );
    let target = profile
        .relative_memory_target(&ObjectSelector::Index { index: 3 }, 12, 1, StandardMemoryService::Classic)
        .expect("the authored pointer is sufficient");
    let OperationTarget::Memory {
        service: MemoryService::Standard,
        address: MemoryAddress::Pointer { space, read, offset: 12, encoding: PointerEncoding::Absolute },
    } = target
    else {
        panic!("relative transfer retains a deferred pointer read")
    };
    assert_eq!(space, ImageSpace::RelativeMemory { object: ObjectSelector::Index { index: 3 } });
    assert_eq!(read.extent.byte_length, 4);
    assert_eq!(read.target, OperationTarget::Property {
        address: PropertyAddress::Indexed { object_index: 3, property_id: 7 },
        start_element: 1,
    });
}

#[test]
fn nested_product_procedure_controls_do_not_preload_property_metadata() {
    let catalog = ProgrammingCatalog::from_xml(GLOBAL_PROPERTY_METADATA).expect("catalog parses");
    let nested_controls = vec![LoadControl::Choose(LdCtrlChoose {
        param_ref_id: "P-outer".to_owned(),
        when: vec![LdCtrlWhen {
            test: Some("1".to_owned()),
            controls: vec![LoadControl::Choose(LdCtrlChoose {
                param_ref_id: "P-inner".to_owned(),
                when: vec![LdCtrlWhen {
                    is_default: Some(true),
                    controls: vec![
                        LoadControl::LdCtrlWriteProp(LdCtrlWriteProp {
                            obj_idx: Some(0),
                            prop_id: 8,
                            inline_data: Some("00000000000000000000".to_owned()),
                            ..Default::default()
                        }),
                        LoadControl::LdCtrlCompareProp(LdCtrlCompareProp {
                            obj_idx: Some(0),
                            prop_id: 86,
                            ..Default::default()
                        }),
                        LoadControl::LdCtrlLoadImageProp(LdCtrlLoadImageProp {
                            obj_idx: Some(0),
                            prop_id: 87,
                            ..Default::default()
                        }),
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            })],
            ..Default::default()
        }],
        ..Default::default()
    })];
    let product = ProductData::default()
        .with_fixture_mask_version_id("MV-0705")
        .with_fixture_load_procedures(vec![LoadProcedure { merge_id: None, controls: nested_controls }]);
    let profile = catalog
        .resolve(ProfileRequest {
            discovery: ProfileDiscovery { dd0: 0x0705, management_descriptor_01: None, management_style: None },
            product: Some(&product),
            variant_hint: VariantHint::Automatic,
        })
        .expect("nested product procedure targets resolve");

    for property_id in [8, 86, 87] {
        assert!(!profile.interface_objects()[0].properties.iter().any(|property| property.property_id == property_id));
        for read in [false, true] {
            assert_eq!(
                profile
                    .property_element_size(&ObjectSelector::Index { index: 0 }, property_id, read)
                    .expect("selected property resolves"),
                Some(2)
            );
        }
    }
}

fn memory(address: u32) -> OperationTarget {
    OperationTarget::Memory { service: MemoryService::Classic, address: MemoryAddress::Fixed(address) }
}

#[test]
fn local_catalog_alternatives_never_enter_a_programming_profile() {
    let xml = RESOURCE_SELECTION.replace(
        "</Resources>",
        r#"
      <Resource Name="Chosen" Access="local1 local2" MgmtStyle="simple">
      <Location AddressSpace="StandardMemory" StartAddress="99"/><ResourceType Length="1"/>
      </Resource></Resources>"#,
    );
    let profile = resolve_resource_selection(&xml).expect("remote alternatives remain unambiguous");
    let selected = profile.resource("Chosen").expect("resource selection").expect("chosen resource");
    assert_eq!(selected.read(StandardMemoryService::Classic).expect("read binds").target, memory(32));
    assert_eq!(selected.id.0, "Chosen");
}

#[test]
fn style_qualified_resource_wins_and_optionality_is_preserved() {
    let profile = resolve_resource_selection(RESOURCE_SELECTION).expect("profile resolves");
    let selected = profile.resource("Chosen").expect("resource selection").expect("chosen resource");
    assert_eq!(selected.read(StandardMemoryService::Classic).expect("read binds").target, memory(32));
    assert!(selected.optional());
}

#[test]
fn property_metadata_keeps_both_selectors_and_unresolved_pdt_tokens() {
    let profile = resolve_resource_selection(RESOURCE_SELECTION).expect("profile resolves");
    let object = &profile.interface_objects()[0];
    assert_eq!(object.index, Some(3));
    assert_eq!(object.object_type, Some(3));
    assert_eq!(object.properties[1].property_data_type, "PDT_FUTURE");
    for read in [false, true] {
        assert_eq!(
            profile.property_element_size(&ObjectSelector::Index { index: 3 }, 7, read).expect("known PDT"),
            Some(2)
        );
        assert_eq!(
            profile
                .property_element_size(&ObjectSelector::Index { index: 3 }, 8, read)
                .expect("unknown PDT remains unresolved"),
            None
        );
    }
}

fn global_profile(xml: &str, product: Option<&ProductData>) -> crate::commissioning::ResolvedProfile {
    ProgrammingCatalog::from_xml(xml)
        .expect("catalog parses")
        .resolve(ProfileRequest {
            discovery: ProfileDiscovery { dd0: 0x0705, management_descriptor_01: None, management_style: None },
            product,
            variant_hint: VariantHint::Automatic,
        })
        .expect("profile selection does not bind property operands")
}

#[test]
fn selected_global_properties_keep_exact_object_precedence_and_asymmetric_widths() {
    let profile = global_profile(GLOBAL_PROPERTY_METADATA, None);
    for read in [false, true] {
        assert_eq!(
            profile.property_element_size(&ObjectSelector::Index { index: 0 }, 78, read).expect("exact hardware PDT"),
            Some(6)
        );
    }
    assert_eq!(
        profile.property_element_size(&ObjectSelector::Index { index: 0 }, 5, false).expect("control value PDT"),
        Some(10)
    );
    assert_eq!(
        profile.property_element_size(&ObjectSelector::Index { index: 0 }, 5, true).expect("control status PDT"),
        Some(1)
    );
}

#[test]
fn product_parameters_and_procedure_controls_use_lazy_global_metadata() {
    let product = ProductData::default()
        .with_fixture_mask_version_id("MV-0705")
        .with_fixture_property_parameters(vec![PropertyParameterLocation {
            id: "P-rate-limit".to_owned(),
            object: PropertyObject::Index(0),
            property_id: 86,
            offset: 0,
            bit_offset: 0,
            size_bits: 1,
            legacy_patch_always: false,
        }])
        .with_fixture_load_procedures(vec![LoadProcedure {
            merge_id: None,
            controls: vec![LoadControl::LdCtrlWriteProp(LdCtrlWriteProp {
                obj_idx: Some(0),
                prop_id: 8,
                inline_data: Some("00000000000000000000".to_owned()),
                ..Default::default()
            })],
        }]);
    let profile = global_profile(GLOBAL_PROPERTY_METADATA, Some(&product));
    assert_eq!(profile.interface_objects()[0].properties.len(), 1);
    assert_eq!(profile.interface_objects()[0].properties[0].property_id, 25);
    for pid in [8, 86] {
        for read in [false, true] {
            assert_eq!(
                profile
                    .property_element_size(&ObjectSelector::Index { index: 0 }, pid, read)
                    .expect("selected global PDT"),
                Some(2)
            );
        }
    }
}

#[test]
fn unselected_nested_property_ambiguity_does_not_prevent_other_operands() {
    let xml = GLOBAL_PROPERTY_METADATA
        .replace("</InterfaceObjectProperties>", r#"<InterfaceObjectProperty Id="PID-0-87-conflict" Number="87" ObjectType="OT-0" Name="conflicting" PDT="PDT-4"/></InterfaceObjectProperties>"#)
        .replace(r#"<Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote" />"#,
            r#"<Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote">
            <choose ParamRefId="P-outer"><when test="1"><choose ParamRefId="P-inner"><when default="true">
            <LdCtrlLoadImageProp ObjIdx="0" PropId="87"/></when></choose></when></choose></Procedure>"#);
    let profile = global_profile(&xml, None);
    assert_eq!(
        profile.property_element_size(&ObjectSelector::Index { index: 0 }, 8, false).expect("other property resolves"),
        Some(2)
    );
    assert!(matches!(
        profile.property_element_size(&ObjectSelector::Index { index: 0 }, 87, false),
        Err(error) if error.kind == CompileErrorKind::InvalidInput && error.message.contains("multiple definitions") && error.message.contains("PID 87")
    ));
}

#[test]
fn legacy_hardware_flavour_supplies_its_scalar_read_width_without_a_global_property_catalogue() {
    let profile = ProgrammingCatalog::from_xml(
        r#"<KNX xmlns="http://knx.org/xml/project/11">
          <MasterData Id="MD" Version="1"><MaskVersions>
            <MaskVersion Id="MV-0705" MaskVersion="1797" Name="System 7"
              ManagementModel="BimM112" MediumTypeRefId="MT-0">
              <HawkConfigurationData>
                <Resources>
                <Resource Name="ManagementStyle" Access="remote">
                  <Location AddressSpace="Constant" StartAddress="2" />
                  <ResourceType Length="1" />
                  <AccessRights Read="Runtime" Write="None" />
                </Resource>
                <Resource Name="HardwareType" Access="remote">
                  <Location AddressSpace="SystemProperty" InterfaceObjectRef="0" PropertyID="78"
                    StartAddress="0" />
                  <ResourceType Length="6" Flavour="HardwareConfig_Identical" />
                  <AccessRights Read="Runtime" Write="Manufacturer" />
                </Resource></Resources>
                <InterfaceObjects><InterfaceObject Index="0" ObjectType="0" /></InterfaceObjects>
              </HawkConfigurationData>
            </MaskVersion>
          </MaskVersions></MasterData>
        </KNX>"#,
    )
    .expect("legacy catalog parses")
    .resolve(ProfileRequest {
        discovery: ProfileDiscovery { dd0: 0x0705, management_descriptor_01: None, management_style: None },
        product: None,
        variant_hint: VariantHint::Automatic,
    })
    .expect("legacy profile resolves");
    for read in [false, true] {
        assert_eq!(
            profile.property_element_size(&ObjectSelector::Index { index: 0 }, 78, read).expect("legacy scalar width"),
            Some(6)
        );
    }
}

#[test]
fn bcu1_pl_flavour_and_independent_locations_are_preserved() {
    let profile = resolve_location_cases();
    let resource = profile.resource("AddressTable").expect("resource selection").expect("address table");
    assert_eq!(profile.disposition, ProfileDisposition::ExcludedPowerLine);
    assert_eq!(
        resource.flavour().expect("known flavour").map(|flavour| flavour.to_string()).as_deref(),
        Some("AddressTable_Bcu1PL")
    );
    assert_eq!(resource.read(StandardMemoryService::Classic).expect("read location").target, memory(256));
    assert_eq!(resource.image_location().expect("image location"), Some(ImageLocation::standard_memory(259)));
}

#[test]
fn property_parameter_selectors_preserve_absent_and_zero_occurrence() {
    use crate::commissioning::catalog::rules::product_property_object;
    use zweidraehte_ets_files::product::PropertyObject;
    use zweidraehte_proto::dpt::InterfaceObjectType;

    for (source, expected) in [(None, Occurrence::Absent), (Some(0), Occurrence::Zero)] {
        let object = product_property_object(PropertyObject::Type {
            object_type: InterfaceObjectType::from(417),
            occurrence: source,
        });
        assert_eq!(object, ObjectSelector::Type { object_type: 417, occurrence: expected });
    }
}

#[test]
fn property_locations_preserve_absent_zero_and_positive_occurrence() {
    let profile = resolve_location_cases();
    for (name, occurrence) in [
        ("PropertyAbsent", Occurrence::Absent),
        ("PropertyZero", Occurrence::Zero),
        ("PropertyOne", Occurrence::Positive { value: NonZeroU16::new(1).expect("one is nonzero") }),
    ] {
        let resource = profile.resource(name).expect("resource selection").expect("property resource");
        assert_eq!(
            resource.property_location().expect("property selector"),
            Some((ObjectSelector::Type { object_type: 6, occurrence }, 5, 0))
        );
    }
}
