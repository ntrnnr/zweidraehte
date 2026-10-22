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
    let catalog = parse_master_data(GLOBAL_PROPERTY_METADATA).expect("catalog parses");
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
    let profile = resolve_catalog_profile(&catalog, Some(&product), &ProfileSelection {
        discovery: ProfileDiscovery { dd0: 0x0705, management_descriptor_01: None, management_style: None },
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
    resolve_catalog_profile(&parse_master_data(xml).expect("catalog parses"), product, &ProfileSelection {
        discovery: ProfileDiscovery { dd0: 0x0705, management_descriptor_01: None, management_style: None },
        variant_hint: VariantHint::Automatic,
    })
    .expect("profile selection does not bind property operands")
}

fn numeric_property_profile() -> crate::commissioning::ResolvedProfile {
    let xml = GLOBAL_PROPERTY_METADATA
        .replace(
            "</PropertyDataTypes>",
            r#"<PropertyDataType Id="PDT-3" Number="3" Name="PDT_INT" Size="2" />
              <PropertyDataType Id="PDT-ZERO" Number="7" Name="Zero" Size="0" />
              <PropertyDataType Id="PDT-VARIABLE" Number="10" Name="Variable" /></PropertyDataTypes>"#,
        )
        .replace(
            "</InterfaceObjectProperties>",
            r#"<InterfaceObjectProperty Id="PID-G-13" Number="13" Name="Shared" PDT="PDT-3"/>
              <InterfaceObjectProperty Id="PID-0-13" Number="13" Name="Device" ObjectType="OT-0" PDT="PDT-22"/>
              <InterfaceObjectProperty Id="PID-421-201" Number="201" Name="Signed" ObjectType="OT-421" PDT="PDT-3"/>
              <InterfaceObjectProperty Id="PID-421-202" Number="202" Name="Unsigned" ObjectType="OT-421" PDT="PDT-4"/>
              <InterfaceObjectProperty Id="PID-421-203" Number="203" Name="Mixed" ObjectType="OT-421" PDT="PDT-3 PDT-4"/>
              <InterfaceObjectProperty Id="PID-421-204" Number="204" Name="Same" ObjectType="OT-421" PDT="PDT-4 PDT-35"/>
              <InterfaceObjectProperty Id="PID-421-205" Number="205" Name="Future" ObjectType="OT-421" PDT="PDT_FUTURE"/>
              <InterfaceObjectProperty Id="PID-421-208" Number="208" Name="Zero" ObjectType="OT-421" PDT="PDT-ZERO"/>
              <InterfaceObjectProperty Id="PID-421-209" Number="209" Name="Variable" ObjectType="OT-421" PDT="PDT-VARIABLE"/>
              </InterfaceObjectProperties>"#,
        )
        .replace(
            "</InterfaceObjects>",
            r#"<InterfaceObject Index="3" ObjectType="421">
              <Property PropertyID="201" PropertyDataType="PDT-4"/>
              </InterfaceObject></InterfaceObjects>"#,
        );
    global_profile(&xml, None)
}

#[test]
fn numeric_lookup_retains_ambiguous_and_unknown_global_entries() {
    let profile = numeric_property_profile();
    let object = ObjectSelector::Type { object_type: 421, occurrence: Occurrence::Absent };
    for (pid, expected) in
        [(201, Some(3)), (202, Some(4)), (203, None), (204, None), (205, None), (208, Some(7)), (209, Some(10))]
    {
        let lookup = profile.property_data_type_lookup(&object, pid).expect("lookup policy");
        assert_eq!(lookup.well_known.get(&Some(421)), Some(&expected), "PID {pid}");
    }
    let absent = profile.property_data_type_lookup(&object, 206).expect("missing metadata");
    assert!(!absent.well_known.contains_key(&Some(421)));
    // Exact PDT identity survives independently of whether it has a usable
    // numeric width. Equal-width alternatives still require discovery.
    assert_eq!(profile.property_element_size(&object, 203, true).expect("same-width alternatives"), Some(2));
}

#[test]
fn numeric_lookup_separates_mask_pdt_from_observed_descriptors() {
    let indexed = ObjectSelector::Index { index: 3 };
    let mut profile = numeric_property_profile();
    crate::commissioning::catalog::profile::testing::append_xml(
        &mut profile,
        "InterfaceObjects",
        r#"<InterfaceObject Index="5"/>"#,
    );
    profile.observed_property_types.insert((indexed.clone(), 201), 3);
    profile.observed_property_types.insert((ObjectSelector::Index { index: 99 }, 201), 22);
    let lookup = profile.property_data_type_lookup(&indexed, 201).expect("independent seeds");
    assert_eq!(lookup.indexed[&3].object_type, Some(421));
    assert_eq!(lookup.indexed[&3].property_data_type, Some(4));
    assert_eq!(lookup.indexed[&3].descriptor, Some(3));
    assert_eq!(lookup.indexed[&99].object_type, None);
    assert_eq!(lookup.indexed[&99].property_data_type, None);
    assert_eq!(lookup.indexed[&99].descriptor, Some(22));
    assert_eq!(lookup.indexed[&5].object_type, Some(0), "native XML defaults omitted roster ObjectType to zero");
    assert_eq!(lookup.initial_descriptor, None);
    assert_eq!(lookup.well_known[&Some(421)], Some(3));
    let typed = ObjectSelector::Type { object_type: 421, occurrence: Occurrence::Absent };
    let typed_lookup = profile.property_data_type_lookup(&typed, 201).expect("typed fallback seeds");
    assert_eq!(typed_lookup.indexed, lookup.indexed, "classic typed fallback needs all indexed objects");
}

#[test]
fn numeric_lookup_does_not_seed_future_declarations() {
    use crate::commissioning::catalog::profile::DeclaredProperty;
    let typed = ObjectSelector::Type { object_type: 421, occurrence: Occurrence::Absent };
    let indexed = ObjectSelector::Index { index: 3 };
    let profile = numeric_property_profile();
    let before = profile.property_data_type_lookup(&typed, 201).expect("initial lookup");
    let profile = profile.with_procedure_property_declarations([
        (DeclaredProperty::new(&typed, 201), "PDT-22"),
        (DeclaredProperty::new(&indexed, 201), "PDT-3"),
    ]);
    let after = profile.property_data_type_lookup(&typed, 201).expect("deferred declaration lookup");
    assert_eq!(after, before);
    assert_eq!(after.initial_descriptor, None);
    assert_eq!(after.declaration_types.get("PDT-22"), Some(&22));
    assert_eq!(after.declaration_types.get("PDT-3"), Some(&3));
    assert_eq!(after.declaration_types.get("PDT-ZERO"), Some(&7));
}

#[test]
fn numeric_lookup_typed_descriptor_cache_ignores_occurrence_and_rejects_conflicts() {
    let absent = ObjectSelector::Type { object_type: 421, occurrence: Occurrence::Absent };
    let zero = ObjectSelector::Type { object_type: 421, occurrence: Occurrence::Zero };
    let mut profile = numeric_property_profile();
    profile.observed_property_types.insert((zero.clone(), 201), 22);
    for target in [&absent, &zero] {
        let lookup = profile.property_data_type_lookup(target, 201).expect("shared typed cache");
        assert_eq!(lookup.initial_descriptor, Some(22));
    }
    profile.observed_property_types.insert((absent.clone(), 201), 3);
    assert!(profile.property_data_type_lookup(&absent, 201).is_err());
}

#[test]
fn numeric_lookup_preserves_scoped_and_unscoped_master_metadata_without_supplements() {
    let profile = numeric_property_profile();
    let indexed = ObjectSelector::Index { index: 0 };
    let typed = ObjectSelector::Type { object_type: 0, occurrence: Occurrence::Absent };
    for target in [&indexed, &typed] {
        let lookup = profile.property_data_type_lookup(target, 13).expect("global policy");
        assert_eq!(lookup.well_known.get(&None), Some(&Some(3)));
        assert_eq!(lookup.well_known.get(&Some(0)), Some(&Some(22)));
    }
    // A roster declaration is an indexed seed, never an invented global PDT.
    let lookup = profile.property_data_type_lookup(&typed, 201).expect("separate namespaces");
    assert_eq!(lookup.well_known.len(), 1);
    assert!(!lookup.well_known.contains_key(&None));
}

#[test]
fn numeric_lookup_rejects_duplicate_roster_indices_properties_and_global_scopes() {
    let target = ObjectSelector::Index { index: 0 };
    for (needle, replacement) in [
        ("</InterfaceObjects>", r#"<InterfaceObject Index="0" ObjectType="421"/></InterfaceObjects>"#),
        (
            "</InterfaceObject>",
            r#"<Property PropertyID="78" PropertyDataType="PDT-4"/>
                                 <Property PropertyID="78" PropertyDataType="PDT-4"/></InterfaceObject>"#,
        ),
        (
            "</InterfaceObjectProperties>",
            r#"<InterfaceObjectProperty Id="PID-G-DUP" Number="78" Name="Duplicate" PDT="PDT-4"/>
                                            </InterfaceObjectProperties>"#,
        ),
    ] {
        let xml = GLOBAL_PROPERTY_METADATA.replace(needle, replacement);
        let profile = global_profile(&xml, None);
        assert!(profile.property_data_type_lookup(&target, 78).is_err(), "{needle}");
    }
}

#[test]
fn dynamic_index_uses_only_unscoped_global_property_metadata() {
    let profile = global_profile(GLOBAL_PROPERTY_METADATA, None);
    let selector = ObjectSelector::Index { index: 99 };

    assert_eq!(profile.property_element_size(&selector, 78, true).unwrap(), Some(2));
    assert_eq!(profile.property_element_size(&selector, 5, true).unwrap(), Some(1));
    assert_eq!(profile.property_element_size(&selector, 5, false).unwrap(), Some(10));
    assert_eq!(profile.property_element_size(&selector, 86, true).unwrap(), None);
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
// A global definition naming only a datapoint subtype does not type the
// property. The reference reads the element width from the target's
// description instead of the datapoint type's parent PDT.
fn global_property_dpt_subtype_leaves_the_width_to_the_target() {
    let xml = GLOBAL_PROPERTY_METADATA
        .replace(
            "</InterfaceObjectProperties>",
            r#"<InterfaceObjectProperty Id="PID-417-109" Number="109" ObjectType="OT-417" Name="PowerUp" DPT="DPST-20-601" /></InterfaceObjectProperties>"#,
        )
        .replace(
            "</PropertyDataTypes>",
            r#"<PropertyDataType Id="PDT-53" Number="53" Name="PDT_ENUM8" Size="1" /></PropertyDataTypes>"#,
        )
        .replace(
            "<MaskVersions>",
            r#"<DatapointTypes><DatapointType Id="DPT-20" PDT="PDT-53"><DatapointSubtypes><DatapointSubtype Id="DPST-20-601" /></DatapointSubtypes></DatapointType></DatapointTypes><MaskVersions>"#,
        );
    let profile = global_profile(&xml, None);
    assert!(!profile.interface_objects().iter().any(|object| object.object_type == Some(417)));
    let object = ObjectSelector::Type { object_type: 417, occurrence: Occurrence::Absent };
    for read in [false, true] {
        assert_eq!(profile.property_element_size(&object, 109, read).expect("untyped PID resolves"), None);
    }
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
            byte_ordered: true,
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
        Err(error) if error.kind == ProfileErrorKind::Invalid && error.message.contains("multiple definitions") && error.message.contains("PID 87")
    ));
}

#[test]
fn legacy_hardware_flavour_supplies_its_scalar_read_width_without_a_global_property_catalogue() {
    let profile = resolve_catalog_profile(
        &parse_master_data(
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
        .expect("legacy catalog parses"),
        None,
        &ProfileSelection {
            discovery: ProfileDiscovery { dd0: 0x0705, management_descriptor_01: None, management_style: None },
            variant_hint: VariantHint::Automatic,
        },
    )
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

// MTXML defaults every omitted `Occurrence` to zero, so both spellings
// select one interface object and must share one image location.
#[test]
fn property_parameter_selectors_default_an_omitted_occurrence_to_zero() {
    use crate::commissioning::catalog::rules::product_property_object;
    use zweidraehte_ets_files::product::PropertyObject;
    use zweidraehte_proto::dpt::InterfaceObjectType;

    for (source, expected) in [(None, Occurrence::Zero), (Some(0), Occurrence::Zero)] {
        let object = product_property_object(PropertyObject::Type {
            object_type: InterfaceObjectType::from(417),
            occurrence: source,
        });
        assert_eq!(object, ObjectSelector::Type { object_type: 417, occurrence: expected });
    }
}

#[test]
fn property_locations_default_an_omitted_occurrence_to_zero() {
    let profile = resolve_location_cases();
    for (name, occurrence) in [
        ("PropertyAbsent", Occurrence::Zero),
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
