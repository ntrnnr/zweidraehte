use crate::commissioning::catalog::profile::testing::{append_xml, declare_property, edit_profile, fixture_profile};
use crate::commissioning::catalog::profile::{ObjectSelector, Occurrence};
use crate::commissioning::compiler::binding::procedure::test_support::{
    ProcedureCompileContext, compile_fixture, compile_fixture_with_profile,
    compile_fixture_with_profile_and_composition, compile_procedure, minimal_profile, root_path,
};
use crate::commissioning::compiler::selection::{ProcedureApplicability, ProcedureComposition};
use crate::commissioning::image::SparseDeviceImage;
use crate::commissioning::procedure::operands::PropertyAddress;
use crate::commissioning::procedure::{
    Comparison, OperationData, OperationExtent, OperationTarget, ProcedureOperation, RestartKind, ToolState,
    WriteIntent,
};
use std::collections::BTreeMap;
use zweidraehte_ets_files::product::ApplicationIdentity;
use zweidraehte_ets_files::schema::{
    LdCtrlCompareProp, LdCtrlConnect, LdCtrlDisconnect, LdCtrlLoadImageProp, LdCtrlWriteProp, LoadControl,
    LoadProcedure,
};

#[test]
fn absent_property_reads_bind_their_read_width_and_keep_dependent_references() {
    let object = ObjectSelector::Index { index: 4 };
    let mut profile = minimal_profile();
    declare_property(&mut profile, &object, 161, 2, 3);

    for inline in [None, Some("A0A1A2A3A4A5".to_owned())] {
        let procedure = LoadProcedure {
            merge_id: None,
            controls: vec![
                LoadControl::LdCtrlLoadImageProp(LdCtrlLoadImageProp {
                    obj_idx: Some(4),
                    prop_id: 161,
                    start_element: Some(3),
                    count: Some(2),
                    ..Default::default()
                }),
                LoadControl::LdCtrlCompareProp(LdCtrlCompareProp {
                    obj_idx: Some(4),
                    prop_id: 161,
                    start_element: Some(3),
                    count: Some(2),
                    inline_data: inline.clone(),
                    ..Default::default()
                }),
            ],
        };

        let normalized = compile_fixture_with_profile(profile.clone(), procedure, Vec::new(), SparseDeviceImage::new())
            .expect("known read metadata can allocate a missing working window");
        let ProcedureOperation::LoadImage { image_location, extent, alignment, .. } = &normalized.steps[0].operation
        else {
            panic!("first control is a working-image load");
        };

        assert_eq!(image_location.space, crate::commissioning::image::ImageSpace::Property {
            object: object.clone(),
            property_id: 161
        });
        assert_eq!(image_location.offset, 6);
        assert_eq!(extent.byte_length, 6);
        assert_eq!(extent.property_elements, Some(2));
        assert_eq!(*alignment, 3);

        let ProcedureOperation::Compare { comparison, .. } = &normalized.steps[1].operation else {
            panic!("second control is the dependent comparison");
        };
        match comparison {
            Comparison::ImageExact { location, length, .. } => {
                assert!(inline.is_none());
                assert_eq!(location, image_location);
                assert_eq!(*length, 6);
            }
            Comparison::Exact { data: OperationData::Buffer { location, length, fallback }, .. } => {
                assert!(inline.is_some());
                assert_eq!(location, image_location);
                assert_eq!(*length, 6);
                assert_eq!(fallback.as_deref(), Some(&[0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5][..]));
            }
            other => panic!("working reference was lost: {other:?}"),
        }
    }
}

#[test]
fn one_property_binding_keeps_read_and_write_widths_distinct() {
    let mut profile = minimal_profile();
    declare_property(&mut profile, &ObjectSelector::Index { index: 4 }, 161, 2, 3);
    append_xml(
        &mut profile,
        "Resources",
        r#"<Resource Name="Value"><Location AddressSpace="SystemProperty" InterfaceObjectRef="4" PropertyID="161" StartAddress="0"/><ResourceType Length="2"/></Resource>"#,
    );
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(Default::default()),
            LoadControl::LdCtrlWriteProp(LdCtrlWriteProp {
                obj_idx: Some(4),
                prop_id: 161,
                inline_data: Some("010200".to_owned()),
                ..Default::default()
            }),
            LoadControl::LdCtrlCompareProp(LdCtrlCompareProp {
                obj_idx: Some(4),
                prop_id: 161,
                inline_data: Some("010203".to_owned()),
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(Default::default()),
        ],
    };
    let program = compile_fixture_with_profile(profile, procedure, Vec::new(), SparseDeviceImage::new())
        .expect("directional PDT widths bind independently");
    assert!(matches!(&program.steps[1].operation, ProcedureOperation::Write {
        data: OperationData::Inline(bytes), extent: OperationExtent { byte_length: 2, property_elements: Some(1) }, ..
    } if bytes == &[1, 2]));
    assert!(matches!(&program.steps[2].operation, ProcedureOperation::Compare {
        comparison: Comparison::Exact { data: OperationData::Buffer { length: 3, .. }, .. },
        extent: OperationExtent { byte_length: 3, property_elements: Some(1) },
        ..
    }));
}

#[test]
fn another_property_occurrence_cannot_supply_or_invalidate_geometry() {
    let mut profile = minimal_profile();
    declare_property(&mut profile, &ObjectSelector::Type { object_type: 11, occurrence: Occurrence::Zero }, 161, 2, 2);
    append_xml(
        &mut profile,
        "Resources",
        r#"<Resource Name="OtherOccurrence" Access="unknown"><Location AddressSpace="Property" InterfaceObjectRef="11" Occurrence="1" PropertyID="161" StartAddress="0"/><ResourceType Length="9"/></Resource>"#,
    );
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(Default::default()),
            LoadControl::LdCtrlWriteProp(LdCtrlWriteProp {
                obj_type: Some(11),
                occurrence: Some(0),
                prop_id: 161,
                inline_data: Some("0102".to_owned()),
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(Default::default()),
        ],
    };
    let program = compile_fixture_with_profile(profile, procedure, Vec::new(), SparseDeviceImage::new())
        .expect("an unused occurrence is not selected");
    assert!(matches!(&program.steps[1].operation, ProcedureOperation::Write {
        extent: OperationExtent { byte_length: 2, .. },
        ..
    }));
}

#[test]
fn read_only_property_does_not_require_a_unique_unused_write_width() {
    let mut profile = minimal_profile();
    append_xml(
        &mut profile,
        "InterfaceObjects",
        r#"<InterfaceObject Index="4"><Property PropertyID="162" PropertyDataType="WIDTH1 WIDTH3"/></InterfaceObject>"#,
    );
    edit_profile(&mut profile, |xml| {
        xml.replace("</PropertyDataTypes>", r#"<PropertyDataType Id="WIDTH1" Name="WIDTH1" Size="1" ReadSize="2"/><PropertyDataType Id="WIDTH3" Name="WIDTH3" Size="3" ReadSize="2"/></PropertyDataTypes>"#)
    });
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(Default::default()),
            LoadControl::LdCtrlCompareProp(LdCtrlCompareProp {
                obj_idx: Some(4),
                prop_id: 162,
                inline_data: Some("0102".to_owned()),
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(Default::default()),
        ],
    };
    let program = compile_fixture_with_profile(profile, procedure, Vec::new(), SparseDeviceImage::new())
        .expect("both PDT alternatives have the same read width");
    assert!(matches!(&program.steps[1].operation, ProcedureOperation::Compare {
        extent: OperationExtent { byte_length: 2, property_elements: Some(1) },
        ..
    }));
}

#[test]
fn bcu2_global_service_control_pdt_truncates_ten_byte_default() {
    let mut profile = fixture_profile(
        "MV-0021",
        "Bcu2",
        "MT-0",
        r#"<Resources></Resources><InterfaceObjects><InterfaceObject Index="0" ObjectType="0"/></InterfaceObjects>"#,
    );

    // MV-0021 does not list PID_SERVICE_CONTROL on its Device Object.
    // Its selected write resolves this PDT-4 shape from the global property
    // catalogue; the interface object itself declares no property geometry.
    edit_profile(&mut profile, |xml| {
        xml.replacen("<PropertyDataTypes>", r#"<InterfaceObjectProperties><InterfaceObjectProperty Id="PID-0-8" Number="8" ObjectType="OT-0" Name="PID_SERVICE_CONTROL" PDT="PDT-4"/></InterfaceObjectProperties><PropertyDataTypes><PropertyDataType Id="PDT-4" Number="4" Name="PDT_UNSIGNED_INT" Size="2"/>"#, 1)
    });
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlWriteProp(LdCtrlWriteProp {
                obj_idx: Some(0),
                prop_id: 8,
                verify: false,
                inline_data: Some("00000000000000000000".to_owned()),
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };

    let normalized = compile_fixture_with_profile_and_composition(
        profile,
        ProcedureComposition::ProductOwned,
        procedure,
        Vec::new(),
        SparseDeviceImage::new(),
    )
    .expect("global PID_SERVICE_CONTROL metadata fixes the BCU2 wire width");

    let ProcedureOperation::Write { target, data, extent, policy } = &normalized.steps[1].operation else {
        panic!("second control is the service-control property write");
    };
    assert_eq!(target, &OperationTarget::Property {
        address: PropertyAddress::Indexed { object_index: 0, property_id: 8 },
        start_element: 1,
    });
    assert_eq!(data, &OperationData::Inline(vec![0, 0]));
    assert_eq!(*extent, OperationExtent::property(2, 1));
    assert_eq!(*policy, WriteIntent::Property { verify: false });
}

#[test]
fn property_pdt_truncates_inline_padding_but_rejects_short_values() {
    let mut profile = minimal_profile();
    declare_property(&mut profile, &ObjectSelector::Index { index: 4 }, 27, 8, 8);
    let compile = |inline_data: &str| {
        compile_procedure(ProcedureCompileContext {
            profile: profile.clone(),
            procedure_id: root_path().procedure,
            composition: ProcedureComposition::Merged,
            procedure: LoadProcedure {
                merge_id: None,
                controls: vec![
                    LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
                    LoadControl::LdCtrlWriteProp(LdCtrlWriteProp {
                        obj_idx: Some(4),
                        prop_id: 27,
                        inline_data: Some(inline_data.to_owned()),
                        ..Default::default()
                    }),
                    LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
                ],
            },
            product_merge_fragments: Vec::new(),
            parameter_values: BTreeMap::new(),
            applicability: ProcedureApplicability::full(),
            image: SparseDeviceImage::new(),
            property_image_facts: Vec::new(),
            relative_memory_facts: Vec::new(),
            progress_messages_by_reference: BTreeMap::new(),
            progress_messages_by_id: BTreeMap::new(),
            initial_tool_state: ToolState::default(),
            restart_kind: RestartKind::Basic,
            application_identity: ApplicationIdentity::default(),
            extension_operations: Vec::new(),
        })
    };

    let normalized =
        compile("00000014003200000000").expect("ten-byte System B MCB buffer is constrained to its eight-byte PDT");
    let ProcedureOperation::Write { data: OperationData::Inline(data), extent, policy, .. } =
        &normalized.steps[1].operation
    else {
        panic!("second control is the property write");
    };
    assert_eq!(data.as_slice(), [0, 0, 0, 0x14, 0, 0x32, 0, 0]);
    assert_eq!(extent.byte_length, 8);
    assert_eq!(extent.property_elements, Some(1));
    assert_eq!(*policy, WriteIntent::Property { verify: false });

    let error = compile("00000014003200").expect_err("PDT padding cannot invent missing wire bytes");
    assert!(error.to_string().contains("has only 7 bytes"));
}

#[test]
fn inline_property_write_uses_its_authored_width_when_metadata_is_absent() {
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlWriteProp(LdCtrlWriteProp {
                obj_idx: Some(7),
                prop_id: 161,
                inline_data: Some("01".to_owned()),
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };

    let normalized =
        compile_fixture(procedure, Vec::new()).expect("an exact vendor-property write can retain its authored width");
    let ProcedureOperation::Write { extent, .. } = &normalized.steps[1].operation else {
        panic!("second control is the property write");
    };

    assert_eq!(extent.byte_length, 1);
    assert_eq!(extent.property_elements, Some(1));
}

#[test]
fn inline_property_compare_uses_its_authored_width_when_metadata_is_absent() {
    let procedure = LoadProcedure {
        merge_id: None,
        controls: vec![
            LoadControl::LdCtrlConnect(LdCtrlConnect::default()),
            LoadControl::LdCtrlCompareProp(LdCtrlCompareProp {
                obj_idx: Some(7),
                prop_id: 162,
                inline_data: Some("01".to_owned()),
                ..Default::default()
            }),
            LoadControl::LdCtrlDisconnect(LdCtrlDisconnect::default()),
        ],
    };

    let normalized = compile_fixture(procedure, Vec::new())
        .expect("a read-only vendor-property comparison can retain its authored width");
    let ProcedureOperation::Compare { extent, .. } = &normalized.steps[1].operation else {
        panic!("second control is the property comparison");
    };

    assert_eq!(extent.byte_length, 1);
    assert_eq!(extent.property_elements, Some(1));
}

/// A System 7 product whose only parameter lives in a manufacturer object
/// property. Neither the mask roster nor global Master Data types it, as for
/// M-00FA_A-2526's object type 421, PID 201.
fn untyped_property_product() -> zweidraehte_ets_files::product::ProductData {
    let xml = r#"<KNX xmlns="http://knx.org/xml/project/23" CreatedBy="property-test" ToolVersion="1">
      <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
        <ApplicationProgram Id="M-00FA_A-0001-01-0000" ApplicationNumber="1" ApplicationVersion="1"
          ProgramType="ApplicationProgram" MaskVersion="MV-0705" Name="untyped property fixture"
          LoadProcedureStyle="ProductProcedure" PeiType="0" DefaultLanguage="en-US"
          DynamicTableManagement="false" Linkable="false">
          <Static>
            <Code><AbsoluteSegment Id="M-00FA_A-0001-01-0000_AS-100" Address="256" Size="4" MemoryType="EEPROM"><Data>AQIDBA==</Data></AbsoluteSegment></Code>
            <ParameterTypes><ParameterType Id="color" Name="Color"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType></ParameterTypes>
            <Parameters>
              <Parameter Id="background" Name="421.201" ParameterType="color" Text="Background" Value="7">
                <Property ObjectType="421" PropertyId="201" Offset="0" BitOffset="0" />
              </Parameter>
            </Parameters>
            <ParameterRefs><ParameterRef Id="background-ref" RefId="background" /></ParameterRefs>
            <LoadProcedures><LoadProcedure>
              <LdCtrlConnect />
              <LdCtrlWriteMem Address="256" Size="4" Verify="false" />
              <LdCtrlWriteProp ObjType="421" PropId="201" Verify="false" />
              <LdCtrlDisconnect />
            </LoadProcedure></LoadProcedures>
          </Static>
          <Dynamic><ChannelIndependentBlock><ParameterBlock Id="page" Name="Settings">
            <ParameterRefRef RefId="background-ref" />
          </ParameterBlock></ChannelIndependentBlock></Dynamic>
        </ApplicationProgram>
      </ApplicationPrograms></Manufacturer></ManufacturerData>
    </KNX>"#;
    zweidraehte_ets_files::product::ProductData::from_mtxml_str(xml).expect("untyped property fixture parses")
}

#[test]
fn untyped_parameter_property_takes_its_width_from_the_observed_pdt() {
    use crate::commissioning::catalog::profile::ProfileDiscovery;
    use crate::commissioning::input::{CommissioningIntent, DownloadMode, TargetSelection};
    use crate::commissioning::test_support::architecture::{catalog, programming_input, resolve_profile};
    use crate::commissioning::{CompileOptions, ProfileSelection};
    use crate::configuration::LoweredDeviceConfiguration;
    use zweidraehte_proto::address::IndividualAddress;

    let catalog = catalog(23);
    let product = untyped_property_product();
    let object = ObjectSelector::Type { object_type: 421, occurrence: Occurrence::Absent };

    // The requirement is derived from the product and exact profile alone.
    let profile = resolve_profile(&catalog, 0x0705, None, &product);
    assert_eq!(profile.untyped_parameter_properties(&product).expect("metadata resolves"), vec![(object.clone(), 201)]);

    let address = IndividualAddress::new(1, 1, 10);
    let mut configuration = LoweredDeviceConfiguration::new(address, Some(15));
    configuration.parameters.push(crate::configuration::ParameterValue { id: "background".to_owned(), value: vec![9] });
    let compile = |selection: &ProfileSelection| {
        programming_input(
            &catalog,
            &product,
            &configuration,
            CommissioningIntent::Download(DownloadMode::Full),
            CompileOptions {
                target: TargetSelection::ExistingAddress(address),
                automatic_sections: None,
                progress_messages_by_reference: BTreeMap::new(),
                progress_messages_by_id: BTreeMap::new(),
            },
        )
        .compile(selection)
    };
    let selection =
        ProfileSelection::new(ProfileDiscovery { dd0: 0x0705, management_descriptor_01: None, management_style: None });

    // Without the target's description, the parameter bytes cannot be sized.
    let error = compile(&selection).expect_err("an unobserved PDT cannot size the write");
    assert!(error.to_string().contains("property description"), "{error}");

    // The fixture's PDT 50 is one octet wide: one element carries the parameter.
    let program = compile(&selection.clone().with_observed_property_type(object.clone(), 201, 50))
        .expect("the observed PDT sizes the parameter write");
    let write = program
        .procedure()
        .expect("download has a procedure")
        .steps
        .iter()
        .find_map(|step| match &step.operation {
            ProcedureOperation::Write {
                target: OperationTarget::Property { address: PropertyAddress::Extended { property_id: 201, .. }, .. },
                data,
                extent,
                ..
            } => Some((data, extent)),
            _ => None,
        })
        .expect("the parameter property is written");
    assert_eq!(*write.1, OperationExtent { byte_length: 1, property_elements: Some(1) });
    assert!(
        matches!(write.0, OperationData::Buffer { location, length: 1, fallback: None }
        if location.space == crate::commissioning::image::ImageSpace::Property { object: object.clone(), property_id: 201 }
            && location.offset == 0),
        "{:?}",
        write.0
    );

    // Master Data stays authoritative; unknown and variable-length PDTs, and
    // conflicting observations, cannot supply a width.
    assert!(profile.clone().with_observed_property_type(object.clone(), 201, 99).is_err());
    let observed = profile.clone().with_observed_property_type(object.clone(), 201, 50).expect("first observation");
    assert!(observed.with_observed_property_type(object.clone(), 201, 4).is_err());
    let typed = ObjectSelector::Index { index: 4 };
    let mut declared = minimal_profile();
    declare_property(&mut declared, &typed, 161, 1, 1);
    let error = declared.with_observed_property_type(typed, 161, 50).expect_err("Master Data types this property");
    assert!(error.to_string().contains("already typed"), "{error}");
}
