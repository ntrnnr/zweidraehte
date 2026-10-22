use crate::commissioning::catalog::profile::testing::{append_xml, declare_property, edit_profile, fixture_profile};
use crate::commissioning::catalog::profile::{ObjectSelector, Occurrence};
use crate::commissioning::catalog_testing::*;
use crate::commissioning::compiler::binding::procedure::test_support::{
    ProcedureCompileContext, compile_fixture, compile_fixture_with_profile,
    compile_fixture_with_profile_and_composition, compile_procedure, minimal_profile, root_path,
};
use crate::commissioning::compiler::selection::{ProcedureApplicability, ProcedureComposition};
use crate::commissioning::image::SparseDeviceImage;
use crate::commissioning::procedure::operands::PropertyAddress;
use crate::commissioning::procedure::{
    Comparison, DescribedPropertyAction, DescribedPropertyOperation, OperationData, OperationExtent, OperationTarget,
    ProcedureOperation, RestartKind, ToolState, WriteIntent,
};
use std::collections::BTreeMap;
use zweidraehte_ets_files::product::ApplicationIdentity;
use zweidraehte_ets_files::schema::{
    LdCtrlCompareProp, LdCtrlConnect, LdCtrlDisconnect, LdCtrlLoadImageProp, LdCtrlWriteProp, LoadControl,
    LoadProcedure,
};

#[test]
fn inline_property_count_write_ignores_ordinary_element_width() {
    for width in [1, 5, 11] {
        let mut profile = minimal_profile();
        let object = ObjectSelector::Type { object_type: 19, occurrence: Occurrence::Zero };
        declare_property(&mut profile, &object, 82, width, width);
        let program = compile_fixture_with_profile(
            profile,
            LoadProcedure {
                merge_id: None,
                controls: vec![LoadControl::LdCtrlWriteProp(LdCtrlWriteProp {
                    obj_type: Some(19),
                    occurrence: Some(0),
                    prop_id: 82,
                    start_element: Some(0),
                    count: Some(1),
                    inline_data: Some("0005FFFF".to_owned()),
                    verify: true,
                    ..Default::default()
                })],
            },
            Vec::new(),
            SparseDeviceImage::new(),
        )
        .expect("inline array count has independent geometry");
        assert!(matches!(&program.steps[0].operation,
            ProcedureOperation::Write { target: OperationTarget::Property { start_element: 0, .. },
                data: OperationData::Inline(bytes), extent, policy: WriteIntent::Property { verify: true } }
                if bytes == &[0, 5] && *extent == OperationExtent::property(2, 1)));
    }
}

#[test]
fn property_count_comparisons_ignore_ordinary_element_width_and_image() {
    use crate::commissioning::image::{ImageLocation, ImageSpace};
    for by_type in [false, true] {
        let object = if by_type {
            ObjectSelector::Type { object_type: 11, occurrence: Occurrence::from_option(Some(0)) }
        } else {
            ObjectSelector::Index { index: 4 }
        };
        for width in [None, Some(1), Some(8)] {
            let mut profile = minimal_profile();
            if let Some(width) = width {
                declare_property(&mut profile, &object, 53, width, width);
            }
            let count_location = ImageLocation {
                space: ImageSpace::PropertyCount { object: object.clone(), property_id: 53 },
                offset: 0,
            };
            let mut image = SparseDeviceImage::new();
            image
                .apply_owned(
                    ImageLocation {
                        space: ImageSpace::Property { object: object.clone(), property_id: 53 },
                        offset: 0,
                    },
                    vec![0xaa; 8],
                )
                .expect("ordinary property image");
            image.apply_owned(count_location.clone(), vec![0, 5]).expect("separate count image");
            let control = LdCtrlCompareProp {
                obj_idx: (!by_type).then_some(4),
                obj_type: by_type.then_some(11),
                occurrence: by_type.then_some(0),
                prop_id: 53,
                start_element: Some(0),
                count: Some(1),
                inline_data: Some("0005".to_owned()),
                ..Default::default()
            };
            let normalized = compile_fixture_with_profile(
                profile,
                LoadProcedure { merge_id: None, controls: vec![LoadControl::LdCtrlCompareProp(control)] },
                Vec::new(),
                image,
            )
            .expect("count comparison has a fixed two-byte width");
            let ProcedureOperation::Compare { comparison, extent, .. } = &normalized.steps[0].operation else {
                panic!("count control stays a comparison");
            };
            assert_eq!(*extent, OperationExtent::property(2, 1));
            let Comparison::Exact { data: OperationData::Buffer { location, length, fallback }, .. } = comparison
            else {
                panic!("count reference retains its independent image identity");
            };
            assert_eq!(location, &count_location);
            assert_eq!(*length, 2);
            assert_eq!(fallback.as_deref(), Some([0, 5].as_slice()));
        }
    }
    for (count, reference) in [(0, "0005"), (2, "00050006")] {
        let error = compile_fixture(
            LoadProcedure {
                merge_id: None,
                controls: vec![LoadControl::LdCtrlCompareProp(LdCtrlCompareProp {
                    obj_idx: Some(4),
                    prop_id: 53,
                    start_element: Some(0),
                    count: Some(count),
                    inline_data: Some(reference.to_owned()),
                    ..Default::default()
                })],
            },
            Vec::new(),
        )
        .expect_err("count comparisons require exactly one element");
        assert!(!error.to_string().is_empty());
    }
}

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
        data: OperationData::Inline(bytes), extent: OperationExtent { byte_length: 2, property_elements: Some(1), property_element_width: None }, ..
    } if bytes == &[1, 2]));
    assert!(matches!(&program.steps[2].operation, ProcedureOperation::Compare {
        comparison: Comparison::Exact { data: OperationData::Buffer { length: 3, .. }, .. },
        extent: OperationExtent { byte_length: 3, property_elements: Some(1), property_element_width: None },
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
        extent: OperationExtent { byte_length: 2, property_elements: Some(1), property_element_width: None },
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
fn property_pdt_truncates_inline_padding_and_omits_short_values_without_an_image() {
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

    let short = compile("00000014003200").expect("a short inline value without an image performs no write");
    assert_eq!(short.steps.len(), 2);
    assert!(matches!(short.steps[0].operation, ProcedureOperation::Connect));
    assert!(matches!(short.steps[1].operation, ProcedureOperation::Disconnect));
}

#[test]
fn inline_property_write_leaves_its_width_to_the_target_when_metadata_is_absent() {
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

    // The authored byte is a payload, not a width: the reference sizes the
    // write from the target's property description when it executes.
    let normalized = compile_fixture(procedure, Vec::new()).expect("a vendor-property write defers its width");
    let ProcedureOperation::DescribedProperty(DescribedPropertyOperation {
        elements,
        action: DescribedPropertyAction::Write { payload, .. },
        ..
    }) = &normalized.steps[1].operation
    else {
        panic!("second control is the described property write");
    };

    assert_eq!(*elements, 1);
    assert_eq!(payload, &[0x01]);
}

#[test]
fn inline_property_compare_leaves_its_width_to_the_target_when_metadata_is_absent() {
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

    let normalized =
        compile_fixture(procedure, Vec::new()).expect("a read-only vendor-property comparison defers its width");
    let ProcedureOperation::DescribedProperty(DescribedPropertyOperation {
        elements,
        action: DescribedPropertyAction::Compare { reference, .. },
        ..
    }) = &normalized.steps[1].operation
    else {
        panic!("second control is the described property comparison");
    };

    assert_eq!(*elements, 1);
    assert_eq!(reference, &[0x01]);
}

/// A System 7 product whose only parameter lives in a manufacturer object
/// property. Neither the mask roster nor global Master Data types it, as for
/// M-00FA_A-2526's object type 421, PID 201. The parameter omits its
/// occurrence while the control states zero: both name the same object.
fn untyped_property_product() -> zweidraehte_ets_files::product::ProductData {
    declared_property_product(
        8,
        r#"<Property ObjectType="421" PropertyId="201" Offset="0" BitOffset="0" />"#,
        r#"<LdCtrlConnect />
              <LdCtrlWriteMem Address="256" Size="4" Verify="false" />
              <LdCtrlWriteProp ObjType="421" Occurrence="0" PropId="201" Verify="false" />
              <LdCtrlDisconnect />"#,
    )
}

/// The untyped-property fixture with an authored parameter width, property
/// location and load procedure.
fn declared_property_product(
    size_bits: u16,
    property: &str,
    controls: &str,
) -> zweidraehte_ets_files::product::ProductData {
    let xml = format!(
        r#"<KNX xmlns="http://knx.org/xml/project/23" CreatedBy="property-test" ToolVersion="1">
      <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
        <ApplicationProgram Id="M-00FA_A-0001-01-0000" ApplicationNumber="1" ApplicationVersion="1"
          ProgramType="ApplicationProgram" MaskVersion="MV-0705" Name="untyped property fixture"
          LoadProcedureStyle="ProductProcedure" PeiType="0" DefaultLanguage="en-US"
          DynamicTableManagement="false" Linkable="false">
          <Static>
            <Code><AbsoluteSegment Id="M-00FA_A-0001-01-0000_AS-100" Address="256" Size="4" MemoryType="EEPROM"><Data>AQIDBA==</Data></AbsoluteSegment>
              <AbsoluteSegment Id="M-00FA_A-0001-01-0000_AS-110" Address="272" Size="1" MemoryType="EEPROM" /></Code>
            <AssociationTable CodeSegment="M-00FA_A-0001-01-0000_AS-110" Offset="0" MaxEntries="0" />
            <ParameterTypes><ParameterType Id="color" Name="Color"><TypeNumber SizeInBit="{size_bits}" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType></ParameterTypes>
            <Parameters>
              <Parameter Id="background" Name="421.201" ParameterType="color" Text="Background" Value="7">
                {property}
              </Parameter>
            </Parameters>
            <ParameterRefs><ParameterRef Id="background-ref" RefId="background" /></ParameterRefs>
            <LoadProcedures><LoadProcedure>
              {controls}
            </LoadProcedure></LoadProcedures>
          </Static>
          <Dynamic><ChannelIndependentBlock><ParameterBlock Id="page" Name="Settings">
            <ParameterRefRef RefId="background-ref" />
          </ParameterBlock></ChannelIndependentBlock></Dynamic>
        </ApplicationProgram>
      </ApplicationPrograms></Manufacturer></ManufacturerData>
    </KNX>"#
    );
    zweidraehte_ets_files::product::ProductData::from_mtxml_str(&xml).expect("untyped property fixture parses")
}

#[test]
fn untyped_parameter_property_takes_its_width_from_the_observed_pdt() {
    use crate::commissioning::CompileOptions;
    use crate::commissioning::input::{CommissioningIntent, DownloadMode, TargetSelection};
    use crate::commissioning::test_support::architecture::{catalog, programming_input, resolve_profile};
    use crate::configuration::MaterializedDevice;
    use zweidraehte_proto::address::IndividualAddress;

    let catalog = catalog(23);
    let product = untyped_property_product();
    let object = ObjectSelector::Type { object_type: 421, occurrence: Occurrence::Zero };

    let profile = resolve_profile(&catalog, 0x0705, None, &product);

    let address = IndividualAddress::new(1, 1, 10);
    let mut configuration = MaterializedDevice::fixture(address, Some(15));
    configuration
        .encoded_mut()
        .parameters
        .push(crate::configuration::EncodedParameter { id: "background".to_owned(), value: vec![9] });
    let compile = |profile: &crate::commissioning::ResolvedProfile| {
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
        .compile(profile)
    };

    // Without an observation, the write reads the target's description by
    // object type when it executes and sends the parameter's one-byte
    // segment.
    let program = compile(&profile).expect("the target sizes the parameter write");
    let described = program
        .procedure()
        .expect("download has a procedure")
        .steps
        .iter()
        .find_map(|step| match &step.operation {
            ProcedureOperation::DescribedProperty(operation) => Some(operation),
            _ => None,
        })
        .expect("the parameter property is written");
    assert!(matches!(described.target, OperationTarget::Property {
        address: PropertyAddress::Extended { property_id: 201, .. },
        start_element: 1
    }));
    assert!(matches!(&described.action, DescribedPropertyAction::WriteImage { length: 1, .. }));

    // The fixture's PDT 50 is one octet wide: one element carries the parameter.
    let observed =
        profile.clone().with_observed_property_type(object.clone(), 201, 50).expect("the property is untyped");
    let program = compile(&observed).expect("the observed PDT sizes the parameter write");
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
    assert_eq!(*write.1, OperationExtent { byte_length: 1, property_elements: Some(1), property_element_width: None });
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
    // An omitted occurrence keys the same observation as zero.
    let absent = ObjectSelector::Type { object_type: 421, occurrence: Occurrence::Absent };
    assert_eq!(observed.property_element_size(&absent, 201, false).expect("observation resolves"), Some(1));
    assert!(observed.with_observed_property_type(object.clone(), 201, 4).is_err());
    let typed = ObjectSelector::Index { index: 4 };
    let mut declared = minimal_profile();
    declare_property(&mut declared, &typed, 161, 1, 1);
    edit_profile(&mut declared, |xml| {
        xml.replacen(
            "</PropertyDataTypes>",
            r#"<PropertyDataType Id="PDT-50" Name="PDT_ONE" Number="50" Size="1" /><PropertyDataType Id="PDT-4" Name="PDT_TWO" Number="4" Size="2" /></PropertyDataTypes>"#,
            1,
        )
    });
    // An observation that agrees with Master Data confirms it; one that
    // contradicts it is rejected.
    let confirmed = declared.clone().with_observed_property_type(typed.clone(), 161, 50).expect("observation agrees");
    assert_eq!(confirmed.property_element_size(&typed, 161, false).expect("Master Data resolves"), Some(1));
    let error = declared.with_observed_property_type(typed, 161, 4).expect_err("Master Data types this property");
    assert!(error.to_string().contains("already typed"), "{error}");
}

/// Compile a full download of `product` with its parameter set to `value` and
/// return the extent and data of its write to `property_id`.
fn declared_property_write(
    catalog: &std::sync::Arc<MasterData>,
    product: &zweidraehte_ets_files::product::ProductData,
    value: &[u8],
    selection: &crate::commissioning::ProfileSelection,
    observed: Option<(ObjectSelector, u16, u8)>,
    property_id: u16,
) -> Result<(OperationExtent, OperationData), crate::commissioning::error::CompileError> {
    use crate::commissioning::CompileOptions;
    use crate::commissioning::input::{CommissioningIntent, DownloadMode, TargetSelection};
    use crate::commissioning::test_support::architecture::programming_input;
    use crate::configuration::MaterializedDevice;
    use zweidraehte_proto::address::IndividualAddress;

    let address = IndividualAddress::new(1, 1, 10);
    let mut configuration = MaterializedDevice::fixture(address, Some(15));
    configuration
        .encoded_mut()
        .parameters
        .push(crate::configuration::EncodedParameter { id: "background".to_owned(), value: value.to_vec() });
    let input = programming_input(
        catalog,
        product,
        &configuration,
        CommissioningIntent::Download(DownloadMode::Full),
        CompileOptions {
            target: TargetSelection::ExistingAddress(address),
            automatic_sections: None,
            progress_messages_by_reference: BTreeMap::new(),
            progress_messages_by_id: BTreeMap::new(),
        },
    );
    let mut profile = input.device().resolve_profile(selection)?;
    if let Some((object, property_id, pdt)) = observed {
        profile = profile.with_observed_property_type(object, property_id, pdt)?;
    }
    let program = input.compile(&profile)?;
    let write = program
        .procedure()
        .expect("download has a procedure")
        .steps
        .iter()
        .find_map(|step| match &step.operation {
            ProcedureOperation::Write { target: OperationTarget::Property { address, .. }, extent, data, .. }
                if match address {
                    PropertyAddress::Indexed { property_id: written, .. } => u16::from(*written) == property_id,
                    PropertyAddress::Extended { property_id: written, .. } => *written == property_id,
                } =>
            {
                Some((*extent, data.clone()))
            }
            _ => None,
        })
        .expect("the parameter property is written");
    Ok(write)
}

fn system7_selection() -> crate::commissioning::ProfileSelection {
    ProfileSelection {
        discovery: ProfileDiscovery { dd0: 0x0705, management_descriptor_01: None, management_style: None },
        variant_hint: VariantHint::Automatic,
    }
}

#[test]
fn procedure_declaration_types_a_property_by_object_type_and_pid() {
    use crate::commissioning::test_support::architecture::catalog;

    // Only the first declaration selected for this download counts. The
    // partial-download declaration is not part of a full download, and the
    // declaration after the write still precedes the later one. A type
    // declaration matches every occurrence of its object type.
    let product = declared_property_product(
        32,
        r#"<Property ObjectType="421" PropertyId="201" Offset="0" BitOffset="0" />"#,
        r#"<LdCtrlConnect />
              <LdCtrlDeclarePropDesc AppliesTo="par" ObjType="421" PropId="201" PropType="PDT_BINARY_INFORMATION" MaxElements="1" ReadAccess="3" WriteAccess="3" Writable="true" />
              <LdCtrlWriteMem Address="256" Size="4" Verify="false" />
              <LdCtrlWriteProp ObjType="421" Occurrence="0" PropId="201" Verify="false" />
              <LdCtrlDeclarePropDesc ObjType="421" Occurrence="3" PropId="201" PropType="PDT_UNSIGNED_LONG" MaxElements="1" ReadAccess="3" WriteAccess="3" Writable="true" />
              <LdCtrlDeclarePropDesc ObjType="421" PropId="201" PropType="PDT_BINARY_INFORMATION" MaxElements="1" ReadAccess="3" WriteAccess="3" Writable="true" />
              <LdCtrlDisconnect />"#,
    );
    let catalog = catalog(23);
    let object = ObjectSelector::Type { object_type: 421, occurrence: Occurrence::Zero };
    let four_bytes = OperationExtent { byte_length: 4, property_elements: Some(1), property_element_width: None };

    let extent = declared_property_write(&catalog, &product, &[0, 0, 0, 9], &system7_selection(), None, 201)
        .expect("the declaration sizes the write")
        .0;
    assert_eq!(extent, four_bytes);

    // The procedure re-declares the property before the device uses it, so a
    // description observed before the download cannot override it.
    let observed = Some((object, 201, 50));
    assert_eq!(
        declared_property_write(&catalog, &product, &[0, 0, 0, 9], &system7_selection(), observed, 201)
            .expect("declaration wins")
            .0,
        four_bytes
    );
}

#[test]
fn procedure_declaration_types_a_property_by_object_index_and_pid() {
    use crate::commissioning::test_support::architecture::catalog;

    // A type declaration never describes an indexed property, even for the
    // same PID.
    let product = declared_property_product(
        32,
        r#"<Property ObjectIndex="12" PropertyId="208" Offset="0" BitOffset="0" />"#,
        r#"<LdCtrlConnect />
              <LdCtrlDeclarePropDesc ObjType="421" PropId="208" PropType="PDT_BINARY_INFORMATION" MaxElements="1" ReadAccess="3" WriteAccess="3" Writable="true" />
              <LdCtrlDeclarePropDesc ObjIdx="12" PropId="208" PropType="PDT_UNSIGNED_LONG" MaxElements="1" ReadAccess="3" WriteAccess="3" Writable="true" />
              <LdCtrlWriteMem Address="256" Size="4" Verify="false" />
              <LdCtrlWriteProp ObjIdx="12" PropId="208" Verify="false" />
              <LdCtrlDisconnect />"#,
    );

    let extent = declared_property_write(&catalog(23), &product, &[0, 0, 0, 9], &system7_selection(), None, 208)
        .expect("the declaration sizes the write")
        .0;
    assert_eq!(extent, OperationExtent { byte_length: 4, property_elements: Some(1), property_element_width: None });
}

#[test]
fn untyped_indexed_parameter_property_writes_its_image_segment_at_the_described_size() {
    use crate::commissioning::CompileOptions;
    use crate::commissioning::image::{ImageLocation, ImageSpace};
    use crate::commissioning::input::{CommissioningIntent, DownloadMode, TargetSelection};
    use crate::commissioning::test_support::architecture::{catalog, programming_input};
    use crate::configuration::MaterializedDevice;
    use zweidraehte_proto::address::IndividualAddress;

    let catalog = catalog(23);
    let compile = |offset: u32, start: u16, inline: Option<&str>| {
        let inline_attribute = inline.map(|bytes| format!(r#" InlineData="{bytes}""#)).unwrap_or_default();
        let product = declared_property_product(
            32,
            &format!(r#"<Property ObjectIndex="12" PropertyId="208" Offset="{offset}" BitOffset="0" />"#),
            &format!(
                r#"<LdCtrlConnect />
              <LdCtrlWriteMem Address="256" Size="4" Verify="false" />
              <LdCtrlWriteProp ObjIdx="12" PropId="208" StartElement="{start}" Count="2" Verify="false"{inline_attribute} />
              <LdCtrlDisconnect />"#
            ),
        );
        let address = IndividualAddress::new(1, 1, 10);
        let mut configuration = MaterializedDevice::fixture(address, Some(15));
        configuration
            .encoded_mut()
            .parameters
            .push(crate::configuration::EncodedParameter { id: "background".to_owned(), value: vec![1, 2, 3, 4] });
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
        .compile_selection(&system7_selection())
        .map(|program| program.procedure().expect("download has a procedure").clone())
    };

    // Nothing types index 12 PID 208, and no observation is needed: the
    // write waits for the target's description. The parameter's four bytes
    // from the property's start are its whole segment.
    let procedure = compile(0, 1, None).expect("the write is sized by the target");
    let operation = procedure
        .steps
        .iter()
        .find_map(|step| match &step.operation {
            ProcedureOperation::DescribedProperty(operation) => Some(operation),
            _ => None,
        })
        .expect("the parameter property is written");
    let segment = ImageLocation {
        space: ImageSpace::Property { object: ObjectSelector::Index { index: 12 }, property_id: 208 },
        offset: 0,
    };
    assert_eq!(operation.elements, 2);
    assert!(
        matches!(&operation.action, DescribedPropertyAction::WriteImage { location, length: 4, .. } if *location == segment),
        "{:?}",
        operation.action
    );

    // The IR retains the clipped source, and derives its wire count from the
    // reported width. Runtime padding preserves an omitted last device byte.
    let width = |bytes| *operation.widths.iter().find(|(_, width)| **width == bytes).expect("fixture PDT width").0;
    for (pdt, sent) in [(width(1), 2), (width(4), 4)] {
        let Some(ProcedureOperation::Write { data, extent, .. }) =
            operation.resolve(pdt).expect("a fixed-width PDT resolves")
        else {
            panic!("the segment is written");
        };
        assert_eq!(extent, OperationExtent::property_window(sent, operation.widths[&pdt]).expect("resolved width"));
        assert_eq!(data, OperationData::Buffer { location: segment.clone(), length: sent, fallback: None });
    }

    let masked = compile(1, 1, None).expect("unowned property bytes are merged with device readback");
    assert!(masked.steps.iter().any(|step| matches!(
        &step.operation,
        ProcedureOperation::DescribedProperty(operation)
            if matches!(&operation.action, DescribedPropertyAction::WriteImage { location, length: 5, .. } if *location == segment)
    )));
    let later = compile(2, 2, Some("A5A5A5A5A5A5A5A5A5A5"))
        .expect("later starts retain the image and defer only their element offset");
    assert!(later.steps.iter().any(|step| matches!(
        &step.operation,
        ProcedureOperation::DescribedProperty(operation)
            if operation.elements == 2 && matches!(&operation.action,
                DescribedPropertyAction::WriteImageWindow { location, length: 6, inline: Some(bytes), .. }
                    if *location == segment && *bytes == vec![0xa5; 10])
    )));
}

#[test]
fn typed_singleton_metadata_sizes_wire_independently_of_declaration() {
    use crate::commissioning::test_support::architecture::edited_catalog;

    // Typed singleton metadata wins wire lookup, while the declaration still
    // supplies the image allocation width.
    let product = declared_property_product(
        8,
        r#"<Property ObjectType="421" PropertyId="201" Offset="0" BitOffset="0" />"#,
        r#"<LdCtrlConnect />
              <LdCtrlDeclarePropDesc ObjType="421" PropId="201" PropType="PDT_UNSIGNED_LONG" MaxElements="1" ReadAccess="3" WriteAccess="3" Writable="true" />
              <LdCtrlWriteMem Address="256" Size="4" Verify="false" />
              <LdCtrlWriteProp ObjType="421" Occurrence="0" PropId="201" Verify="false" />
              <LdCtrlDisconnect />"#,
    );
    let catalog = edited_catalog(23, |xml| {
        xml.replacen(
            "<PropertyDataTypes>",
            r#"<InterfaceObjectProperties><InterfaceObjectProperty Id="PID-421-201" Number="201" ObjectType="OT-421" Name="PID_MANUFACTURER_201" PDT="PDT-50"/></InterfaceObjectProperties><PropertyDataTypes>"#,
            1,
        )
    });

    let (extent, _) = declared_property_write(&catalog, &product, &[9], &system7_selection(), None, 201)
        .expect("typed singleton metadata wins wire lookup");
    assert_eq!(extent, OperationExtent::property(1, 1));

    // Equal-width alternatives still do not form an exact well-known PDT.
    // Keep the conservative conflict check when that native fast path is absent.
    let ambiguous = edited_catalog(23, |xml| {
        xml.replacen(
        "<PropertyDataTypes>",
        r#"<InterfaceObjectProperties><InterfaceObjectProperty Id="PID-421-201" Number="201" ObjectType="OT-421" Name="PID_MANUFACTURER_201" PDT="PDT-50 PDT-2"/></InterfaceObjectProperties><PropertyDataTypes><PropertyDataType Id="PDT-2" Number="2" Name="PDT_UNSIGNED_CHAR" Size="1" />"#,
        1,
    )
    });
    let error = declared_property_write(&ambiguous, &product, &[9], &system7_selection(), None, 201)
        .expect_err("ambiguous metadata cannot bypass declaration conflict checks");
    assert!(error.to_string().contains("declares PDT_UNSIGNED_LONG"), "{error}");
}

#[test]
fn declared_buffer_allocation_does_not_expand_to_the_typed_wire_width() {
    use crate::commissioning::CompileOptions;
    use crate::commissioning::image::{ImageLocation, ImageSpace};
    use crate::commissioning::input::{CommissioningIntent, DownloadMode, TargetSelection};
    use crate::commissioning::test_support::architecture::{edited_catalog, programming_input};
    use crate::configuration::MaterializedDevice;
    use zweidraehte_proto::address::IndividualAddress;

    let catalog = edited_catalog(23, |xml| {
        xml.replacen(
        "<PropertyDataTypes>",
        r#"<InterfaceObjectProperties><InterfaceObjectProperty Id="PID-421-201" Number="201" ObjectType="OT-421" Name="PID_MANUFACTURER_201" PDT="PDT-21"/></InterfaceObjectProperties><PropertyDataTypes><PropertyDataType Id="PDT-21" Number="21" Name="PDT_GENERIC_05" Size="5" />"#,
        1,
    )
    });
    for inline in ["1122334455", "11223344"] {
        let controls = format!(
            r#"<LdCtrlConnect />
            <LdCtrlDeclarePropDesc ObjType="421" PropId="201" PropType="PDT_BINARY_INFORMATION" MaxElements="1" ReadAccess="3" WriteAccess="3" Writable="true" />
            <LdCtrlWriteMem Address="256" Size="4" Verify="false" />
            <LdCtrlWriteProp ObjType="421" Occurrence="0" PropId="201" Verify="false" InlineData="{inline}" />
            <LdCtrlDisconnect />"#
        );
        // A memory parameter keeps this fixture's ordinary configuration valid
        // without contributing any property bytes or ownership.
        let product = declared_property_product(
            8,
            r#"<Memory CodeSegment="M-00FA_A-0001-01-0000_AS-100" Offset="0" BitOffset="0" />"#,
            &controls,
        );
        let address = IndividualAddress::new(1, 1, 10);
        let configuration = MaterializedDevice::fixture(address, Some(15));
        let program = programming_input(
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
        .compile_selection(&system7_selection())
        .expect("different allocation and wire PDTs compile");
        let location = ImageLocation {
            space: ImageSpace::Property {
                object: ObjectSelector::Type { object_type: 421, occurrence: Occurrence::Zero },
                property_id: 201,
            },
            offset: 0,
        };
        assert_eq!(program.image().byte(&location), Some((0, 0)));
        assert!(program.image().byte(&ImageLocation { offset: 1, ..location.clone() }).is_none());
        let (data, extent) = program
            .procedure()
            .expect("download procedure")
            .steps
            .iter()
            .find_map(|step| match &step.operation {
                ProcedureOperation::Write {
                    target:
                        OperationTarget::Property { address: PropertyAddress::Extended { property_id: 201, .. }, .. },
                    data,
                    extent,
                    ..
                } => Some((data, extent)),
                _ => None,
            })
            .expect("property write survives final binding");
        if inline.len() == 10 {
            assert_eq!(*data, OperationData::Inline(vec![0x11, 0x22, 0x33, 0x44, 0x55]));
            assert_eq!(*extent, OperationExtent::property(5, 1));
        } else {
            assert_eq!(*data, OperationData::Buffer { location, length: 1, fallback: None });
            assert_eq!(*extent, OperationExtent::property_window(1, 5).expect("five-byte element"));
        }
    }
}

#[test]
fn inline_property_write_keeps_its_payload_only_where_the_image_owns_no_bits() {
    use crate::commissioning::test_support::architecture::catalog;

    // The parameter owns only the second octet of the declared four-octet
    // property. A write with authored InlineData sends the authored octets
    // with the image's owned bits overlaid, as for an exact property
    // comparison; it neither discards the authored bytes nor the configured
    // parameter.
    let product = declared_property_product(
        8,
        r#"<Property ObjectType="421" PropertyId="201" Offset="1" BitOffset="0" />"#,
        r#"<LdCtrlConnect />
              <LdCtrlDeclarePropDesc ObjType="421" PropId="201" PropType="PDT_UNSIGNED_LONG" MaxElements="1" ReadAccess="3" WriteAccess="3" Writable="true" />
              <LdCtrlWriteMem Address="256" Size="4" Verify="false" />
              <LdCtrlWriteProp ObjType="421" Occurrence="0" PropId="201" Verify="false" InlineData="11223344" />
              <LdCtrlDisconnect />"#,
    );

    let (extent, data) = declared_property_write(&catalog(23), &product, &[9], &system7_selection(), None, 201)
        .expect("the declaration sizes the write");
    assert_eq!(extent, OperationExtent { byte_length: 4, property_elements: Some(1), property_element_width: None });
    assert_eq!(data, OperationData::Inline(vec![0x11, 0x09, 0x33, 0x44]));
}
