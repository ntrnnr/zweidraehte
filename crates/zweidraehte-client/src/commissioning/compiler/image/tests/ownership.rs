use super::*;
use crate::commissioning::image::ImageSegment;
use std::sync::Arc;
use zweidraehte_ets_files::product::SelectedProduct;

fn raw_parameter_product(location: &str, byte_order: &str, capacity: u32) -> ProductData {
    parameter_product(location, byte_order, &format!(r#"<TypeRawData MaxSize="{capacity}"/>"#))
}

fn parameter_product(location: &str, byte_order: &str, parameter_type: &str) -> ProductData {
    let template = zweidraehte_ets_files::product::fixtures::SYSTEM7_MTXML;
    let (prefix, rest) = template.split_once("<Parameters>").expect("fixture parameters");
    let (_, suffix) = rest.split_once("</Parameters>").expect("fixture parameter end");
    let xml = format!(
        r#"{prefix}<Options ParameterByteOrder="{byte_order}"/>
        <ParameterTypes><ParameterType Id="raw-type" Name="Raw">{parameter_type}</ParameterType></ParameterTypes>
        <Parameters><Parameter Id="raw" Name="Raw" Text="Raw" ParameterType="raw-type" Value="">{location}</Parameter></Parameters>{suffix}"#
    )
    .replace(
        r#"Id="M-00FA_A-0306-02-0000_AS-4300" Address="17152" Size="4" MemoryType="EEPROM"><Data>AQIDBA==</Data>"#,
        r#"Id="M-00FA_A-0306-02-0000_AS-4300" Address="17152" Size="16" MemoryType="EEPROM">"#,
    );
    ProductData::from_mtxml_str(&xml).expect("raw parameter product parses")
}

#[test]
fn raw_property_count_defaults_to_bytes_independently_of_global_wire_pdt() {
    use crate::commissioning::catalog::profile::{ObjectSelector, Occurrence};

    let object = ObjectSelector::Type { object_type: 0, occurrence: Occurrence::from_option(Some(0)) };
    let mut profile = table_profile();
    crate::commissioning::catalog::profile::testing::edit_profile(&mut profile, |xml| {
        xml.replace(
            "<MaskVersions>",
            r#"<PropertyDataTypes><PropertyDataType Id="PDT-22" Number="22" Name="PDT_GENERIC_06" Size="6"/></PropertyDataTypes>
            <InterfaceObjectProperties><InterfaceObjectProperty Id="PID-0-78" Number="78" ObjectType="OT-0" Name="PID_HARDWARE_TYPE" PDT="PDT-22"/></InterfaceObjectProperties><MaskVersions>"#,
        )
    });
    assert_eq!(profile.property_element_size(&object, 78, false).expect("global wire PDT"), Some(6));
    let location = ImageLocation { space: ImageSpace::Property { object: object.clone(), property_id: 78 }, offset: 0 };
    let count_location = ImageLocation { space: ImageSpace::PropertyCount { object, property_id: 78 }, offset: 0 };

    for (parameter_type, expected_count) in
        [(r#"<TypeRawData MaxSize="6"/>"#, 6), (r#"<TypeRestriction Base="BinaryValue" SizeInBit="48"/>"#, 1)]
    {
        let product = parameter_product(
            r#"<Property ObjectType="0" PropertyId="78" Offset="0" BitOffset="0"/>"#,
            "BigEndian",
            parameter_type,
        );
        let mut configuration = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 1), Some(15));
        configuration.parameters = vec![ParameterValue { id: "raw".to_owned(), value: vec![0, 0, 0, 0x20, 0, 3] }];
        let mut image = SparseDeviceImage::new();
        image.apply_section(
            ProgrammingSection::Configuration,
            &ImageSegment::owned(count_location.clone(), vec![0, 1]).expect("prior count"),
        );
        apply_property_parameters(&profile, &product, &configuration, &mut image, ImageDemand::Complete)
            .expect("hardware type parameter");
        assert_eq!(image.range(&location, 6).expect("parameter bytes").data(), [0, 0, 0, 0x20, 0, 3]);
        assert!(image.range(&location, 7).is_err(), "allocation keeps its original width");
        assert_eq!(image.range(&count_location, 2).expect("count image").data(), [0, expected_count]);
    }
}

#[test]
fn raw_property_count_uses_declared_object_type_as_pdt_instead_of_prop_type() {
    use crate::commissioning::catalog::profile::{DeclaredProperty, ObjectSelector, Occurrence};

    let object = ObjectSelector::Type { object_type: 260, occurrence: Occurrence::from_option(Some(0)) };
    let mut profile = table_profile();
    crate::commissioning::catalog::profile::testing::edit_profile(&mut profile, |xml| {
        xml.replace(
            "<MaskVersions>",
            r#"<PropertyDataTypes><PropertyDataType Id="PDT-0" Number="0" Name="PDT_CONTROL" Size="10" ReadSize="1"/><PropertyDataType Id="PDT-4" Number="4" Name="PDT_UNSIGNED_INT" Size="2"/><PropertyDataType Id="PDT-22" Number="22" Name="PDT_GENERIC_06" Size="6"/></PropertyDataTypes><MaskVersions>"#,
        )
    });
    let profile = profile.with_procedure_property_declarations([(DeclaredProperty::new(&object, 201), "PDT-22")]);
    let product = raw_parameter_product(
        r#"<Property ObjectType="260" PropertyId="201" Offset="0" BitOffset="0"/>"#,
        "BigEndian",
        6,
    );
    let mut configuration = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 1), Some(15));
    configuration.parameters = vec![ParameterValue { id: "raw".to_owned(), value: vec![1, 2, 3, 4, 5] }];
    let mut image = SparseDeviceImage::new();
    apply_property_parameters(&profile, &product, &configuration, &mut image, ImageDemand::Complete)
        .expect("declared raw property");
    let count = ImageLocation { space: ImageSpace::PropertyCount { object, property_id: 201 }, offset: 0 };
    assert_eq!(image.range(&count, 2).expect("native formatter count").data(), [0, 2]);

    let object = ObjectSelector::Index { index: 9 };
    let profile = profile.with_procedure_property_declarations([(DeclaredProperty::new(&object, 201), "PDT-22")]);
    let product = raw_parameter_product(
        r#"<Property ObjectIndex="9" PropertyId="201" Offset="0" BitOffset="0"/>"#,
        "BigEndian",
        12,
    );
    configuration.parameters[0].value = vec![0x11; 11];
    let mut image = SparseDeviceImage::new();
    apply_property_parameters(&profile, &product, &configuration, &mut image, ImageDemand::Complete)
        .expect("indexed declaration keeps native default object type zero");
    let count = ImageLocation { space: ImageSpace::PropertyCount { object, property_id: 201 }, offset: 0 };
    assert_eq!(image.range(&count, 2).expect("PDT zero counts ten-byte elements").data(), [0, 1]);
}

#[test]
fn raw_memory_parameters_own_their_length_header_and_payload_only() {
    // These expectations come from native ApplyParameter probes: empty values
    // still write a four-byte zero header, payload order stays unchanged, and
    // capacity beyond the actual payload remains the device's responsibility.
    for (byte_order, payload, expected) in [
        ("BigEndian", vec![], vec![0, 0, 0, 0]),
        ("LittleEndian", vec![], vec![0, 0, 0, 0]),
        ("BigEndian", vec![0x11, 0x22], vec![0, 0, 0, 2, 0x11, 0x22]),
        ("LittleEndian", vec![0x11, 0x22], vec![2, 0, 0, 0, 0x11, 0x22]),
    ] {
        let product = raw_parameter_product(
            r#"<Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" Offset="0" BitOffset="0"/>"#,
            byte_order,
            8,
        );
        assert_eq!(product.raw_data_parameter_max_size("raw"), Some(8));
        let mut configuration = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 1), Some(15));
        configuration.parameters = vec![ParameterValue { id: "raw".to_owned(), value: payload }];
        let mut image = SparseDeviceImage::new();
        let regions = seed_segments(&product, ImageDemand::Complete, &mut image).expect("raw memory allocation");
        apply_parameters(&product, &configuration, &regions, &mut image, ImageDemand::Complete)
            .expect("raw memory parameter");
        let bytes = image.project(&ImageLocation::standard_memory(0x4300), &[0xA5; 16]).expect("raw memory image");
        assert_eq!(&bytes.data()[..expected.len()], expected, "{byte_order}");
        assert!(bytes.mask()[..expected.len()].iter().all(|mask| *mask == 255));
        assert!(bytes.mask()[expected.len()..].iter().all(|mask| *mask == 0));
        assert!(bytes.data()[expected.len()..].iter().all(|byte| *byte == 0xA5));
    }
}

#[test]
fn raw_property_parameters_keep_capacity_unowned_and_count_elements_separately() {
    use crate::commissioning::catalog::profile::{DeclaredProperty, ObjectSelector};

    let object = ObjectSelector::Index { index: 9 };
    let mut profile = table_profile();
    crate::commissioning::catalog::profile::testing::edit_profile(&mut profile, |xml| {
        xml.replace(
            "<MaskVersions>",
            r#"<PropertyDataTypes><PropertyDataType Id="PDT_RAW_PAIR" Name="PDT_RAW_PAIR" Size="2"/><PropertyDataType Id="PDT-0" Number="0" Name="PDT_CONTROL" Size="10" ReadSize="1"/></PropertyDataTypes><MaskVersions>"#,
        )
    });
    let profile = profile.with_procedure_property_declarations([(DeclaredProperty::new(&object, 71), "PDT_RAW_PAIR")]);
    for byte_order in ["BigEndian", "LittleEndian"] {
        // Indexed declarations omit ObjType. The formatter reads its default
        // zero as PDT 0, independently of the allocation's two-byte PDT.
        for (payload, count) in [(vec![], [0, 0]), (vec![0x11], [0, 0]), (vec![0x11, 0x22, 0x33], [0, 0])] {
            let product = raw_parameter_product(
                r#"<Property ObjectIndex="9" PropertyId="71" Offset="0" BitOffset="0"/>"#,
                byte_order,
                5,
            );
            let mut configuration = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 1), Some(15));
            configuration.parameters = vec![ParameterValue { id: "raw".to_owned(), value: payload.clone() }];
            let mut image = SparseDeviceImage::new();
            apply_property_parameters(&profile, &product, &configuration, &mut image, ImageDemand::Complete)
                .expect("raw property parameter");
            let location =
                ImageLocation { space: ImageSpace::Property { object: object.clone(), property_id: 71 }, offset: 0 };
            let bytes = image.range(&location, 6).expect("capacity rounds to a whole element");
            assert_eq!(&bytes.data()[..payload.len()], payload, "payload has no memory length header");
            assert!(bytes.mask()[..payload.len()].iter().all(|mask| *mask == 255));
            assert!(bytes.mask()[payload.len()..].iter().all(|mask| *mask == 0));
            assert!(image.range(&location, 7).is_err(), "capacity does not extend beyond rounded MaxSize");
            let count_location = ImageLocation {
                space: ImageSpace::PropertyCount { object: object.clone(), property_id: 71 },
                offset: 0,
            };
            let count_bytes = image.range(&count_location, 2).expect("array count has separate image state");
            assert_eq!(count_bytes.data(), count, "count rounds payload length down and stays big-endian");
            assert_eq!(count_bytes.mask(), [255, 255]);

            for existing_count in [false, true] {
                let mut image = SparseDeviceImage::new();
                image.represent_range(&location, 6).expect("procedure allocates raw payload buffer");
                if existing_count {
                    image.apply_section(
                        ProgrammingSection::Configuration,
                        &ImageSegment::owned(count_location.clone(), vec![0xaa, 0xbb]).expect("existing raw count"),
                    );
                }
                apply_property_parameters(&profile, &product, &configuration, &mut image, ImageDemand::Complete)
                    .expect("raw parameter in preallocated property buffer");
                let bytes = image.range(&location, 6).expect("procedure allocation survives");
                assert_eq!(&bytes.data()[..payload.len()], payload);
                assert!(bytes.mask()[..payload.len()].iter().all(|mask| *mask == 255));
                assert!(bytes.mask()[payload.len()..].iter().all(|mask| *mask == 0));
                if existing_count {
                    assert_eq!(image.range(&count_location, 2).expect("existing count updates").data(), count);
                    assert_eq!(image.sections_for_range(&count_location, 2), [ProgrammingSection::Parameters].into());
                } else {
                    assert!(
                        image.range(&count_location, 2).is_err(),
                        "existing payload allocation does not invent a count"
                    );
                }
            }
        }
    }
}

#[test]
fn raw_property_demand_selects_empty_and_nonempty_values_by_data_capacity_or_count() {
    use crate::commissioning::catalog::profile::{DeclaredProperty, ObjectSelector};

    let object = ObjectSelector::Index { index: 9 };
    let mut profile = table_profile();
    crate::commissioning::catalog::profile::testing::edit_profile(&mut profile, |xml| {
        xml.replace(
            "<MaskVersions>",
            r#"<PropertyDataTypes><PropertyDataType Id="PDT_RAW_PAIR" Name="PDT_RAW_PAIR" Size="2"/><PropertyDataType Id="PDT-0" Number="0" Name="PDT_CONTROL" Size="10" ReadSize="1"/></PropertyDataTypes><MaskVersions>"#,
        )
    });
    let profile = profile.with_procedure_property_declarations([(DeclaredProperty::new(&object, 71), "PDT_RAW_PAIR")]);
    let product = raw_parameter_product(
        r#"<Property ObjectIndex="9" PropertyId="71" Offset="0" BitOffset="0"/>"#,
        "BigEndian",
        5,
    );
    let data = ImageLocation { space: ImageSpace::Property { object: object.clone(), property_id: 71 }, offset: 0 };
    let count = ImageLocation { space: ImageSpace::PropertyCount { object, property_id: 71 }, offset: 0 };

    for payload in [vec![], vec![0x11, 0x22]] {
        let mut configuration = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 1), Some(15));
        configuration.parameters = vec![ParameterValue { id: "raw".to_owned(), value: payload.clone() }];
        // The data demand lies beyond the payload, inside its declared
        // capacity. A count-only demand must select the same producer.
        for required in [
            RequiredImageRange { location: ImageLocation { offset: 4, ..data.clone() }, length: 1 },
            RequiredImageRange { location: count.clone(), length: 2 },
        ] {
            let mut image = SparseDeviceImage::new();
            apply_property_parameters(&profile, &product, &configuration, &mut image, ImageDemand::Ranges(&[required]))
                .expect("selected raw property producer");
            let buffer = image.range(&data, 6).expect("selected raw allocation");
            assert_eq!(&buffer.data()[..payload.len()], payload);
            assert!(buffer.mask()[payload.len()..].iter().all(|mask| *mask == 0));
            assert_eq!(image.range(&count, 2).expect("selected raw count").data(), [0, (payload.len() / 10) as u8]);
        }

        let mut image = SparseDeviceImage::new();
        apply_property_parameters(
            &table_profile(),
            &product,
            &configuration,
            &mut image,
            ImageDemand::Ranges(&[RequiredImageRange { location: ImageLocation::standard_memory(0), length: 1 }]),
        )
        .expect("unselected raw property needs no PDT resolution");
        assert!(image.spaces().next().is_none(), "unselected raw producer contributes no data or count");
    }
}

#[test]
fn evaluated_parameter_overlays_preserve_union_property_legacy_and_module_order() {
    use crate::configuration::{DeviceIdentity, InstallationConfiguration, ResolvedDevice, ResolvedKeyMaterial};
    use zweidraehte_ets_files::runtime::{
        Device,
        configuration::{ProductConfiguration, apply_configuration},
    };

    let template = zweidraehte_ets_files::product::fixtures::SYSTEM7_MTXML;
    let (prefix, rest) = template.split_once("<Parameters>").expect("fixture parameters");
    let (_, suffix) = rest.split_once("</Parameters>").expect("fixture parameter end");
    let xml = format!(r#"{prefix}
      <ParameterTypes><ParameterType Id="byte" Name="Byte"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType></ParameterTypes>
      <Parameters>
        <Union SizeInBit="8"><Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" Offset="0" BitOffset="0" />
          <Parameter Id="base" Name="Base" Text="Base" ParameterType="byte" Value="7" Offset="0" BitOffset="0" DefaultUnionParameter="true" />
          <Parameter Id="overlay" Name="Overlay" Text="Overlay" ParameterType="byte" Value="8" Offset="0" BitOffset="0" />
        </Union>
        <Parameter Id="legacy" Name="Legacy" Text="Legacy" ParameterType="byte" Value="21" LegacyPatchAlways="true"><Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" Offset="2" BitOffset="0" /></Parameter>
        <Union SizeInBit="8"><Property ObjectIndex="3" PropertyId="100" Offset="0" BitOffset="0" />
          <Parameter Id="property-base" Name="PropertyBase" Text="Property base" ParameterType="byte" Value="3" Offset="0" BitOffset="0" DefaultUnionParameter="true" />
          <Parameter Id="property-overlay" Name="PropertyOverlay" Text="Property overlay" ParameterType="byte" Value="6" Offset="0" BitOffset="0" />
        </Union>
        <Parameter Id="property-legacy" Name="PropertyLegacy" Text="Property legacy" ParameterType="byte" Value="23" LegacyPatchAlways="true"><Property ObjectIndex="3" PropertyId="100" Offset="1" BitOffset="0" /></Parameter>
      </Parameters>
      <ParameterRefs>
        <ParameterRef Id="base-ref" RefId="base" Value="9" />
        <ParameterRef Id="overlay-ref" RefId="overlay" Value="11" />
        <ParameterRef Id="property-base-ref" RefId="property-base" Value="4" />
      </ParameterRefs>{suffix}"#).replace("</ApplicationProgram>", r#"
      <ModuleDefs><ModuleDef Id="channel" Name="Channel"><Arguments><Argument Id="base-arg" Name="ParameterBase" /></Arguments>
        <Static><Parameters><Parameter Id="level" Name="Level" Text="Level" ParameterType="byte" Value="5"><Memory CodeSegment="M-00FA_A-0306-02-0000_AS-4300" BaseOffset="base-arg" Offset="0" BitOffset="0" /></Parameter></Parameters>
        <ParameterRefs><ParameterRef Id="level-ref" RefId="level" Value="13" /></ParameterRefs></Static>
        <Dynamic><ChannelIndependentBlock><ParameterBlock Id="channel-page" Name="Channel"><ParameterRefRef RefId="level-ref" /></ParameterBlock></ChannelIndependentBlock></Dynamic>
      </ModuleDef></ModuleDefs>
      <Dynamic><ChannelIndependentBlock><ParameterBlock Id="page" Name="Settings"><ParameterRefRef RefId="base-ref" /><ParameterRefRef RefId="overlay-ref" /><ParameterRefRef RefId="property-base-ref" /></ParameterBlock></ChannelIndependentBlock>
        <Module Id="first" RefId="channel"><NumericArg RefId="base-arg" Value="3" /></Module>
      </Dynamic></ApplicationProgram>"#)
      .replace("<LdCtrlConnect />", r#"<LdCtrlConnect /><choose ParamRefId="first::level-ref"><when test="13" /></choose>"#);
    for duplicate in [None, Some(9), Some(10)] {
        let xml = if let Some(value) = duplicate {
            xml.replace(
                "<ParameterRefs>",
                &format!(r#"<ParameterRefs><ParameterRef Id="second-base-ref" RefId="base" Value="{value}" />"#),
            )
            .replacen(
                r#"<ParameterRefRef RefId="base-ref" />"#,
                r#"<ParameterRefRef RefId="base-ref" /><ParameterRefRef RefId="second-base-ref" />"#,
                1,
            )
        } else {
            xml.clone()
        };
        let parsed = zweidraehte_ets_files::runtime::parser::parse_application_program(&xml).expect("overlay fixture");
        let selected = SelectedProduct::from_document(parsed, None, None).expect("product geometry");
        let mut device = Device::from_product(Arc::new(selected), None, None);
        let settings = ProductConfiguration::default();
        apply_configuration(&mut device, &settings).expect("overlay configuration");
        let configuration = InstallationConfiguration {
            identity: DeviceIdentity { desired_address: IndividualAddress::new(1, 1, 1), serial_number: None },
            data_secure_enabled: false,
            object_memberships: Vec::new(),
            net_security: Default::default(),
            topology: Default::default(),
            max_apdu: None,
        };
        let evaluated = device.evaluate(&settings.objects).expect("checked overlays");
        assert_eq!(evaluated.modules().len(), 1);
        assert_eq!(evaluated.modules()[0].instance_id, "first");
        let modules = evaluated.modules().as_ptr();
        let resolved = ResolvedDevice::from_evaluated(evaluated, configuration);
        if duplicate == Some(10) {
            assert!(resolved.expect_err("conflicting visible refs").to_string().contains("conflicting values"));
            continue;
        }
        let resolved = resolved.expect("equal references share one overlay");
        // The compiler receives the allocation that geometry was resolved from,
        // without a second editor traversal or cloning the evaluated roster.
        assert_eq!(resolved.modules().as_ptr(), modules);
        let materialized = resolved.into_materialized(ResolvedKeyMaterial::new(None)).expect("materialized input");
        assert_eq!(materialized.modules().as_ptr(), modules);
        let selector = materialized
            .configuration()
            .procedure_parameters
            .get("first::level-ref")
            .expect("load procedure retains its concrete module selector");
        assert!(selector.active);
        assert_eq!(selector.value, crate::configuration::ProcedureParameterValue::Signed(13));
        let mut image = SparseDeviceImage::new();
        let regions = seed_segments(materialized.product(), ImageDemand::Complete, &mut image).expect("seeded memory");
        apply_parameters(
            materialized.product(),
            materialized.configuration(),
            &regions,
            &mut image,
            ImageDemand::Complete,
        )
        .expect("memory overlays");
        apply_property_parameters(
            &table_profile(),
            materialized.product(),
            materialized.configuration(),
            &mut image,
            ImageDemand::Complete,
        )
        .expect("property overlays");

        // Both union members own the same byte: the visible later member wins.
        // The hidden legacy value and instantiated reference retain their slots.
        assert_eq!(image.byte(&ImageLocation::standard_memory(0x4300)), Some((11, 255)));
        assert_eq!(image.byte(&ImageLocation::standard_memory(0x4302)), Some((21, 255)));
        assert_eq!(image.byte(&ImageLocation::standard_memory(0x4303)), Some((13, 255)));
        let property = ImageLocation {
            space: ImageSpace::Property {
                object: crate::commissioning::catalog::profile::ObjectSelector::Index { index: 3 },
                property_id: 100,
            },
            offset: 0,
        };
        let bytes = image.range(&property, 2).expect("property union and hidden legacy");
        assert_eq!(bytes.data(), [6, 23]);
        assert_eq!(bytes.mask(), [255, 255]);
    }
}

#[test]
fn packed_parameter_transfer_preserves_seed_bits_and_owns_only_touched_bytes() {
    let (_, profile, product, mut configuration) = plain_fixture();
    for (size_bits, bit_offset, value, expected) in [
        (3, 2, vec![2], vec![0x92]),
        (12, 3, vec![0x0a, 0xbc], vec![0xb5, 0x78]),
        (4, 0, vec![5], vec![0x5a]),
        (8, 0, vec![0x7e], vec![0x7e]),
    ] {
        let mut segments = product.segments().to_vec();
        segments[0].data[..3].copy_from_slice(&[0xaa, 0xcc, 0xdd]);
        segments[0].mask = Some(vec![0; segments[0].data.len()]);
        let product =
            product.clone().with_fixture_segments(segments).with_fixture_parameters(vec![ParameterLocation {
                id: "packed".to_owned(),
                code_segment: product.segments()[0].id.clone(),
                offset: 0,
                bit_offset,
                size_bits,
                legacy_patch_always: false,
                seeds_default: false,
                byte_ordered: true,
            }]);
        configuration.parameters = vec![ParameterValue { id: "packed".to_owned(), value }];
        let compiled = compile_partial_image(&profile, &product, &configuration, ProgramSections::PARAMETERS).unwrap();
        let bytes = compiled.image.range(&ImageLocation::standard_memory(0x100), expected.len() as u32).unwrap();
        assert_eq!(bytes.data(), expected);
        assert!(bytes.mask().iter().all(|mask| *mask == 0xff));
        assert_eq!(compiled.image.byte(&ImageLocation::standard_memory(0x100 + expected.len() as u32)), None);
    }
}

#[test]
fn packed_property_parameters_preserve_prior_overlay_and_own_complete_touched_bytes() {
    use zweidraehte_ets_files::product::{PropertyObject, PropertyParameterLocation};
    let (_, profile, product, mut configuration) = plain_fixture();
    let product = product.with_fixture_property_parameters(vec![
        PropertyParameterLocation {
            id: "seed".to_owned(),
            object: PropertyObject::Index(1),
            property_id: 100,
            offset: 0,
            bit_offset: 0,
            size_bits: 24,
            legacy_patch_always: false,
            byte_ordered: true,
        },
        PropertyParameterLocation {
            id: "packed".to_owned(),
            object: PropertyObject::Index(1),
            property_id: 100,
            offset: 0,
            bit_offset: 3,
            size_bits: 12,
            legacy_patch_always: false,
            byte_ordered: true,
        },
    ]);
    configuration.parameters =
        vec![ParameterValue { id: "seed".to_owned(), value: vec![0xaa, 0xcc, 0xdd] }, ParameterValue {
            id: "packed".to_owned(),
            value: vec![0x0a, 0xbc],
        }];
    let mut image = SparseDeviceImage::new();
    apply_property_parameters(&profile, &product, &configuration, &mut image, ImageDemand::Complete).unwrap();
    let location = ImageLocation {
        space: ImageSpace::Property {
            object: crate::commissioning::catalog::profile::ObjectSelector::Index { index: 1 },
            property_id: 100,
        },
        offset: 0,
    };
    let bytes = image.range(&location, 3).unwrap();
    assert_eq!(bytes.data(), [0xb5, 0x78, 0xdd]);
    assert_eq!(bytes.mask(), [0xff; 3]);

    // Materialization places an active union member after its inactive
    // sibling. Reversing that precedence must reverse the winning write,
    // even though the product's declaration order stays the same.
    configuration.parameters.reverse();
    let mut image = SparseDeviceImage::new();
    apply_property_parameters(&profile, &product, &configuration, &mut image, ImageDemand::Complete)
        .expect("property overlays");
    let bytes = image.range(&location, 3).expect("property range");
    assert_eq!(bytes.data(), [0xaa, 0xcc, 0xdd]);
    assert_eq!(bytes.mask(), [0xff; 3]);
}

#[test]
fn property_parameter_buffers_represent_gaps_without_owning_them() {
    use zweidraehte_ets_files::product::{PropertyObject, PropertyParameterLocation};
    let (_, profile, product, mut configuration) = plain_fixture();
    let product = product.with_fixture_property_parameters(
        [("delay", 3), ("threshold", 6)]
            .into_iter()
            .map(|(id, offset)| PropertyParameterLocation {
                id: id.to_owned(),
                object: PropertyObject::Index(7),
                property_id: 52,
                offset,
                bit_offset: 0,
                size_bits: 8,
                legacy_patch_always: false,
                byte_ordered: true,
            })
            .collect(),
    );
    configuration.parameters = vec![ParameterValue { id: "delay".to_owned(), value: vec![5] }, ParameterValue {
        id: "threshold".to_owned(),
        value: vec![9],
    }];
    let mut image = SparseDeviceImage::new();
    apply_property_parameters(&profile, &product, &configuration, &mut image, ImageDemand::Complete)
        .expect("property parameters");
    let location = ImageLocation {
        space: ImageSpace::Property {
            object: crate::commissioning::catalog::profile::ObjectSelector::Index { index: 7 },
            property_id: 52,
        },
        offset: 0,
    };
    let bytes = image.range(&location, 7).expect("property buffer includes the prefix and parameter gaps");
    assert_eq!(bytes.data(), [0, 0, 0, 5, 0, 0, 9]);
    assert_eq!(bytes.mask(), [0, 0, 0, 255, 0, 0, 255]);
    assert!(image.range(&location, 8).is_err(), "a write cannot invent capacity beyond the parameter buffer");
}

#[test]
fn bit_parameter_patch_claims_only_its_bits() {
    // `BitOffset` counts from the byte's MSB. Flip all three bits in the
    // declared window so this test proves both that the value is written
    // and that the five neighbouring bits remain untouched.
    let mut image = SparseDeviceImage::new();
    let location = ParameterLocation {
        id: "P-1".to_owned(),
        code_segment: "S-1".to_owned(),
        offset: 0,
        bit_offset: 2,
        size_bits: 3,
        legacy_patch_always: false,
        seeds_default: true,
        byte_ordered: true,
    };
    let value = ParameterValue { id: "P-1".to_owned(), value: vec![0b0000_0010] };

    let (data, mask) =
        encode_parameter(&value, location.size_bits, location.bit_offset, true, &ParameterByteOrder::BigEndian)
            .expect("parameter encodes");
    let address = ImageLocation::standard_memory(0x100);
    image.apply(&ImageSegment::new(address.clone(), data, mask).expect("parameter segment"));
    assert_eq!(image.overlay(&address, &[0b1010_1010]).expect("overlay"), [0b1001_0010]);
    assert_eq!(image.range(&address, 1).expect("parameter byte").mask(), [0b0011_1000]);
}

#[test]
fn parameter_values_do_not_change_application_program_ownership() {
    let location = ParameterLocation {
        id: "P-1".to_owned(),
        code_segment: "S-1".to_owned(),
        offset: 0,
        bit_offset: 0,
        size_bits: 2,
        legacy_patch_always: false,
        seeds_default: true,
        byte_ordered: true,
    };
    let compile = |raw| {
        let value = ParameterValue { id: "P-1".to_owned(), value: vec![raw] };
        let (data, mask) =
            encode_parameter(&value, location.size_bits, location.bit_offset, true, &ParameterByteOrder::BigEndian)
                .expect("parameter encodes");

        let mut manifest = SparseDeviceImage::default();
        manifest.apply_section(
            ProgrammingSection::ApplicationProgram1,
            &ImageSegment::owned(ImageLocation::standard_memory(0x100), vec![0]).expect("application segment"),
        );
        manifest.apply_section(
            ProgrammingSection::Parameters,
            &ImageSegment::new(ImageLocation::standard_memory(0x100), data, mask).expect("parameter ownership segment"),
        );
        manifest.manifest()
    };

    let default_value = compile(0);
    let changed_value = compile(2);

    assert_eq!(
        default_value.section(ProgrammingSection::ApplicationProgram1),
        changed_value.section(ProgrammingSection::ApplicationProgram1),
    );
    assert_ne!(
        default_value.section(ProgrammingSection::Parameters),
        changed_value.section(ProgrammingSection::Parameters),
    );
}

#[test]
fn expert_image_input_rejects_oversized_packed_parameter_with_short_value() {
    let (catalog, profile, product, mut configuration) = plain_fixture();
    let parameter_id = "P-oversized-packed-field";
    configuration.parameters = vec![ParameterValue { id: parameter_id.to_owned(), value: vec![1] }];

    // Expert inputs can bypass product-value lowering. Validate the field
    // declaration as well as the supplied bytes before the bit encoder
    // shifts: neither a 65-bit field nor a misaligned 72-bit field fits.
    for (size_bits, bit_offset) in [(65, 0), (72, 1)] {
        let malformed = product.clone().with_fixture_parameters(vec![ParameterLocation {
            id: parameter_id.to_owned(),
            code_segment: product.segments()[0].id.clone(),
            offset: 0,
            bit_offset,
            size_bits,
            legacy_patch_always: false,
            seeds_default: false,
            byte_ordered: true,
        }]);

        let error = compile_full_image(&catalog, &profile, &malformed, &configuration)
            .expect_err("packed fields must fit the parameter type");
        assert_eq!(error.kind, CompileErrorKind::InvalidInput);
        assert!(error.message.contains(parameter_id));
    }
}

#[test]
fn native_regions_preserve_adjacent_allocations_and_unowned_capacity() {
    let (catalog, profile, product, configuration) = plain_fixture();
    let mut sources = product.segments().to_vec();
    let mut reserved = sources[0].clone();
    reserved.id = "reserved".to_owned();
    reserved.address = Some(0x200);
    reserved.size = 4;
    reserved.data = vec![0xA5];
    reserved.mask = Some(vec![0x0F]);
    sources.push(reserved);
    let product = product.with_fixture_segments(sources);
    let image = compile_full_image(&catalog, &profile, &product, &configuration).expect("native image");
    assert_eq!(image.regions.len(), 2);
    let reserved = &image.regions[1];
    assert_eq!(reserved.source_id.as_deref(), Some("reserved"));
    assert_eq!(reserved.seed, [0xA5]);
    let projected = image.image.project(&reserved.location, &[0xA5, 0, 0, 0]).expect("native region");
    assert_eq!(projected.data(), [0xA5, 0, 0, 0]);
    assert_eq!(projected.mask(), [0x0F, 0, 0, 0]);
    let preview: Vec<_> = image.projected_regions().collect();
    assert_eq!(preview.len(), 2);
    assert_eq!(preview[1].1.mask(), [0x0F, 0, 0, 0]);
}

#[test]
fn unmasked_segments_own_only_their_authored_data() {
    let (catalog, profile, product, configuration) = plain_fixture();
    let mut sources = product.segments().to_vec();
    for (id, address, data) in [("short", 0x200, vec![0xA5]), ("empty", 0x210, Vec::new())] {
        let mut allocation = sources[0].clone();
        allocation.id = id.to_owned();
        allocation.address = Some(address);
        allocation.size = 4;
        allocation.data = data;
        allocation.mask = None;
        sources.push(allocation);
    }
    let product = product.with_fixture_segments(sources);
    let image = compile_full_image(&catalog, &profile, &product, &configuration).expect("native image");

    // Authored data defines the owned extent of an unmasked segment; the rest
    // of its allocation stays unowned (M-017A_A-0001 authors 560 of 1370
    // bytes, and the reference leaves the remainder to parameters).
    let short = image.image.project(&ImageLocation::standard_memory(0x200), &[0; 4]).expect("native region");
    assert_eq!(short.data(), [0xA5, 0, 0, 0]);
    assert_eq!(short.mask(), [0xFF, 0, 0, 0]);

    // A segment without data is a zero-filled allocation the reference's
    // provider masks out entirely: nothing of it is owned.
    let empty = image.image.project(&ImageLocation::standard_memory(0x210), &[0xEE; 4]).expect("native region");
    assert_eq!(empty.mask(), [0; 4]);
}

#[test]
fn little_endian_products_reorder_only_numeric_parameters() {
    // A little-endian product reverses numbers, restrictions, floats and
    // times. Text, IP addresses, colours and raw data keep their byte
    // sequence: "ABC" stays "ABC" and 192.168.1.1 stays C0 A8 01 01.
    let text = ParameterValue { id: "P-1".to_owned(), value: b"ABC".to_vec() };
    let address = ParameterValue { id: "P-2".to_owned(), value: vec![0xc0, 0xa8, 0x01, 0x01] };
    let number = ParameterValue { id: "P-3".to_owned(), value: vec![0x01, 0x02] };

    let encoded = |value: &ParameterValue, ordered| {
        encode_parameter(value, value.value.len() as u16 * 8, 0, ordered, &ParameterByteOrder::LittleEndian)
            .expect("parameter encodes")
            .0
    };
    assert_eq!(encoded(&text, false), b"ABC");
    assert_eq!(encoded(&address, false), [0xc0, 0xa8, 0x01, 0x01]);
    assert_eq!(encoded(&number, true), [0x02, 0x01]);
}
