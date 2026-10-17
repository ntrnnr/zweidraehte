use super::*;

#[test]
fn unique_product_property_writes_allocate_their_unowned_tail() {
    use crate::commissioning::catalog::profile::{DeclaredProperty, ObjectSelector};
    use crate::commissioning::compiler::binding::procedure::ParsedProcedure;
    use crate::commissioning::compiler::selection::{ProcedureApplicability, ProcedureRequest, RecipeSet};
    use crate::commissioning::procedure::operands::PropertyAddress;
    use crate::commissioning::procedure::{
        OperationData, OperationExtent, OperationTarget, ProcedureOperation, ProcedureStep, WriteIntent,
    };
    use zweidraehte_ets_files::product::LoadProcedureStyle;

    let (_, mut profile, product, configuration) = plain_fixture();
    crate::commissioning::catalog::profile::testing::edit_profile(&mut profile, |xml| {
        xml.replace(
        "<MaskVersions>",
        "<PropertyDataTypes><PropertyDataType Id=\"PDT_UNSIGNED_INT\" Name=\"PDT_UNSIGNED_INT\" Size=\"2\" /></PropertyDataTypes><MaskVersions>",
    )
    });
    for declared in [false, true] {
        let profile = if declared {
            profile.clone().with_procedure_property_declarations([(
                DeclaredProperty::new(&ObjectSelector::Index { index: 9 }, 23),
                "PDT_UNSIGNED_INT",
            )])
        } else {
            profile.clone()
        };
        for style in [LoadProcedureStyle::Default, LoadProcedureStyle::Merged, LoadProcedureStyle::Product] {
            for repeated in [false, true] {
                let product = product.clone().with_fixture_load_procedure_style(style);
                let input = image_input(&product, &configuration, false);
                let mut context = image_context(&input, &profile, None);
                let location = ImageLocation {
                    space: ImageSpace::Property { object: ObjectSelector::Index { index: 9 }, property_id: 23 },
                    offset: 4,
                };
                let mut parsed = ParsedProcedure::feature_fixture(&profile);
                for fallback in [None, Some(vec![0; 6])].into_iter().take(if repeated { 2 } else { 1 }) {
                    parsed.program.steps.push(ProcedureStep {
                        path: crate::commissioning::compiler::binding::procedure::test_support::root_path(),
                        source_control_code: None,
                        sections: Default::default(),
                        secure_only: false,
                        on_error: Vec::new(),
                        operation: ProcedureOperation::Write {
                            target: OperationTarget::Property {
                                address: PropertyAddress::Indexed { object_index: 9, property_id: 23 },
                                start_element: 3,
                            },
                            data: OperationData::Buffer { location: location.clone(), length: 6, fallback },
                            extent: OperationExtent::property(6, 3),
                            policy: WriteIntent::Property { verify: false },
                        },
                    });
                }
                context.recipes = RecipeSet::Exact {
                    request: ProcedureRequest {
                        procedure_type: "Load",
                        subtype: "all",
                        applicability: ProcedureApplicability::full(),
                    },
                    procedure: Box::new(parsed),
                };
                context.build_image().expect("selected image builds");
                let start = ImageLocation { offset: 0, ..location };
                if declared && style != LoadProcedureStyle::Default && !repeated {
                    let bytes = context.image.image.range(&start, 10).expect("unique write allocates its full prefix");
                    assert_eq!(bytes.mask(), [0; 10]);
                    assert!(context.image.image.sections_for_range(&start, 10).is_empty());
                    assert!(context.image.image.range(&start, 11).is_err());
                } else {
                    assert!(
                        context.image.image.range(&start, 10).is_err(),
                        "{style:?}, repeated={repeated}, declared={declared}"
                    );
                }
            }
        }
    }
}

#[test]
fn selected_property_image_reads_represent_unowned_bytes_before_execution() {
    use crate::commissioning::catalog::profile::ObjectSelector;
    use crate::commissioning::compiler::binding::procedure::ParsedProcedure;
    use crate::commissioning::compiler::selection::{ProcedureApplicability, ProcedureRequest, RecipeSet};
    use crate::commissioning::procedure::operands::PropertyAddress;
    use crate::commissioning::procedure::{OperationExtent, OperationTarget, ProcedureOperation, ProcedureStep};

    let (_, profile, product, configuration) = plain_fixture();
    let input = image_input(&product, &configuration, false);
    let mut context = image_context(&input, &profile, None);
    let location = ImageLocation {
        space: ImageSpace::Property { object: ObjectSelector::Index { index: 3 }, property_id: 27 },
        offset: 0,
    };
    let mut parsed = ParsedProcedure::feature_fixture(&profile);
    parsed.program.steps.push(ProcedureStep {
        path: crate::commissioning::compiler::binding::procedure::test_support::root_path(),
        source_control_code: None,
        sections: Default::default(),
        secure_only: false,
        on_error: Vec::new(),
        operation: ProcedureOperation::LoadImage {
            target: OperationTarget::Property {
                address: PropertyAddress::Indexed { object_index: 3, property_id: 27 },
                start_element: 1,
            },
            image_location: location.clone(),
            extent: OperationExtent::property(8, 1),
            alignment: 8,
        },
    });
    context.recipes = RecipeSet::Exact {
        request: ProcedureRequest {
            procedure_type: "Load",
            subtype: "par",
            applicability: ProcedureApplicability::partial(ProgramSections::PARAMETERS),
        },
        procedure: Box::new(parsed),
    };
    context.build_image().expect("selected image builds");
    let bytes = context.image.image.range(&location, 8).expect("future property read allocates its buffer");
    assert_eq!(bytes.mask(), [0; 8]);
    assert!(context.image.image.sections_for_range(&location, 8).is_empty());
    assert!(context.image.regions.iter().any(|region| region.location == location && region.length == 8));
}

#[test]
fn code_seed_address_reservations_follow_family_and_merged_allocation_coverage() {
    let (_, _, product, _) = plain_fixture();
    for (mask, model, slot) in [
        (0x0012, "Bcu1", Some(0x117)),
        (0x1012, "Bcu1", Some(0x117)),
        (0x0701, "BimM112", Some(0x4001)),
        (0x0705, "BimM112", Some(0x4001)),
        (0x2705, "BimM112", Some(0x4001)),
        (0x5705, "BimM112", Some(0x4001)),
        (0x0020, "Bcu2", Some(0x117)),
        (0x0021, "Bcu2", Some(0x117)),
        (0x0025, "Bcu2", Some(0x117)),
    ] {
        let profile = table_profile_for_mask(mask, model, "AddressTable_Bcu1", "AssociationTable_Bcu1");
        assert_eq!(profile.code_seed_address_reservation(), slot.map(ImageLocation::standard_memory));
        let at = slot.unwrap_or(0x117);
        for split in [false, true] {
            for ownership in [vec![255; 4], vec![255, 15, 240, 255], vec![255, 0, 0, 255]] {
                let mut segments = product.segments()[..1].to_vec();
                segments[0].address = Some(at - 1);
                segments[0].data = vec![0xaa, 0x12, 0x34, 0xbb];
                segments[0].size = 4;
                segments[0].mask = Some(ownership.clone());
                if split {
                    let mut second = segments[0].clone();
                    second.id.push_str("-second");
                    second.address = Some(at + 1);
                    second.data = second.data[2..].to_vec();
                    second.mask = Some(ownership[2..].to_vec());
                    second.size = 2;
                    segments[0].data.truncate(2);
                    segments[0].mask.as_mut().unwrap().truncate(2);
                    segments[0].size = 2;
                    segments.push(second);
                }
                let product = product.clone().with_fixture_segments(segments);
                let mut image = SparseDeviceImage::new();
                let buffers = seed_segments(&product, ImageDemand::Complete, &mut image).unwrap();
                reserve_code_seed_address(&profile, &buffers, &mut image);
                let projected =
                    image.project(&ImageLocation::standard_memory(at - 1), &[0xaa, 0x12, 0x34, 0xbb]).unwrap();
                let expected = if slot.is_some() { vec![255, 0, 0, 255] } else { ownership };
                assert_eq!(projected.mask(), expected, "{mask:04X}, split={split}");
                assert_eq!(projected.data(), &[0xaa, 0x12, 0x34, 0xbb]);
            }
        }
    }
}

#[test]
fn published_memory_windows_bridge_code_seed_gaps_only_in_the_same_space() {
    let (_, _, product, _) = plain_fixture();
    for (space, length, clears) in [("StandardMemory", 1, false), ("StandardMemory", 2, true), ("UserMemory", 2, false)]
    {
        let catalog = ProgrammingCatalog::from_xml(&format!(
            r#"
          <KNX xmlns="http://knx.org/xml/project/20"><MasterData Id="test" Version="1"><MaskVersions>
            <MaskVersion Id="MV-0012" MaskVersion="18" Name="BCU1" ManagementModel="Bcu1">
              <HawkConfigurationData><MemorySegments><MemorySegment Length="{length}">
                <Location AddressSpace="{space}" StartAddress="279" />
                <AccessRights Read="Runtime" Write="Configuration" />
              </MemorySegment></MemorySegments></HawkConfigurationData>
            </MaskVersion>
          </MaskVersions></MasterData></KNX>"#
        ))
        .unwrap();
        let profile = catalog
            .resolve(ProfileRequest {
                discovery: ProfileDiscovery { dd0: 0x0012, management_descriptor_01: None, management_style: None },
                product: None,
                variant_hint: VariantHint::Automatic,
            })
            .unwrap();
        let mut segments = product.segments()[..1].to_vec();
        segments[0].address = Some(0x116);
        segments[0].size = 2;
        segments[0].data = vec![1, 0xff];
        segments[0].mask = None;
        let product = product.clone().with_fixture_segments(segments);
        let mut image = SparseDeviceImage::new();
        let buffers = seed_segments(&product, ImageDemand::Complete, &mut image).unwrap();
        reserve_code_seed_address(&profile, &buffers, &mut image);
        assert_eq!(image.byte(&ImageLocation::standard_memory(0x117)), (!clears).then_some((0xff, 0xff)));
        assert_eq!(image.byte(&ImageLocation::standard_memory(0x116)), Some((1, 0xff)));
    }
}

#[test]
fn full_and_selective_compilation_reserve_seed_before_parameter_ownership() {
    let (catalog, profile, product, mut configuration) = plain_fixture();
    let segment = product.segments()[0].id.clone();
    let product = product.with_fixture_parameters(vec![ParameterLocation {
        id: "address-overlap".to_owned(),
        code_segment: segment,
        offset: 23,
        bit_offset: 0,
        size_bits: 8,
        legacy_patch_always: false,
        seeds_default: false,
        byte_ordered: true,
    }]);
    configuration.parameters = vec![ParameterValue { id: "address-overlap".to_owned(), value: vec![0x56] }];
    for selected in [
        None,
        Some(ProgramSections::PARAMETERS),
        Some(ProgramSections::GROUP_COMMUNICATION),
        Some(ProgramSections::PARAMETERS.union(ProgramSections::GROUP_COMMUNICATION)),
        Some(ProgramSections::CONFIGURATION),
    ] {
        let compiled = match selected {
            None => compile_full_image(&catalog, &profile, &product, &configuration),
            Some(sections) => compile_partial_image(&profile, &product, &configuration, sections),
        }
        .unwrap();
        let parameters = selected.is_none_or(|s| s.contains(ProgramSections::PARAMETERS));
        assert_eq!(
            compiled.image.byte(&ImageLocation::standard_memory(0x117)),
            parameters.then_some((0x56, 255)),
            "{selected:?}"
        );
        assert_eq!(compiled.image.byte(&ImageLocation::standard_memory(0x118)), None);
    }
}

#[test]
fn bcu2_selected_packed_parameter_reowns_reserved_slot_with_seed_neighbor_bits() {
    let (catalog, _, product, mut configuration) = plain_fixture();
    let mut segments = product.segments().to_vec();
    segments[0].data[23..25].copy_from_slice(&[0xff, 0xff]);
    let segment = segments[0].id.clone();
    let product = product.with_fixture_segments(segments).with_fixture_parameters(vec![ParameterLocation {
        id: "address-overlap".to_owned(),
        code_segment: segment,
        offset: 23,
        bit_offset: 0,
        size_bits: 4,
        legacy_patch_always: false,
        seeds_default: false,
        byte_ordered: true,
    }]);
    configuration.parameters = vec![ParameterValue { id: "address-overlap".to_owned(), value: vec![5] }];
    let par = ProgramSections::PARAMETERS;
    let grp = ProgramSections::GROUP_COMMUNICATION;
    let cfg = ProgramSections::CONFIGURATION;
    for mask in [0x0020, 0x0021, 0x0025] {
        let profile = table_profile_for_mask(mask, "Bcu2", "AddressTable_Bcu1", "AssociationTable_Bcu2");
        for selected in [
            None,
            Some(par),
            Some(grp),
            Some(cfg),
            Some(par.union(grp)),
            Some(par.union(cfg)),
            Some(grp.union(cfg)),
            Some(par.union(grp).union(cfg)),
        ] {
            let compiled = match selected {
                None => compile_full_image(&catalog, &profile, &product, &configuration),
                Some(sections) => compile_partial_image(&profile, &product, &configuration, sections),
            }
            .unwrap();
            let owns = selected.is_none_or(|s| s.contains(par));
            assert_eq!(
                compiled.image.byte(&ImageLocation::standard_memory(0x117)),
                owns.then_some((0x5f, 255)),
                "{mask:04X}, {selected:?}"
            );
            assert_eq!(compiled.image.byte(&ImageLocation::standard_memory(0x118)), None);
        }
    }
}

#[test]
fn coupler_configuration_defaults_seed_only_segments_covering_the_block() {
    let (_, _, product, _) = plain_fixture();
    let defaults = [
        (0x10d, 0xff),
        (0x112, 0xc3),
        (0x113, 0xc3),
        (0x114, 0xc3),
        (0x115, 0xc3),
        (0x116, 0x01),
        (0x11a, 0xff),
        (0x11b, 0xcc),
        (0x11c, 0xff),
    ];

    // Witness: the M-0072 coupler family authors 00h at LKerror (011Ah) under
    // a full mask, and the reference download carries FFh ("no errors").
    for (mask, address, size, seeded) in [
        (0x0912, 0x100, 0x100, true),
        (0x0910, 0x10d, 0x10, true),
        (0x091a, 0x100, 0x100, true),
        (0x0912, 0x10e, 0xf2, false),
        (0x0912, 0x100, 0x1c, false),
        (0x0701, 0x100, 0x100, false),
    ] {
        let profile = table_profile_for_mask(mask, "Bcu1", "AddressTable_Bcu1", "AssociationTable_Bcu1");
        let mut segments = product.segments()[..1].to_vec();
        segments[0].address = Some(address);
        segments[0].size = size;
        segments[0].data = vec![0; size as usize];
        segments[0].mask = Some(vec![0xff; size as usize]);
        let product = product.clone().with_fixture_segments(segments);

        let mut image = SparseDeviceImage::new();
        seed_segments(&product, ImageDemand::Complete, &mut image).unwrap();
        seed_coupler_configuration(&profile, &product, ImageDemand::Complete, &mut image).unwrap();

        for (at, value) in defaults {
            let authored = (address..address + size).contains(&at).then_some((0, 0xff));
            let expected = if seeded { Some((value, 0xff)) } else { authored };
            assert_eq!(
                image.byte(&ImageLocation::standard_memory(at)),
                expected,
                "{mask:04X} {address:#x}+{size:#x} at {at:#x}"
            );
        }
    }
}

#[test]
fn only_a_published_slave_memory_window_is_mirrored() {
    for (segments, expected) in [
        (
            r#"<MemorySegment MemoryType="EEPROM" Length="256">
                <Location AddressSpace="StandardMemory" StartAddress="256" />
                <AccessRights Read="Configuration" Write="Configuration" />
              </MemorySegment>
              <MemorySegment MemoryType="EEPROM" Length="256">
                <Location AddressSpace="LcSlaveMemory" StartAddress="256" />
                <AccessRights Read="Configuration" Write="Configuration" />
              </MemorySegment>"#,
            Some((256, 256)),
        ),
        (
            r#"<MemorySegment MemoryType="EEPROM" Length="8192">
                <Location AddressSpace="LcFilterMemory" StartAddress="512" />
                <AccessRights Read="Configuration" Write="Configuration" />
              </MemorySegment>"#,
            None,
        ),
    ] {
        let catalog = ProgrammingCatalog::from_xml(&format!(
            r#"
          <KNX xmlns="http://knx.org/xml/project/20"><MasterData Id="test" Version="1"><MaskVersions>
            <MaskVersion Id="MV-0912" MaskVersion="2322" Name="Coupler" ManagementModel="Bcu1">
              <HawkConfigurationData><MemorySegments>{segments}</MemorySegments></HawkConfigurationData>
            </MaskVersion>
          </MaskVersions></MasterData></KNX>"#
        ))
        .unwrap();
        let profile = catalog
            .resolve(ProfileRequest {
                discovery: ProfileDiscovery { dd0: 0x0912, management_descriptor_01: None, management_style: None },
                product: None,
                variant_hint: VariantHint::Automatic,
            })
            .unwrap();
        assert_eq!(profile.line_coupler_slave_mirror(), expected);
    }
}
