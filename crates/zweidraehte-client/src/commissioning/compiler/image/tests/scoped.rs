use super::*;

#[test]
fn native_object_count_preserves_owned_seed_and_uses_effective_roster_for_selective_groups() {
    let (catalog, profile, product, mut configuration) = plain_fixture();
    configuration.com_objects.retain(|object| object.number == 0);
    for active in [true, false] {
        if !active {
            configuration.com_objects.clear();
            configuration.links.clear();
        }
        let full = compile_full_image(&catalog, &profile, &product, &configuration).unwrap();
        let partial =
            compile_partial_image(&profile, &product, &configuration, ProgramSections::GROUP_COMMUNICATION).unwrap();
        let count = ImageLocation::standard_memory(0x150);
        assert_eq!(full.image.byte(&count), Some((2, 0xff)));
        assert_eq!(partial.image.byte(&count), Some((u8::from(active), 0xff)));
        assert!(full.regions().iter().any(|region| region.location == ImageLocation::standard_memory(0x100)));
        assert_eq!(full.regions(), partial.regions());
    }
}

#[test]
fn selected_parameter_ownership_preserves_current_object_count_for_group_formatter() {
    let (_, profile, product, mut configuration) = plain_fixture();
    configuration.com_objects.retain(|object| object.number == 0);
    let code_segment = product.segments()[0].id.clone();
    let product = product.with_fixture_parameters(vec![ParameterLocation {
        id: "count".to_owned(),
        code_segment,
        offset: 80,
        bit_offset: 0,
        size_bits: 8,
        legacy_patch_always: false,
        seeds_default: false,
        byte_ordered: true,
    }]);
    configuration.parameters = vec![ParameterValue { id: "count".to_owned(), value: vec![2] }];
    let compiled = compile_partial_image(
        &profile,
        &product,
        &configuration,
        ProgramSections::PARAMETERS.union(ProgramSections::GROUP_COMMUNICATION),
    )
    .unwrap();
    assert_eq!(compiled.image.byte(&ImageLocation::standard_memory(0x150)), Some((2, 0xff)));
}

#[test]
fn selective_producers_preserve_parameter_and_table_values_in_shared_storage() {
    let (_, profile, product, mut configuration) = plain_fixture();
    let mut segments = product.segments().to_vec();
    segments[0].data[81] = 0xac; // firmware's object-table RAM-flags pointer
    let code_segment = product.segments()[0].id.clone();
    let product = product.with_fixture_segments(segments).with_fixture_parameters(vec![ParameterLocation {
        id: "packed-pointer".to_owned(),
        code_segment,
        offset: 81,
        bit_offset: 0,
        size_bits: 4,
        legacy_patch_always: false,
        seeds_default: false,
        byte_ordered: true,
    }]);
    configuration.parameters = vec![ParameterValue { id: "packed-pointer".to_owned(), value: vec![5] }];
    let parameters = ProgramSections::PARAMETERS;
    let groups = ProgramSections::GROUP_COMMUNICATION;
    for (sections, value, count) in [
        (parameters, Some((0x5c, 0xff)), None),
        (groups, Some((0xac, 0xff)), Some((2, 0xff))),
        (parameters.union(groups), Some((0x5c, 0xff)), Some((2, 0xff))),
        (ProgramSections::CONFIGURATION, None, None),
    ] {
        let compiled = compile_partial_image(&profile, &product, &configuration, sections).unwrap();
        assert_eq!(compiled.image.byte(&ImageLocation::standard_memory(0x151)), value, "{sections:?}");
        assert_eq!(compiled.image.byte(&ImageLocation::standard_memory(0x150)), count, "{sections:?}");
        assert!(compiled.regions().iter().any(|region| region.location == ImageLocation::standard_memory(0x100)));
    }
}

#[test]
fn selective_parameters_do_not_require_unselected_table_codecs_or_fixups() {
    let (_, _, product, mut configuration) = plain_fixture();
    let mut product =
        ProductData::from_mtxml_str(&BCU1_MTXML.replace("<Offset>239</Offset>", "<Offset>4294967295</Offset>"))
            .unwrap()
            .with_fixture_segments(product.segments().to_vec());
    let code_segment = product.segments()[0].id.clone();
    product = product.with_fixture_parameters(vec![ParameterLocation {
        id: "selected".to_owned(),
        code_segment,
        offset: 0,
        bit_offset: 0,
        size_bits: 8,
        legacy_patch_always: false,
        seeds_default: false,
        byte_ordered: true,
    }]);
    configuration.parameters = vec![ParameterValue { id: "selected".to_owned(), value: vec![0x7e] }];
    let profile = table_profile_with_flavours("AddressTable_Future", "AssociationTable_Bcu1");
    let compiled = compile_partial_image(&profile, &product, &configuration, ProgramSections::PARAMETERS)
        .expect("unselected producers have no dependency on their codec or fixup");
    assert_eq!(compiled.image.byte(&ImageLocation::standard_memory(0x100)), Some((0x7e, 0xff)));
}

#[test]
fn fixed_legacy_association_pointer_belongs_to_selected_group_communication() {
    let (_, _, product, configuration) = plain_fixture();
    for association in ["AssociationTable_Bcu1", "AssociationTable_Bcu2"] {
        let profile = table_profile_with_flavours("AddressTable_Bcu1", association);
        for sections in [ProgramSections::GROUP_COMMUNICATION, ProgramSections::PARAMETERS] {
            let compiled = compile_partial_image(&profile, &product, &configuration, sections).unwrap();
            let association_span =
                compiled.table_spans().iter().find(|span| span.kind == CompiledTableKind::Association);
            if sections == ProgramSections::GROUP_COMMUNICATION {
                let value = association_span.unwrap().location.offset as u8;
                assert_eq!(compiled.image.byte(&ImageLocation::standard_memory(0x111)), Some((value, 0xff)));
                assert!(
                    compiled
                        .image
                        .sections_for_range(&ImageLocation::standard_memory(0x111), 1)
                        .contains(&ProgrammingSection::GroupCommunication)
                );
            } else {
                assert_eq!(compiled.image.byte(&ImageLocation::standard_memory(0x111)), None);
                assert!(association_span.is_none());
            }
        }
    }
}

#[test]
fn bcu2_association_pointer_is_limited_to_its_nominal_one_byte_page() {
    let (catalog, _, original, configuration) = plain_fixture();
    let profile = table_profile_with_flavours("AddressTable_Bcu1", "AssociationTable_Bcu2");
    let (before, tail) = BCU1_MTXML.split_once("<FixupList>").unwrap();
    let (_, after) = tail.split_once("</FixupList>").unwrap();
    let xml = format!("{before}{after}");
    for offset in [0, 255, 256, 511] {
        let product = ProductData::from_mtxml_str(
            &xml.replace("Offset=\"60\" MaxEntries=\"5\"", &format!("Offset=\"{offset}\" MaxEntries=\"5\"")),
        )
        .unwrap();
        let mut segments = original.segments().to_vec();
        segments[0].size = 1024;
        segments[0].data.resize(1024, 0);
        segments[0].data[17] = 0xa5;
        let product = product.with_fixture_segments(segments);
        let nominal = 0x100 + offset;
        assert_eq!(product.association_table_offset(), offset);
        let partial =
            compile_partial_image(&profile, &product, &configuration, ProgramSections::GROUP_COMMUNICATION).unwrap();
        let full = compile_full_image(&catalog, &profile, &product, &configuration).unwrap();
        let pointer = ImageLocation::standard_memory(0x111);
        if nominal <= 0x1ff {
            assert_eq!(partial.image.byte(&pointer), Some((nominal as u8, 0xff)));
            assert_eq!(full.image.byte(&pointer), Some((nominal as u8, 0xff)));
        } else {
            assert_eq!(partial.image.byte(&pointer), None);
            assert_eq!(full.image.byte(&pointer), Some((0xa5, 0xff)));
        }
    }
}

#[test]
fn complete_image_rejects_overflowing_fixups_without_binding_unselected_ones() {
    let (_, profile, _, _) = plain_fixture();
    let product =
        ProductData::from_mtxml_str(&BCU1_MTXML.replace("<Offset>239</Offset>", "<Offset>4294967295</Offset>"))
            .expect("fixup offset fits its declared u32 field");
    let mut image = SparseDeviceImage::new();
    let buffers = seed_segments(&product, ImageDemand::Complete, &mut image).expect("valid segment geometry");
    apply_fixups(&profile, &product, &buffers, &mut image, ImageDemand::Ranges(&[]))
        .expect("a genuinely unselected fixup is irrelevant");
    let error = apply_fixups(&profile, &product, &buffers, &mut image, ImageDemand::Complete)
        .expect_err("a complete image cannot silently drop its overflowing fixup");
    assert!(error.message.contains("fixup") && error.message.contains("overflow"), "{error}");
}

#[test]
fn scoped_compilation_matches_full_image_for_demanded_bits() {
    let (catalog, profile, product, configuration) = plain_fixture();
    let full = compile_full_image(&catalog, &profile, &product, &configuration).expect("full image");
    // Address assignment reserves the two bytes between count and group rows.
    // Compare only the bytes owned by this download's producers.
    let required = [
        RequiredImageRange { location: ImageLocation::standard_memory(0x116), length: 1 },
        RequiredImageRange { location: ImageLocation::standard_memory(0x119), length: 2 },
        RequiredImageRange { location: ImageLocation::standard_memory(0x1c8), length: 1 },
    ];
    let scoped = compile_unload(&catalog, &profile, &product, &configuration, &required).expect("demanded image");
    for range in &required {
        assert_eq!(
            scoped.image.range(&range.location, range.length).expect("scoped bytes"),
            full.image.range(&range.location, range.length).expect("full bytes")
        );
    }
    assert!(scoped.image.range(&ImageLocation::standard_memory(0x100), 1).is_err());

    let table = full
        .table_spans
        .iter()
        .find(|span| span.kind == CompiledTableKind::Association)
        .expect("fixture has associations");
    let mut interior = table.location.clone();
    interior.offset += 1;
    let required = [RequiredImageRange { location: interior.clone(), length: 1 }];
    let scoped = compile_unload(&catalog, &profile, &product, &configuration, &required)
        .expect("a demand inside a table selects its producer");
    assert_eq!(scoped.image.range(&interior, 1), full.image.range(&interior, 1));
}

#[test]
fn scoped_image_without_group_filter_does_not_require_routing_extension() {
    let (catalog, mut profile, product, configuration) = plain_fixture();
    profile.set_test_disposition(crate::commissioning::catalog::profile::ProfileDisposition::CouplerRoutingRequired);
    let location = ImageLocation::standard_memory(0x100);
    let required = [RequiredImageRange { location: location.clone(), length: 1 }];
    let scoped = compile_unload(&catalog, &profile, &product, &configuration, &required)
        .expect("ordinary image bytes do not depend on the routing selector");
    assert!(scoped.image.range(&location, 1).is_ok());
    assert_eq!(
        compile_full_image(&catalog, &profile, &product, &configuration)
            .expect_err("full image requires the routing selector")
            .kind,
        CompileErrorKind::Unsupported
    );
}

#[test]
fn scoped_unload_ignores_unrelated_formats_after_ruling_out_shared_allocation() {
    let (catalog, _, _, configuration) = plain_fixture();
    let product = ProductData::from_mtxml_str(
        &BCU1_MTXML.replace("DynamicTableManagement=\"false\"", "DynamicTableManagement=\"true\""),
    )
    .expect("dynamic product parses");
    let profile = table_profile_with_flavours("AddressTable_Future", "AssociationTable_Bcu2");
    let location = ImageLocation::standard_memory(0x100);
    let required = [RequiredImageRange { location: location.clone(), length: 1 }];

    let image = compile_unload(&catalog, &profile, &product, &configuration, &required)
        .expect("BCU2 association format rules out shared allocation without interpreting the address format");
    assert!(image.image.range(&location, 1).is_ok());
}
