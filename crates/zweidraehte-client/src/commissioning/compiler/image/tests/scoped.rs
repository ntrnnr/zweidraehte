use super::*;

#[test]
fn native_object_count_preserves_owned_seed_and_static_roster_for_selective_groups() {
    let (catalog, profile, product, mut configuration) = plain_fixture();
    configuration.encoded_mut().com_objects.retain(|object| object.number == 0);
    for active in [true, false] {
        if !active {
            configuration.encoded_mut().com_objects.clear();
            configuration.object_memberships_mut().clear();
        }
        let full = compile_full_image(&catalog, &profile, &product, &configuration).unwrap();
        let partial =
            compile_partial_image(&profile, &product, &configuration, ProgramSections::GROUP_COMMUNICATION).unwrap();
        let count = ImageLocation::standard_memory(0x150);
        assert_eq!(full.image.byte(&count), Some((2, 0xff)));
        assert_eq!(partial.image.byte(&count), Some((2, 0xff)));
        assert!(full.regions().iter().any(|region| region.location == ImageLocation::standard_memory(0x100)));
        assert_eq!(full.regions(), partial.regions());
    }
}

#[test]
fn selected_parameter_ownership_preserves_current_object_count_for_group_formatter() {
    let (_, profile, product, mut configuration) = plain_fixture();
    configuration.encoded_mut().com_objects.retain(|object| object.number == 0);
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
    configuration.encoded_mut().parameters = vec![EncodedParameter { id: "count".to_owned(), value: vec![2] }];
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
    configuration.encoded_mut().parameters = vec![EncodedParameter { id: "packed-pointer".to_owned(), value: vec![5] }];
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
    configuration.encoded_mut().parameters = vec![EncodedParameter { id: "selected".to_owned(), value: vec![0x7e] }];
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
fn coupler_routing_profiles_compile_scoped_and_full_images() {
    let (catalog, mut profile, product, configuration) = plain_fixture();
    profile.set_test_disposition(crate::commissioning::catalog::profile::ProfileDisposition::CouplerRoutingRequired);
    let location = ImageLocation::standard_memory(0x100);
    let required = [RequiredImageRange { location: location.clone(), length: 1 }];
    let scoped = compile_unload(&catalog, &profile, &product, &configuration, &required)
        .expect("ordinary image bytes do not depend on the routing selector");
    assert!(scoped.image.range(&location, 1).is_ok());
    // The routing selector is an ordinary product parameter, so the full
    // image compiles without a selector binding of its own.
    let full = compile_full_image(&catalog, &profile, &product, &configuration)
        .expect("the product parameters carry the routing selector");
    assert_eq!(full.image.range(&location, 1), scoped.image.range(&location, 1));
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

/// A BCU1-style profile whose Master Data `Load all` consists of `controls`.
fn absolute_load_profile(controls: &str) -> ResolvedProfile {
    let catalog = parse_master_data(&format!(
        r#"
        <KNX xmlns="http://knx.org/xml/project/20"><MasterData Id="MD" Version="1"><MaskVersions>
          <MaskVersion Id="MV-0012" MaskVersion="18" Name="Image fixture" ManagementModel="Bcu1" MediumTypeRefId="MT-0">
            <HawkConfigurationData>
              <Procedures><Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote">{controls}</Procedure></Procedures>
            </HawkConfigurationData>
          </MaskVersion>
        </MaskVersions></MasterData></KNX>"#
    ))
    .expect("procedure catalogue parses");
    resolve_catalog_profile(&catalog, None, &ProfileSelection {
        discovery: ProfileDiscovery {
            dd0: 0x0012,
            management_descriptor_01: None,
            management_style: Some(crate::commissioning::catalog::profile::ResourceManagementStyle::Simple),
        },
        variant_hint: VariantHint::Automatic,
    })
    .expect("procedure profile resolves")
}

#[test]
fn memory_no_load_write_sends_from_the_image_belongs_to_no_section() {
    // MV-0012 writes RunError only inline and stops its last image write one
    // byte before the segment ends. Neither byte can confirm AP1.
    let (_, _, product, _) = plain_fixture();
    let profile = absolute_load_profile(
        r#"<LdCtrlConnect />
           <LdCtrlWriteMem Address="256" Size="1" Verify="true" InlineData="00" />
           <LdCtrlLoadImageMem Address="257" Size="1" />
           <LdCtrlWriteMem Address="257" Size="2" Verify="true" />
           <LdCtrlRestart />"#,
    );
    let start = ImageLocation::standard_memory(256);
    let mut image = SparseDeviceImage::new();
    image.apply_section(
        ProgrammingSection::ApplicationProgram1,
        &ImageSegment::owned(start.clone(), vec![0x00, 0x11, 0x22, 0x33]).expect("product bytes"),
    );
    let desired = image.clone();

    super::super::scope::release_untransferred_memory(&profile, &product, &mut image);

    let section = |offset| image.sections_for_range(&ImageLocation::standard_memory(offset), 1);
    assert!(section(256).is_empty(), "an inline-only byte is not sent from the image");
    assert_eq!(section(257), [ProgrammingSection::ApplicationProgram1].into());
    assert_eq!(section(258), [ProgrammingSection::ApplicationProgram1].into());
    assert!(section(259).is_empty(), "a byte past the last write is never sent");
    assert_eq!(image.range(&start, 4).expect("bytes stay owned"), desired.range(&start, 4).expect("desired bytes"));
}

#[test]
fn memory_ownership_is_unchanged_when_the_source_procedure_cannot_bound_it() {
    let (_, _, product, _) = plain_fixture();
    for controls in [
        // A segment transfer sends image bytes a plain memory scan cannot see.
        r#"<LdCtrlWriteMem Address="256" Size="1" Verify="true" />
           <LdCtrlAbsSegment LsmIdx="1" SegType="0" Address="256" Size="4" Access="255" MemType="2" SegFlags="128" />"#,
        // No image write at all describes no layout.
        r#"<LdCtrlConnect /><LdCtrlRestart />"#,
    ] {
        let profile = absolute_load_profile(controls);
        let mut image = SparseDeviceImage::new();
        image.apply_section(
            ProgrammingSection::ApplicationProgram1,
            &ImageSegment::owned(ImageLocation::standard_memory(256), vec![1, 2, 3, 4]).expect("product bytes"),
        );
        let desired = image.clone();
        super::super::scope::release_untransferred_memory(&profile, &product, &mut image);
        assert_eq!(image.manifest(), desired.manifest(), "{controls}");
    }
}

#[test]
fn property_parameters_no_procedure_writes_belong_to_no_section() {
    use crate::commissioning::catalog::profile::ObjectSelector;
    use zweidraehte_ets_files::product::{PropertyObject, PropertyParameterLocation};
    // The GTS stores firmware and hardware checks in PIDs 25 and 78 of the
    // device object. Here only PID 78 has an image-backed write; PID 25 is
    // written inline, which never sends the parameter's bytes.
    let parameter = |id: &str, property_id, size_bits| PropertyParameterLocation {
        id: id.into(),
        object: PropertyObject::Index(0),
        property_id,
        offset: 0,
        bit_offset: 0,
        size_bits,
        legacy_patch_always: false,
        byte_ordered: true,
    };
    let (_, _, product, _) = plain_fixture();
    let product = product.with_fixture_property_parameters(vec![parameter("P-907", 25, 16), parameter("P-27", 78, 48)]);
    let profile = absolute_load_profile(
        r#"<LdCtrlConnect />
           <LdCtrlWriteProp ObjIdx="0" PropId="25" Verify="false" InlineData="0800" />
           <LdCtrlWriteProp ObjIdx="0" PropId="78" Verify="false" />
           <LdCtrlRestart />"#,
    );
    let location = |property_id| ImageLocation {
        space: ImageSpace::Property { object: ObjectSelector::Index { index: 0 }, property_id },
        offset: 0,
    };
    let mut image = SparseDeviceImage::new();
    image.apply_section(ProgrammingSection::Parameters, &ImageSegment::owned(location(25), vec![8, 0]).unwrap());
    image.apply_section(
        ProgrammingSection::Parameters,
        &ImageSegment::owned(location(78), vec![0, 0x83, 0, 0, 3, 40]).unwrap(),
    );
    let desired = image.clone();

    super::super::scope::release_unwritable_property_parameters(&profile, &product, &mut image);

    assert!(image.sections_for_range(&location(25), 2).is_empty(), "no procedure sends PID 25 from the image");
    assert_eq!(image.sections_for_range(&location(78), 6), [ProgrammingSection::Parameters].into());
    for property_id in [25, 78] {
        let length = if property_id == 25 { 2 } else { 6 };
        assert_eq!(
            image.range(&location(property_id), length).unwrap(),
            desired.range(&location(property_id), length).unwrap()
        );
    }
}
