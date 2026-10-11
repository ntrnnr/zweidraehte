use super::*;

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
        (0x0020, "Bcu2", None),
        (0x0021, "Bcu2", None),
        (0x0025, "Bcu2", None),
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
