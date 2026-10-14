use super::*;
use crate::commissioning::catalog::profile::ObjectSelector;
use crate::commissioning::input::security::DesiredDataSecurity;

#[test]
fn dynamic_bcu1_tables_relocate_and_release_unused_seed_ownership() {
    let (_catalog, profile, _, configuration) = plain_fixture();
    let xml = BCU1_MTXML.replace("DynamicTableManagement=\"false\"", "DynamicTableManagement=\"true\"");
    let (before, tail) = xml.split_once("<FixupList>").expect("fixture has fixups");
    let (_, after) = tail.split_once("</FixupList>").expect("fixture closes fixups");
    let product = ProductData::from_mtxml_str(&format!("{before}{after}")).expect("dynamic fixture parses");
    let mut segments = product.segments().to_vec();
    segments[0].data[80] = 2;
    let product = product.with_fixture_segments(segments);
    let input = image_input(&product, &configuration, false).data_security(DesiredDataSecurity::Preserve);
    let mut context = image_context(&input, &profile, None);
    context.feature_sections = ProgramSections::empty();
    context.build_image().expect("dynamic table image compiles");
    let result = context.image;

    let pointer = result.image.range(&ImageLocation::standard_memory(0x111), 1).expect("pointer exists");
    assert_eq!(pointer.data(), &[0x1b]);
    let addresses = result
        .image
        .project(&ImageLocation::standard_memory(0x116), &[22, 23, 24, 25, 26])
        .expect("address table exists");
    assert_eq!(addresses.data(), &[2, 23, 24, 0x0a, 3], "IA seed survives table programming");
    assert_eq!(addresses.mask(), &[255, 0, 0, 255, 255], "address assignment owns the IA slot");
    let association = result
        .table_spans
        .iter()
        .find(|span| span.kind == CompiledTableKind::Association)
        .expect("association span exists");
    assert_eq!(association.location, ImageLocation::standard_memory(0x11b));
    assert_eq!(association.len, 5, "declared inactive objects still occupy sending slots");
    let unused = result
        .image
        .project(&ImageLocation::standard_memory(0x120), &[0; 0x147 - 0x120])
        .expect("unused allocation remains addressable");
    assert!(unused.mask().iter().all(|mask| *mask == 0), "old tables are not seeded back into the image");
    assert_eq!(
        result.image.range(&ImageLocation::standard_memory(0x147), 1).expect("following byte exists").mask(),
        &[0xff],
        "bytes outside the allocation retain ownership"
    );
}

#[test]
fn dynamic_bcu1_tables_share_capacity_but_cannot_overrun_the_pool() {
    let (_, profile, _, mut configuration) = plain_fixture();
    let xml = BCU1_MTXML
        .replace("DynamicTableManagement=\"false\"", "DynamicTableManagement=\"true\"")
        .replace("Offset=\"22\" MaxEntries=\"5\"", "Offset=\"22\" MaxEntries=\"1\"");
    let product = ProductData::from_mtxml_str(&xml).expect("small nominal address table parses");
    let mut segments = product.segments().to_vec();
    segments[0].data[80] = 2;
    let product = product.with_fixture_segments(segments);
    configuration.links.push(GroupLink { group_address: GroupAddress::from_three_level(1, 2, 4), com_object: 0 });
    let mut image = SparseDeviceImage::new();
    let buffers = seed_segments(&product, ImageDemand::Complete, &mut image).expect("segments seed");
    let layout =
        CommunicationTables::prepare(&profile, &product, &configuration, &buffers, &mut image, ImageDemand::Complete)
            .expect("second address borrows unused association capacity");
    let spans = layout.write(&mut image).expect("tables encode");
    assert_eq!(
        spans
            .iter()
            .find(|span| span.kind == CompiledTableKind::Association)
            .expect("association placement")
            .location
            .offset,
        0x11d
    );

    let overlapping =
        ProductData::from_mtxml_str(&xml.replace("Offset=\"60\" MaxEntries=\"5\"", "Offset=\"60\" MaxEntries=\"20\""))
            .expect("overlapping allocation parses");
    let overlapping_buffers = seed_segments(&overlapping, ImageDemand::Complete, &mut image).expect("segments seed");
    assert!(
        CommunicationTables::prepare(
            &profile,
            &overlapping,
            &configuration,
            &overlapping_buffers,
            &mut image,
            ImageDemand::Complete
        )
        .is_err(),
        "dynamic tables cannot invalidate the group-object allocation"
    );

    for address in 5..12 {
        configuration
            .links
            .push(GroupLink { group_address: GroupAddress::from_three_level(1, 2, address), com_object: 0 });
    }
    let mut image = SparseDeviceImage::new();
    let buffers = seed_segments(&product, ImageDemand::Complete, &mut image).expect("segments seed");
    let original_image = image.clone();
    assert!(
        CommunicationTables::prepare(&profile, &product, &configuration, &buffers, &mut image, ImageDemand::Complete)
            .is_err()
    );
    assert_eq!(image, original_image, "invalid layout does not clear unrelated seed ownership");
}

#[test]
fn dynamic_bcu2_shared_tables_preserve_seeded_gaps_between_nominal_capacities() {
    let (_, _, product, mut configuration) = plain_fixture();
    let xml = BCU1_MTXML.replace("DynamicTableManagement=\"false\"", "DynamicTableManagement=\"true\"");
    let (before, tail) = xml.split_once("<FixupList>").expect("fixture has fixups");
    let (_, after) = tail.split_once("</FixupList>").expect("fixture closes fixups");
    let dynamic = ProductData::from_mtxml_str(&format!("{before}{after}")).expect("dynamic fixture parses");
    configuration.links.clear();

    // Both BCU2 association realizations keep authored bytes between their
    // nominal table capacities. BCU1 instead releases the whole shared pool,
    // as covered by dynamic_bcu1_tables_relocate_and_release_unused_seed_ownership.
    for association in ["AssociationTable_Bcu1", "AssociationTable_Bcu2"] {
        let profile = table_profile_for_mask(0x0021, "Bcu2", "AddressTable_Bcu1", association);
        for mask in [0xff, 0x0f, 0x00] {
            let mut segments = product.segments().to_vec();
            segments[0].mask = Some(vec![0xff; segments[0].data.len()]);
            for offset in 35..60 {
                segments[0].data[offset] = 0xa5;
                segments[0].mask.as_mut().expect("fixture supplies mask")[offset] = mask;
            }
            let product = dynamic.clone().with_fixture_segments(segments);
            let mut image = SparseDeviceImage::new();
            let buffers = seed_segments(&product, ImageDemand::Complete, &mut image).expect("segments seed");
            let layout = CommunicationTables::prepare(
                &profile,
                &product,
                &configuration,
                &buffers,
                &mut image,
                ImageDemand::Complete,
            )
            .expect("empty shared tables prepare");
            layout.write(&mut image).expect("empty shared tables encode");

            let gap = image.project(&ImageLocation::standard_memory(0x123), &[0; 25]).expect("gap projects");
            assert_eq!(gap.mask(), &[mask; 25], "{association}, mask {mask:02x}");
            for (data, owned) in gap.data().iter().zip(gap.mask()) {
                assert_eq!(data & owned, 0xa5 & mask, "authored gap values survive");
            }
            assert_eq!(
                image.byte(&ImageLocation::standard_memory(0x13c)),
                None,
                "unused nominal association header is released"
            );
            assert_eq!(
                image.byte(&ImageLocation::standard_memory(0x146)),
                None,
                "unused nominal association tail is released"
            );
            assert_eq!(
                image.byte(&ImageLocation::standard_memory(0x122)),
                None,
                "unused nominal addresses are released"
            );
            assert_eq!(
                image.byte(&ImageLocation::standard_memory(0x147)),
                Some((71, 255)),
                "following code retains ownership"
            );
        }
    }
}

#[test]
fn system_b_association_entry_size_controls_exact_bytes() {
    let associations = [(1, 1), (2, 2), (3, 4), (4, 5)];
    let small = AssociationTable::from_flavour(ResourceFlavour::AssociationTableSystemBSmall)
        .and_then(|codec| codec.encode(&associations, &[]))
        .map(|table| table.data)
        .expect("identifiers fit small rows");
    assert_eq!(small, [0, 4, 1, 1, 2, 2, 3, 4, 4, 5]);

    let big = AssociationTable::from_flavour(ResourceFlavour::AssociationTableSystemBBig)
        .and_then(|codec| codec.encode(&associations, &[]))
        .map(|table| table.data)
        .expect("identifiers fit big rows");
    assert_eq!(big, [0, 4, 0, 1, 0, 1, 0, 2, 0, 2, 0, 3, 0, 4, 0, 4, 0, 5]);
    let error = AssociationTable::from_flavour(ResourceFlavour::AssociationTableSystemB)
        .and_then(|codec| codec.encode(&associations, &[]))
        .map(|table| table.data)
        .expect_err("generic rows need an observed width");
    assert_eq!(error.kind, CompileErrorKind::MissingEvidence);
}

#[test]
fn small_system_b_associations_check_each_identifier_independently_of_count() {
    assert_eq!(
        AssociationTable::from_flavour(ResourceFlavour::AssociationTableSystemBSmall)
            .and_then(|codec| codec.encode(&[(255, 255)], &[]))
            .map(|table| table.data)
            .expect("maximum one-octet identifiers fit"),
        [0, 1, 255, 255]
    );
    for row in [(256, 1), (1, 256)] {
        let error = AssociationTable::from_flavour(ResourceFlavour::AssociationTableSystemBSmall)
            .and_then(|codec| codec.encode(&[row], &[]))
            .map(|table| table.data)
            .expect_err("each identifier must fit one byte");
        assert_eq!(error.kind, CompileErrorKind::InvalidInput);
        assert!(error.message.contains("association identifier"));
    }
    assert_eq!(
        AssociationTable::from_flavour(ResourceFlavour::AssociationTableSystemBBig)
            .and_then(|codec| codec.encode(&[(256, 256)], &[]))
            .map(|table| table.data)
            .expect("two-octet identifiers fit"),
        [0, 1, 1, 0, 1, 0]
    );

    // More than 255 associations still fit small rows when each identifier
    // fits: the two-octet count must not silently change the row width.
    let mut rows: Vec<_> = (1..=255).map(|asap| (1, asap)).collect();
    rows.push((2, 1));
    let bytes = AssociationTable::from_flavour(ResourceFlavour::AssociationTableSystemBSmall)
        .and_then(|codec| codec.encode(&rows, &[]))
        .map(|table| table.data)
        .expect("256 small associations fit a two-octet count");
    assert_eq!(&bytes[..2], &[1, 0]);
    assert_eq!(bytes.len(), 2 + 256 * 2);
}

#[test]
fn system_300_group_object_rows_retain_flags_and_dpt_identity() {
    let objects = vec![ComObjectDef {
        number: 1,
        object_type: ComObjectType::Uint1,
        datapoint_type: Some("DPT-1 DPST-1-1".to_owned()),
        flags: ComObjectFlags::from_byte(0x95),
    }];

    let product =
        ProductData::from_mtxml_str(BCU1_MTXML).expect("fixture parses").with_fixture_com_objects(objects, vec![0, 1]);
    let configuration = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 1), Some(15))
        .with_com_objects(product.com_objects().to_vec());
    let table = TableCodec::new(CompiledTableKind::GroupObject, ResourceFlavour::GroupObjectTableSystem300)
        .expect("known format")
        .encode(&TableInput::new(&product, &configuration), || panic!("property rows need no firmware seed"))
        .expect("table encodes")
        .data;

    assert_eq!(&table[..6], &[0; 6], "unused ASAP 0 stays disabled");
    assert_eq!(&table[6..], &[0, 0x95, 0, 1, 0, 1]);
}

#[test]
fn compiled_table_spans_report_encoded_extents_instead_of_resource_capacity() {
    let product = ProductData::from_mtxml_str(BCU1_MTXML).expect("BCU1 fixture parses");
    let mut product_segments = product.segments().to_vec();
    product_segments[0].data[80] = 2;
    let product = product.with_fixture_segments(product_segments);
    let mut project = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 1), Some(15));
    project.links.push(GroupLink { group_address: GroupAddress::from_three_level(1, 2, 3), com_object: 0 });
    let configuration = project.with_com_objects(product.com_objects().to_vec());
    let profile = table_profile();
    let mut image = SparseDeviceImage::new();
    let buffers = seed_segments(&product, ImageDemand::Complete, &mut image).expect("product segments seed");

    let spans =
        CommunicationTables::prepare(&profile, &product, &configuration, &buffers, &mut image, ImageDemand::Complete)
            .and_then(|tables| tables.write(&mut image))
            .expect("tables compile");

    assert_eq!(spans.len(), 3);
    assert_eq!(spans, [
        CompiledTableSpan {
            kind: CompiledTableKind::GroupAddress,
            location: ImageLocation::standard_memory(0x116),
            len: 5,
        },
        CompiledTableSpan {
            kind: CompiledTableKind::Association,
            location: ImageLocation::standard_memory(0x13c),
            len: 5,
        },
        CompiledTableSpan {
            kind: CompiledTableKind::GroupObject,
            location: ImageLocation::standard_memory(0x150),
            len: 8,
        },
    ]);
}

#[test]
fn a_zero_filled_ia_slot_is_not_owned() {
    // M-006C_A-0908 declares its BCU2 address-table segment without data or
    // mask. Zero-filling owns the allocation, but the IA slot belongs to
    // address assignment; owning it would send 00 00 into the device address.
    let product = ProductData::from_mtxml_str(BCU1_MTXML).expect("BCU1 fixture parses");
    let mut product_segments = product.segments().to_vec();
    assert!(product_segments[0].mask.is_none(), "the fixture segment is unmasked");
    product_segments[0].data.truncate(0x117 - 0x100);
    let product = product.with_fixture_segments(product_segments);
    // Truncation also blanks the object table later in this shared segment,
    // so the configuration activates no objects.
    let configuration = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 1), Some(15));
    let mut image = SparseDeviceImage::new();
    let buffers = seed_segments(&product, ImageDemand::Complete, &mut image).expect("product segments seed");
    let seeded = image.project(&ImageLocation::standard_memory(0x116), &[0; 3]).expect("in range");
    assert_eq!(seeded.mask(), &[0xff; 3], "zero-filling owns the whole allocation");

    CommunicationTables::prepare(
        &table_profile(),
        &product,
        &configuration,
        &buffers,
        &mut image,
        ImageDemand::Complete,
    )
    .and_then(|tables| tables.write(&mut image))
    .expect("tables compile");

    let table = image.project(&ImageLocation::standard_memory(0x116), &[0; 3]).expect("in range");
    assert_eq!(table.mask(), &[0xff, 0, 0], "only the count is table data");
}

#[test]
fn fixed_tables_own_their_rows_but_not_the_ia_slot_or_unused_capacity() {
    let product = ProductData::from_mtxml_str(BCU1_MTXML).expect("BCU1 fixture parses");
    let mut product_segments = product.segments().to_vec();
    product_segments[0].data[80] = 2;
    let product = product.with_fixture_segments(product_segments);
    let mut project = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 1), Some(15));
    project.links.push(GroupLink { group_address: GroupAddress::from_three_level(1, 2, 3), com_object: 0 });
    let configuration = project.with_com_objects(product.com_objects().to_vec());
    let profile = table_profile();
    let mut image = SparseDeviceImage::new();
    let buffers = seed_segments(&product, ImageDemand::Complete, &mut image).expect("product segments seed");
    let max_entries = product.address_table_max_entries().expect("fixture declares its address capacity");
    let capacity = 3 + 2 * u32::from(max_entries);
    // The seed owns the declared capacity before the tables are compiled.
    let seeded = image.project(&ImageLocation::standard_memory(0x116), &vec![0; capacity as usize]).expect("in range");
    assert!(seeded.mask()[5..].iter().any(|mask| *mask != 0), "the fixture seeds its spare capacity");

    CommunicationTables::prepare(&profile, &product, &configuration, &buffers, &mut image, ImageDemand::Complete)
        .and_then(|tables| tables.write(&mut image))
        .expect("tables compile");

    // The table owns the count and group addresses. The individual-address
    // slot retains its seed and ownership; spare rows become unowned.
    let table = image.project(&ImageLocation::standard_memory(0x116), &vec![0; capacity as usize]).expect("in range");
    assert_eq!(&table.mask()[..5], &[0xff, seeded.mask()[1], seeded.mask()[2], 0xff, 0xff]);
    assert_eq!(&table.data()[1..3], &seeded.data()[1..3], "the configured IA 1.1.1 is not written");
    assert!(table.mask()[5..].iter().all(|mask| *mask == 0), "unused capacity is not owned");
}

#[test]
fn object_overlay_keeps_firmware_pointer_and_selector_ownership() {
    let objects = [ComObjectDef {
        number: 0,
        flags: ComObjectFlags::from_byte(0x47),
        object_type: ComObjectType::Uint1,
        datapoint_type: None,
    }];
    let mut table = [1, 0xCE, 0xC6, 0x67, 0xC3];
    let mask = NativeObjectTable::new(NativeObjectFormat::Bcu2)
        .overlay(&mut table, &objects.iter().map(|o| (o.number, o.flags, o.object_type)).collect::<Vec<_>>())
        .expect("valid RT2 table");
    assert_eq!(mask, [0, 0, 0, 0xDF, 0x3F]);
    assert_eq!(&table[..3], &[1, 0xCE, 0xC6]);
    assert_eq!(table[3] & 0x20, 0x20);
    assert_eq!(table[4], 0xC0, "firmware type bits survive the configured size");
}

#[test]
fn adjacent_table_placement_keeps_family_padding_and_the_combined_end() {
    use zweidraehte_ets_files::product::fixtures::SYSTEM7_MTXML;

    for (flavour, start, header) in [("AssociationTable_Bcu2", 0x116, 4), ("AssociationTable_M112", 0x4000, 3)] {
        let xml = SYSTEM7_MTXML
            .replace("DynamicTableManagement=\"false\"", "DynamicTableManagement=\"true\"")
            .replace("Address=\"16384\"", &format!("Address=\"{start}\""))
            .replace("Address=\"16640\"", &format!("Address=\"{}\"", start + 17));
        let product = ProductData::from_mtxml_str(&xml).expect("adjacent table fixture parses");
        let profile = table_profile_with_flavours("AddressTable_Bcu1", flavour);
        for groups in [0, 1, 3, 6] {
            let mut configuration = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 1), Some(15));
            for address in 1..=groups {
                configuration
                    .links
                    .push(GroupLink { group_address: GroupAddress::from_two_level(0, address), com_object: 1 });
            }
            let mut image = SparseDeviceImage::new();
            let buffers = seed_segments(&product, ImageDemand::Complete, &mut image).expect("segments seed");
            let tables = CommunicationTables::prepare(
                &profile,
                &product,
                &configuration,
                &buffers,
                &mut image,
                ImageDemand::Complete,
            )
            .expect("tables share their pool");
            let moves = tables.relocations();
            let length = header + 2 * u32::from(groups);
            assert_eq!(moves.len(), 2);
            assert_eq!(moves[0].from, (start, 17));
            assert_eq!(moves[0].to, (start, length));
            assert_eq!(moves[1].from, (start + 17, 15));
            assert_eq!(moves[1].to, (start + length, 32 - length));
        }
    }
}

#[test]
fn system7_dynamic_placement_rejects_overflow_without_mutating_the_image() {
    use zweidraehte_ets_files::product::fixtures::SYSTEM7_MTXML;

    let xml = SYSTEM7_MTXML
        .replace("DynamicTableManagement=\"false\"", "DynamicTableManagement=\"true\"")
        .replace("Address=\"16640\"", "Address=\"16401\"");
    let product = ProductData::from_mtxml_str(&xml).expect("adjacent table fixture parses");
    let profile = table_profile_with_flavours("AddressTable_Bcu1", "AssociationTable_M112");
    let mut configuration = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 1), Some(15));
    for address in 1..=8 {
        configuration.links.push(GroupLink { group_address: GroupAddress::from_two_level(0, address), com_object: 1 });
    }
    let mut image = SparseDeviceImage::new();
    let buffers = seed_segments(&product, ImageDemand::Complete, &mut image).expect("segments seed");
    let before = image.clone();
    assert!(
        CommunicationTables::prepare(&profile, &product, &configuration, &buffers, &mut image, ImageDemand::Complete,)
            .is_err()
    );
    assert_eq!(image, before);

    configuration.links.pop();
    let tables =
        CommunicationTables::prepare(&profile, &product, &configuration, &buffers, &mut image, ImageDemand::Complete)
            .expect("seven groups exactly fill the pool");
    assert_eq!(tables.relocations()[1].to, (0x4011, 15));
}

#[test]
fn system7_dynamic_tables_release_only_nominal_capacity() {
    use zweidraehte_ets_files::product::fixtures::SYSTEM7_MTXML;

    // A 19-byte address segment holds the 17-byte capacity of seven groups
    // plus two authored code bytes, as M-0001_A-140C's 513-byte segment
    // keeps two bytes past its 254-group capacity. The seed inside the
    // capacity is table storage; the two tail bytes are product code.
    let xml = SYSTEM7_MTXML
        .replace("DynamicTableManagement=\"false\"", "DynamicTableManagement=\"true\"")
        .replace(
            r#"Address="16384" Size="17" MemoryType="EEPROM" />"#,
            r#"Address="16384" Size="19" MemoryType="EEPROM"><Data>/////////////3f///////8SNA==</Data></AbsoluteSegment>"#,
        )
        .replace("Address=\"16640\"", "Address=\"16403\"");
    let product = ProductData::from_mtxml_str(&xml).expect("adjacent table fixture parses");
    let profile = table_profile_with_flavours("AddressTable_Bcu1", "AssociationTable_M112");
    for groups in [0, 1, 3] {
        let mut configuration = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 1), Some(15));
        for address in 1..=groups {
            configuration
                .links
                .push(GroupLink { group_address: GroupAddress::from_two_level(0, address), com_object: 1 });
        }
        let mut image = SparseDeviceImage::new();
        let buffers = seed_segments(&product, ImageDemand::Complete, &mut image).expect("segments seed");
        let tables = CommunicationTables::prepare(
            &profile,
            &product,
            &configuration,
            &buffers,
            &mut image,
            ImageDemand::Complete,
        )
        .expect("tables share their pool");
        tables.write(&mut image).expect("tables write");

        let byte = |address: u32| image.byte(&ImageLocation::standard_memory(address));
        assert_eq!(byte(0x4011), Some((0x12, 0xff)), "groups={groups}");
        assert_eq!(byte(0x4012), Some((0x34, 0xff)), "groups={groups}");
        let used_end = 0x4000 + 3 + 2 * u32::from(groups);
        let association_end = used_end + 1 + u32::from(groups);
        if association_end <= 0x400a {
            assert!(byte(0x400a).is_none(), "groups={groups}: the seed inside the capacity is released");
        }
    }
}

fn adjacent_bcu2_fixture(flags: u8) -> String {
    zweidraehte_ets_files::product::fixtures::SYSTEM7_MTXML
        .replace("DynamicTableManagement=\"false\"", "DynamicTableManagement=\"true\"")
        .replace("Address=\"16384\"", "Address=\"278\"")
        .replace("Address=\"16640\"", "Address=\"788\"")
        .replace("Size=\"17\"", "Size=\"510\"")
        .replace("Size=\"15\"", "Size=\"508\"")
        .replace("Offset=\"0\" MaxEntries=\"7\"", "Offset=\"0\" MaxEntries=\"108\"")
        .replace("AS-4100\" Offset=\"0\" MaxEntries=\"108\"", "AS-4100\" Offset=\"0\" MaxEntries=\"253\"")
        .replace("SegFlags=\"128\"", &format!("SegFlags=\"{flags}\""))
}

#[test]
fn adjacent_bcu2_alignment_and_code_tails_follow_full_and_selective_ownership() {
    use zweidraehte_project::ProgrammingSection;

    let profile = table_profile_with_flavours("AddressTable_Bcu1", "AssociationTable_Bcu2");
    for flags in [0, 0x80] {
        let product = ProductData::from_mtxml_str(&adjacent_bcu2_fixture(flags)).unwrap();
        for groups in [0, 1, 3, 6, 9, 16, 40] {
            let mut configuration = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 1), Some(15));
            for address in 1..=groups {
                configuration
                    .links
                    .push(GroupLink { group_address: GroupAddress::from_two_level(0, address), com_object: 1 });
            }
            for scope in 0..8 {
                let sections = if scope == 0 {
                    ProgramSections::all()
                } else {
                    let mut selected = ProgramSections::empty();
                    for (bit, section) in [
                        (1, ProgramSections::PARAMETERS),
                        (2, ProgramSections::GROUP_COMMUNICATION),
                        (4, ProgramSections::CONFIGURATION),
                    ] {
                        if scope & bit != 0 {
                            selected = selected.union(section);
                        }
                    }
                    selected
                };
                for mask in [0, 0x0f, 0xff] {
                    let mut image = SparseDeviceImage::new();
                    let buffers = seed_segments(&product, ImageDemand::Complete, &mut image).unwrap();
                    for (address, byte) in [(787, 0xa5), (1295, 0x5a)] {
                        image.invalidate(&ImageLocation::standard_memory(address), 1);
                        image.apply_section(
                            ProgrammingSection::ApplicationProgram1,
                            &ImageSegment::new(ImageLocation::standard_memory(address), vec![byte], vec![mask])
                                .unwrap(),
                        );
                    }
                    if scope != 0 {
                        scope::retain_download_sections(&mut image, sections).unwrap();
                    }
                    if sections.contains(ProgramSections::GROUP_COMMUNICATION) {
                        // No selected allocation: static source metadata also
                        // supports automatic previews and partial downloads.
                        let tables = CommunicationTables::prepare(
                            &profile,
                            &product,
                            &configuration,
                            &buffers,
                            &mut image,
                            ImageDemand::Complete,
                        )
                        .unwrap();
                        let length = 3 + 2 * u32::from(groups) + u32::from(flags & 0x80 != 0);
                        assert_eq!(tables.relocations()[0].to, (278, length));
                        assert_eq!(tables.relocations()[1].to, (278 + length, 1018 - length));
                        tables.write(&mut image).unwrap();
                        assert!(image.byte(&ImageLocation::standard_memory(279)).is_none());
                        assert!(image.byte(&ImageLocation::standard_memory(280)).is_none());
                    }
                    for (address, byte) in [(787, 0xa5), (1295, 0x5a)] {
                        let owned = image
                            .byte(&ImageLocation::standard_memory(address))
                            .map(|(data, mask)| (data & mask, mask));
                        assert_eq!(
                            owned,
                            (scope == 0 && mask != 0).then_some((byte & mask, mask)),
                            "flags={flags} groups={groups} scope={scope} address={address}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn adjacent_bcu2_rejects_missing_or_ambiguous_flags_before_mutating_the_image() {
    let profile = table_profile_with_flavours("AddressTable_Bcu1", "AssociationTable_Bcu2");
    let source = adjacent_bcu2_fixture(0);
    let record = "<LdCtrlAbsSegment LsmIdx=\"1\" SegType=\"0\" Address=\"278\" Size=\"510\" Access=\"255\" MemType=\"3\" SegFlags=\"0\" />";
    assert!(source.contains(record));
    let ambiguous =
        source.replace(record, &format!("{record}{}", record.replace("SegFlags=\"0\"", "SegFlags=\"128\"")));
    let missing = source.replace(record, "");
    let too_small = source.replace("MaxEntries=\"108\"", "MaxEntries=\"254\"");
    for xml in [ambiguous, missing, too_small] {
        let product = ProductData::from_mtxml_str(&xml).unwrap();
        let configuration = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 1), Some(15));
        let mut image = SparseDeviceImage::new();
        let buffers = seed_segments(&product, ImageDemand::Complete, &mut image).unwrap();
        let before = image.clone();
        assert!(
            CommunicationTables::prepare(
                &profile,
                &product,
                &configuration,
                &buffers,
                &mut image,
                ImageDemand::Complete
            )
            .is_err()
        );
        assert_eq!(image, before);
    }
}

#[test]
fn adjacent_bcu2_uses_the_selected_typed_allocation_flags() {
    use crate::commissioning::compiler::binding::procedure::test_support::compile_fixture;
    use zweidraehte_ets_files::schema::{LdCtrlAbsSegment, LoadControl, LoadProcedure};

    let profile = table_profile_with_flavours("AddressTable_Bcu1", "AssociationTable_Bcu2");
    for flags in [0, 0x80] {
        // Opposite flags in the unselected static source: placement must
        // follow the already resolved program rather than selecting it again.
        let product = ProductData::from_mtxml_str(&adjacent_bcu2_fixture(flags ^ 0x80)).unwrap();
        let program = compile_fixture(
            LoadProcedure {
                merge_id: None,
                controls: vec![LoadControl::LdCtrlAbsSegment(LdCtrlAbsSegment {
                    lsm_idx: Some(1),
                    address: 278,
                    size: 510,
                    mem_type: 3,
                    seg_flags: flags,
                    ..Default::default()
                })],
            },
            Vec::new(),
        )
        .unwrap();
        let configuration = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 1), Some(15));
        let mut image = SparseDeviceImage::new();
        let buffers = seed_segments(&product, ImageDemand::Complete, &mut image).unwrap();
        let tables = CommunicationTables::prepare_for_program(
            &profile,
            &product,
            &configuration,
            &buffers,
            &mut image,
            ImageDemand::Complete,
            Some(&program),
        )
        .unwrap();
        assert_eq!(tables.relocations()[0].to, (278, 3 + u32::from(flags != 0)));
    }
}

#[test]
fn fixed_nonadjacent_and_scoped_system7_tables_keep_authored_geometry() {
    use zweidraehte_ets_files::product::fixtures::SYSTEM7_MTXML;

    let adjacent = SYSTEM7_MTXML.replace("Address=\"16640\"", "Address=\"16401\"");
    let dynamic = SYSTEM7_MTXML.replace("DynamicTableManagement=\"false\"", "DynamicTableManagement=\"true\"");
    let dynamic_adjacent = dynamic.replace("Address=\"16640\"", "Address=\"16401\"");
    let profile = table_profile_with_flavours("AddressTable_Bcu1", "AssociationTable_M112");
    let configuration = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 1, 1), Some(15));
    for (xml, demand) in [
        (adjacent, ImageDemand::Complete),
        (dynamic, ImageDemand::Complete),
        (dynamic_adjacent, ImageDemand::Ranges(&[])),
    ] {
        let product = ProductData::from_mtxml_str(&xml).expect("table fixture parses");
        let mut image = SparseDeviceImage::new();
        let buffers = seed_segments(&product, ImageDemand::Complete, &mut image).expect("segments seed");
        let before = image.clone();
        let tables = CommunicationTables::prepare(&profile, &product, &configuration, &buffers, &mut image, demand)
            .expect("authored geometry stays valid");
        assert!(tables.relocations().is_empty());
        assert_eq!(image, before);
    }
}

#[test]
fn system_b_relative_tables_do_not_rewrite_nominal_absolute_storage() {
    let (catalog, _, product, configuration) = plain_fixture();
    for association in ["AssociationTable_SystemBSmall", "AssociationTable_SystemBBig"] {
        let resources: String = [
            ("GroupAddressTable", "AddressTable_SystemB", 1),
            ("GroupAssociationTable", association, 2),
            ("GroupObjectTable", "GroupObjectTable_SystemB", 3),
        ]
        .into_iter()
        .map(|(name, flavour, index)| {
            format!(
                r#"
            <Resource Name="{name}" Access="remote">
              <Location AddressSpace="RelativeMemory" InterfaceObjectRef="{index}" PropertyID="7" StartAddress="0" />
              <ResourceType Length="2" Flavour="{flavour}" />
              <AccessRights Read="Runtime" Write="Configuration" />
            </Resource>"#
            )
        })
        .collect();
        let profile = crate::commissioning::catalog::profile::testing::association_profile_xml(&resources);
        let mut seed = SparseDeviceImage::new();
        seed_segments(&product, ImageDemand::Complete, &mut seed).expect("absolute firmware seeds");
        let original = seed.project(&ImageLocation::standard_memory(0x100), &vec![0; 256]).expect("seed exists");
        let full = compile_full_image(&catalog, &profile, &product, &configuration).expect("full image compiles");
        let groups = compile_partial_image(&profile, &product, &configuration, ProgramSections::GROUP_COMMUNICATION)
            .expect("selective group image compiles");

        for compiled in [&full, &groups] {
            for (kind, index) in [
                (CompiledTableKind::GroupAddress, 1),
                (CompiledTableKind::Association, 2),
                (CompiledTableKind::GroupObject, 3),
            ] {
                let location = ImageLocation {
                    space: ImageSpace::RelativeMemory { object: ObjectSelector::Index { index } },
                    offset: 0,
                };
                let span = compiled.table_spans().iter().find(|span| span.kind == kind).expect("table exists");
                assert_eq!(span.location, location, "{association}: {kind:?}");
                let data = compiled
                    .image
                    .range(&location, u32::try_from(span.len).expect("small table"))
                    .expect("table bytes exist");
                assert!(data.mask().iter().all(|mask| *mask == 0xff));
            }
        }
        let absolute = full
            .image
            .project(&ImageLocation::standard_memory(0x100), &vec![0; 256])
            .expect("firmware storage stays present");
        assert_eq!(absolute.data(), original.data(), "table offsets cannot overwrite absolute firmware");
        assert_eq!(absolute.mask(), original.mask(), "table capacity cannot release absolute firmware ownership");
        assert!(groups.image.ranges().all(|range| range.location.space != ImageSpace::StandardMemory));
    }
}

#[test]
fn bcu2_shared_pool_relocates_only_selected_tables_without_split_padding() {
    let (catalog, _, _, mut configuration) = plain_fixture();
    let xml = BCU1_MTXML
        .replace("DynamicTableManagement=\"false\"", "DynamicTableManagement=\"true\"")
        .replace("Offset=\"22\" MaxEntries=\"5\"", "Offset=\"22\" MaxEntries=\"40\"")
        .replace("Offset=\"60\" MaxEntries=\"5\"", "Offset=\"105\" MaxEntries=\"40\"")
        .replace("Offset=\"80\"", "Offset=\"186\"");
    let (before, tail) = xml.split_once("<FixupList>").unwrap();
    let (_, after) = tail.split_once("</FixupList>").unwrap();
    let product = ProductData::from_mtxml_str(&format!("{before}{after}")).unwrap();
    let mut segments = product.segments().to_vec();
    segments[0].data[186] = 2;
    let product = product.with_fixture_segments(segments);
    // Definitions outside the active roster do not occupy sending slots.
    // Allocation capacity must use the same roster as the emitted codec.
    let mut definitions = product.com_objects().to_vec();
    let mut inactive = definitions[1].clone();
    inactive.number = 17;
    definitions.push(inactive);
    let product = product.with_fixture_com_objects(definitions, (0..18).collect());
    let profile = table_profile_for_mask(0x0020, "Bcu2", "AddressTable_Bcu1", "AssociationTable_Bcu2");
    let par = ProgramSections::PARAMETERS;
    let grp = ProgramSections::GROUP_COMMUNICATION;
    let cfg = ProgramSections::CONFIGURATION;
    for groups in [0, 1, 3, 6, 9, 16, 40] {
        configuration.links = (0..groups)
            .map(|i| GroupLink {
                group_address: GroupAddress::from_three_level(0, 0, i + 1),
                com_object: u16::from(i % 2),
            })
            .collect();
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
            let owns_tables = selected.is_none_or(|s| s.contains(grp));
            let association_start = 0x119 + 2 * u32::from(groups);
            assert_eq!(
                compiled.image.byte(&ImageLocation::standard_memory(0x111)),
                owns_tables.then_some(((association_start - 0x100) as u8, 255)),
                "{groups}, {selected:?}"
            );
            let association = compiled.table_spans.iter().find(|s| s.kind == CompiledTableKind::Association);
            assert_eq!(
                association.map(|s| s.location.clone()),
                owns_tables.then_some(ImageLocation::standard_memory(association_start)),
                "{groups}, {selected:?}"
            );
            assert_eq!(compiled.image.byte(&ImageLocation::standard_memory(0x117)), None);
            assert_eq!(compiled.image.byte(&ImageLocation::standard_memory(0x118)), None);
        }
    }
    configuration.links = (0..41)
        .map(|i| GroupLink { group_address: GroupAddress::from_three_level(0, 0, i + 1), com_object: 0 })
        .collect();
    let mut image = SparseDeviceImage::new();
    let buffers = seed_segments(&product, ImageDemand::Complete, &mut image).unwrap();
    let before = image.clone();
    assert!(
        CommunicationTables::prepare(&profile, &product, &configuration, &buffers, &mut image, ImageDemand::Complete)
            .is_err(),
        "shared nominal capacity still bounds both tables"
    );
    assert_eq!(image, before, "capacity rejection does not clear seeded ownership");
}
