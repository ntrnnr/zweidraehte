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
    let mut table = [1, 0xCE, 0xC6, 0x67, 0];
    let mask = NativeObjectTable::new(NativeObjectFormat::Rt2)
        .overlay(&mut table, &objects.iter().map(|o| (o.number, o.flags, o.object_type)).collect::<Vec<_>>())
        .expect("valid RT2 table");
    assert_eq!(mask, [0, 0, 0, 0xDF, 0xFF]);
    assert_eq!(&table[..3], &[1, 0xCE, 0xC6]);
    assert_eq!(table[3] & 0x20, 0x20);
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
