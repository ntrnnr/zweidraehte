use super::*;
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
    let addresses = result.image.range(&ImageLocation::standard_memory(0x116), 5).expect("address table exists");
    assert_eq!(addresses.data(), &[2, 23, 24, 0x0a, 3], "IA seed survives table programming");
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
fn object_overlay_keeps_firmware_pointer_and_selector_ownership() {
    let objects = [ComObjectDef {
        number: 0,
        flags: ComObjectFlags::from_byte(0x47),
        object_type: ComObjectType::Uint1,
        datapoint_type: None,
    }];
    let mut table = [1, 0xCE, 0xC6, 0x67, 0];
    let mask = NativeObjectTable::new(NativeObjectFormat::Rt2)
        .overlay(
            &mut table,
            &objects.iter().map(|o| (o.number, o.flags, o.object_type)).collect::<Vec<_>>(),
            &objects.iter().map(|o| (o.number, o.flags, o.object_type)).collect::<Vec<_>>(),
        )
        .expect("valid RT2 table");
    assert_eq!(mask, [0, 0, 0, 0xDF, 0xFF]);
    assert_eq!(&table[..3], &[1, 0xCE, 0xC6]);
    assert_eq!(table[3] & 0x20, 0x20);
}
