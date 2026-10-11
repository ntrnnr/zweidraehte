use super::*;
use crate::commissioning::catalog::profile::ResourceFlavour;
use zweidraehte_ets_files::product::ComObjectDef;
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};
use zweidraehte_proto::com_object::ComObjectFlags;
use zweidraehte_proto::com_object::ComObjectType;

fn ga(main: u8, middle: u8, sub: u8) -> GroupAddress {
    GroupAddress::from_three_level(main, middle, sub)
}

#[test]
fn addr8_blob_matches_device_layout() {
    // Mirrors the device crate's addr8 loaded_table fixture:
    // length 4, IA 1.0.1, GAs 0/0/1 0/0/2 0/0/4.
    let blob = AddressTable::from_flavour(ResourceFlavour::AddressTableBcu1)
        .and_then(|codec| codec.encode(IndividualAddress::new(1, 0, 1), &[ga(0, 0, 1), ga(0, 0, 2), ga(0, 0, 4)]))
        .map(|table| table.data)
        .expect("3 entries fit");
    assert_eq!(blob, [4, 0x10, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x04]);
}

#[test]
fn system7_association_blob_sorts_and_dedups() {
    let blob = AssociationTable::from_flavour(ResourceFlavour::AssociationTableM112)
        .and_then(|codec| codec.encode(&[(2, 5), (1, 3), (2, 4), (1, 3)], &[]))
        .map(|table| table.data)
        .expect("fits");
    assert_eq!(blob, [3, 1, 3, 2, 4, 2, 5]);
}

#[test]
fn indexed_associations_group_extra_rows_without_sorting_each_objects_links() {
    // Native BCU captures keep sending rows in their indexed slots, then
    // traverse objects in ascending ASAP order. Each object's authored link
    // order survives even when its TSAPs descend or the roster is reversed.
    let links = [(1, 0), (2, 1), (3, 2), (2, 2), (3, 0), (1, 2), (2, 0)];
    let expected = [7, 1, 0, 2, 1, 3, 2, 3, 0, 2, 0, 2, 2, 1, 2];

    for flavour in [ResourceFlavour::AssociationTableBcu1, ResourceFlavour::AssociationTableBcu2] {
        for roster in [[0, 1, 2], [2, 1, 0]] {
            let table = AssociationTable::from_flavour(flavour)
                .and_then(|codec| codec.encode(&links, &roster))
                .expect("seven rows fit");

            assert_eq!(table.entries, 7);
            assert_eq!(table.data, expected);
            assert_eq!(table.mask, [0xff; 15]);
        }
    }
}

#[test]
fn indexed_association_hole_reuse_retains_duplicate_links() {
    // Duplicate receive links survive moving one into the unused sending slot.
    // A group used by another object's sender cannot take that unused slot.
    let links = [(3, 2), (2, 0), (2, 2), (1, 0), (1, 2), (1, 0)];

    for flavour in [ResourceFlavour::AssociationTableBcu1, ResourceFlavour::AssociationTableBcu2] {
        let table = AssociationTable::from_flavour(flavour)
            .and_then(|codec| codec.encode(&links, &[2, 0]))
            .expect("six rows fit after hole reuse");

        assert_eq!(table.entries, 6);
        assert_eq!(table.data, [6, 2, 0, 1, 0, 3, 2, 1, 0, 2, 2, 1, 2]);
    }
}

#[test]
fn indexed_associations_reuse_holes_only_for_groups_without_a_sender() {
    // Independent native witnesses start their active roster at 3. GA 3 has
    // no sender and both of its receiving rows fill leading holes. Cross-links
    // to GA 1/2 must stay in the tail, preserving their sending slots at 3/4.
    let links = [(1, 3), (2, 4), (3, 4), (3, 3), (1, 4), (2, 3)];
    let expected = [7, 3, 3, 3, 4, 254, 2, 1, 3, 2, 4, 2, 3, 1, 4];
    for flavour in [ResourceFlavour::AssociationTableBcu1, ResourceFlavour::AssociationTableBcu2] {
        for roster in [[3, 4], [4, 3]] {
            let table = AssociationTable::from_flavour(flavour)
                .and_then(|codec| codec.encode(&links, &roster))
                .expect("native roster fits");
            assert_eq!(table.data, expected);
            assert_eq!(table.entries, 7);
            assert_eq!(table.mask, [255; 15]);
        }

        let blocked = AssociationTable::from_flavour(flavour)
            .and_then(|codec| codec.encode(&[(1, 3), (2, 4), (2, 3), (1, 4)], &[3, 4]))
            .expect("cross-linked sending groups fit");
        assert_eq!(blocked.data, [7, 254, 0, 254, 1, 254, 2, 1, 3, 2, 4, 2, 3, 1, 4]);
    }
}

#[test]
fn cot_blob_matches_the_ets_trace() {
    // The exact bytes ETS wrote for the six-object light switch
    // (same fixture the device crate parses in co_system7.rs).
    let mut blob =
        [7, 0, 0, 0, 0, 0, 0, 0, 0, 0x47, 0, 0, 0, 0xD7, 0, 0, 0, 0x47, 3, 0, 0, 0x43, 0, 0, 0, 0xD3, 0, 0, 0, 0, 0];
    let rows = [
        (1, ComObjectFlags::from_byte(0x47), ComObjectType::Uint1),
        (2, ComObjectFlags::from_byte(0xD7), ComObjectType::Uint1),
        (3, ComObjectFlags::from_byte(0x47), ComObjectType::Uint4),
        (4, ComObjectFlags::from_byte(0x43), ComObjectType::Uint1),
        (5, ComObjectFlags::from_byte(0xD3), ComObjectType::Uint1),
    ];
    NativeObjectTable::new(NativeObjectFormat::System7).overlay(&mut blob, &rows).expect("native table fits");
    assert_eq!(blob, [
        0x07, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x47, 0x00, //
        0x00, 0x00, 0xD7, 0x00, //
        0x00, 0x00, 0x47, 0x03, //
        0x00, 0x00, 0x43, 0x00, //
        0x00, 0x00, 0xD3, 0x00, //
        0x00, 0x00, 0x00, 0x00, //
    ]);
}

#[test]
fn addr1_addr2_and_addr8_share_the_length_coding() {
    // The realization-facing names share the byte codec, while their
    // locations and load procedures remain profile decisions.
    let blob = AddressTable::from_flavour(ResourceFlavour::AddressTableBcu1)
        .and_then(|codec| codec.encode(IndividualAddress::new(1, 0, 1), &[ga(0, 0, 1), ga(0, 0, 2), ga(0, 0, 4)]))
        .map(|table| table.data)
        .expect("3 entries fit");
    assert_eq!(blob, [4, 0x10, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x04]);
}

#[test]
fn cot2_blob_and_overlay_use_one_octet_pointers() {
    let blob = [0x02, 0xCE, 0xC6, 0x47, 0x00, 0xC7, 0xD7, 0x03];
    assert_eq!(blob, [0x02, 0xCE, 0xC6, 0x47, 0x00, 0xC7, 0xD7, 0x03]);

    // Overlay patches config/type in place, preserving the
    // firmware's RAM-flags and data pointers. Inactive row 0 lies inside the
    // roster, so it formats as a blank entry: only the read-on-init and
    // priority bits of the seed survive.
    let mut defaults = blob.clone();
    NativeObjectTable::new(NativeObjectFormat::Rt2)
        .overlay(&mut defaults, &[(1, ComObjectFlags::from_byte(0x43), ComObjectType::Uint1)])
        .expect("row 1 exists");
    assert_eq!(defaults, [0x02, 0xCE, 0xC6, 0x03, 0x00, 0xC7, 0x43, 0x00]);

    // A row beyond the product's RT2 table is refused.
    assert!(
        NativeObjectTable::new(NativeObjectFormat::Rt2)
            .overlay(&mut defaults, &[(2, ComObjectFlags::from_byte(0), ComObjectType::Uint1)])
            .is_err()
    );
}

#[test]
fn compact_cot_overlay_rejects_a_physically_truncated_row() {
    // Count declares two System 7 rows, but only row 0 is physically
    // present. The declared range and the storage bound remain distinct.
    let mut defaults = [2, 0, 0, 0, 0, 0x47, 0];
    let error = NativeObjectTable::new(NativeObjectFormat::System7)
        .overlay(&mut defaults, &[(1, ComObjectFlags::from_byte(0x43), ComObjectType::Uint1)])
        .expect_err("row 1 is truncated");

    assert!(error.to_string().contains("truncated before object 1"));
}

#[test]
fn system7_blank_entries_keep_firmware_flags_and_rows_after_the_last_active_object_stay_seeded() {
    let mut defaults = [
        4, 0x12, 0x34, // Stored count and RAM-flags pointer are firmware-owned.
        0xDE, 0xAD, 0xFF, 0xD1, // Inactive row inside the active roster.
        0xBE, 0xEF, 0x84, 0x82, // Active row, the roster's last.
        0xCA, 0xFE, 0x4F, 0x03, // Inactive rows after it stay as seeded,
        0xAB, 0xCD, 0xF7, 0x44, // whether or not the product declares them.
    ];
    NativeObjectTable::new(NativeObjectFormat::System7)
        .overlay(&mut defaults, &[(1, ComObjectFlags::from_byte(0xD7), ComObjectType::Uint1)])
        .expect("descriptors fit");
    assert_eq!(defaults, [
        4, 0x12, 0x34, 0xDE, 0xAD, 0xFB, 0xD1, 0xBE, 0xEF, 0xD7, 0x80, 0xCA, 0xFE, 0x4F, 0x03, 0xAB, 0xCD, 0xF7, 0x44,
    ]);
}

#[test]
fn system7_active_descriptors_preserve_firmware_selector_and_type_bits() {
    for template_flags in 0..=u8::MAX {
        for type_bits in [0x00, 0x40, 0x80, 0xC0] {
            let mut defaults = [1, 0x12, 0x34, 0xAB, 0xCD, template_flags, type_bits | 0x01];
            NativeObjectTable::new(NativeObjectFormat::System7)
                .overlay(&mut defaults, &[(0, ComObjectFlags::from_byte(0xDF), ComObjectType::Byte1)])
                .expect("one descriptor fits");
            assert_eq!(&defaults[..5], &[1, 0x12, 0x34, 0xAB, 0xCD]);
            assert_eq!(defaults[5], 0xDF | (template_flags & 0x20));
            assert_eq!(defaults[6], type_bits | u8::from(ComObjectType::Byte1));
        }
    }
}

#[test]
fn system7_group_section_owns_only_the_bits_its_overlay_can_change() {
    let mut bytes = [3, 0x12, 0x34, 0xAB, 0xCD, 0xFF, 0xC1, 0xDE, 0xAD, 0x84, 0x82, 0xBE, 0xEF, 0x4F, 0x03];
    let firmware = bytes;
    let object = |number, flags| ComObjectDef {
        number,
        flags: ComObjectFlags::from_byte(flags),
        object_type: ComObjectType::Byte1,
        datapoint_type: None,
    };
    let ownership = NativeObjectTable::new(NativeObjectFormat::System7)
        .overlay(&mut bytes, &[object(1, 0xDF)].iter().map(|o| (o.number, o.flags, o.object_type)).collect::<Vec<_>>())
        .expect("three descriptors fit");

    // Row 0 is a blank entry inside the roster; row 2 follows its last
    // active object and is not formatted at all.
    assert_eq!(ownership, [0, 0, 0, 0, 0, 0x04, 0, 0, 0, 0xDF, 0x3F, 0, 0, 0, 0]);
    for ((before, after), mask) in firmware.iter().zip(bytes).zip(ownership) {
        assert_eq!((before ^ after) & !mask, 0, "the overlay must preserve application-owned bits");
    }
}

#[test]
fn cot1_forces_config_bit_7() {
    // Same fixture as the Cot2 test, but the RT1 coding must set
    // bit 7 of every config octet regardless of what the flags
    // carry (03/05/01 §4.18.3 fixes it at 1).
    let blob = [0x02, 0xCE, 0xC6, 0xC7, 0x00, 0xC7, 0xD7, 0x03];
    assert_eq!(blob, [0x02, 0xCE, 0xC6, 0xC7, 0x00, 0xC7, 0xD7, 0x03]);

    let mut defaults = blob.clone();
    NativeObjectTable::new(NativeObjectFormat::Rt1)
        .overlay(&mut defaults, &[(1, ComObjectFlags::from_byte(0x43), ComObjectType::Uint1)])
        .expect("row 1 exists");
    // Blank row 0 preserves only the firmware bit 7 and priority bits.
    assert_eq!(defaults, [0x02, 0xCE, 0xC6, 0x83, 0x00, 0xC7, 0xC3, 0x00]);
}

#[test]
fn system_b_blobs_use_two_octet_counts() {
    // RT7 address table: no IA slot, 16-bit count.
    let adt = AddressTable::from_flavour(ResourceFlavour::AddressTableSystemB)
        .and_then(|codec| codec.encode(IndividualAddress::new(1, 0, 1), &[ga(0, 0, 1), ga(0, 0, 2)]))
        .map(|table| table.data)
        .expect("fits");
    assert_eq!(adt, [0x00, 0x02, 0x00, 0x01, 0x00, 0x02]);

    // SystemBBig associations: 16-bit TSAP and ASAP.
    let ast = AssociationTable::from_flavour(ResourceFlavour::AssociationTableSystemBBig)
        .and_then(|codec| codec.encode(&[(2, 5), (1, 3)], &[]))
        .map(|table| table.data)
        .expect("fits");
    assert_eq!(ast, [0x00, 0x02, 0x00, 0x02, 0x00, 0x05, 0x00, 0x01, 0x00, 0x03]);

    // RT7 group objects: flags octet then type octet, 1-based.
    let product = zweidraehte_ets_files::product::ProductData::from_mtxml_str(
        zweidraehte_ets_files::product::fixtures::BCU1_MTXML,
    )
    .expect("fixture parses");
    let objects = [
        ComObjectDef {
            number: 1,
            flags: ComObjectFlags::from_byte(0x47),
            object_type: ComObjectType::Uint1,
            datapoint_type: None,
        },
        ComObjectDef {
            number: 2,
            flags: ComObjectFlags::from_byte(0xD7),
            object_type: ComObjectType::Uint4,
            datapoint_type: None,
        },
    ];
    let cot = ObjectTable::from_flavour(ResourceFlavour::GroupObjectTableSystemB)
        .and_then(|codec| codec.encode(&product, &objects, || panic!("generated table needs no seed")))
        .map(|table| table.data)
        .expect("two objects fit");
    assert_eq!(cot, [0x00, 0x02, 0x47, 0x00, 0xD7, 0x03]);
}

#[test]
fn system_b_object_zero_has_no_descriptor_but_keeps_its_association() {
    let product =
        ProductData::from_mtxml_str(zweidraehte_ets_files::product::fixtures::BCU1_MTXML).expect("fixture parses");
    let objects = [0, 1, 3].map(|number| ComObjectDef {
        number,
        flags: ComObjectFlags::from_byte(0xff),
        object_type: ComObjectType::Uint4,
        datapoint_type: None,
    });
    let codec = ObjectTable::from_flavour(ResourceFlavour::GroupObjectTableSystemB).expect("descriptor codec");
    let table =
        codec.encode(&product, &objects, || panic!("descriptors need no seed")).expect("object zero is accepted");
    assert_eq!(table.data, [0, 3, 0xff, 3, 0, 0, 0xff, 3]);
    assert_eq!(table.entries, 3);
    assert_eq!(table.mask, [0xff; 8]);

    let zero_only = codec
        .encode(&product, &objects[..1], || panic!("descriptors need no seed"))
        .expect("a zero-only roster has no descriptor rows");
    assert_eq!(zero_only.data, [0, 0]);
    assert_eq!(zero_only.entries, 0);

    for (flavour, expected) in [
        (ResourceFlavour::AssociationTableSystemBSmall, vec![0, 2, 1, 0, 2, 3]),
        (ResourceFlavour::AssociationTableSystemBBig, vec![0, 2, 0, 1, 0, 0, 0, 2, 0, 3]),
    ] {
        let associations = AssociationTable::from_flavour(flavour)
            .and_then(|codec| codec.encode(&[(1, 0), (2, 3)], &[0, 1, 3]))
            .expect("association zero remains representable");
        assert_eq!(associations.data, expected);
    }
}

#[test]
fn small_system_b_associations_keep_primary_order_and_deduplicate() {
    let bytes = AssociationTable::from_flavour(ResourceFlavour::AssociationTableSystemBSmall)
        .and_then(|codec| codec.encode(&[(2, 5), (1, 5), (2, 5)], &[]))
        .map(|table| table.data)
        .expect("two distinct rows fit");
    assert_eq!(bytes, [0, 2, 2, 5, 1, 5]);
    assert_eq!(
        AssociationTable::from_flavour(ResourceFlavour::AssociationTableSystemBSmall)
            .and_then(|codec| codec.encode(&[], &[]))
            .map(|table| table.data)
            .expect("empty table fits"),
        [0, 0]
    );
}

#[test]
fn wide_object_links_reach_the_selected_table_codec_without_truncation() {
    use crate::configuration::GroupLink;

    let product =
        ProductData::from_mtxml_str(zweidraehte_ets_files::product::fixtures::BCU1_MTXML).expect("fixture parses");
    let mut configuration = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 0, 1), None);
    configuration.com_objects = vec![ComObjectDef {
        number: 971,
        flags: ComObjectFlags::from_byte(0x47),
        object_type: ComObjectType::Uint1,
        datapoint_type: None,
    }];
    // Authored primary first, even though its group address sorts last.
    configuration.links =
        [2, 1, 2].map(|address| GroupLink { group_address: ga(0, 0, address), com_object: 971 }).to_vec();
    let input = TableInput::new(&product, &configuration);
    assert_eq!(input.associations().expect("associations resolve"), [(2, 971), (1, 971), (2, 971)]);
    assert_eq!(input.linked_objects()[0].flags.to_byte(), 0x47);

    let encoded = TableCodec::new(CompiledTableKind::Association, ResourceFlavour::AssociationTableSystemBBig)
        .and_then(|codec| codec.encode(&input, || panic!("associations need no seed")))
        .expect("wide identifiers fit four-byte rows");
    assert_eq!(encoded.entries, 2);
    assert_eq!(encoded.data, [0, 2, 0, 2, 3, 0xcb, 0, 1, 3, 0xcb]);
    assert_eq!(encoded.mask, [0xff; 10]);

    for flavour in [
        ResourceFlavour::AssociationTableSystemBSmall,
        ResourceFlavour::AssociationTableBcu1,
        ResourceFlavour::AssociationTableBcu2,
        ResourceFlavour::AssociationTableM112,
    ] {
        let error = TableCodec::new(CompiledTableKind::Association, flavour)
            .and_then(|codec| codec.encode(&input, || panic!("associations need no seed")))
            .expect_err("narrow formats must reject wide identifiers");
        assert_eq!(error.kind, crate::commissioning::error::CompileErrorKind::InvalidInput);
    }

    let descriptors = TableCodec::new(CompiledTableKind::GroupObject, ResourceFlavour::GroupObjectTableSystemB)
        .and_then(|codec| codec.encode(&input, || panic!("descriptors need no seed")))
        .expect("wide roster compiles");
    assert_eq!(&descriptors.data[..2], &[3, 0xcb]);
    assert_eq!(&descriptors.data[2 * 971..], &[0x47, 0]);
    assert!(descriptors.data[2..2 * 971].iter().all(|byte| *byte == 0));
}

#[test]
fn overflow_is_checked_on_the_written_count() {
    // 256 distinct associations overflow the one-octet count...
    let too_many: Vec<(u16, u16)> = (0..=255u16).map(|n| (n, n)).collect();
    assert!(
        AssociationTable::from_flavour(ResourceFlavour::AssociationTableM112)
            .and_then(|codec| codec.encode(&too_many, &[]))
            .map(|table| table.data)
            .is_err()
    );

    // ...but duplicates that dedup away below the cap do not: the
    // check tests the count as written, not the input length.
    let mut with_duplicates = too_many.clone();
    with_duplicates.truncate(255);
    with_duplicates.push((0, 0));
    assert_eq!(with_duplicates.len(), 256);
    let blob = AssociationTable::from_flavour(ResourceFlavour::AssociationTableM112)
        .and_then(|codec| codec.encode(&with_duplicates, &[]))
        .map(|table| table.data)
        .expect("255 after dedup fits");
    assert_eq!(blob[0], 255);
}

#[test]
fn reserved_association_capacity_does_not_encode_a_transmitted_count() {
    for flavour in [
        ResourceFlavour::AssociationTableBcu1,
        ResourceFlavour::AssociationTableBcu2,
        ResourceFlavour::AssociationTableM112,
    ] {
        let codec = AssociationTable::from_flavour(flavour).expect("compact association format");
        assert_eq!(codec.capacity(4096).expect("reserved storage"), 8193);
        let encoded = codec.encode(&[(1, 1)], &[1]).expect("actual rows fit the count");
        assert!(encoded.data.len() < 8193);
        let overflowing: Vec<_> = (0..=255).map(|n| (n, n)).collect();
        assert!(codec.encode(&overflowing, &[]).is_err(), "actual count remains bounded");
    }
}

// Exercise the common image-facing contract as well as the individual formats.
// A caller supplies one semantic input and never decodes headers or pointer rows.
#[test]
fn unified_codec_reports_normalized_entries_and_preserves_primary_links() {
    use crate::configuration::GroupLink;
    use ResourceFlavour::*;

    let product =
        ProductData::from_mtxml_str(zweidraehte_ets_files::product::fixtures::BCU1_MTXML).expect("fixture parses");
    let mut project = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 0, 1), Some(15));
    project.links = [2, 1, 2].map(|address| GroupLink { group_address: ga(0, 0, address), com_object: 1 }).to_vec();
    let configuration = project.with_com_objects(product.com_objects().to_vec());
    let input = TableInput::new(&product, &configuration);

    let cases: &[(CompiledTableKind, ResourceFlavour, &[u8], usize)] = &[
        (CompiledTableKind::GroupAddress, AddressTableBcu1, &[3, 0x10, 1, 0, 1, 0, 2], 2),
        (CompiledTableKind::GroupAddress, AddressTableBcu1Pl, &[3, 0x10, 1, 0, 1, 0, 2], 2),
        (CompiledTableKind::GroupAddress, AddressTableSystemB, &[0, 2, 0, 1, 0, 2], 2),
        (CompiledTableKind::Association, AssociationTableBcu1, &[3, 1, 1, 2, 1, 2, 1], 3),
        (CompiledTableKind::Association, AssociationTableBcu2, &[3, 1, 1, 2, 1, 2, 1], 3),
        (CompiledTableKind::Association, AssociationTableM112, &[2, 1, 1, 2, 1], 2),
        (CompiledTableKind::Association, AssociationTableSystemBSmall, &[0, 2, 2, 1, 1, 1], 2),
        (CompiledTableKind::Association, AssociationTableSystemBBig, &[0, 2, 0, 2, 0, 1, 0, 1, 0, 1], 2),
    ];
    for &(kind, flavour, expected, entries) in cases {
        let codec = TableCodec::new(kind, flavour).expect("known resource format");
        let table = codec.encode(&input, || panic!("these tables need no native seed")).expect("table fits");
        assert_eq!(table.data, expected, "{flavour:?}");
        // Legacy address tables leave the IA slot to address assignment.
        let mut mask = vec![0xff; expected.len()];
        if matches!(flavour, AddressTableBcu1 | AddressTableBcu1Pl) {
            mask[1..3].fill(0);
        }
        assert_eq!(table.mask, mask, "{flavour:?}");
        assert_eq!(table.entries, entries, "{flavour:?}");
    }
}

#[test]
fn unified_object_codec_preserves_native_bits_and_requests_only_required_seeds() {
    use crate::configuration::LoweredDeviceConfiguration;
    use ResourceFlavour::*;

    let object = ComObjectDef {
        number: 1,
        flags: ComObjectFlags::from_byte(0x47),
        object_type: ComObjectType::Uint1,
        datapoint_type: Some("DPST-1-1".to_owned()),
    };
    let product = ProductData::from_mtxml_str(zweidraehte_ets_files::product::fixtures::BCU1_MTXML)
        .expect("fixture parses")
        .with_fixture_com_objects(vec![object], vec![1]);
    let mut configuration = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 0, 1), Some(15))
        .with_com_objects(product.com_objects().to_vec());
    // Linked, so the configured flags reach every codec unchanged; the
    // unlinked communication-enable rule has its own test below.
    configuration.links.push(crate::configuration::GroupLink {
        group_address: GroupAddress::from_three_level(1, 2, 3),
        com_object: 1,
    });
    let input = TableInput::new(&product, &configuration);
    let compact_seed = &[2, 0xce, 0xc6, 0xff, 0, 0xc7, 0xff, 0xc3][..];

    struct Case {
        flavours: &'static [ResourceFlavour],
        seed: Option<&'static [u8]>,
        data: &'static [u8],
        mask: &'static [u8],
        entries: usize,
    }
    let cases = [
        Case {
            flavours: &[GroupObjectTableBcu10, GroupObjectTableBcu11, GroupObjectTableBcu1Pl],
            seed: Some(compact_seed),
            data: &[2, 0xce, 0xc6, 0xa3, 0, 0xc7, 0xe7, 0],
            mask: &[0xff; 8],
            entries: 2,
        },
        Case {
            flavours: &[GroupObjectTableBcu2],
            seed: Some(compact_seed),
            data: &[2, 0xce, 0xc6, 0x23, 0, 0xc7, 0x67, 0],
            mask: &[0xff; 8],
            entries: 2,
        },
        Case {
            flavours: &[GroupObjectTableM112],
            seed: Some(&[2, 0x12, 0x34, 0xab, 0xcd, 0xff, 0, 0xde, 0xad, 0xff, 0xc3]),
            data: &[2, 0x12, 0x34, 0xab, 0xcd, 0xfb, 0, 0xde, 0xad, 0x67, 0xc0],
            mask: &[0xff; 11],
            entries: 2,
        },
        Case { flavours: &[GroupObjectTableSystemB], seed: None, data: &[0, 1, 0x47, 0], mask: &[0xff; 4], entries: 1 },
        Case {
            flavours: &[GroupObjectTableSystem300],
            seed: None,
            data: &[0, 0, 0, 0, 0, 0, 0, 0x47, 0, 1, 0, 1],
            mask: &[0xff; 12],
            entries: 2,
        },
    ];
    for case in cases {
        for &flavour in case.flavours {
            let codec = TableCodec::new(CompiledTableKind::GroupObject, flavour).expect("known object format");
            let mut seed_reads = 0;
            let table = codec
                .encode(&input, || {
                    seed_reads += 1;
                    Ok(TableSeed {
                        data: case.seed.expect("only native formats request a seed").to_vec(),
                        first_byte_owned: true,
                    })
                })
                .expect("declared object fits");
            assert_eq!(seed_reads, usize::from(case.seed.is_some()), "{flavour:?}");
            assert_eq!(table.data, case.data, "{flavour:?}");
            assert_eq!(table.mask, case.mask, "{flavour:?}");
            assert_eq!(table.entries, case.entries, "{flavour:?}");
        }
    }
}

#[test]
fn native_object_transfer_owns_preserved_header_and_roster_but_leaves_trailing_rows_unowned() {
    for (format, seed, header, row) in [
        (NativeObjectFormat::Rt1, vec![3, 0xce, 0xc6, 0xff, 0xc1, 0xc7, 0xff, 0xc3, 0xc8, 0x43, 0x82], 2, 3),
        (NativeObjectFormat::Rt2, vec![3, 0xce, 0xc6, 0xff, 0xc1, 0xc7, 0xff, 0xc3, 0xc8, 0x43, 0x82], 2, 3),
        (
            NativeObjectFormat::System7,
            vec![3, 0x12, 0x34, 0xab, 0xcd, 0xff, 0xc1, 0xde, 0xad, 0xff, 0xc3, 0xbe, 0xef, 0x43, 0x82],
            3,
            4,
        ),
    ] {
        let codec = ObjectTable::Native(NativeObjectTable::new(format));
        for effective in [Vec::new(), vec![ComObjectDef {
            number: 1,
            flags: ComObjectFlags::from_byte(0x47),
            object_type: ComObjectType::Byte1,
            datapoint_type: None,
        }]] {
            let table = codec
                .encode(&ProductData::default(), &effective, || {
                    Ok(TableSeed { data: seed.clone(), first_byte_owned: true })
                })
                .unwrap();
            let owned = header + if effective.is_empty() { 0 } else { 2 * row };
            assert!(table.mask[..owned].iter().all(|mask| *mask == 0xff), "{format:?}");
            assert!(table.mask[owned..].iter().all(|mask| *mask == 0), "{format:?}");
            assert_eq!(&table.data[..header], &seed[..header]);
            assert_eq!(&table.data[header + 2 * row..], &seed[header + 2 * row..]);
            assert_eq!(table.entries, 3);
            let unowned = codec
                .encode(&ProductData::default(), &effective, || {
                    Ok(TableSeed { data: seed.clone(), first_byte_owned: false })
                })
                .unwrap();
            let count = if effective.is_empty() { 0 } else { 2 };
            assert_eq!(unowned.data[0], count, "{format:?}");
            assert_eq!(unowned.entries, usize::from(count), "{format:?}");
            assert_eq!(unowned.data.len(), owned, "{format:?}");
            assert!(unowned.mask.iter().all(|mask| *mask == 0xff), "{format:?}");
            assert_eq!(&unowned.data[1..header], &seed[1..header]);
            assert_eq!(&unowned.data[header..], &table.data[header..owned]);
        }
    }
}

#[test]
fn unlinked_active_objects_lose_communication_enable_except_system_300_rows() {
    use crate::configuration::LoweredDeviceConfiguration;

    let objects = [1, 2].map(|number| ComObjectDef {
        number,
        flags: ComObjectFlags::from_byte(0x47),
        object_type: ComObjectType::Uint1,
        datapoint_type: Some("DPST-1-1".to_owned()),
    });
    let product = ProductData::from_mtxml_str(zweidraehte_ets_files::product::fixtures::BCU1_MTXML)
        .expect("fixture parses")
        .with_fixture_com_objects(objects.to_vec(), vec![1, 2]);
    let mut configuration = LoweredDeviceConfiguration::new(IndividualAddress::new(1, 0, 1), Some(15))
        .with_com_objects(product.com_objects().to_vec());
    configuration.links.push(crate::configuration::GroupLink {
        group_address: GroupAddress::from_three_level(1, 2, 3),
        com_object: 2,
    });
    let input = TableInput::new(&product, &configuration);

    // Object 1 has no link: ETS writes its row with communication enable off.
    let flags: Vec<u8> = input.linked_objects().iter().map(|object| object.flags.to_byte()).collect();
    assert_eq!(flags, [0x43, 0x47]);

    let system_b = TableCodec::new(CompiledTableKind::GroupObject, ResourceFlavour::GroupObjectTableSystemB)
        .expect("System B rows")
        .encode(&input, || panic!("no native seed"))
        .expect("rows fit");
    assert_eq!(system_b.data, [0, 2, 0x43, 0, 0x47, 0]);

    let system_300 = TableCodec::new(CompiledTableKind::GroupObject, ResourceFlavour::GroupObjectTableSystem300)
        .expect("System 300 rows")
        .encode(&input, || panic!("no native seed"))
        .expect("rows fit");
    assert_eq!(system_300.data[7], 0x47, "System 300 keeps the configured bit until measured");
}
