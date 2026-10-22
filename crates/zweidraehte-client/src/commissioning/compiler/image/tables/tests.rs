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
    // roster, so it formats as a blank entry with low priority and preserves
    // the firmware's memory-segment bit.
    let mut defaults = blob.clone();
    NativeObjectTable::new(NativeObjectFormat::Bcu2)
        .overlay(&mut defaults, &[(1, ComObjectFlags::from_byte(0x43), ComObjectType::Uint1)])
        .expect("row 1 exists");
    assert_eq!(defaults, [0x02, 0xCE, 0xC6, 0x03, 0x00, 0xC7, 0x43, 0x00]);

    // A row beyond the product's RT2 table is refused.
    assert!(
        NativeObjectTable::new(NativeObjectFormat::Bcu2)
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
    NativeObjectTable::new(NativeObjectFormat::Bcu11)
        .overlay(&mut defaults, &[(1, ComObjectFlags::from_byte(0x43), ComObjectType::Uint1)])
        .expect("row 1 exists");
    // BCU1 1.1 sets its fixed update bit and gives blank rows low priority.
    assert_eq!(defaults, [0x02, 0xCE, 0xC6, 0x83, 0x00, 0xC7, 0xC3, 0x00]);
}

#[test]
fn legacy_object_flavours_keep_native_fixed_flags_gap_priority_and_type_bits() {
    // Native seed probes retain the type octet's top two bits, reset gaps
    // to low priority and distinguish BCU1 1.0's fixed transmit bit. PL110's
    // firmware update-bit policy comes from the native formatter; a complete
    // PL110 download still needs a supported provider and product witness.
    let seed = [3, 0xce, 0xc6, 0x02, 0xc7, 0xc7, 0x21, 0xc1, 0xc8, 0xe2, 0x82];
    for (flavour, expected) in [
        (ResourceFlavour::GroupObjectTableBcu10, [3, 0xce, 0xc6, 0xc3, 0xc7, 0xc7, 0xe1, 0xc0, 0xc8, 0xe2, 0x82]),
        (ResourceFlavour::GroupObjectTableBcu11, [3, 0xce, 0xc6, 0x83, 0xc7, 0xc7, 0xa1, 0xc0, 0xc8, 0xe2, 0x82]),
        (ResourceFlavour::GroupObjectTableBcu1Pl, [3, 0xce, 0xc6, 0x03, 0xc7, 0xc7, 0x21, 0xc0, 0xc8, 0xe2, 0x82]),
        (ResourceFlavour::GroupObjectTableBcu2, [3, 0xce, 0xc6, 0x03, 0xc7, 0xc7, 0x21, 0xc0, 0xc8, 0xe2, 0x82]),
    ] {
        let codec = ObjectTable::from_flavour(flavour).expect("legacy object flavour is supported");
        let effective = [ComObjectDef {
            number: 1,
            flags: ComObjectFlags::from_byte(1),
            object_type: ComObjectType::Uint1,
            datapoint_type: None,
        }];
        let table = codec
            .encode(&ProductData::default(), &effective, || {
                Ok(TableSeed { data: seed.to_vec(), mask: vec![0xff; seed.len()], first_byte_owned: true })
            })
            .expect("one active object fits its native seed");

        assert_eq!(table.data, expected, "{flavour:?}");
        assert_eq!(table.mask, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0]);
        assert_eq!(table.entries, 3);
    }
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
    use crate::configuration::ObjectMembership;

    let product =
        ProductData::from_mtxml_str(zweidraehte_ets_files::product::fixtures::BCU1_MTXML).expect("fixture parses");
    let mut configuration = MaterializedDevice::fixture(IndividualAddress::new(1, 0, 1), None);
    configuration.encoded_mut().com_objects = vec![ComObjectDef {
        number: 971,
        flags: ComObjectFlags::from_byte(0x47),
        object_type: ComObjectType::Uint1,
        datapoint_type: None,
    }];
    // Authored primary first, even though its group address sorts last.
    *configuration.object_memberships_mut() =
        [2, 1, 2].map(|address| ObjectMembership::primary(ga(0, 0, address), 971)).to_vec();
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
    let error = AssociationTable::from_flavour(ResourceFlavour::AssociationTableM112)
        .and_then(|codec| codec.encode(&too_many, &[]))
        .map(|table| table.data)
        .expect_err("256 rows overflow the count");
    assert_eq!(
        error.kind,
        crate::commissioning::error::CompileErrorKind::TableOverflow(
            crate::commissioning::error::OverflowedTable::Association
        )
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

// The PL110 discriminator occupies bit 15. Main groups 16-31 already set it,
// so encoding them would alias a lower group and shift later association rows.
#[test]
fn pl110_address_table_rejects_groups_that_use_the_discriminator_bit() {
    use address::AddressTable;

    let table = AddressTable::from_flavour(ResourceFlavour::AddressTableBcu1Pl).expect("PL110 format");
    let individual = IndividualAddress::new(1, 0, 1);
    assert_eq!(table.encode(individual, &[ga(15, 7, 255)]).expect("highest PL110 group").data, [
        2, 0x10, 1, 0xff, 0xff
    ]);
    for group in [ga(16, 0, 1), ga(31, 7, 255)] {
        let error = table.encode(individual, &[ga(0, 0, 1), group]).expect_err("bit 15 is the discriminator");
        assert!(error.to_string().contains("bit 15"), "{error}");
    }

    // Twisted pair has no discriminator and keeps the full group range.
    let twisted_pair = AddressTable::from_flavour(ResourceFlavour::AddressTableBcu1).expect("TP format");
    assert_eq!(twisted_pair.encode(individual, &[ga(16, 0, 1)]).expect("TP group").data, [2, 0x10, 1, 0x80, 1]);
}

// Exercise the common image-facing contract as well as the individual formats.
// A caller supplies one semantic input and never decodes headers or pointer rows.
#[test]
fn unified_codec_reports_normalized_entries_and_preserves_primary_links() {
    use crate::configuration::ObjectMembership;
    use ResourceFlavour::*;

    let product =
        ProductData::from_mtxml_str(zweidraehte_ets_files::product::fixtures::BCU1_MTXML).expect("fixture parses");
    let mut project = MaterializedDevice::fixture(IndividualAddress::new(1, 0, 1), Some(15));
    *project.object_memberships_mut() =
        [2, 1, 2].map(|address| ObjectMembership::primary(ga(0, 0, address), 1)).to_vec();
    let configuration = project.with_com_objects(product.com_objects().to_vec());
    let input = TableInput::new(&product, &configuration);

    let cases: &[(CompiledTableKind, ResourceFlavour, &[u8], usize)] = &[
        (CompiledTableKind::GroupAddress, AddressTableBcu1, &[3, 0x10, 1, 0, 1, 0, 2], 2),
        (CompiledTableKind::GroupAddress, AddressTableBcu1Pl, &[3, 0x10, 1, 0x80, 1, 0x80, 2], 2),
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
    use crate::configuration::MaterializedDevice;
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
    let mut configuration = MaterializedDevice::fixture(IndividualAddress::new(1, 0, 1), Some(15))
        .with_com_objects(product.com_objects().to_vec());
    // Linked, so the configured flags reach every codec unchanged; the
    // unlinked communication-enable rule has its own test below.
    configuration
        .object_memberships_mut()
        .push(crate::configuration::ObjectMembership::primary(GroupAddress::from_three_level(1, 2, 3), 1));
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
            flavours: &[GroupObjectTableBcu10],
            seed: Some(compact_seed),
            data: &[2, 0xce, 0xc6, 0xe3, 0, 0xc7, 0xe7, 0xc0],
            mask: &[0xff; 8],
            entries: 2,
        },
        Case {
            flavours: &[GroupObjectTableBcu11, GroupObjectTableBcu1Pl],
            seed: Some(compact_seed),
            data: &[2, 0xce, 0xc6, 0xa3, 0, 0xc7, 0xe7, 0xc0],
            mask: &[0xff; 8],
            entries: 2,
        },
        Case {
            flavours: &[GroupObjectTableBcu2],
            seed: Some(compact_seed),
            data: &[2, 0xce, 0xc6, 0x23, 0, 0xc7, 0x67, 0xc0],
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
            seed: Some(&[0, 0, 0, 20, 0, 3]),
            data: &[0, 0x47, 0, 20, 0, 3],
            mask: &[0xff; 6],
            entries: 1,
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
                        mask: vec![0xff; case.seed.expect("a seed was requested").len()],
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
        (NativeObjectFormat::Bcu11, vec![3, 0xce, 0xc6, 0xff, 0xc1, 0xc7, 0xff, 0xc3, 0xc8, 0x43, 0x82], 2, 3),
        (NativeObjectFormat::Bcu2, vec![3, 0xce, 0xc6, 0xff, 0xc1, 0xc7, 0xff, 0xc3, 0xc8, 0x43, 0x82], 2, 3),
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
                    Ok(TableSeed { data: seed.clone(), mask: vec![0xff; seed.len()], first_byte_owned: true })
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
                    Ok(TableSeed { data: seed.clone(), mask: vec![0; seed.len()], first_byte_owned: false })
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
fn owned_counts_below_the_roster_stay_while_every_effective_row_is_formatted() {
    // Witnesses (MV-0012, MV-0021, MV-0701, MV-0705) place the object table in
    // a segment without data, so the transfer owns a zero count. The reference
    // keeps a disagreeing owned count and still formats the full roster.
    for (format, seed) in [
        (NativeObjectFormat::Bcu11, vec![
            3, 0xce, 0xc6, 0xff, 0xc1, 0xc7, 0xff, 0xc3, 0xc8, 0x43, 0x82, 0xc9, 0x11, 0x22,
        ]),
        (NativeObjectFormat::Bcu2, vec![
            3, 0xce, 0xc6, 0xff, 0xc1, 0xc7, 0xff, 0xc3, 0xc8, 0x43, 0x82, 0xc9, 0x11, 0x22,
        ]),
        (NativeObjectFormat::System7, vec![
            3, 0x12, 0x34, 0xab, 0xcd, 0xff, 0xc1, 0xde, 0xad, 0xff, 0xc3, 0xbe, 0xef, 0x43, 0x82, 0xca, 0xfe, 0x11,
            0x22,
        ]),
    ] {
        let codec = ObjectTable::Native(NativeObjectTable::new(format));
        let effective = [0, 2].map(|number| ComObjectDef {
            number,
            flags: ComObjectFlags::from_byte(0x47),
            object_type: ComObjectType::Byte1,
            datapoint_type: None,
        });
        let encode = |count| {
            let mut data = seed.clone();
            data[0] = count;
            codec
                .encode(&ProductData::default(), &effective, || {
                    Ok(TableSeed { mask: vec![0xff; data.len()], data, first_byte_owned: true })
                })
                .expect("the physical table holds the effective roster")
        };
        let declared = encode(3);
        let zero = encode(0);

        assert_eq!(zero.data[0], 0, "{format:?}");
        assert_eq!(zero.data[1..], declared.data[1..], "{format:?}");
        assert_eq!(zero.mask, declared.mask, "{format:?}");
        assert_eq!(zero.entries, 0, "{format:?}");
    }
}

#[test]
fn unlinked_active_objects_lose_communication_enable_except_system_300_rows() {
    use crate::configuration::MaterializedDevice;

    let objects = [1, 2].map(|number| ComObjectDef {
        number,
        flags: ComObjectFlags::from_byte(0x47),
        object_type: ComObjectType::Uint1,
        datapoint_type: Some("DPST-1-1".to_owned()),
    });
    let product = ProductData::from_mtxml_str(zweidraehte_ets_files::product::fixtures::BCU1_MTXML)
        .expect("fixture parses")
        .with_fixture_com_objects(objects.to_vec(), vec![1, 2]);
    let mut configuration = MaterializedDevice::fixture(IndividualAddress::new(1, 0, 1), Some(15))
        .with_com_objects(product.com_objects().to_vec());
    configuration
        .object_memberships_mut()
        .push(crate::configuration::ObjectMembership::primary(GroupAddress::from_three_level(1, 2, 3), 2));
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
        .encode(&input, || Ok(TableSeed { data: Vec::new(), mask: Vec::new(), first_byte_owned: false }))
        .expect("rows fit");
    assert_eq!(system_300.data[1], 0x47, "System 300 retains the configured communication bit");
}

#[test]
fn system_300_overlays_flags_without_replacing_seed_dpt_or_ownership() {
    let codec = ObjectTable::from_flavour(ResourceFlavour::GroupObjectTableSystem300).expect("System 300 codec");
    assert_eq!(codec.first_object_number(), 1);
    for datapoint_type in [None, Some("DPST-1-1".to_owned())] {
        let object = ComObjectDef {
            number: 1,
            flags: ComObjectFlags::from_byte(0x37),
            object_type: ComObjectType::Byte1,
            datapoint_type,
        };
        let table = codec
            .encode(&ProductData::default(), &[object], || {
                Ok(TableSeed {
                    data: vec![0xab, 0xe0, 0, 20, 0, 3],
                    mask: vec![0x0f, 0, 0xff, 0xff, 0xff, 0xff],
                    first_byte_owned: true,
                })
            })
            .expect("the parameter image supplies DPT20.3");
        assert_eq!(table.data, [0xab, 0x17, 0, 20, 0, 3]);
        assert_eq!(table.mask, [0x0f, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(table.entries, 1);
    }
}

#[test]
fn system_300_parameter_loading_fills_only_wholly_unowned_bytes() {
    let product = ProductData::default();
    let configuration =
        MaterializedDevice::fixture(IndividualAddress::new(1, 0, 1), Some(15)).with_com_objects(vec![ComObjectDef {
            number: 1,
            flags: ComObjectFlags::from_byte(0x37),
            object_type: ComObjectType::Byte1,
            datapoint_type: None,
        }]);
    let codec = TableCodec::new(CompiledTableKind::GroupObject, ResourceFlavour::GroupObjectTableSystem300)
        .expect("System 300 codec");
    for load_parameters in [false, true] {
        let mut input = TableInput::new(&product, &configuration);
        input.load_parameters = load_parameters;
        let table = codec
            .encode(&input, || {
                Ok(TableSeed {
                    data: vec![0xab, 0, 0xcd, 20, 0, 3],
                    mask: vec![0x0f, 0, 0, 255, 255, 255],
                    first_byte_owned: true,
                })
            })
            .expect("parameter mode resolves");
        assert_eq!(table.data, [0xab, 0x17, if load_parameters { 0 } else { 0xcd }, 20, 0, 3]);
        assert_eq!(table.mask, [0x0f, 255, if load_parameters { 255 } else { 0 }, 255, 255, 255]);
    }
}

#[test]
fn system_300_skips_object_zero_formats_gaps_and_emits_only_the_active_prefix() {
    let codec = ObjectTable::from_flavour(ResourceFlavour::GroupObjectTableSystem300).expect("System 300 codec");
    let objects = [0, 3].map(|number| ComObjectDef {
        number,
        flags: ComObjectFlags::from_byte(0xff),
        object_type: ComObjectType::Byte1,
        datapoint_type: None,
    });
    let seed = (0..24).collect::<Vec<u8>>();
    let table = codec
        .encode(&ProductData::default(), &objects, || {
            Ok(TableSeed { data: seed.clone(), mask: vec![0x55; seed.len()], first_byte_owned: true })
        })
        .expect("three rows overlay the longer seed");
    let mut expected = seed[..18].to_vec();
    expected[1] = 3;
    expected[7] = 3;
    expected[13] = 0xdf;
    assert_eq!(table.data, expected);
    assert_eq!(table.entries, 3);
    for offset in 0..18 {
        assert_eq!(table.mask[offset], if offset % 6 == 1 { 0xff } else { 0x55 });
    }
    // No emitted bytes cover the final seed row; the image merger retains it.
    assert_eq!(table.data.len(), seed.len() - 6);
    let zero = codec
        .encode(&ProductData::default(), &objects[..1], || {
            Ok(TableSeed { data: seed.clone(), mask: vec![0xff; seed.len()], first_byte_owned: true })
        })
        .expect("object zero contributes no physical row");
    assert!(zero.data.is_empty());
    assert!(zero.mask.is_empty());
    assert_eq!(zero.entries, 0);
}

#[test]
fn system_300_extends_missing_seed_without_inventing_owned_dpt_bytes() {
    let codec = ObjectTable::from_flavour(ResourceFlavour::GroupObjectTableSystem300).expect("System 300 codec");
    let object = ComObjectDef {
        number: 2,
        flags: ComObjectFlags::from_byte(0x67),
        object_type: ComObjectType::Byte1,
        datapoint_type: None,
    };
    let table = codec
        .encode(&ProductData::default(), &[object], || {
            Ok(TableSeed { data: vec![0xab], mask: vec![0x0f], first_byte_owned: true })
        })
        .expect("missing seed bytes remain unowned");
    assert_eq!(table.data, [0xab, 3, 0, 0, 0, 0, 0, 0x47, 0, 0, 0, 0]);
    assert_eq!(table.mask, [0x0f, 0xff, 0, 0, 0, 0, 0, 0xff, 0, 0, 0, 0]);
    assert_eq!(table.entries, 2);
}
