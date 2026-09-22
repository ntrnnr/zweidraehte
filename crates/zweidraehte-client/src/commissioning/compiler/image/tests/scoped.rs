use super::*;

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
    let required =
        [RequiredImageRange { location: ImageLocation::standard_memory(0x116), length: 5 }, RequiredImageRange {
            location: ImageLocation::standard_memory(0x1c8),
            length: 1,
        }];
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
