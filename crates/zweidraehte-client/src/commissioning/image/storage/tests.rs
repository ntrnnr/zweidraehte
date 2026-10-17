use crate::commissioning::image::{ImageLocation, ImageSegment, SparseDeviceImage};

#[test]
fn represented_buffers_preserve_owned_bits_sections_and_adjacent_holes() {
    use zweidraehte_project::ProgrammingSection;
    let location = ImageLocation::standard_memory(100);
    let mut image = SparseDeviceImage::new();
    image.apply_section(
        ProgrammingSection::Parameters,
        &ImageSegment::new(location.clone(), vec![0xa0], vec![0xf0]).expect("parameter bits"),
    );
    image.represent_range(&location, 3).expect("declared buffer");
    image.represent_range(&location, 3).expect("repeated declaration");
    let bytes = image.range(&location, 3).expect("represented buffer");
    assert_eq!(bytes.data(), [0xa0, 0, 0]);
    assert_eq!(bytes.mask(), [0xf0, 0, 0]);
    assert!(image.sections_for_range(&location, 3).contains(&ProgrammingSection::Parameters));
    assert_eq!(image.byte(&ImageLocation::standard_memory(103)), None);
    assert!(image.represent_range(&ImageLocation::standard_memory(u32::MAX), 1).is_err());
    assert_eq!(image.byte_count(), 3);
}

#[test]
fn later_patches_replace_only_their_owned_bits() {
    let location = ImageLocation::standard_memory(0x12345);
    let mut image = SparseDeviceImage::new();

    image.apply(&ImageSegment::new(location.clone(), vec![0b1010_0000], vec![0b1111_0000]).expect("base patch"));

    image.apply(&ImageSegment::new(location, vec![0b0000_0101], vec![0b0000_1111]).expect("second patch"));

    let segments = image.segments();
    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0].data(), &[0b1010_0101]);
    assert_eq!(segments[0].mask(), &[0xff]);
}

#[test]
fn twenty_bit_addresses_are_not_truncated() {
    let location = ImageLocation::standard_memory(0x0f_f000);
    let segment = ImageSegment::owned(location.clone(), vec![1, 2, 3]).expect("valid segment");
    let mut image = SparseDeviceImage::new();

    image.apply(&segment);

    assert_eq!(image.segments()[0].location(), &location);
}

#[test]
fn unequal_masks_fail_before_entering_the_image() {
    let error = ImageSegment::new(ImageLocation::standard_memory(0), vec![1, 2], vec![0xff])
        .expect_err("mask length must match data length");

    assert!(matches!(error, super::ImageError::MaskLength { .. }));
}

#[test]
fn geometry_queries_preserve_gaps_masks_spaces_and_checked_empty_ranges() {
    use crate::commissioning::image::ImageSpace;
    let mut image = SparseDeviceImage::new();
    assert!(image.require_range(&ImageLocation::standard_memory(0), 0).is_err());
    assert_eq!(image.end_offset(&ImageSpace::StandardMemory), None);
    image.apply(
        &ImageSegment::new(ImageLocation::standard_memory(7), vec![1, 2, 3, 4], vec![1, 255, 0, 2])
            .expect("masked range"),
    );
    image.apply_owned(ImageLocation { space: ImageSpace::UserMemory, offset: 7 }, vec![9]).expect("distinct space");
    image.apply_owned(ImageLocation::standard_memory(u32::MAX - 1), vec![5]).expect("last representable byte");

    let ranges: Vec<_> = image.ranges().map(|range| (range.location, range.length)).collect();
    let materialized: Vec<_> =
        image.segments().iter().map(|segment| (segment.location().clone(), segment.data().len() as u32)).collect();
    assert_eq!(ranges, materialized);
    assert_eq!(image.end_offset(&ImageSpace::StandardMemory), Some(u32::MAX));
    assert_eq!(image.end_offset(&ImageSpace::UserMemory), Some(8));
    for (offset, length) in [(7, 2), (7, 4), (9, 1), (10, 1), (50, 0), (u32::MAX, 0), (u32::MAX, 1)] {
        let location = ImageLocation::standard_memory(offset);
        assert_eq!(
            image.require_range(&location, length),
            image.range(&location, length).map(|_| ()),
            "{offset}/{length}"
        );
    }
    assert!(image.require_range(&ImageLocation::standard_memory(7), 2).is_ok(), "partial masks still represent bytes");
    assert!(image.require_range(&ImageLocation::standard_memory(7), 4).is_err(), "zero-mask hole stays absent");
}

#[test]
fn a_mirror_replaces_the_target_range_with_the_source_range() {
    use crate::commissioning::image::ImageSpace;
    use zweidraehte_project::ProgrammingSection;

    let mut image = SparseDeviceImage::new();
    image.apply_section(
        ProgrammingSection::Parameters,
        &ImageSegment::new(ImageLocation::standard_memory(0x100), vec![0xff, 0x00, 0x72], vec![0xff, 0x00, 0xf0])
            .expect("source patch"),
    );
    let slave = |offset| ImageLocation { space: ImageSpace::LineCouplerSlave, offset };
    // Stale slave bytes inside the range go; the byte after it stays.
    image.apply(&ImageSegment::owned(slave(0x101), vec![0x11, 0x22, 0x33]).expect("stale slave bytes"));

    image.mirror(&ImageLocation::standard_memory(0x100), 3, &ImageSpace::LineCouplerSlave);

    assert_eq!(image.byte(&slave(0x100)), Some((0xff, 0xff)));
    assert_eq!(image.byte(&slave(0x101)), None);
    assert_eq!(image.byte(&slave(0x102)), Some((0x70, 0xf0)));
    assert_eq!(image.byte(&slave(0x103)), Some((0x33, 0xff)));
    assert_eq!(image.sections_for_range(&slave(0x100), 3), [ProgrammingSection::Parameters].into());
    assert_eq!(image.byte(&ImageLocation::standard_memory(0x102)), Some((0x70, 0xf0)));
}
