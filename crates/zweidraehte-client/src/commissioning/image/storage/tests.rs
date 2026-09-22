use crate::commissioning::image::{ImageLocation, ImageSegment, SparseDeviceImage};

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
