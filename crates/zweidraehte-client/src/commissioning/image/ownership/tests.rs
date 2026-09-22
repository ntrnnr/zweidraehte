use super::*;
use crate::commissioning::{ImageLocation, ImageSegment};

fn patch(image: &mut SparseDeviceImage, section: ProgrammingSection, offset: u32, data: &[u8], mask: &[u8]) {
    image.apply_section(
        section,
        &ImageSegment::new(ImageLocation::standard_memory(offset), data.to_vec(), mask.to_vec())
            .expect("matching lengths"),
    );
}

#[test]
fn later_patch_transfers_only_overlapping_bits() {
    let mut image = SparseDeviceImage::new();
    patch(&mut image, ProgrammingSection::ApplicationProgram1, 1, &[0xa5], &[0xff]);
    patch(&mut image, ProgrammingSection::Parameters, 1, &[0x03], &[0x0f]);

    assert_eq!(image.byte(&ImageLocation::standard_memory(1)), Some((0xa3, 0xff)));
    let owners = image.ownership();
    assert_eq!(owners.len(), 2);
    assert_eq!(owners[0].section, ProgrammingSection::ApplicationProgram1);
    assert_eq!(owners[0].mask, [0xf0]);
    assert_eq!(owners[1].section, ProgrammingSection::Parameters);
    assert_eq!(owners[1].mask, [0x0f]);
}

#[test]
fn image_and_ownership_runs_preserve_holes_and_address_spaces() {
    let mut image = SparseDeviceImage::new();
    patch(&mut image, ProgrammingSection::Parameters, 4, &[1, 2, 3], &[0xff; 3]);
    patch(&mut image, ProgrammingSection::Configuration, 5, &[8], &[0xff]);
    patch(&mut image, ProgrammingSection::Parameters, 8, &[4], &[0xff]);
    let user = ImageLocation { space: ImageSpace::UserMemory, offset: 9 };
    image.apply_section(
        ProgrammingSection::Parameters,
        &ImageSegment::owned(user.clone(), vec![5, 6]).expect("bounded user range"),
    );

    let segments = image.segments();
    assert_eq!(segments.len(), 3);
    assert_eq!(segments[0].data(), [1, 8, 3]);
    assert_eq!(segments[1].location(), &ImageLocation::standard_memory(8));
    assert_eq!(segments[2].location(), &user);
    let owners = image.ownership();
    let parameters: Vec<_> = owners.iter().filter(|owner| owner.section == ProgrammingSection::Parameters).collect();
    assert_eq!(parameters.len(), 4, "another section's byte splits the parameter range");
    assert_eq!(parameters.iter().map(|owner| owner.location.offset).collect::<Vec<_>>(), [4, 6, 8, 9]);
    assert_eq!(parameters[3].location.space, ImageSpace::UserMemory);
    assert_eq!(parameters[3].mask, [0xff, 0xff]);
}

#[test]
fn large_image_has_one_section_digest() {
    let mut image = SparseDeviceImage::new();
    patch(&mut image, ProgrammingSection::ApplicationProgram1, 0, &vec![0x5a; 40_000], &vec![0xff; 40_000]);
    let manifest = image.manifest();
    assert_eq!(manifest.sections.len(), 1);
    assert!(manifest.credentials.is_empty());
}

#[test]
fn executable_ranges_report_only_intersecting_owners() {
    let mut image = SparseDeviceImage::new();
    patch(&mut image, ProgrammingSection::Parameters, 4, &[1], &[0xff]);
    patch(&mut image, ProgrammingSection::Configuration, 5, &[2], &[0xff]);
    assert_eq!(
        image.sections_for_range(&ImageLocation::standard_memory(4), 1),
        BTreeSet::from([ProgrammingSection::Parameters])
    );
    assert_eq!(
        image.sections_for_range(&ImageLocation::standard_memory(4), 2),
        BTreeSet::from([ProgrammingSection::Parameters, ProgrammingSection::Configuration])
    );
}

#[test]
fn section_digests_do_not_depend_on_patch_grouping() {
    let mut joined = SparseDeviceImage::new();
    patch(&mut joined, ProgrammingSection::Parameters, 4, &[1, 2], &[0xff, 0xff]);
    let mut split = SparseDeviceImage::new();
    patch(&mut split, ProgrammingSection::Parameters, 4, &[1], &[0xff]);
    patch(&mut split, ProgrammingSection::Parameters, 5, &[2], &[0xff]);
    assert_eq!(joined.manifest(), split.manifest());
}

#[test]
fn unknown_bits_do_not_change_owned_section_digest() {
    let mut first = SparseDeviceImage::new();
    patch(&mut first, ProgrammingSection::Parameters, 1, &[0x13], &[0x0f]);
    let mut second = SparseDeviceImage::new();
    patch(&mut second, ProgrammingSection::Parameters, 1, &[0xa3], &[0x0f]);
    assert_eq!(first.manifest(), second.manifest());
}

#[test]
fn siat_digest_retains_senders_and_geometry_but_not_live_replay_counters() {
    use crate::commissioning::catalog::profile::Occurrence;

    let image = |object_type, bytes: Vec<u8>| {
        let mut image = SparseDeviceImage::new();
        let location = ImageLocation {
            space: ImageSpace::Property {
                object: ObjectSelector::Type { object_type, occurrence: Occurrence::Zero },
                property_id: pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE,
            },
            offset: 0,
        };
        image.apply_section(
            ProgrammingSection::GroupCommunication,
            &ImageSegment::owned(location, bytes).expect("bounded table"),
        );
        image
    };
    let security = u16::from(InterfaceObjectType::Security);
    let first = image(security, vec![0x11, 2, 0, 0, 0, 0, 0, 7]);
    let later = image(security, vec![0x11, 2, 0, 0, 0, 0, 0xc3, 0x50]);
    assert_eq!(first.manifest(), later.manifest());
    assert_ne!(first, later, "execution retains safe current counters");
    assert_ne!(first.manifest(), image(security, vec![0x11, 3, 0, 0, 0, 0, 0, 7]).manifest());
    assert_ne!(
        first.manifest(),
        image(security, vec![0x11, 2, 0, 0, 0, 0, 0, 7, 0x11, 3, 0, 0, 0, 0, 0, 7]).manifest()
    );
    assert_ne!(
        image(0, vec![0x11, 2, 0, 0, 0, 0, 0, 7]).manifest(),
        image(0, vec![0x11, 2, 0, 0, 0, 0, 0, 8]).manifest(),
        "other objects' PID 54 remains exact"
    );
}
