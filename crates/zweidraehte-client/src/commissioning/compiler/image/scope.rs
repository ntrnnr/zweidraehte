//! A selected procedure's applicability bounds its desired image ownership.

use crate::commissioning::error::CompileError;
use crate::commissioning::image::{ImageSegment, SparseDeviceImage};
use crate::commissioning::input::ProgramSections;
use zweidraehte_project::ProgrammingSection;

pub(super) fn retain_download_sections(
    image: &mut SparseDeviceImage,
    selected: ProgramSections,
) -> Result<(), CompileError> {
    let mut scoped = SparseDeviceImage::new();
    for ownership in image.ownership() {
        let section = match ownership.section {
            ProgrammingSection::ApplicationProgram1 => ProgramSections::APPLICATION_PROGRAM_1,
            ProgrammingSection::ApplicationProgram2 => ProgramSections::APPLICATION_PROGRAM_2,
            ProgrammingSection::Parameters => ProgramSections::PARAMETERS,
            ProgrammingSection::GroupCommunication => ProgramSections::GROUP_COMMUNICATION,
            ProgrammingSection::Configuration => ProgramSections::CONFIGURATION,
            ProgrammingSection::Address => continue,
        };
        if !selected.contains(section) {
            continue;
        }
        let data = ownership
            .mask
            .iter()
            .enumerate()
            .map(|(index, _)| {
                let mut location = ownership.location.clone();
                location.offset += index as u32;
                image.byte(&location).expect("ownership runs refer to canonical image bytes").0
            })
            .collect();
        scoped.apply_section(ownership.section, &ImageSegment::new(ownership.location, data, ownership.mask)?);
    }
    *image = scoped;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commissioning::image::ImageLocation;

    #[test]
    fn partial_scope_retains_selected_bits_without_promoting_other_bits_or_bytes() {
        let location = ImageLocation::standard_memory(256);
        let mut image = SparseDeviceImage::new();
        image.apply_section(
            ProgrammingSection::ApplicationProgram1,
            &ImageSegment::owned(location.clone(), vec![0xaa, 0xcc, 0x33]).unwrap(),
        );
        image.apply_section(
            ProgrammingSection::Parameters,
            &ImageSegment::new(location.clone(), vec![0x05], vec![0x0f]).unwrap(),
        );
        image.apply_section(
            ProgrammingSection::GroupCommunication,
            &ImageSegment::owned(ImageLocation::standard_memory(257), vec![0x77]).unwrap(),
        );
        for (sections, parameter_mask, group) in [
            (ProgramSections::PARAMETERS, 0x0f, false),
            (ProgramSections::GROUP_COMMUNICATION, 0, true),
            (ProgramSections::PARAMETERS.union(ProgramSections::GROUP_COMMUNICATION), 0x0f, true),
            (ProgramSections::CONFIGURATION, 0, false),
        ] {
            let mut result = image.clone();
            retain_download_sections(&mut result, sections).unwrap();
            assert_eq!(
                result.byte(&location).map(|(value, mask)| (value & mask, mask)),
                (parameter_mask != 0).then_some((5, parameter_mask))
            );
            assert_eq!(result.byte(&ImageLocation::standard_memory(257)), group.then_some((0x77, 0xff)));
            assert_eq!(result.byte(&ImageLocation::standard_memory(258)), None);
        }
        assert_eq!(image.byte(&location), Some((0xa5, 0xff)));
    }
}
