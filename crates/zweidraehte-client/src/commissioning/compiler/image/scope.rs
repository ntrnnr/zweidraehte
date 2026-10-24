//! A selected procedure's applicability bounds its desired image ownership.

use crate::commissioning::catalog::profile::ResolvedProfile;
use crate::commissioning::compiler::selection::sources::select_master_procedure;
use crate::commissioning::compiler::selection::syntax::parse_memory_location;
use crate::commissioning::error::CompileError;
use crate::commissioning::image::{ImageSegment, ImageSpace, SparseDeviceImage};
use crate::commissioning::input::ProgramSections;
use zweidraehte_ets_files::product::{LoadProcedureStyle, ProductData};
use zweidraehte_ets_files::schema::LoadControl;
use zweidraehte_project::ProgrammingSection;

/// Attribute no section to memory bytes that the mask's download never sends
/// from the image.
///
/// A product segment can cover bytes that the load procedure leaves alone or
/// writes only with authored constants. BCU1 (MV-0012) is the witness: its
/// `Load all` writes 230 bytes from 0119h, so the segment's last byte at
/// 01FFh is never sent, and it writes `RunError` (010Dh) only as inline 00h
/// and FFh. Such bytes cannot be confirmed after a download, so a section
/// owning them would never count as programmed.
///
/// The bound is static only when the product loads through the mask's
/// Master Data `Load all` and that procedure addresses memory with nothing
/// but absolute `LdCtrlWriteMem` writes. Every other control set (segments,
/// relative memory, properties, `choose`, merges, product procedures) leaves
/// ownership unchanged. Partial downloads write a subset of `Load all`, so
/// its writes bound them too. Desired bytes and masks are unchanged: only
/// section digests lose the bytes.
pub(super) fn release_untransferred_memory(
    profile: &ResolvedProfile,
    product: &ProductData,
    image: &mut SparseDeviceImage,
) {
    if product.load_procedure_style() != LoadProcedureStyle::Default {
        return;
    }
    // Without one selectable source procedure there is no bound to apply;
    // compiling the download itself reports that failure.
    let Ok((_, source)) = select_master_procedure(profile, "Load", "all") else { return };
    let mut covered: Vec<(ImageSpace, u32, u32)> = Vec::new();
    for control in &source.controls {
        match control {
            LoadControl::LdCtrlWriteMem(write) => {
                let Some(location) = parse_memory_location(write.address_space.as_deref(), write.address) else {
                    return;
                };
                // Inline data replaces the image bytes on the wire.
                if write.inline_data.is_none() {
                    covered.push((location.space, location.offset, location.offset.saturating_add(write.size)));
                }
            }
            // These controls read, compare or sequence; none sends image bytes.
            LoadControl::LdCtrlConnect(_)
            | LoadControl::LdCtrlDisconnect(_)
            | LoadControl::LdCtrlRestart(_)
            | LoadControl::LdCtrlMasterReset(_)
            | LoadControl::LdCtrlDelay(_)
            | LoadControl::LdCtrlSetControlVariable(_)
            | LoadControl::LdCtrlMapError(_)
            | LoadControl::LdCtrlProgressText(_)
            | LoadControl::LdCtrlLoadImageMem(_)
            | LoadControl::LdCtrlCompareMem(_)
            | LoadControl::LdCtrlMaxLength(_)
            | LoadControl::LdCtrlClearCachedObjectTypes(_) => {}
            _ => return,
        }
    }
    // A source that sends no image bytes at all describes no image layout;
    // releasing everything would only hide that the product was not loaded.
    if covered.is_empty() {
        return;
    }
    for space in [
        ImageSpace::StandardMemory,
        ImageSpace::UserMemory,
        ImageSpace::LineCouplerSlave,
        ImageSpace::LineCouplerFilter,
    ] {
        image.release_sections(&space, |offset| {
            !covered
                .iter()
                .any(|(covered_space, start, end)| *covered_space == space && (*start..*end).contains(&offset))
        });
    }
}

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
    // Keep the buffer geometry of selected property producers. Removing
    // ownership cannot turn a declared parameter gap into a missing source,
    // or make a masked partial download claim another section's bytes.
    for range in image.ranges() {
        let ImageSpace::Property { object, property_id } = &range.location.space else { continue };
        let count = ImageSpace::PropertyCount { object: object.clone(), property_id: *property_id };
        // An empty raw payload owns only its separate count word. That
        // selected producer still needs its unowned data allocation intact.
        if scoped.spaces().any(|space| *space == range.location.space || *space == count) {
            scoped.represent_range(&range.location, range.length)?;
        }
    }
    *image = scoped;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commissioning::image::ImageLocation;

    #[test]
    fn selected_empty_raw_count_preserves_only_its_matching_data_allocation() {
        use crate::commissioning::catalog::profile::ObjectSelector;

        let object = ObjectSelector::Index { index: 9 };
        let data = ImageLocation { space: ImageSpace::Property { object: object.clone(), property_id: 71 }, offset: 0 };
        let count =
            ImageLocation { space: ImageSpace::PropertyCount { object: object.clone(), property_id: 71 }, offset: 0 };
        let unrelated = ImageLocation { space: ImageSpace::Property { object, property_id: 72 }, offset: 0 };
        let mut original = SparseDeviceImage::new();
        original.represent_range(&data, 6).expect("raw property allocation");
        original.represent_range(&unrelated, 6).expect("unrelated property allocation");
        original.apply_section(
            ProgrammingSection::Parameters,
            &ImageSegment::owned(count.clone(), vec![0, 0]).expect("empty raw count"),
        );

        let mut selected = original.clone();
        retain_download_sections(&mut selected, ProgramSections::PARAMETERS).expect("selected parameter scope");
        assert_eq!(selected.range(&data, 6).expect("empty raw allocation survives").mask(), [0; 6]);
        assert!(selected.sections_for_range(&data, 6).is_empty(), "allocation does not own desired data");
        assert_eq!(selected.range(&count, 2).expect("selected count survives").data(), [0, 0]);
        assert!(selected.range(&unrelated, 1).is_err(), "count does not retain a different property's allocation");

        retain_download_sections(&mut original, ProgramSections::CONFIGURATION).expect("unselected parameter scope");
        assert!(original.range(&data, 1).is_err(), "unselected count does not retain raw data geometry");
        assert!(original.range(&count, 2).is_err(), "unselected count ownership is removed");
    }

    #[test]
    fn selected_property_buffers_keep_unowned_geometry_without_other_section_bits() {
        use crate::commissioning::catalog::profile::ObjectSelector;
        use crate::commissioning::image::ImageSpace;
        let space = ImageSpace::Property { object: ObjectSelector::Index { index: 7 }, property_id: 52 };
        let start = ImageLocation { space: space.clone(), offset: 0 };
        let mut image = SparseDeviceImage::new();
        image.apply_section(
            ProgrammingSection::ApplicationProgram1,
            &ImageSegment::owned(start.clone(), vec![0xaa]).expect("application byte"),
        );
        image.apply_section(
            ProgrammingSection::Parameters,
            &ImageSegment::owned(ImageLocation { space, offset: 3 }, vec![5]).expect("parameter byte"),
        );
        image.represent_range(&start, 6).expect("property buffer");
        retain_download_sections(&mut image, ProgramSections::PARAMETERS).expect("selected parameter scope");
        let bytes = image.range(&start, 6).expect("selected property geometry");
        assert_eq!(bytes.data(), [0, 0, 0, 5, 0, 0]);
        assert_eq!(bytes.mask(), [0, 0, 0, 255, 0, 0]);
        assert_eq!(image.sections_for_range(&start, 6), [ProgrammingSection::Parameters].into());
    }

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
