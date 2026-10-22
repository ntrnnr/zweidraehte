//! Section ownership and digests are views of the canonical image.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};
use zweidraehte_project::{ProgrammingManifest, ProgrammingSection};

use super::fingerprint::hash_image_space;
use super::{ImageLocation, ImageSpace, SparseDeviceImage};
use crate::commissioning::catalog::profile::ObjectSelector;
use zweidraehte_proto::{dpt::InterfaceObjectType, pid};

/// Final ownership of bits in one contiguous image range.
///
/// Exhaustive by design: a range and its bit mask fully describe ownership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageOwnership {
    pub section: ProgrammingSection,
    pub location: ImageLocation,
    pub mask: Vec<u8>,
}

impl SparseDeviceImage {
    pub fn ownership(&self) -> Vec<ImageOwnership> {
        let mut result: Vec<ImageOwnership> = Vec::new();
        for (space, bytes) in &self.bytes {
            for (owner, section) in ALL_SECTIONS.into_iter().enumerate() {
                for (&offset, byte) in bytes {
                    let mask = byte.owners[owner];
                    if mask == 0 {
                        continue;
                    }
                    if let Some(run) = result.last_mut()
                        && run.section == section
                        && run.location.space == *space
                        && run.location.offset + run.mask.len() as u32 == offset
                    {
                        run.mask.push(mask);
                    } else {
                        result.push(ImageOwnership {
                            section,
                            location: ImageLocation { space: space.clone(), offset },
                            mask: vec![mask],
                        });
                    }
                }
            }
        }
        result
    }

    pub fn sections_for_range(&self, location: &ImageLocation, length: u32) -> BTreeSet<ProgrammingSection> {
        let mut sections = BTreeSet::new();
        if let Some(bytes) = self.bytes.get(&location.space) {
            for (_, byte) in bytes
                .range(location.offset..)
                .take_while(|(offset, _)| u64::from(**offset) < u64::from(location.offset) + u64::from(length))
            {
                for (index, section) in ALL_SECTIONS.into_iter().enumerate() {
                    if byte.owners[index] != 0 {
                        sections.insert(section);
                    }
                }
            }
        }
        sections
    }

    /// Hash each owned byte in address order, independently of patch boundaries.
    pub fn manifest(&self) -> ProgrammingManifest {
        let mut manifest = ProgrammingManifest::default();
        for (owner, section) in ALL_SECTIONS.into_iter().enumerate() {
            let mut hash = Sha256::new();
            hash.update(b"zweidraehte-section-image-v2\0");
            let mut present = false;
            for (space, bytes) in &self.bytes {
                for (&offset, byte) in bytes {
                    let mask = byte.owners[owner];
                    if mask == 0 {
                        continue;
                    }
                    present = true;
                    hash_image_space(&mut hash, space);
                    hash.update(offset.to_be_bytes());
                    // SIAT receive counters advance autonomously. They remain
                    // exact executable bytes, but desired group configuration
                    // commits to row presence and sender addresses only.
                    let replay_counter = section == ProgrammingSection::GroupCommunication
                        && matches!(space, ImageSpace::Property {
                            object: ObjectSelector::Type { object_type, .. }, property_id,
                        } if *object_type == u16::from(InterfaceObjectType::Security)
                            && *property_id == pid::security::SECURITY_INDIVIDUAL_ADDRESS_TABLE)
                        && offset % 8 >= 2;
                    hash.update([mask, if replay_counter { 0 } else { byte.data & mask }]);
                }
            }
            if present {
                manifest.insert(section, hash.finalize().into());
            }
        }
        manifest
    }
}

pub(super) fn section_index(section: ProgrammingSection) -> usize {
    ALL_SECTIONS.iter().position(|candidate| *candidate == section).expect("all programming sections are listed")
}

const ALL_SECTIONS: [ProgrammingSection; 6] = [
    ProgrammingSection::Address,
    ProgrammingSection::ApplicationProgram1,
    ProgrammingSection::ApplicationProgram2,
    ProgrammingSection::Parameters,
    ProgrammingSection::GroupCommunication,
    ProgrammingSection::Configuration,
];

#[cfg(test)]
mod tests;
