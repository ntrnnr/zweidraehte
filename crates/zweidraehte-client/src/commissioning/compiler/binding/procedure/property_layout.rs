//! Bind one selected property's target, image range, and directional wire width.

use super::*;
use crate::commissioning::catalog::profile::{ObjectSelector, ReadAccess, ResourceId};
use crate::commissioning::catalog::property_resources;
use crate::commissioning::catalog::rules::product_property_object;
use crate::commissioning::image::ImageSpace;

pub(super) struct BoundProperty {
    pub target: OperationTarget,
    pub image_range: Option<(ImageLocation, u32)>,
    pub wire_length: Option<u32>,
    pub capture_as: Option<ResourceId>,
}

impl ProcedureLowerer<'_> {
    /// Image width describes the desired representation; PDT read width may
    /// differ. A LoadImage control consumes only the image width.
    pub(super) fn property_operand(
        &self,
        object: &ObjectSelector,
        property_id: u16,
        start_element: u16,
        count: u16,
        wire_read: Option<bool>,
        path: &ControlPath,
    ) -> Result<BoundProperty, CompileError> {
        let profile = self.context.profile;
        let target = crate::commissioning::procedure::operands::property_target(object, property_id, start_element)
            .map_err(|error| error.with_path(path))?;
        let resources = property_resources(profile, object, property_id).map_err(|error| error.with_path(path))?;
        let parameter_owned = self.context.property_parameters.iter().any(|parameter| {
            product_property_object(parameter.object) == *object && parameter.property_id == property_id
        });
        let included = |name: &str| name != "PeiprogId" || self.context.peiprog_identity_reference;
        let identity = |name: &str| matches!(name, "ApplicationId" | "PeiprogId");
        let width = |read| {
            profile
                .catalog
                .property_width(profile, object, property_id, read, Some(&resources))
                .map_err(|error| error.with_path(path))
        };
        let write_width = if wire_read == Some(false)
            || parameter_owned
            || resources
                .iter()
                .any(|(resource, offset)| offset.is_some() && included(resource.name()) && !identity(resource.name()))
        {
            width(false)?
        } else {
            None
        };
        let wire_width = match wire_read {
            Some(true) => width(true)?,
            Some(false) => write_width,
            None => None,
        };
        let byte_length = |width: u32| {
            if width == 0 {
                return Err(CompileError::at(
                    path,
                    format!("property {property_id} on {object:?} has zero-byte elements"),
                ));
            }
            u32::from(count).checked_mul(width).ok_or_else(|| CompileError::at(path, "property length exceeds 32 bits"))
        };
        let wire_length = wire_width.map(byte_length).transpose()?;

        let mut layout = if parameter_owned {
            let width = write_width.ok_or_else(|| {
                CompileError::at(
                    path,
                    format!("property {property_id} on {object:?} has no fixed element size in the exact profile"),
                )
            })?;
            Some((
                ImageLocation { space: ImageSpace::Property { object: object.clone(), property_id }, offset: 0 },
                1,
                width,
            ))
        } else {
            None
        };
        for (resource, property_offset) in &resources {
            let Some(property_offset) = property_offset.filter(|_| included(resource.name())) else { continue };
            // Versioned Master Data omits PID13 PDTs; its exact identity
            // resource length is authoritative even when inline XML is padded.
            let element_size = if identity(resource.name()) {
                if resource.length() == 0 {
                    return Err(CompileError::at(
                        path,
                        format!("property {property_id} on {object:?} has no fixed element size in the exact profile"),
                    ));
                }
                resource.length()
            } else if let Some(width) = write_width {
                width
            } else {
                continue;
            };
            if element_size == 0 || property_offset % element_size != 0 {
                return Err(CompileError::at(
                    path,
                    format!(
                        "property {property_id} on {object:?} starts at byte {property_offset}, which is not aligned to {element_size}-byte elements"
                    ),
                ));
            }
            let first_element = (property_offset / element_size).checked_add(1)
                .and_then(|element| u16::try_from(element).ok())
                .ok_or_else(|| CompileError::at(path, format!(
                    "property {property_id} on {object:?} byte offset {property_offset} cannot be represented as a wire element of size {element_size}"
                )))?;
            let location = resource
                .image_location()
                .map_err(|error| error.with_path(path))?
                .expect("property resource has an image location");
            let candidate = (location, first_element, element_size);
            if layout.as_ref().is_some_and(|first| first != &candidate) {
                return Err(CompileError::at(
                    path,
                    format!(
                        "property {property_id} on {object:?} has conflicting image layouts {layout:?} and {candidate:?}"
                    ),
                ));
            }
            layout = Some(candidate);
        }
        // Procedure-owned Coupler stamps have no resource declaration. Their
        // already-bound output descriptor supplies this one image location.
        if layout.is_none() {
            layout = self
                .context
                .download_stamps
                .iter()
                .find(|stamp| {
                    stamp.image_location.space == ImageSpace::Property { object: object.clone(), property_id }
                })
                .map(|stamp| (stamp.image_location.clone(), 1, stamp.read.extent.byte_length));
        }
        let image_range = layout
            .map(|(mut location, first_element, element_size)| -> Result<_, CompileError> {
                let length = byte_length(element_size)?;
                let element_delta = start_element.checked_sub(first_element).ok_or_else(|| {
                    CompileError::at(
                        path,
                        format!(
                            "property read starts at element {start_element}, before image element {first_element}"
                        ),
                    )
                })?;
                location.offset = u32::from(element_delta)
                    .checked_mul(element_size)
                    .and_then(|delta| location.offset.checked_add(delta))
                    .ok_or_else(|| CompileError::at(path, "property image offset exceeds 32-bit address space"))?;
                Ok((location, length))
            })
            .transpose()?;

        let mut captures = BTreeSet::new();
        if wire_read.is_none()
            && start_element == 1
            && count == 1
            && let Some((_, length)) = &image_range
        {
            for (resource, offset) in &resources {
                if *offset == Some(0)
                    && resource.length() == *length
                    && resource.source.resource_type.as_ref().and_then(|kind| kind.flavour.as_deref())
                        == Some("Stamp_SystemB")
                    && resource.access_rights().map_err(|error| error.with_path(path))?.read == ReadAccess::Runtime
                {
                    captures.insert(resource.id.clone());
                }
            }
            if captures.is_empty() {
                captures.extend(
                    self.context
                        .download_stamps
                        .iter()
                        .filter(|stamp| {
                            stamp.image_location
                                == ImageLocation {
                                    space: ImageSpace::Property { object: object.clone(), property_id },
                                    offset: 0,
                                }
                                && stamp.read.extent.byte_length == *length
                        })
                        .map(|stamp| stamp.id.clone()),
                );
            }
        }
        if captures.len() > 1 {
            return Err(CompileError::at(
                path,
                format!("property {property_id} on {object:?} resolves more than one download-stamp resource"),
            ));
        }
        Ok(BoundProperty { target, image_range, wire_length, capture_as: captures.into_iter().next() })
    }
}

#[cfg(test)]
mod tests;
