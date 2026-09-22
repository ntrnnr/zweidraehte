//! Resolve the selected property's wire geometry directly from authored metadata.

use super::{CompileError, ProgrammingCatalog, ResourceOrder, SelectedResource};
use crate::commissioning::catalog::profile::{ObjectSelector, Occurrence, ResolvedProfile};
use std::collections::BTreeSet;
use zweidraehte_ets_files::schema::master_data::{AddressSpaceLocation, InterfaceObject, Location};

impl ProgrammingCatalog {
    pub(crate) fn selected_property_element_size(
        &self,
        profile: &ResolvedProfile,
        selector: &ObjectSelector,
        property_id: u16,
        read: bool,
    ) -> Result<Option<u32>, CompileError> {
        self.property_width(profile, selector, property_id, read, None)
    }

    pub(crate) fn property_width(
        &self,
        profile: &ResolvedProfile,
        selector: &ObjectSelector,
        property_id: u16,
        read: bool,
        resources: Option<&[(SelectedResource<'_>, Option<u32>)]>,
    ) -> Result<Option<u32>, CompileError> {
        let variant = profile.source();
        let mut objects: Vec<_> = variant
            .interface_objects
            .iter()
            .flat_map(|objects| &objects.objects)
            .filter(|object| match selector {
                ObjectSelector::Index { index } => object.index.map(u16::from) == Some(*index),
                ObjectSelector::Type { object_type, .. } => object.object_type == Some(*object_type),
            })
            .collect();
        match selector {
            ObjectSelector::Index { index } if objects.len() > 1 => {
                return Err(CompileError::invalid(format!(
                    "interface object index {index} is declared more than once"
                )));
            }
            ObjectSelector::Type { occurrence, .. } if objects.len() > 1 => {
                let index = match occurrence {
                    Occurrence::Absent | Occurrence::Zero => 0,
                    Occurrence::Positive { value: index } => usize::from(index.get()),
                };
                objects = objects.get(index).copied().into_iter().collect();
            }
            _ => {}
        }
        let standard = super::rules::ip::standard_property(profile, selector, property_id);
        let Some(object) = objects.first() else { return Ok(standard.and_then(|(_, width)| width)) };
        let explicit: Vec<_> =
            object.properties.iter().filter(|property| property.property_id == property_id).collect();
        match explicit.as_slice() {
            [property] => {
                if let Some((token, width)) = standard
                    && (property.property_data_type != token
                        || self.pdt_width(&property.property_data_type, None, false) != width
                        || self.pdt_width(&property.property_data_type, None, true) != width)
                {
                    return Err(CompileError::invalid(format!(
                        "property {property_id} on {selector:?}: declared PDT {} conflicts with standard IP PDT {token}",
                        property.property_data_type
                    )));
                }
                return Ok(self.pdt_width(&property.property_data_type, None, read));
            }
            [] => {}
            _ => {
                return Err(CompileError::invalid(format!(
                    "interface object {selector:?} declares PID {property_id} more than once"
                )));
            }
        }
        if let Some((_, width)) = standard {
            return Ok(width);
        }

        // Only a selected resource's complete scalar width can disambiguate
        // global PDT alternatives. Parameter bit counts and padded control
        // buffers never supply a property width.
        let resolved_resources;
        let resources = if let Some(resources) = resources {
            resources
        } else {
            resolved_resources = property_resources(profile, selector, property_id)?;
            &resolved_resources
        };
        let mut hints: Vec<_> = resources
            .iter()
            .map(|(resource, _)| {
                (resource.length(), resource.source.resource_type.as_ref().and_then(|kind| kind.flavour.as_deref()))
            })
            .collect();
        if hints.is_empty() {
            hints.push((0, None));
        }
        let mut widths = BTreeSet::new();
        for (length, flavour) in hints {
            let (declared, width) =
                self.global_property_width(object, property_id, (length != 0).then_some(length), read)?;
            let width = if declared {
                width
            } else {
                matches!(flavour, Some("HardwareConfig_Identical" | "HardwareConfig_Version")).then_some(length)
            };
            widths.extend(width);
        }
        if widths.len() > 1 {
            return Err(CompileError::invalid(format!(
                "property {property_id} on {selector:?} has conflicting element sizes {widths:?}"
            )));
        }
        Ok(widths.first().copied())
    }

    fn global_property_width(
        &self,
        object: &InterfaceObject,
        property_id: u16,
        length: Option<u32>,
        read: bool,
    ) -> Result<(bool, Option<u32>), CompileError> {
        let object_type = object.object_type.map(|value| format!("OT-{value}"));
        let mut candidates: Vec<_> = self
            .master_data
            .interface_object_properties()
            .iter()
            .filter(|property| {
                property.number == property_id
                    && (property.object_type.is_none() || property.object_type == object_type)
            })
            .collect();
        if candidates.iter().any(|property| property.object_type == object_type) {
            candidates.retain(|property| property.object_type == object_type);
        }
        match candidates.as_slice() {
            [] => Ok((false, None)),
            [property] => Ok((
                true,
                property.property_data_types.as_deref().and_then(|tokens| self.pdt_width(tokens, length, read)),
            )),
            _ => Err(CompileError::invalid(format!(
                "global interface-object metadata has multiple definitions for object index {:?}, type {:?}, PID {property_id}: {:?}",
                object.index,
                object.object_type,
                candidates.iter().map(|property| &property.id).collect::<Vec<_>>()
            ))),
        }
    }

    fn pdt_width(&self, tokens: &str, length: Option<u32>, read: bool) -> Option<u32> {
        let mut alternatives = tokens
            .split_whitespace()
            .map(|token| {
                Some((
                    self.master_data.property_data_type_size(token)?,
                    self.master_data.property_data_type_read_size(token)?,
                ))
            })
            .collect::<Option<Vec<_>>>()?;
        if alternatives.len() > 1
            && let Some(length) = length
        {
            alternatives.retain(|(width, _)| *width == length);
        }
        let widths: BTreeSet<_> =
            alternatives.into_iter().map(|(width, read_width)| if read { read_width } else { width }).collect();
        (widths.len() == 1).then(|| *widths.first().expect("one property width"))
    }
}

/// Select only declarations that supply this property's online or image geometry.
/// Keep the online byte offset alongside the borrowed declaration for image binding.
pub(crate) fn property_resources<'a>(
    profile: &'a ResolvedProfile,
    selector: &ObjectSelector,
    property_id: u16,
) -> Result<Vec<(SelectedResource<'a>, Option<u32>)>, CompileError> {
    let relevant =
        |location: &Location| location.property_id == Some(property_id) && property_object_matches(location, selector);
    let matching_offset = |location: Option<&Location>| -> Result<Option<u32>, CompileError> {
        let Some(location) = location.filter(|location| relevant(location)) else { return Ok(None) };
        Ok(property_location(location)?.map(|(_, _, offset)| offset))
    };
    let mut resources = Vec::new();
    for resource in profile.selected_resources_matching(ResourceOrder::SelectedDeclaration, |source| {
        source.location.iter().chain(source.image_location.iter()).any(relevant)
    })? {
        let online = matching_offset(resource.source.location.as_ref())?;
        if online.is_none() {
            matching_offset(resource.source.image_location.as_ref())?;
        }
        resources.push((resource, online));
    }
    Ok(resources)
}

/// Filter raw declarations before parsing selected operands. An unrelated
/// malformed property must not invalidate this control's resource binding.
pub(crate) fn property_object_matches(location: &Location, object: &ObjectSelector) -> bool {
    match object {
        ObjectSelector::Index { index } => {
            location.interface_object_ref == Some(*index)
                && matches!(location.address_space.as_str(), "SystemProperty" | "AppProperty")
        }
        ObjectSelector::Type { object_type, occurrence } => {
            location.interface_object_ref == Some(*object_type)
                && location.address_space == "Property"
                && Occurrence::from_option(location.occurrence) == *occurrence
        }
    }
}

pub(crate) fn property_location(location: &Location) -> Result<Option<(ObjectSelector, u16, u32)>, CompileError> {
    if !matches!(location.address_space.as_str(), "SystemProperty" | "AppProperty" | "Property") {
        return Ok(None);
    }
    Ok(Some(match location.to_address_space().map_err(|error| CompileError::invalid(error.to_string()))? {
        AddressSpaceLocation::SystemProperty { interface_object_ref, property_id, start_address, occurrence }
        | AddressSpaceLocation::AppProperty { interface_object_ref, property_id, start_address, occurrence } => {
            (super::resource_view::indexed_object(interface_object_ref, occurrence)?, property_id, start_address)
        }
        AddressSpaceLocation::Property { object_type, property_id, start_address, occurrence } => (
            ObjectSelector::Type { object_type, occurrence: Occurrence::from_option(occurrence) },
            property_id,
            start_address,
        ),
        _ => unreachable!("property address spaces filtered"),
    }))
}
