//! Resolve the selected property's wire geometry directly from authored metadata.

use super::{ProfileError, ResourceOrder, SelectedResource};
use crate::commissioning::catalog::profile::{DeclaredProperty, ObjectSelector, Occurrence, ResolvedProfile};
use crate::commissioning::procedure::{IndexedPropertyDataTypeSeed, PropertyDataTypeLookup};
use std::collections::{BTreeMap, BTreeSet};
use zweidraehte_ets_files::schema::master_data::{AddressSpaceLocation, InterfaceObject, Location};

impl ResolvedProfile {
    /// Capture immutable metadata and initial observations without treating
    /// future procedure declarations as already executed descriptor updates.
    pub(crate) fn property_data_type_lookup(
        &self,
        selector: &ObjectSelector,
        property_id: u16,
    ) -> Result<PropertyDataTypeLookup, ProfileError> {
        let mut lookup = PropertyDataTypeLookup::default();
        for data_type in self.master_data.property_data_types() {
            let Some(pdt) = data_type.number.and_then(|number| u8::try_from(number).ok()) else { continue };
            // Source declarations use Name; global references use Id. Both
            // spellings identify the same wire type, never a cached fact.
            for token in [&data_type.id, &data_type.name].into_iter().filter(|token| !token.is_empty()) {
                if let Some(previous) = lookup.declaration_types.insert(token.clone(), pdt)
                    && previous != pdt
                {
                    return Err(ProfileError::invalid(format!(
                        "property data type token {token} has multiple numbers"
                    )));
                }
            }
        }
        let exact_pdt = |tokens: &str| {
            let mut tokens = tokens.split_whitespace();
            let token = tokens.next()?;
            if tokens.next().is_some() {
                return None;
            }
            lookup.declaration_types.get(token).copied()
        };

        // Retain every indexed object: classic typed discovery first resolves
        // an index and then applies that index's distinct mask/cache policy.
        for object in self.interface_objects() {
            let properties: Vec<_> = object.properties.iter().filter(|p| p.property_id == property_id).collect();
            let property_data_type = match properties.as_slice() {
                [] => None,
                [property] => exact_pdt(&property.property_data_type),
                _ => {
                    return Err(ProfileError::invalid(format!(
                        "interface object {:?} declares PID {property_id} more than once",
                        object.index
                    )));
                }
            };
            if let Some(index) = object.index
                && lookup
                    .indexed
                    .insert(index, IndexedPropertyDataTypeSeed {
                        // Native XML ObjectType is a non-nullable ushort;
                        // identification caches zero when it is omitted.
                        object_type: Some(object.object_type.unwrap_or(0)),
                        property_data_type,
                        descriptor: None,
                    })
                    .is_some()
            {
                return Err(ProfileError::invalid(format!(
                    "interface object index {index} is declared more than once"
                )));
            }
        }

        // Global metadata is a separate namespace. An ambiguous scoped entry
        // must remain present so execution cannot fall back to an unscoped PDT.
        for property in self.master_data.interface_object_properties().iter().filter(|p| p.number == property_id) {
            let object_type = property
                .object_type
                .as_deref()
                .map(|token| {
                    token.strip_prefix("OT-").unwrap_or(token).parse::<u16>().map_err(|_| {
                        ProfileError::invalid(format!("invalid interface object type {token} for PID {property_id}"))
                    })
                })
                .transpose()?;
            // The reference's well-known entry carries only declared PDTs. A
            // datapoint type does not type the property; such an entry stays
            // present but untyped, so execution reads the target's description.
            let tokens = property.property_data_types.as_deref();
            if lookup.well_known.insert(object_type, tokens.and_then(exact_pdt)).is_some() {
                return Err(ProfileError::invalid(format!(
                    "global interface-object metadata has multiple definitions for {object_type:?}, PID {property_id}"
                )));
            }
        }

        let selected_type = match selector {
            ObjectSelector::Type { object_type, .. } => Some(*object_type),
            ObjectSelector::Index { .. } => None,
        };
        let mut typed_descriptors = BTreeMap::new();
        for ((object, pid), pdt) in &self.observed_property_types {
            if *pid != property_id {
                continue;
            }
            match object {
                ObjectSelector::Index { index } => {
                    let index = u8::try_from(*index).map_err(|_| {
                        ProfileError::invalid(format!("observed interface object index {index} exceeds the wire range"))
                    })?;
                    lookup.indexed.entry(index).or_default().descriptor = Some(*pdt);
                }
                ObjectSelector::Type { object_type, .. } => {
                    if let Some(previous) = typed_descriptors.insert(*object_type, *pdt)
                        && previous != *pdt
                    {
                        return Err(ProfileError::invalid(format!(
                            "property {property_id} on object type {object_type} has contradictory observed PDTs"
                        )));
                    }
                }
            }
        }
        lookup.initial_descriptor = selected_type.and_then(|object_type| typed_descriptors.get(&object_type).copied());
        Ok(lookup)
    }

    /// Image allocation uses only the mask roster or a procedure declaration.
    /// Global metadata and live descriptions can type a wire transfer without
    /// causing the native image builder to allocate a buffer for it.
    pub(crate) fn procedure_property_buffer_width(
        &self,
        selector: &ObjectSelector,
        property_id: u16,
    ) -> Result<Option<u32>, ProfileError> {
        if self.roster_types_property(selector, property_id)? {
            return self.metadata_property_width(selector, property_id, false, None);
        }
        Ok(self
            .declared_property_types
            .get(&DeclaredProperty::new(selector, property_id))
            .and_then(|property_type| self.pdt_width(property_type, None, false)))
    }

    pub(crate) fn selected_property_element_size(
        &self,
        selector: &ObjectSelector,
        property_id: u16,
        read: bool,
    ) -> Result<Option<u32>, ProfileError> {
        self.property_width(selector, property_id, read, None)
    }

    pub(crate) fn property_width(
        &self,
        selector: &ObjectSelector,
        property_id: u16,
        read: bool,
        resources: Option<&[(SelectedResource<'_>, Option<u32>)]>,
    ) -> Result<Option<u32>, ProfileError> {
        let declared = self
            .declared_property_types
            .get(&DeclaredProperty::new(selector, property_id))
            .map(|property_type| (property_type, self.pdt_width(property_type, None, read)));
        if let Some(width) = self.metadata_property_width(selector, property_id, read, resources)? {
            // Typed access resolves an exact well-known PDT before consulting
            // the descriptor cache updated by declarations. Indexed access has
            // a different priority. A width inferred from ambiguous global PDTs
            // is not evidence of that typed fast path.
            if let Some((property_type, declared_width)) = declared
                && declared_width != Some(width)
                && !self.roster_types_property(selector, property_id)?
            {
                if let ObjectSelector::Type { object_type, .. } = selector {
                    let lookup = self.property_data_type_lookup(selector, property_id)?;
                    if lookup
                        .well_known
                        .get(&Some(*object_type))
                        .or_else(|| lookup.well_known.get(&None))
                        .is_some_and(Option::is_some)
                    {
                        return Ok(Some(width));
                    }
                }
                return Err(ProfileError::invalid(format!(
                    "property {property_id} on {selector:?} is typed by Master Data with {width}-byte elements, \
                     but the load procedure declares {property_type}"
                )));
            }
            return Ok(Some(width));
        }

        // The selected load procedure can declare a property before writing
        // it. The declaration then defines the property on the target, so it
        // supersedes any description observed before the download.
        if let Some((_, width)) = declared {
            return Ok(width);
        }

        // Master Data leaves some application properties untyped. The target's
        // own property description then supplies the PDT, observed during
        // preparation or recorded with an offline self selection.
        let key = (crate::commissioning::catalog::profile::schema_selector(selector.clone()), property_id);
        let observed = self.observed_property_types.get(&key);
        Ok(observed.and_then(|pdt| {
            let token = self.master_data.property_data_type_token(u16::from(*pdt))?;
            self.pdt_width(token, None, read)
        }))
    }

    /// Width declared by Master Data alone, without target observations.
    pub(crate) fn metadata_property_width(
        &self,
        selector: &ObjectSelector,
        property_id: u16,
        read: bool,
        resources: Option<&[(SelectedResource<'_>, Option<u32>)]>,
    ) -> Result<Option<u32>, ProfileError> {
        let objects = roster_objects(self, selector)?;
        let standard = super::rules::ip::standard_property(self, selector, property_id);
        if let Some(object) = objects.first() {
            let explicit: Vec<_> =
                object.properties.iter().filter(|property| property.property_id == property_id).collect();
            match explicit.as_slice() {
                [property] => {
                    if let Some((token, width)) = standard
                        && (property.property_data_type != token
                            || self.pdt_width(&property.property_data_type, None, false) != width
                            || self.pdt_width(&property.property_data_type, None, true) != width)
                    {
                        return Err(ProfileError::invalid(format!(
                            "property {property_id} on {selector:?}: declared PDT {} conflicts with standard IP PDT {token}",
                            property.property_data_type
                        )));
                    }
                    return Ok(self.pdt_width(&property.property_data_type, None, read));
                }
                [] => {}
                _ => {
                    return Err(ProfileError::invalid(format!(
                        "interface object {selector:?} declares PID {property_id} more than once"
                    )));
                }
            }
        } else if matches!(selector, ObjectSelector::Index { .. }) {
            if let Some((_, width)) = standard {
                return Ok(width);
            }

            // A product can address a dynamic application-object index absent
            // from the mask roster. Unscoped global metadata still describes
            // that property's width; object-specific declarations cannot.
            return self.global_property_width(selector, None, property_id, None, read).map(|(_, width)| width);
        }
        if let Some((_, width)) = standard {
            return Ok(width);
        }
        // Application object types can have global property metadata without
        // appearing in the mask's fixed interface-object roster.
        let object_type = objects.first().and_then(|object| object.object_type).or_else(|| match selector {
            ObjectSelector::Type { object_type, .. } => Some(*object_type),
            ObjectSelector::Index { .. } => None,
        });

        // Only a selected resource's complete scalar width can disambiguate
        // global PDT alternatives. Parameter bit counts and padded control
        // buffers never supply a property width.
        let resolved_resources;
        let resources = if let Some(resources) = resources {
            resources
        } else {
            resolved_resources = property_resources(self, selector, property_id)?;
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
                self.global_property_width(selector, object_type, property_id, (length != 0).then_some(length), read)?;
            let width = if declared {
                width
            } else {
                matches!(flavour, Some("HardwareConfig_Identical" | "HardwareConfig_Version")).then_some(length)
            };
            widths.extend(width);
        }
        if widths.len() > 1 {
            return Err(ProfileError::invalid(format!(
                "property {property_id} on {selector:?} has conflicting element sizes {widths:?}"
            )));
        }
        Ok(widths.first().copied())
    }

    /// Whether the mask's interface-object roster itself declares the PID.
    fn roster_types_property(&self, selector: &ObjectSelector, property_id: u16) -> Result<bool, ProfileError> {
        Ok(roster_objects(self, selector)?
            .first()
            .is_some_and(|object| object.properties.iter().any(|property| property.property_id == property_id)))
    }

    fn global_property_width(
        &self,
        selector: &ObjectSelector,
        object_type: Option<u16>,
        property_id: u16,
        length: Option<u32>,
        read: bool,
    ) -> Result<(bool, Option<u32>), ProfileError> {
        let object_type = object_type.map(|value| format!("OT-{value}"));
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
            // Only declared PDTs size a property. A DPT-only definition (such
            // as PID_BEHAVIOUR_BUS_POWER_UP on OT-417) leaves the element width
            // to the target's property description, as the reference does.
            [property] => Ok((
                true,
                property.property_data_types.as_deref().and_then(|tokens| self.pdt_width(tokens, length, read)),
            )),
            _ => Err(ProfileError::invalid(format!(
                "global interface-object metadata has multiple definitions for {selector:?}, PID {property_id}: {:?}",
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

/// The selected object in the mask's interface-object roster, if any.
fn roster_objects<'a>(
    profile: &'a ResolvedProfile,
    selector: &ObjectSelector,
) -> Result<Vec<&'a InterfaceObject>, ProfileError> {
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
            return Err(ProfileError::invalid(format!("interface object index {index} is declared more than once")));
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
    Ok(objects)
}

/// Select only declarations that supply this property's online or image geometry.
/// Keep the online byte offset alongside the borrowed declaration for image binding.
pub(crate) fn property_resources<'a>(
    profile: &'a ResolvedProfile,
    selector: &ObjectSelector,
    property_id: u16,
) -> Result<Vec<(SelectedResource<'a>, Option<u32>)>, ProfileError> {
    let relevant =
        |location: &Location| location.property_id == Some(property_id) && property_object_matches(location, selector);
    let matching_offset = |location: Option<&Location>| -> Result<Option<u32>, ProfileError> {
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
                && location.occurrence.unwrap_or(0) == occurrence.instance()
        }
    }
}

pub(crate) fn property_location(location: &Location) -> Result<Option<(ObjectSelector, u16, u32)>, ProfileError> {
    if !matches!(location.address_space.as_str(), "SystemProperty" | "AppProperty" | "Property") {
        return Ok(None);
    }
    Ok(Some(match location.to_address_space().map_err(|error| ProfileError::invalid(error.to_string()))? {
        AddressSpaceLocation::SystemProperty { interface_object_ref, property_id, start_address, occurrence }
        | AddressSpaceLocation::AppProperty { interface_object_ref, property_id, start_address, occurrence } => {
            (super::resource_view::indexed_object(interface_object_ref, occurrence)?, property_id, start_address)
        }
        AddressSpaceLocation::Property { object_type, property_id, start_address, occurrence } => (
            ObjectSelector::Type { object_type, occurrence: Occurrence::from_schema(occurrence) },
            property_id,
            start_address,
        ),
        _ => unreachable!("property address spaces filtered"),
    }))
}
