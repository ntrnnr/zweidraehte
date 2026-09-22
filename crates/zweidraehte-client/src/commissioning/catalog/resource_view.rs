//! Select one authored resource, then bind only the operand the caller uses.

use super::{CompileError, ProgrammingCatalog};
use crate::commissioning::catalog::profile::{
    AssociationTableEntrySize, ObjectSelector, Occurrence, ReadAccess, ResolvedProfile, ResourceAccessRights,
    ResourceFlavour, ResourceId, ResourceManagementStyle, WriteAccess,
};
use crate::commissioning::image::{ImageLocation, ImageSpace};
use crate::commissioning::procedure::OperationExtent;
use crate::commissioning::procedure::operands::{
    MemoryAddress, MemoryService, OperationTarget, PointerEncoding, ServiceRead, StandardMemoryService,
    pure_property_address,
};
use std::collections::BTreeSet;
use zweidraehte_ets_files::schema::master_data::{
    AccessRights, AddressSpaceLocation, Location, Resource, ResourceAccess, ResourceAccessSet,
    ResourceManagementStyle as XmlManagementStyle,
};

/// A borrowed declaration selected by exact mask, variant and management style.
/// Reading and imaging are separate: an image does not prove an online service
/// exists, and an unused online declaration cannot invalidate an image operand.
#[derive(Debug, Clone)]
pub struct SelectedResource<'a> {
    pub id: ResourceId,
    pub source: &'a Resource,
    pub(crate) profile: &'a ResolvedProfile,
    source_index: usize,
}

/// Stamp output historically follows the first demanded declaration of each
/// name; geometry consumers follow the selected declaration's position.
pub(crate) enum ResourceOrder {
    SelectedDeclaration,
    FirstDemandedName,
}

impl ResolvedProfile {
    /// Demand names without parsing geometry, select from all their alternatives,
    /// then retain only winners which satisfy the demand. This keeps unused
    /// malformed geometry irrelevant without hiding ambiguous requested names.
    pub(crate) fn selected_resources_matching(
        &self,
        order: ResourceOrder,
        relevant: impl Fn(&Resource) -> bool,
    ) -> Result<Vec<SelectedResource<'_>>, CompileError> {
        let mut seen = BTreeSet::new();
        let mut selected = Vec::new();
        for source in self.source().resources.iter().flat_map(|resources| &resources.resources) {
            if relevant(source)
                && seen.insert(source.name.as_str())
                && let Some(resource) = self.resource(&source.name)?
                && relevant(resource.source)
            {
                selected.push(resource);
            }
        }
        if matches!(order, ResourceOrder::SelectedDeclaration) {
            selected.sort_by_key(|resource| resource.source_index);
        }
        Ok(selected)
    }
}

impl ProgrammingCatalog {
    pub(crate) fn selected_resource<'a>(
        &'a self,
        profile: &'a ResolvedProfile,
        name: &str,
    ) -> Result<Option<SelectedResource<'a>>, CompileError> {
        let variant = profile.source();
        let mut candidates = Vec::new();
        for (index, resource) in variant.resources.iter().flat_map(|resources| &resources.resources).enumerate() {
            if resource.name != name {
                continue;
            }
            // Unknown access must not hide a requested operand as if it were local.
            validate_access(resource.access.as_ref())?;
            if resource.supports_access("remote") {
                candidates.push((index, resource));
            }
        }
        let style = profile.management_style.map(management_style_name);
        let matches_style = |resource: &Resource| style.is_some_and(|style| resource.declares_management_style(style));
        let qualified = candidates.iter().any(|(_, resource)| matches_style(resource));
        let mut selected = candidates.iter().filter(|(_, resource)| {
            candidates.len() == 1
                || if qualified { matches_style(resource) } else { resource.management_style.is_none() }
        });
        let (source_index, source) = match (selected.next(), selected.next()) {
            (None, _) if candidates.is_empty() => return Ok(None),
            (Some((index, source)), None) => (*index, *source),
            _ => {
                return Err(CompileError::invalid(format!(
                    "resource {name:?} has ambiguous realizations after access/style selection: {:?}",
                    candidates
                        .iter()
                        .map(|(index, resource)| format!("r{index}:{}", resource.name))
                        .collect::<Vec<_>>()
                )));
            }
        };
        resolve_resource_style(source, profile.management_style)?;
        Ok(Some(SelectedResource { id: ResourceId(source.name.clone()), source, profile, source_index }))
    }
}

impl SelectedResource<'_> {
    pub fn property_location(&self) -> Result<Option<(ObjectSelector, u16, u32)>, CompileError> {
        self.source.location.as_ref().map(super::property_location).transpose().map(Option::flatten)
    }

    pub fn object_selector(&self) -> Result<Option<ObjectSelector>, CompileError> {
        if let Some((object, _, _)) = self.property_location()? {
            return Ok(Some(object));
        }
        let Some(location) = &self.source.location else { return Ok(None) };
        if !matches!(location.address_space.as_str(), "RelativeMemory" | "RelativeMemoryByObjectType") {
            return Ok(None);
        }
        Ok(match location.to_address_space().map_err(|error| self.invalid(error.to_string()))? {
            AddressSpaceLocation::RelativeMemory { interface_object_ref, occurrence, .. } => {
                Some(indexed_object(interface_object_ref, occurrence)?)
            }
            AddressSpaceLocation::RelativeMemoryByObjectType { object_type, occurrence, .. } => {
                Some(typed_object(object_type, occurrence))
            }
            _ => None,
        })
    }

    pub fn name(&self) -> &str {
        &self.source.name
    }
    pub fn length(&self) -> u32 {
        self.source.resource_type.as_ref().map_or(0, |kind| kind.length)
    }
    pub fn optional(&self) -> bool {
        self.source.optional.unwrap_or(false)
    }
    pub fn access_rights(&self) -> Result<ResourceAccessRights, CompileError> {
        resolve_access_rights(self.source.access_rights.as_ref())
    }
    pub fn flavour(&self) -> Result<Option<ResourceFlavour>, CompileError> {
        let flavour = self
            .source
            .resource_type
            .as_ref()
            .and_then(|kind| kind.flavour.as_deref())
            .map(|flavour| {
                flavour.parse().map_err(|_| {
                    CompileError::unsupported(format!("resource {:?} has unknown flavour {flavour:?}", self.name()))
                })
            })
            .transpose()?;
        Ok(match (flavour, self.profile.association_entry_size) {
            (Some(ResourceFlavour::AssociationTableSystemB), Some(AssociationTableEntrySize::TwoBytes)) => {
                Some(ResourceFlavour::AssociationTableSystemBSmall)
            }
            (Some(ResourceFlavour::AssociationTableSystemB), Some(AssociationTableEntrySize::FourBytes)) => {
                Some(ResourceFlavour::AssociationTableSystemBBig)
            }
            _ => flavour,
        })
    }

    pub fn image_location(&self) -> Result<Option<ImageLocation>, CompileError> {
        self.source
            .image_location
            .as_ref()
            .or(self.source.location.as_ref())
            .map(|location| self.bind_image(location))
            .transpose()
    }

    fn bind_image(&self, location: &Location) -> Result<ImageLocation, CompileError> {
        let location = location.to_address_space().map_err(|error| self.invalid(error.to_string()))?;
        Ok(match location {
            AddressSpaceLocation::StandardMemory { start_address } => ImageLocation::standard_memory(start_address),
            AddressSpaceLocation::UserMemory { start_address } => {
                ImageLocation { space: ImageSpace::UserMemory, offset: start_address }
            }
            AddressSpaceLocation::SystemProperty { interface_object_ref, property_id, start_address, occurrence }
            | AddressSpaceLocation::AppProperty { interface_object_ref, property_id, start_address, occurrence } => {
                let object = indexed_object(interface_object_ref, occurrence)?;
                ImageLocation { space: ImageSpace::Property { object, property_id }, offset: start_address }
            }
            AddressSpaceLocation::Property { object_type, property_id, start_address, occurrence } => ImageLocation {
                space: ImageSpace::Property { object: typed_object(object_type, occurrence), property_id },
                offset: start_address,
            },
            AddressSpaceLocation::RelativeMemory { interface_object_ref, start_address, occurrence, .. } => {
                ImageLocation {
                    space: ImageSpace::RelativeMemory { object: indexed_object(interface_object_ref, occurrence)? },
                    offset: start_address,
                }
            }
            AddressSpaceLocation::RelativeMemoryByObjectType { object_type, start_address, occurrence, .. } => {
                ImageLocation {
                    space: ImageSpace::RelativeMemory { object: typed_object(object_type, occurrence) },
                    offset: start_address,
                }
            }
            AddressSpaceLocation::Pointer { ptr_resource } => {
                ImageLocation { space: ImageSpace::Pointer { resource_id: self.pointer(&ptr_resource)?.id }, offset: 0 }
            }
            AddressSpaceLocation::LcFilterMemory { start_address }
            | AddressSpaceLocation::LcFilter { start_address } => {
                ImageLocation { space: ImageSpace::LineCouplerFilter, offset: start_address }
            }
            AddressSpaceLocation::LcSlaveMemory { start_address } | AddressSpaceLocation::LcSlave { start_address } => {
                ImageLocation { space: ImageSpace::LineCouplerSlave, offset: start_address }
            }
            _ => return Err(self.invalid("resource location has no image address")),
        })
    }

    pub fn read(&self, service: StandardMemoryService) -> Result<ServiceRead, CompileError> {
        let location = self
            .source
            .location
            .as_ref()
            .ok_or_else(|| self.invalid("resource has no online location"))?
            .to_address_space()
            .map_err(|error| self.invalid(error.to_string()))?;
        let mut extent = OperationExtent::bytes(self.length());
        let memory = |service, address| OperationTarget::Memory { service, address: MemoryAddress::Fixed(address) };
        let target = match location {
            AddressSpaceLocation::StandardMemory { start_address } => {
                memory(service.for_range(start_address, self.length()), start_address)
            }
            AddressSpaceLocation::UserMemory { start_address } => memory(MemoryService::User, start_address),
            AddressSpaceLocation::LcFilterMemory { start_address }
            | AddressSpaceLocation::LcFilter { start_address } => memory(MemoryService::Filter, start_address),
            AddressSpaceLocation::LcSlaveMemory { start_address } | AddressSpaceLocation::LcSlave { start_address } => {
                memory(MemoryService::Router, start_address)
            }
            AddressSpaceLocation::SystemProperty { interface_object_ref, property_id, start_address, occurrence }
            | AddressSpaceLocation::AppProperty { interface_object_ref, property_id, start_address, occurrence } => {
                extent.property_elements = Some(1);
                self.property_target(&indexed_object(interface_object_ref, occurrence)?, property_id, start_address)?
            }
            AddressSpaceLocation::Property { object_type, property_id, start_address, occurrence } => {
                extent.property_elements = Some(1);
                self.property_target(&typed_object(object_type, occurrence), property_id, start_address)?
            }
            AddressSpaceLocation::RelativeMemory { interface_object_ref, property_id, start_address, occurrence } => {
                self.relative_target(
                    indexed_object(interface_object_ref, occurrence)?,
                    property_id,
                    start_address,
                    service,
                )?
            }
            AddressSpaceLocation::RelativeMemoryByObjectType {
                object_type,
                property_id,
                start_address,
                occurrence,
            } => self.relative_target(typed_object(object_type, occurrence), property_id, start_address, service)?,
            AddressSpaceLocation::Pointer { ptr_resource } => {
                let pointer = self.pointer(&ptr_resource)?;
                let encoding = match (pointer.flavour()?, pointer.length()) {
                    (Some(ResourceFlavour::PtrStandardMemory100), 1) => PointerEncoding::PageOne,
                    (Some(ResourceFlavour::PtrStandardMemory), 1..=4) => PointerEncoding::Absolute,
                    _ => return Err(self.invalid("pointer resource has no supported encoding")),
                };
                if pointer.source.location.as_ref().is_some_and(|location| location.address_space == "Pointer") {
                    return Err(self.invalid("nested pointer resources are unsupported"));
                }
                OperationTarget::Memory {
                    service: service.for_pointer(pointer.length(), 0, self.length()),
                    address: MemoryAddress::Pointer {
                        space: ImageSpace::Pointer { resource_id: pointer.id.clone() },
                        read: Box::new(pointer.read(service)?),
                        offset: 0,
                        encoding,
                    },
                }
            }
            AddressSpaceLocation::Constant { value } => {
                let bytes = value.to_be_bytes();
                let mut value = vec![0; self.length() as usize];
                let width = value.len().min(bytes.len());
                let start = value.len() - width;
                value[start..].copy_from_slice(&bytes[bytes.len() - width..]);
                OperationTarget::Constant(value)
            }
            AddressSpaceLocation::Adc { channel } => OperationTarget::Adc {
                channel: u8::try_from(channel)
                    .ok()
                    .filter(|channel| *channel <= 0x3F)
                    .ok_or_else(|| self.invalid("ADC channel exceeds six bits"))?,
            },
            AddressSpaceLocation::None => return Err(self.invalid("resource has no online location")),
        };
        let read = ServiceRead { target, extent };
        read.minimum_apdu().map_err(|error| self.invalid(error.to_string()))?;
        Ok(read)
    }

    fn pointer(&self, name: &str) -> Result<SelectedResource<'_>, CompileError> {
        self.profile
            .resource(name)?
            .ok_or_else(|| self.invalid(format!("pointer refers to unavailable resource {name:?}")))
    }

    fn property_target(
        &self,
        object: &ObjectSelector,
        property_id: u16,
        offset: u32,
    ) -> Result<OperationTarget, CompileError> {
        let start_element = if offset == 0 {
            1
        } else {
            let width = self
                .profile
                .property_element_size(object, property_id, false)?
                .filter(|width| *width != 0 && offset % width == 0)
                .ok_or_else(|| self.invalid("property offset has no aligned element width"))?;
            u16::try_from(offset / width + 1).map_err(|_| self.invalid("property element exceeds 16 bits"))?
        };
        let address = pure_property_address(object, property_id).map_err(|error| self.invalid(error.to_string()))?;
        Ok(OperationTarget::Property { address, start_element })
    }

    fn relative_target(
        &self,
        object: ObjectSelector,
        property_id: u16,
        offset: u32,
        service: StandardMemoryService,
    ) -> Result<OperationTarget, CompileError> {
        let width = self
            .profile
            .property_element_size(&object, property_id, false)?
            .filter(|width| (1..=4).contains(width))
            .ok_or_else(|| self.invalid("pointer property requires one through four bytes"))?;
        Ok(OperationTarget::Memory {
            service: service.for_pointer(width, offset, self.length()),
            address: MemoryAddress::Pointer {
                read: Box::new(ServiceRead {
                    target: self.property_target(&object, property_id, 0)?,
                    extent: OperationExtent::property(width, 1),
                }),
                space: ImageSpace::RelativeMemory { object },
                offset,
                encoding: PointerEncoding::Absolute,
            },
        })
    }

    fn invalid(&self, reason: impl Into<String>) -> CompileError {
        CompileError::invalid(format!("resource {}: {}", self.name(), reason.into()))
    }
}

pub(crate) fn indexed_object(index: u16, occurrence: Option<u16>) -> Result<ObjectSelector, CompileError> {
    if let Some(occurrence) = occurrence {
        return Err(CompileError::invalid(format!("indexed property unexpectedly declares occurrence {occurrence}")));
    }
    Ok(ObjectSelector::Index { index })
}

pub(crate) fn typed_object(object_type: u16, occurrence: Option<u16>) -> ObjectSelector {
    ObjectSelector::Type { object_type, occurrence: Occurrence::from_option(occurrence) }
}

impl ResolvedProfile {
    /// Explicit pointer resources retain their nominal width even when the
    /// interface-object metadata is sparse. Resolve only the used object.
    pub(crate) fn relative_memory_target(
        &self,
        object: &ObjectSelector,
        offset: u32,
        length: u32,
        service: StandardMemoryService,
    ) -> Result<OperationTarget, CompileError> {
        let relevant = |location: &Location| match object {
            ObjectSelector::Index { index } => {
                location.interface_object_ref == Some(*index)
                    && matches!(location.address_space.as_str(), "RelativeMemory" | "SystemProperty" | "AppProperty")
            }
            ObjectSelector::Type { object_type, occurrence } => {
                location.interface_object_ref == Some(*object_type)
                    && Occurrence::from_option(location.occurrence) == *occurrence
                    && matches!(location.address_space.as_str(), "RelativeMemoryByObjectType" | "Property")
            }
        };
        let resources = self.selected_resources_matching(ResourceOrder::SelectedDeclaration, |resource| {
            resource.location.iter().chain(resource.image_location.iter()).any(|location| {
                relevant(location)
                    && matches!(location.address_space.as_str(), "RelativeMemory" | "RelativeMemoryByObjectType")
            }) || (resource.resource_type.as_ref().and_then(|kind| kind.flavour.as_deref())
                == Some("Ptr_StandardMemory")
                && resource
                    .location
                    .as_ref()
                    .is_some_and(|location| relevant(location) && location.property_id == Some(7)))
        })?;
        let mut properties = BTreeSet::new();
        let mut pointer = None;
        let invalid = |reason: &str| CompileError::invalid(format!("resource {object:?}: {reason}"));
        for resource in resources {
            for location in
                resource.source.location.iter().chain(resource.source.image_location.iter()).filter(|location| {
                    relevant(location)
                        && matches!(location.address_space.as_str(), "RelativeMemory" | "RelativeMemoryByObjectType")
                })
            {
                match location.to_address_space().map_err(|error| invalid(&error.to_string()))? {
                    AddressSpaceLocation::RelativeMemory { interface_object_ref, property_id, occurrence, .. } => {
                        indexed_object(interface_object_ref, occurrence)?;
                        properties.insert(property_id);
                    }
                    AddressSpaceLocation::RelativeMemoryByObjectType { property_id, .. } => {
                        properties.insert(property_id);
                    }
                    _ => {}
                }
            }
            if resource.source.resource_type.as_ref().and_then(|kind| kind.flavour.as_deref())
                == Some("Ptr_StandardMemory")
                && resource.property_location()? == Some((object.clone(), 7, 0))
            {
                properties.insert(7);
                if !(1..=4).contains(&resource.length()) {
                    return Err(invalid("pointer resource requires one through four bytes"));
                }
                if pointer.replace(resource.read(service)?).is_some() {
                    return Err(invalid("multiple relative-memory pointer resources are resolved"));
                }
            }
        }
        let property_id = match properties.len() {
            0 => return Err(invalid("no relative-memory property is resolved")),
            1 => *properties.first().expect("one property is present"),
            _ => return Err(invalid("multiple relative-memory properties are resolved")),
        };
        let read = if let Some(pointer) = pointer {
            pointer
        } else {
            let width = self
                .property_element_size(object, property_id, false)?
                .filter(|width| (1..=4).contains(width))
                .ok_or_else(|| invalid("pointer property requires one through four bytes"))?;
            ServiceRead {
                target: OperationTarget::Property {
                    address: pure_property_address(object, property_id).map_err(|error| invalid(&error.to_string()))?,
                    start_element: 1,
                },
                extent: OperationExtent::property(width, 1),
            }
        };
        Ok(OperationTarget::Memory {
            service: service.for_pointer(read.extent.byte_length, offset, length),
            address: MemoryAddress::Pointer {
                space: ImageSpace::RelativeMemory { object: object.clone() },
                read: Box::new(read),
                offset,
                encoding: PointerEncoding::Absolute,
            },
        })
    }
}

pub(crate) fn validate_access(access: Option<&ResourceAccessSet>) -> Result<(), CompileError> {
    let Some(access) = access else {
        return Ok(());
    };

    let mut unique = BTreeSet::new();
    for entry in access.iter() {
        let path = match entry {
            ResourceAccess::Remote => "remote",
            ResourceAccess::Local1 => "local1",
            ResourceAccess::Local2 => "local2",
            ResourceAccess::Unknown(value) => {
                return Err(CompileError::unsupported(format!("unknown resource access token {value:?}")));
            }
        };

        if !unique.insert(path) {
            return Err(CompileError::invalid(format!("resource access path {path:?} is declared more than once")));
        }
    }

    if unique.is_empty() {
        return Err(CompileError::invalid("resource access set is explicitly empty"));
    }

    Ok(())
}

pub(super) fn resolve_resource_style(
    resource: &Resource,
    selected: Option<ResourceManagementStyle>,
) -> Result<Option<ResourceManagementStyle>, CompileError> {
    let Some(styles) = &resource.management_style else {
        return Ok(None);
    };

    if let Some(unknown) = styles.unknown().next() {
        return Err(CompileError::unsupported(format!("unknown resource management-style token {unknown:?}")));
    }

    let mut unique = BTreeSet::new();
    for style in styles.iter() {
        let style = match style {
            XmlManagementStyle::Simple => ResourceManagementStyle::Simple,
            XmlManagementStyle::LoadStateMachine => ResourceManagementStyle::LoadStateMachine,
            XmlManagementStyle::Unknown(_) => continue,
        };

        if !unique.insert(style) {
            return Err(CompileError::invalid(format!(
                "resource management style {style:?} is declared more than once"
            )));
        }
    }

    if unique.is_empty() {
        return Err(CompileError::invalid("resource management-style set is explicitly empty"));
    }

    if let Some(selected) = selected {
        return Ok(styles.contains_name(management_style_name(selected)).then_some(selected));
    }

    let styles: Vec<_> = unique.into_iter().collect();

    Ok(match styles.as_slice() {
        [style] => Some(*style),
        _ => None,
    })
}

pub(super) fn resolve_access_rights(access: Option<&AccessRights>) -> Result<ResourceAccessRights, CompileError> {
    let Some(access) = access else {
        return Ok(ResourceAccessRights { read: ReadAccess::None, write: WriteAccess::None });
    };

    let read = match access.read.as_str() {
        "None" => ReadAccess::None,
        "Configuration" => ReadAccess::Configuration,
        "Runtime" => ReadAccess::Runtime,
        value => return Err(CompileError::unsupported(format!("unknown resource read-access token {value:?}"))),
    };
    let write = match access.write.as_str() {
        "None" => WriteAccess::None,
        "Configuration" => WriteAccess::Configuration,
        "Manufacturer" => WriteAccess::Manufacturer,
        value => return Err(CompileError::unsupported(format!("unknown resource write-access token {value:?}"))),
    };

    Ok(ResourceAccessRights { read, write })
}

pub(super) fn management_style_name(style: ResourceManagementStyle) -> &'static str {
    match style {
        ResourceManagementStyle::Simple => "simple",
        ResourceManagementStyle::LoadStateMachine => "lsm",
    }
}
