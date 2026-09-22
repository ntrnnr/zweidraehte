//! An exact selection into immutable Master Data, not a second property schema.

use super::{
    ManagementModel, MaskIdentity, ObjectSelector, ProfileDisposition, ProfileVariant, ResourceFlavour, ResourceId,
    ResourceManagementStyle,
};
use crate::commissioning::catalog::ProgrammingCatalog;
use crate::commissioning::catalog::SelectedResource;
use crate::commissioning::error::AssociationTableEntrySizeError;
use crate::commissioning::error::CompileError;
use std::collections::BTreeSet;
use zweidraehte_ets_files::schema::master_data::{HawkConfigurationData, InterfaceObject, MaskVersion};

/// Identity is selected by the catalog and remains coupled to its source.
///
/// ```compile_fail
/// use zweidraehte_client::commissioning::ResolvedProfile;
/// fn replace_identity(profile: &mut ResolvedProfile) {
///     profile.mask.dd0 = 0x0705;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProfile {
    pub(in crate::commissioning::catalog) mask: MaskIdentity,
    pub(in crate::commissioning::catalog) variant: ProfileVariant,
    pub(in crate::commissioning::catalog) management_model: ManagementModel,
    pub(in crate::commissioning::catalog) management_style: Option<ResourceManagementStyle>,
    pub(in crate::commissioning::catalog) disposition: ProfileDisposition,
    pub(in crate::commissioning::catalog) master_data_fingerprint: [u8; 32],
    pub(crate) catalog: ProgrammingCatalog,
    pub(crate) source_mask_index: usize,
    pub(crate) source_variant_index: usize,
    pub(crate) association_entry_size: Option<AssociationTableEntrySize>,
    /// The product authorizes the fixed IP fields; the bool enables its secure fields.
    pub(crate) tool_managed_ip: Option<bool>,
}

impl ResolvedProfile {
    pub fn mask(&self) -> &MaskIdentity {
        &self.mask
    }
    pub fn variant(&self) -> &ProfileVariant {
        &self.variant
    }
    pub fn management_model(&self) -> ManagementModel {
        self.management_model
    }
    pub fn management_style(&self) -> Option<ResourceManagementStyle> {
        self.management_style
    }
    pub fn disposition(&self) -> &ProfileDisposition {
        &self.disposition
    }
    pub fn master_data_fingerprint(&self) -> [u8; 32] {
        self.master_data_fingerprint
    }

    pub fn source(&self) -> &HawkConfigurationData {
        &self.mask_source().hawk_configs[self.source_variant_index]
    }

    pub fn mask_source(&self) -> &MaskVersion {
        &self.catalog.master_data.mask_versions().expect("selected mask catalogue").versions[self.source_mask_index]
    }

    pub fn interface_objects(&self) -> &[InterfaceObject] {
        self.source().interface_objects.as_ref().map_or(&[], |objects| objects.objects.as_slice())
    }

    pub fn feature(&self, name: &str) -> Result<Option<u32>, CompileError> {
        let mut selected = self
            .source()
            .features
            .iter()
            .flat_map(|features| &features.features)
            .filter(|feature| feature.name == name);
        let Some(feature) = selected.next() else { return Ok(None) };
        if selected.next().is_some() {
            return Err(CompileError::invalid(format!("selected profile declares feature {name:?} more than once")));
        }
        feature.value.parse().map(Some).map_err(|_| {
            CompileError::invalid(format!("profile feature {name:?} has non-numeric value {:?}", feature.value))
        })
    }

    pub fn resource_names(&self) -> impl Iterator<Item = &str> {
        self.source()
            .resources
            .iter()
            .flat_map(|resources| &resources.resources)
            .filter(|resource| resource.supports_access("remote"))
            .map(|resource| resource.name.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
    }

    pub fn resource(&self, name: &str) -> Result<Option<SelectedResource<'_>>, CompileError> {
        self.catalog.selected_resource(self, name)
    }

    pub fn resource_by_id(&self, id: &ResourceId) -> Result<Option<SelectedResource<'_>>, CompileError> {
        self.resource(&id.0)
    }

    pub fn property_element_size(
        &self,
        object: &ObjectSelector,
        property_id: u16,
        read: bool,
    ) -> Result<Option<u32>, CompileError> {
        self.catalog.selected_property_element_size(self, object, property_id, read)
    }

    pub fn image_requirements(&self) -> Result<Vec<ImageRequirement>, CompileError> {
        let Some(resource) = self.resource("GroupAssociationTable")? else { return Ok(Vec::new()) };
        Ok(if resource.flavour()? == Some(ResourceFlavour::AssociationTableSystemB) {
            vec![ImageRequirement::AssociationTableEntrySize { resource: resource.id }]
        } else {
            Vec::new()
        })
    }

    pub fn with_association_table_entry_size(
        mut self,
        size: AssociationTableEntrySize,
    ) -> Result<Self, AssociationTableEntrySizeError> {
        let resource = self
            .resource("GroupAssociationTable")
            .map_err(|error| AssociationTableEntrySizeError::Metadata(error.to_string()))?
            .ok_or(AssociationTableEntrySizeError::MissingTable)?;
        let flavour =
            resource.flavour().map_err(|error| AssociationTableEntrySizeError::Metadata(error.to_string()))?;
        let declared = match flavour {
            Some(ResourceFlavour::AssociationTableSystemB) => None,
            Some(ResourceFlavour::AssociationTableSystemBSmall) => Some(AssociationTableEntrySize::TwoBytes),
            Some(ResourceFlavour::AssociationTableSystemBBig) => Some(AssociationTableEntrySize::FourBytes),
            _ => {
                return Err(AssociationTableEntrySizeError::UnsupportedFlavour {
                    flavour: flavour.map(|value| value.to_string()),
                });
            }
        };
        if let Some(declared) = declared.or(self.association_entry_size)
            && declared != size
        {
            return Err(AssociationTableEntrySizeError::ConflictingSize { declared, requested: size });
        }
        self.association_entry_size = Some(size);
        Ok(self)
    }
}

/// Discovered width of a System B association-table row.
///
/// Both realizations use a two-octet entry count. The row width is a target
/// capability, not a choice based on the current number of links or objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AssociationTableEntrySize {
    /// One-octet TSAP followed by one-octet ASAP.
    TwoBytes,
    /// Two-octet big-endian TSAP followed by two-octet big-endian ASAP.
    FourBytes,
}

/// Facts which an offline image request cannot establish from Master Data.
///
/// A requirement is not an image error or an invitation to select a default.
/// The observer supplies the fact before the same compiler resumes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ImageRequirement {
    AssociationTableEntrySize { resource: ResourceId },
    DataSecurityMode,
}
