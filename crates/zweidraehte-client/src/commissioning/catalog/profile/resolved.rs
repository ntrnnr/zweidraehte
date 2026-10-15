//! An exact selection into immutable Master Data, not a second property schema.

use super::{
    ManagementModel, MaskIdentity, ObjectSelector, ProfileDisposition, ProfileVariant, ResourceFlavour, ResourceId,
    ResourceManagementStyle,
};
use crate::commissioning::catalog::ProgrammingCatalog;
use crate::commissioning::catalog::SelectedResource;
use crate::commissioning::error::AssociationTableEntrySizeError;
use crate::commissioning::error::CompileError;
use std::collections::{BTreeMap, BTreeSet};
use zweidraehte_ets_files::product::ProductData;
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
    /// PDT numbers the target reported for properties Master Data leaves untyped.
    pub(crate) observed_property_types: BTreeMap<(ObjectSelector, u16), u8>,
    /// `PropType` of the first property declaration for each address in the
    /// selected load procedure; see [`DeclaredProperty`].
    pub(crate) declared_property_types: BTreeMap<DeclaredProperty, String>,
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

    /// Element width of every fixed-size property data type in Master Data,
    /// keyed by its wire number, for one transfer direction.
    ///
    /// A target's property description reports a PDT by number. The executor
    /// sizes a described property control from this table, since it holds no
    /// Master Data of its own.
    pub(crate) fn property_data_type_widths(&self, read: bool) -> BTreeMap<u8, u32> {
        let master_data = &self.catalog.master_data;
        (0..=u8::MAX)
            .filter_map(|number| {
                let token = master_data.property_data_type_token(u16::from(number))?;
                let width = if read {
                    master_data.property_data_type_read_size(token)
                } else {
                    master_data.property_data_type_size(token)
                }?;

                (width != 0).then_some((number, width))
            })
            .collect()
    }

    /// Parameter-owned properties whose element width Master Data does not
    /// define, neither in this profile's object roster nor globally.
    ///
    /// Application-specific objects, such as manufacturer object types or an
    /// object index outside the mask roster, can carry parameters. Their wire
    /// element size is then a fact of the target, reported by its property
    /// description; it cannot be inferred from the parameter's bit size.
    /// Supply each one with [`Self::with_observed_property_type`] before
    /// compiling a plan that writes those parameters.
    ///
    /// Properties of an indexed object are omitted: their writes read the
    /// description themselves when they run, as the reference does, and are
    /// clipped to the parameters' image segment.
    pub fn untyped_parameter_properties(
        &self,
        product: &ProductData,
    ) -> Result<Vec<(ObjectSelector, u16)>, CompileError> {
        let mut untyped = BTreeSet::new();
        for location in product.property_parameters() {
            let object = crate::commissioning::catalog::rules::product_property_object(location.object);
            if matches!(object, ObjectSelector::Index { .. }) {
                continue;
            }
            let key = (object, location.property_id);
            if untyped.contains(&key) {
                continue;
            }

            let width = self.catalog.metadata_property_width(self, &key.0, key.1, false, None)?;
            if width.is_none() {
                untyped.insert(key);
            }
        }
        Ok(untyped.into_iter().collect())
    }

    /// Add the PDT which the target reported for a property that Master Data
    /// leaves untyped.
    ///
    /// Master Data remains authoritative wherever it defines a width. An
    /// observation of such a property is accepted only when its read and
    /// write widths agree with Master Data, and then changes nothing; a
    /// contradicting one is rejected rather than silently ignored. Other
    /// tools learn the width of such a property from the target when their
    /// own metadata cannot place the object, so the same observation can
    /// describe both. The PDT must have a fixed element size.
    pub fn with_observed_property_type(
        mut self,
        object: ObjectSelector,
        property_id: u16,
        pdt: u8,
    ) -> Result<Self, CompileError> {
        let object = schema_selector(object);

        let master_data = &self.catalog.master_data;
        let Some(token) = master_data.property_data_type_token(u16::from(pdt)) else {
            return Err(CompileError::invalid(format!(
                "property {property_id} on {object:?}: target reports PDT {pdt:#04x}, which Master Data does not declare"
            )));
        };
        let (Some(write_width), Some(read_width)) =
            (master_data.property_data_type_size(token), master_data.property_data_type_read_size(token))
        else {
            return Err(CompileError::invalid(format!(
                "property {property_id} on {object:?}: target reports PDT {token}, which has no fixed element size"
            )));
        };

        let typed = (
            self.catalog.metadata_property_width(&self, &object, property_id, false, None)?,
            self.catalog.metadata_property_width(&self, &object, property_id, true, None)?,
        );
        match typed {
            (None, None) => {}
            (Some(write), Some(read)) if (write, read) == (write_width, read_width) => return Ok(self),
            _ => {
                return Err(CompileError::invalid(format!(
                    "property {property_id} on {object:?} is already typed by Master Data with other widths than PDT {token}"
                )));
            }
        }

        match self.observed_property_types.insert((object.clone(), property_id), pdt) {
            Some(previous) if previous != pdt => Err(CompileError::invalid(format!(
                "property {property_id} on {object:?} was observed with PDTs {previous:#04x} and {pdt:#04x}"
            ))),
            _ => Ok(self),
        }
    }
}

/// Property address by which a load procedure's property declaration types
/// image and wire geometry that Master Data leaves open.
///
/// An index declaration describes one interface object. A type declaration
/// describes the property on every object of that type: its occurrence does
/// not narrow the match. An index declaration never describes a
/// type-addressed property, nor the reverse, even when both name one object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum DeclaredProperty {
    Index { index: u16, property_id: u16 },
    Type { object_type: u16, property_id: u16 },
}

impl DeclaredProperty {
    pub(crate) fn new(object: &ObjectSelector, property_id: u16) -> Self {
        match object {
            ObjectSelector::Index { index } => Self::Index { index: *index, property_id },
            ObjectSelector::Type { object_type, .. } => Self::Type { object_type: *object_type, property_id },
        }
    }
}

impl ResolvedProfile {
    /// Add the property declarations of the load procedure selected for one
    /// compilation, in procedure order.
    ///
    /// A procedure declares a property's type before it writes the property,
    /// so the declaration describes the property this download addresses.
    /// Where Master Data does not type the property, the first declaration
    /// for its address supplies the element width; later declarations of the
    /// same address are ignored.
    pub(crate) fn with_procedure_property_declarations<'a>(
        mut self,
        declarations: impl IntoIterator<Item = (DeclaredProperty, &'a str)>,
    ) -> Self {
        self.declared_property_types.clear();
        for (property, property_type) in declarations {
            self.declared_property_types.entry(property).or_insert_with(|| property_type.to_owned());
        }
        self
    }
}

/// Spell a type selector's omitted occurrence as the schema default, zero, so
/// both spellings key one observed property.
pub(crate) fn schema_selector(object: ObjectSelector) -> ObjectSelector {
    match object {
        ObjectSelector::Type { object_type, occurrence } => {
            ObjectSelector::Type { object_type, occurrence: super::Occurrence::from_schema(occurrence.value()) }
        }
        index => index,
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
