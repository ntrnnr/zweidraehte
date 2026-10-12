//! Exact target identity, selectors, and supplied discovery facts.

mod flavour;
mod resolved;

use crate::commissioning::error::UnknownProfileToken;
pub use flavour::{ManagementModel, ResourceFlavour};
pub use resolved::{AssociationTableEntrySize, ImageRequirement, ResolvedProfile};

use std::collections::BTreeMap;
use zweidraehte_ets_files::product::ProductData;
pub use zweidraehte_project::{MaskIdentity, ObjectSelector, Occurrence, ResourceId};

/// Identity of the selected programming configuration inside a mask entry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProfileVariant {
    /// Stable position in the source document, retained for diagnostics and
    /// fingerprints. Selection never relies on this ordering.
    pub source_index: usize,

    /// `None` means the source schema did not declare the attribute. A modern
    /// variant explicitly declaring zero therefore remains distinguishable.
    pub legacy_version: Option<i32>,

    /// Proprietary system plug-in required by this variant, when declared.
    pub ets3_system_plugin: Option<String>,
}

/// How the catalog classifies one mask/profile variant during audit.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileDisposition {
    /// The built-in compiler and device-management layer cover the variant.
    Executable,

    /// Master Data supplies the platform procedure, but a concrete product
    /// must supply its product-owned load procedure before execution.
    ProductProcedureRequired,

    /// Coupler Model 2.0 needs the product-defined routing selector.
    CouplerRoutingRequired,

    /// Proprietary ETS3 system plugins have no supported programming implementation.
    UnsupportedPlugin { plugin: String },

    /// The entry describes a device that has no application programming
    /// procedure.
    NonProgrammable,

    /// KNX PL profiles are retained losslessly in the catalog but are outside
    /// the executable commissioning scope.
    ExcludedPowerLine,

    /// KNX IoT is deliberately outside this commissioning engine.
    ExcludedIot,
}

/// Management realization declared by the selected resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResourceManagementStyle {
    Simple,
    LoadStateMachine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadAccess {
    None,
    Configuration,
    Runtime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteAccess {
    None,
    Configuration,
    Manufacturer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceAccessRights {
    pub read: ReadAccess,
    pub write: WriteAccess,
}

/// Facts obtained without mutating the target device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileDiscovery {
    pub dd0: u16,
    pub management_descriptor_01: Option<[u8; 10]>,
    /// Result of a mask-defined management-style probe, when the style is not
    /// a constant resource.
    pub management_style: Option<ResourceManagementStyle>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariantHint {
    Automatic,
    LegacyVersion(i32),
}

/// Inputs to exact profile resolution.
pub struct ProfileRequest<'a> {
    pub discovery: ProfileDiscovery,
    pub product: Option<&'a ProductData>,
    pub variant_hint: VariantHint,
}

/// Device facts and explicit choices used to resolve a product's exact profile.
/// This contains no catalog resources or independently resolved procedures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSelection {
    pub discovery: ProfileDiscovery,
    pub variant_hint: VariantHint,
    pub association_table_entry_size: Option<AssociationTableEntrySize>,
    /// PDT numbers the target reported for properties Master Data leaves
    /// untyped; see [`ResolvedProfile::untyped_parameter_properties`].
    pub observed_property_types: BTreeMap<(ObjectSelector, u16), u8>,
}

impl ProfileSelection {
    pub fn new(discovery: ProfileDiscovery) -> Self {
        Self {
            discovery,
            variant_hint: VariantHint::Automatic,
            association_table_entry_size: None,
            observed_property_types: BTreeMap::new(),
        }
    }

    pub fn with_variant(mut self, hint: VariantHint) -> Self {
        self.variant_hint = hint;
        self
    }

    pub fn with_association_table_entry_size(mut self, width: AssociationTableEntrySize) -> Self {
        self.association_table_entry_size = Some(width);
        self
    }

    pub fn with_observed_property_type(mut self, object: ObjectSelector, property_id: u16, pdt: u8) -> Self {
        self.observed_property_types.insert((object, property_id), pdt);
        self
    }
}

/// Exact identifier of a selected Master Data procedure.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcedureId {
    pub procedure_type: String,
    pub subtype: Option<String>,
    pub management_style: Option<ResourceManagementStyle>,
    pub source_index: usize,
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod testing;
