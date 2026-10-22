//! Exact target identity, selectors, and supplied discovery facts.

mod flavour;
mod resolved;

use crate::commissioning::error::UnknownProfileToken;
pub use flavour::{ManagementModel, ResourceFlavour};
pub use resolved::{AssociationTableEntrySize, ImageRequirement, ResolvedProfile};
pub(crate) use resolved::{DeclaredProperty, schema_selector};

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
pub(crate) struct ProfileDiscovery {
    pub(crate) dd0: u16,
    pub(crate) management_descriptor_01: Option<[u8; 10]>,
    /// Result of a mask-defined management-style probe, when the style is not
    /// a constant resource.
    pub(crate) management_style: Option<ResourceManagementStyle>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariantHint {
    Automatic,
    LegacyVersion(i32),
}

/// Device identity and explicit choices that select one exact profile.
///
/// This holds only what a caller can know about a target: its DD0, its
/// optional Device Object PID 72, an observed management style, and a variant
/// choice. The product, when there is one, comes from the device being
/// resolved. Per-target refinements that depend on the resolved profile, such
/// as the association-table row width or observed property types, are added
/// to the [`super::ResolvedProfile`] instead.
///
/// ```
/// use zweidraehte_client::commissioning::{ProfileSelection, ResourceManagementStyle};
///
/// let selection = ProfileSelection::discovered(0x07B0)
///     .with_management_style(ResourceManagementStyle::LoadStateMachine);
/// assert_eq!(selection.dd0(), 0x07B0);
/// assert_eq!(selection.management_descriptor_01(), None);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSelection {
    pub(crate) discovery: ProfileDiscovery,
    pub(crate) variant_hint: VariantHint,
}

impl ProfileSelection {
    /// Select by the target's reported (or the product's authored) DD0.
    pub fn discovered(dd0: u16) -> Self {
        Self {
            discovery: ProfileDiscovery { dd0, management_descriptor_01: None, management_style: None },
            variant_hint: VariantHint::Automatic,
        }
    }

    /// Qualify an ambiguous DD0 by the target's Device Object PID 72.
    pub fn with_management_descriptor(mut self, descriptor: [u8; 10]) -> Self {
        self.discovery.management_descriptor_01 = Some(descriptor);
        self
    }

    /// Record the management style a mask-defined probe observed.
    pub fn with_management_style(mut self, style: ResourceManagementStyle) -> Self {
        self.discovery.management_style = Some(style);
        self
    }

    pub fn with_variant(mut self, hint: VariantHint) -> Self {
        self.variant_hint = hint;
        self
    }

    pub fn dd0(&self) -> u16 {
        self.discovery.dd0
    }

    pub fn management_descriptor_01(&self) -> Option<&[u8; 10]> {
        self.discovery.management_descriptor_01.as_ref()
    }

    pub fn management_style(&self) -> Option<ResourceManagementStyle> {
        self.discovery.management_style
    }

    pub fn variant(&self) -> VariantHint {
        self.variant_hint
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
