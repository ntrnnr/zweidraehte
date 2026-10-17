//! Versioned Master Data, exact target selection and resource-resolution order.

mod loading;
mod property_view;
mod resource_view;

use crate::commissioning::error::CompileError;
pub use loading::{
    LoadedProgrammingCatalog, ProgrammingCatalogLoadError, ProgrammingCatalogLoadRequest, ProgrammingCatalogProvenance,
    ProgrammingCatalogSource,
};
pub(crate) use property_view::{property_location, property_object_matches, property_resources};
pub use resource_view::SelectedResource;
pub(crate) use resource_view::{ResourceOrder, validate_access};

use self::loading::validate_mask_tokens;
use crate::commissioning::catalog::profile::{
    MaskIdentity, ProfileDiscovery, ProfileDisposition, ProfileRequest, ProfileVariant, ResolvedProfile,
    ResourceManagementStyle, VariantHint,
};
use std::collections::BTreeSet;
use std::sync::Arc;
use zweidraehte_ets_files::MasterData;
use zweidraehte_ets_files::product::{LoadProcedureStyle, ProductData};
use zweidraehte_ets_files::schema::master_data::{
    AddressSpaceLocation, HawkConfigurationData, MaskVersion, ResourceManagementStyle as XmlManagementStyle,
};

/// Versioned, immutable Master Data plus its content fingerprint.
#[derive(Debug, Clone)]
pub struct ProgrammingCatalog {
    pub(crate) master_data: Arc<MasterData>,
    fingerprint: [u8; 32],
}

impl PartialEq for ProgrammingCatalog {
    fn eq(&self, other: &Self) -> bool {
        self.fingerprint == other.fingerprint
    }
}
impl Eq for ProgrammingCatalog {}

impl AsRef<MasterData> for ProgrammingCatalog {
    /// Borrow the same document that supplies compilation metadata.
    fn as_ref(&self) -> &MasterData {
        &self.master_data
    }
}

impl ProgrammingCatalog {
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Resolve the exact mask, configuration variant, resources, and
    /// procedures needed by the compiler.
    pub fn resolve(&self, request: ProfileRequest<'_>) -> Result<ResolvedProfile, CompileError> {
        // Exact identity precedes variant and access selection. Similar mask
        // numbers never supply missing behavior or resources.
        let mask = self.resolve_exact_mask(&request.discovery)?;
        self.resolve_with_mask(request, mask)
    }

    /// Resolve a product's application profile for explicit offline authoring.
    ///
    /// Application aliases select metadata without fabricating device facts.
    /// The supplied DD0 must match that profile, and any supplied PID 72 must
    /// agree with it. Use [`Self::resolve`] for physical-device discovery,
    /// including its requirement for PID 72 when DD0 is ambiguous.
    ///
    /// Returns an error for a missing product, unknown profile, conflicting
    /// identity evidence or unsupported programming configuration.
    pub fn resolve_application_profile(&self, request: ProfileRequest<'_>) -> Result<ResolvedProfile, CompileError> {
        let product =
            request.product.ok_or_else(|| CompileError::invalid("application profile selection requires a product"))?;
        let mask = self.master_data.get_mask_version(product.programming_profile_id()).ok_or_else(|| {
            CompileError::unsupported(format!(
                "Master Data has no application profile {:?} for authored mask {:?}",
                product.programming_profile_id(),
                product.mask_version_id()
            ))
        })?;
        if request.discovery.dd0 != mask.mask_version_code {
            return Err(CompileError::invalid(format!(
                "application profile {} does not match supplied DD0 {:04X}",
                mask.id, request.discovery.dd0
            )));
        }
        if let Some(observed) = request.discovery.management_descriptor_01
            && mask.management_descriptor_01 != Some(observed)
        {
            return Err(CompileError::invalid(format!(
                "application profile {} contradicts observed PID 72 {:?}",
                mask.id, observed
            )));
        }
        self.resolve_with_mask(request, mask)
    }

    fn resolve_with_mask(
        &self,
        request: ProfileRequest<'_>,
        mask: &MaskVersion,
    ) -> Result<ResolvedProfile, CompileError> {
        self.verify_product_compatibility(mask, request.product)?;

        let (variant_index, variant) = select_variant(mask, request.product, request.variant_hint)?;
        let disposition = classify_variant(mask, variant);
        validate_mask_tokens(mask)?;

        // The engine programs devices through bus management services. Local
        // interface qualifiers remain catalog metadata for auditing; USB versus
        // tunnel transport is supplied by the caller when preparing/executing.
        // Resource selection also depends on the management realization.
        let management_style =
            resolve_management_style(mask, variant, request.product, request.discovery.management_style)?;

        let source_mask_index = self
            .master_data
            .mask_versions()
            .expect("selected mask catalogue")
            .versions
            .iter()
            .position(|candidate| std::ptr::eq(candidate, mask))
            .expect("selected mask belongs to catalogue");

        Ok(ResolvedProfile {
            mask: mask_identity(mask),
            variant: profile_variant(variant_index, variant),
            management_model: mask.management_model.parse().map_err(|_| {
                CompileError::unsupported(format!("unknown Master Data management model {:?}", mask.management_model))
            })?,
            management_style,
            disposition,
            master_data_fingerprint: self.fingerprint,
            catalog: self.clone(),
            source_mask_index,
            source_variant_index: variant_index,
            association_entry_size: None,
            observed_property_types: Default::default(),
            declared_property_types: Default::default(),
            tool_managed_ip: None,
        })
    }
}

pub(super) fn mask_identity(mask: &MaskVersion) -> MaskIdentity {
    MaskIdentity {
        full_id: mask.id.clone(),
        dd0: mask.mask_version_code,
        management_descriptor_01: mask.management_descriptor_01,
    }
}

pub(super) fn profile_variant(source_index: usize, variant: &HawkConfigurationData) -> ProfileVariant {
    ProfileVariant {
        source_index,
        legacy_version: variant.legacy_version,
        ets3_system_plugin: variant.ets3_system_plugin.clone(),
    }
}

fn is_iot(mask: &MaskVersion) -> bool {
    mask.medium_type_ref_id.as_deref() == Some("MT-6")
        || mask.other_medium_type_ref_id.as_deref() == Some("MT-6")
        || matches!(mask.mask_version_code, 0x6800 | 0x6900)
}

fn is_power_line(mask: &MaskVersion) -> bool {
    mask.medium_type_ref_id.as_deref() == Some("MT-1") || mask.other_medium_type_ref_id.as_deref() == Some("MT-1")
}

pub(super) fn classify_variant(mask: &MaskVersion, variant: &HawkConfigurationData) -> ProfileDisposition {
    if is_iot(mask) {
        return ProfileDisposition::ExcludedIot;
    }

    if mask.management_model == "None" {
        return ProfileDisposition::NonProgrammable;
    }

    // PL110 System B uses the same image and management services as its
    // TP1 counterpart, including the legacy hybrid load endpoints. Other
    // power-line families still need their own table and domain mappings.
    if is_power_line(mask) && !(mask.id == "MV-17B0" && mask.management_model == "SystemB") {
        return ProfileDisposition::ExcludedPowerLine;
    }

    // Coupler Model 2.0 standardizes the filter-table storage and PID 67,
    // but deliberately leaves the Filter/RouteAll/BlockAll selector in the
    // product model. Master Data alone therefore cannot compile a complete
    // routing configuration for MV-2920.
    if mask.id == "MV-2920" {
        return ProfileDisposition::CouplerRoutingRequired;
    }

    if let Some(plugin) = &variant.ets3_system_plugin {
        return ProfileDisposition::UnsupportedPlugin { plugin: plugin.clone() };
    }

    let procedures = variant.procedures.as_ref().map(|procedures| procedures.procedures.as_slice()).unwrap_or_default();
    if !procedures.iter().any(|procedure| procedure.is_load()) {
        return ProfileDisposition::ProductProcedureRequired;
    }

    ProfileDisposition::Executable
}

pub(super) fn select_variant<'a>(
    mask: &'a MaskVersion,
    product: Option<&ProductData>,
    hint: VariantHint,
) -> Result<(usize, &'a HawkConfigurationData), CompileError> {
    if mask.hawk_configs.is_empty() {
        return Err(CompileError::unsupported(format!("mask {} has no programming configuration", mask.id)));
    }

    if let VariantHint::LegacyVersion(version) = hint {
        return unique_variant(mask, version);
    }

    if mask.hawk_configs.len() == 1 {
        return Ok((0, &mask.hawk_configs[0]));
    }

    let Some(product) = product else {
        return Err(CompileError::missing_evidence(format!(
            "mask {} has multiple programming configurations; supply an explicit variant hint",
            mask.id
        )));
    };

    // The line-coupler product option is the published selector for both 0912
    // and 091A. XML ordering differs between them, so selection is always by
    // `LegacyVersion`, never by position.
    if matches!(mask.mask_version_code, 0x0912 | 0x091a) {
        let modern = product.programming_options().line_coupler_0912_new_programming_style().value;
        return unique_variant(mask, if modern { 0 } else { 1 });
    }

    // Procedure ownership does not select a legacy image profile. The
    // reference resolver uses version zero for every procedure style, apart
    // from the published line-coupler option above. Legacy image profiles
    // remain available through an explicit variant hint.
    unique_variant(mask, 0)
}

fn unique_variant(mask: &MaskVersion, legacy_version: i32) -> Result<(usize, &HawkConfigurationData), CompileError> {
    let mut variants = mask
        .hawk_configs
        .iter()
        .enumerate()
        .filter(|(_, variant)| variant.legacy_version.unwrap_or(0) == legacy_version);
    let result = variants.next().ok_or_else(|| {
        CompileError::invalid(format!("mask {} has no configuration with LegacyVersion {legacy_version}", mask.id))
    })?;

    if variants.next().is_some() {
        return Err(CompileError::invalid(format!(
            "mask {} has multiple configurations with LegacyVersion {legacy_version}",
            mask.id
        )));
    }

    Ok(result)
}
impl ProgrammingCatalog {
    /// Whether DD0 alone is insufficient and Device Object PID 72 must be
    /// read before selecting an exact mask profile.
    pub fn requires_management_descriptor_01(&self, dd0: u16) -> Result<bool, CompileError> {
        let mut candidates = self.master_data.get_mask_versions_by_code(dd0);
        candidates
            .next()
            .ok_or_else(|| CompileError::unsupported(format!("Master Data has no mask for DD0 {dd0:04X}")))?;

        Ok(candidates.next().is_some())
    }

    pub(super) fn resolve_exact_mask(&self, discovery: &ProfileDiscovery) -> Result<&MaskVersion, CompileError> {
        let candidates: Vec<_> = self.master_data.get_mask_versions_by_code(discovery.dd0).collect();

        match candidates.as_slice() {
            [] => Err(CompileError::unsupported(format!("Master Data has no mask for DD0 {:04X}", discovery.dd0))),
            [mask] => {
                if discovery.management_descriptor_01.is_some()
                    && discovery.management_descriptor_01 != mask.management_descriptor_01
                {
                    return Err(CompileError::invalid(format!(
                        "DD0 {:04X} has no profile matching observed PID 72 {:?}",
                        discovery.dd0, discovery.management_descriptor_01
                    )));
                }

                Ok(mask)
            }
            _ if discovery.management_descriptor_01.is_none() => Err(CompileError::missing_evidence(format!(
                "DD0 {:04X} is ambiguous; read Device Object PID 72 before selecting a profile",
                discovery.dd0
            ))),
            _ => {
                let descriptor = discovery.management_descriptor_01.as_ref();
                let mut matching =
                    candidates.into_iter().filter(|mask| mask.management_descriptor_01.as_ref() == descriptor);
                let mask = matching.next().ok_or_else(|| {
                    CompileError::invalid(format!(
                        "DD0 {:04X} has no profile matching observed PID 72 {:?}",
                        discovery.dd0, discovery.management_descriptor_01
                    ))
                })?;

                if matching.next().is_some() {
                    return Err(CompileError::invalid(format!(
                        "DD0 {:04X} and PID 72 still identify multiple profiles",
                        discovery.dd0
                    )));
                }

                Ok(mask)
            }
        }
    }

    pub(super) fn verify_product_compatibility(
        &self,
        device_mask: &MaskVersion,
        product: Option<&ProductData>,
    ) -> Result<(), CompileError> {
        let Some(product) = product else {
            return Ok(());
        };

        let product_mask = self.master_data.get_mask_version(product.programming_profile_id()).ok_or_else(|| {
            CompileError::unsupported(format!("Master Data has no product mask ID {:?}", product.mask_version_id()))
        })?;

        if !device_mask.is_downward_compatible_with(product_mask.mask_version_code) {
            return Err(CompileError::invalid(format!(
                "product mask {} is not compatible with device mask {}",
                product_mask.id, device_mask.id
            )));
        }

        // Descriptor-qualified profiles sharing DD0 are different execution
        // architectures, not downward-compatible aliases.
        if device_mask.mask_version_code == product_mask.mask_version_code
            && (device_mask.management_descriptor_01.is_some() || product_mask.management_descriptor_01.is_some())
            && device_mask.id != product_mask.id
        {
            return Err(CompileError::invalid(format!(
                "product mask {} is not compatible with device mask {}",
                product_mask.id, device_mask.id
            )));
        }

        Ok(())
    }
}

pub(super) fn resolve_management_style(
    mask: &MaskVersion,
    variant: &HawkConfigurationData,
    product: Option<&ProductData>,
    discovered: Option<ResourceManagementStyle>,
) -> Result<Option<ResourceManagementStyle>, CompileError> {
    let resources = variant.resources.as_ref().map(|resources| resources.resources.as_slice()).unwrap_or_default();
    let mut constants = BTreeSet::new();

    for resource in resources.iter().filter(|resource| resource.name == "ManagementStyle") {
        let Some(location) = resource.location.as_ref() else { continue };
        let AddressSpaceLocation::Constant { value } =
            location.to_address_space().map_err(|error| CompileError::invalid(error.to_string()))?
        else {
            continue;
        };

        constants.insert(match value {
            1 => ResourceManagementStyle::Simple,
            2 => ResourceManagementStyle::LoadStateMachine,
            value => {
                return Err(CompileError::unsupported(format!(
                    "management-style resource returned unsupported value {value}"
                )));
            }
        });
    }

    if constants.len() > 1 {
        return Err(CompileError::invalid(format!("mask {} declares conflicting constant management styles", mask.id)));
    }

    if let Some(fixed) = constants.into_iter().next() {
        if product.is_none()
            && let Some(observed) = discovered
            && observed != fixed
        {
            return Err(CompileError::invalid(format!(
                "device reports management style {observed:?}, but the exact profile fixes it to {fixed:?}"
            )));
        }

        return Ok(Some(fixed));
    }

    // BCU2 is the one published classic model whose application image chooses
    // between the simple and load-state-machine realizations. The MTXML
    // `LoadProcedureStyle` selects the replacement image; a live probe only
    // describes the application currently installed on the device.
    if mask.management_model == "Bcu2" {
        if let Some(product) = product {
            return Ok(Some(match product.load_procedure_style() {
                LoadProcedureStyle::Default => ResourceManagementStyle::Simple,
                LoadProcedureStyle::Product | LoadProcedureStyle::Merged => ResourceManagementStyle::LoadStateMachine,
            }));
        }

        return discovered.map(Some).ok_or_else(|| {
            CompileError::missing_evidence("the selected profile requires a live management-style probe")
        });
    }

    if let Some(discovered) = discovered {
        return Ok(Some(discovered));
    }

    let mut declared = BTreeSet::new();
    for resource in resources.iter().filter(|resource| resource.supports_access("remote")) {
        if let Some(styles) = &resource.management_style {
            for style in styles.iter() {
                match style {
                    XmlManagementStyle::Simple => {
                        declared.insert(ResourceManagementStyle::Simple);
                    }
                    XmlManagementStyle::LoadStateMachine => {
                        declared.insert(ResourceManagementStyle::LoadStateMachine);
                    }
                    XmlManagementStyle::Unknown(value) => {
                        return Err(CompileError::unsupported(format!(
                            "unknown resource management-style token {value:?}"
                        )));
                    }
                }
            }
        }
    }

    match declared.len() {
        0 if mask.management_model == "Bcu1" => Ok(Some(ResourceManagementStyle::Simple)),
        // `ManagementModel` does not define a universal wire realization.
        // Every other executable classic profile must publish a constant,
        // style-qualified resource, live probe, or product selector. Guessing
        // LSM here would make a newly published model executable with the
        // wrong services instead of producing a preflight diagnostic.
        1 => Ok(declared.into_iter().next()),
        _ => Err(CompileError::missing_evidence("the selected profile requires a live management-style probe")),
    }
}

#[cfg(test)]
mod tests;

pub(crate) mod profile;
pub(crate) mod rules;
