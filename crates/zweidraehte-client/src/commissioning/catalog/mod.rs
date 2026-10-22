//! Versioned Master Data, exact target selection and resource-resolution order.
//!
//! Master Data is used directly as [`MasterData`]: the product carries the
//! document it compiles against, and a [`ResolvedProfile`] keeps a handle to
//! the same document. No second catalog handle exists that could disagree.

mod property_view;
mod resource_view;
mod schema;

use crate::commissioning::error::ProfileError;
pub(crate) use property_view::{property_location, property_object_matches, property_resources};
pub use resource_view::SelectedResource;
pub(crate) use resource_view::{ResourceOrder, validate_access};
pub(crate) use schema::{bound_master_data, validate_for_live_commissioning};

use self::schema::{supported_master_data_schema, validate_mask_tokens};
use crate::commissioning::catalog::profile::{
    MaskIdentity, ProfileDisposition, ProfileSelection, ProfileVariant, ResolvedProfile, ResourceManagementStyle,
    VariantHint,
};
use std::collections::BTreeSet;
use std::sync::Arc;
use zweidraehte_ets_files::MasterData;
use zweidraehte_ets_files::product::{LoadProcedureStyle, ProductData};
use zweidraehte_ets_files::schema::master_data::{
    AddressSpaceLocation, HawkConfigurationData, MaskVersion, ResourceManagementStyle as XmlManagementStyle,
};

/// Resolve the exact mask, configuration variant, resources, and procedures
/// needed by the compiler.
///
/// Exact identity precedes variant and access selection. Similar mask numbers
/// never supply missing behavior or resources.
///
/// When the selection leaves an ambiguous DD0 unqualified, the product's own
/// programming profile ([`ProductData::programming_profile_id`]) selects among
/// the masks sharing it. This covers both a descriptor-qualified authored mask
/// and the plain `MV-0300` application alias. It is application metadata, not
/// a device observation: a supplied PID 72 always takes precedence, and
/// physical discovery reads PID 72 whenever DD0 is ambiguous, so this rule only
/// serves offline compilation.
pub(crate) fn resolve_profile(
    master_data: &Arc<MasterData>,
    product: Option<&ProductData>,
    selection: &ProfileSelection,
) -> Result<ResolvedProfile, ProfileError> {
    // Raw documents may be newer or older than the compiler understands. An
    // unversioned document stays usable for offline inspection; live
    // preparation additionally requires the namespace.
    if let Some(version) = master_data.schema_version() {
        supported_master_data_schema(version)?;
    }

    let discovery = &selection.discovery;
    let mask = match authored_profile(master_data, product, selection) {
        Some(mask) => mask,
        None => resolve_exact_mask(master_data, discovery.dd0, discovery.management_descriptor_01.as_ref())?,
    };
    verify_product_compatibility(master_data, mask, product)?;

    let (variant_index, variant) = select_variant(mask, product, selection.variant_hint)?;
    let disposition = classify_variant(mask, variant);
    validate_mask_tokens(mask)?;

    // The engine programs devices through bus management services. Local
    // interface qualifiers remain catalog metadata for auditing; USB versus
    // tunnel transport is supplied by the caller when preparing/executing.
    // Resource selection also depends on the management realization.
    let management_style = resolve_management_style(mask, variant, product, discovery.management_style)?;

    let source_mask_index = master_data
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
            ProfileError::unsupported(format!("unknown Master Data management model {:?}", mask.management_model))
        })?,
        management_style,
        disposition,
        master_data: Arc::clone(master_data),
        product_id: product.map(|product| product.id().to_owned()),
        source_mask_index,
        source_variant_index: variant_index,
        association_entry_size: None,
        observed_property_types: Default::default(),
        declared_property_types: Default::default(),
        tool_managed_ip: None,
    })
}

/// The product's programming profile, when it alone can disambiguate DD0.
///
/// Only an unqualified, ambiguous DD0 matching that profile's own code
/// selects it. Every other case resolves by discovery evidence, so a
/// contradicting observation is still reported against the device.
fn authored_profile<'a>(
    master_data: &'a MasterData,
    product: Option<&ProductData>,
    selection: &ProfileSelection,
) -> Option<&'a MaskVersion> {
    let product = product?;
    let discovery = &selection.discovery;
    if discovery.management_descriptor_01.is_some() {
        return None;
    }
    // A unique DD0 needs no disambiguation.
    master_data.get_mask_versions_by_code(discovery.dd0).nth(1)?;
    master_data
        .get_mask_version(product.programming_profile_id())
        .filter(|mask| mask.mask_version_code == discovery.dd0)
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

    // These PL110 profiles have explicit table codecs and ordinary management
    // services. Application loading does not imply assigning a domain address;
    // network configuration remains a separate, explicit operation.
    let supported_power_line = (mask.id == "MV-17B0" && mask.management_model == "SystemB")
        || (mask.id == "MV-1013" && mask.management_model == "Bcu1");
    if is_power_line(mask) && !supported_power_line {
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
) -> Result<(usize, &'a HawkConfigurationData), ProfileError> {
    if mask.hawk_configs.is_empty() {
        return Err(ProfileError::unsupported(format!("mask {} has no programming configuration", mask.id)));
    }

    if let VariantHint::LegacyVersion(version) = hint {
        return unique_variant(mask, version);
    }

    if mask.hawk_configs.len() == 1 {
        return Ok((0, &mask.hawk_configs[0]));
    }

    let Some(product) = product else {
        return Err(ProfileError::missing_evidence(format!(
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

fn unique_variant(mask: &MaskVersion, legacy_version: i32) -> Result<(usize, &HawkConfigurationData), ProfileError> {
    let mut variants = mask
        .hawk_configs
        .iter()
        .enumerate()
        .filter(|(_, variant)| variant.legacy_version.unwrap_or(0) == legacy_version);
    let result = variants.next().ok_or_else(|| {
        ProfileError::invalid(format!("mask {} has no configuration with LegacyVersion {legacy_version}", mask.id))
    })?;

    if variants.next().is_some() {
        return Err(ProfileError::invalid(format!(
            "mask {} has multiple configurations with LegacyVersion {legacy_version}",
            mask.id
        )));
    }

    Ok(result)
}
/// Whether DD0 alone is insufficient and Device Object PID 72 must be
/// read before selecting an exact mask profile.
pub(crate) fn requires_management_descriptor_01(master_data: &MasterData, dd0: u16) -> Result<bool, ProfileError> {
    let mut candidates = master_data.get_mask_versions_by_code(dd0);
    candidates.next().ok_or_else(|| ProfileError::unsupported(format!("Master Data has no mask for DD0 {dd0:04X}")))?;

    Ok(candidates.next().is_some())
}

pub(super) fn resolve_exact_mask<'a>(
    master_data: &'a MasterData,
    dd0: u16,
    management_descriptor_01: Option<&[u8; 10]>,
) -> Result<&'a MaskVersion, ProfileError> {
    let candidates: Vec<_> = master_data.get_mask_versions_by_code(dd0).collect();

    match candidates.as_slice() {
        [] => Err(ProfileError::unsupported(format!("Master Data has no mask for DD0 {:04X}", dd0))),
        [mask] => {
            if management_descriptor_01.is_some() && management_descriptor_01 != mask.management_descriptor_01.as_ref()
            {
                return Err(ProfileError::invalid(format!(
                    "DD0 {:04X} has no profile matching observed PID 72 {:?}",
                    dd0, management_descriptor_01
                )));
            }

            Ok(mask)
        }
        _ if management_descriptor_01.is_none() => Err(ProfileError::missing_evidence(format!(
            "DD0 {:04X} is ambiguous; read Device Object PID 72 before selecting a profile",
            dd0
        ))),
        _ => {
            let mut matching = candidates
                .into_iter()
                .filter(|mask| mask.management_descriptor_01.as_ref() == management_descriptor_01);
            let mask = matching.next().ok_or_else(|| {
                ProfileError::invalid(format!(
                    "DD0 {:04X} has no profile matching observed PID 72 {:?}",
                    dd0, management_descriptor_01
                ))
            })?;

            if matching.next().is_some() {
                return Err(ProfileError::invalid(format!(
                    "DD0 {:04X} and PID 72 still identify multiple profiles",
                    dd0
                )));
            }

            Ok(mask)
        }
    }
}

pub(super) fn verify_product_compatibility(
    master_data: &MasterData,
    device_mask: &MaskVersion,
    product: Option<&ProductData>,
) -> Result<(), ProfileError> {
    let Some(product) = product else {
        return Ok(());
    };

    let product_mask = master_data.get_mask_version(product.programming_profile_id()).ok_or_else(|| {
        ProfileError::unsupported(format!("Master Data has no product mask ID {:?}", product.mask_version_id()))
    })?;

    if !device_mask.is_downward_compatible_with(product_mask.mask_version_code) {
        return Err(ProfileError::invalid(format!(
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
        return Err(ProfileError::invalid(format!(
            "product mask {} is not compatible with device mask {}",
            product_mask.id, device_mask.id
        )));
    }

    Ok(())
}

pub(super) fn resolve_management_style(
    mask: &MaskVersion,
    variant: &HawkConfigurationData,
    product: Option<&ProductData>,
    discovered: Option<ResourceManagementStyle>,
) -> Result<Option<ResourceManagementStyle>, ProfileError> {
    let resources = variant.resources.as_ref().map(|resources| resources.resources.as_slice()).unwrap_or_default();
    let mut constants = BTreeSet::new();

    for resource in resources.iter().filter(|resource| resource.name == "ManagementStyle") {
        let Some(location) = resource.location.as_ref() else { continue };
        let AddressSpaceLocation::Constant { value } =
            location.to_address_space().map_err(|error| ProfileError::invalid(error.to_string()))?
        else {
            continue;
        };

        constants.insert(match value {
            1 => ResourceManagementStyle::Simple,
            2 => ResourceManagementStyle::LoadStateMachine,
            value => {
                return Err(ProfileError::unsupported(format!(
                    "management-style resource returned unsupported value {value}"
                )));
            }
        });
    }

    if constants.len() > 1 {
        return Err(ProfileError::invalid(format!("mask {} declares conflicting constant management styles", mask.id)));
    }

    if let Some(fixed) = constants.into_iter().next() {
        if product.is_none()
            && let Some(observed) = discovered
            && observed != fixed
        {
            return Err(ProfileError::invalid(format!(
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
            ProfileError::missing_evidence("the selected profile requires a live management-style probe")
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
                        return Err(ProfileError::unsupported(format!(
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
        _ => Err(ProfileError::missing_evidence("the selected profile requires a live management-style probe")),
    }
}

#[cfg(test)]
mod tests;

pub(crate) mod profile;
pub(crate) mod rules;
