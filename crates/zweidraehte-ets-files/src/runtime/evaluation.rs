//! The immutable boundary between editable product state and image lowering.

use std::borrow::Cow;
use std::collections::HashSet;

use super::Device;
use super::configuration::{
    ConfigurationError, EffectiveComObject, ObjectSetting, ProductConfiguration, configuration_from_device,
    effective_com_objects, effective_default, validate_configuration, validate_stored_setting,
};
use super::model::ParameterValue;
use crate::product::{MaterializedModule, ProductData, SelectedProduct};
use crate::schema::{ParameterRef, ParameterTypeDef};

/// Why a value participates in the ordered programming overlays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterSource<'a> {
    /// Seed ordinary memory parameters and designated default union members.
    Default,
    /// Apply an exact visible ParameterRef. Keep competing references until
    /// encoding: different semantic values can produce identical bytes. The
    /// overlay's [`ReferenceWriteOrder`] decides which competitor is stored.
    Reference(Cow<'a, str>),
    /// Apply an authored base edit, hidden legacy patch or property value.
    Value,
    /// Replace the first entry for this storage ID, or append if absent.
    /// Property lowering reads the first match, so appending alone is wrong.
    Derived,
}

/// One typed input to programming, before protocol byte encoding.
///
/// IDs of module parameters/references use `instance_id::local_id`; the prefix
/// identifies an entry in [`EvaluatedProduct::modules`]. UI-only parameters and
/// inactive module instances have no overlay. This is separate from the sorted,
/// non-default authored edits in [`EvaluatedProduct::settings`].
#[derive(Debug, Clone)]
pub struct ParameterOverlay<'a> {
    pub id: Cow<'a, str>,
    pub source: ParameterSource<'a>,
    pub value: Cow<'a, ParameterValue>,
    pub parameter_type: Option<&'a ParameterTypeDef>,
    pub size_bits: u16,
    /// Present exactly for [`ParameterSource::Reference`] overlays.
    pub reference_order: Option<ReferenceWriteOrder>,
}

// ================================================================================
// Competing visible references
// ================================================================================

/// Where one visible ParameterRef falls among the others for its stored
/// parameter when a download writes them.
///
/// Every active reference owns its own value, and the reference tool writes
/// each active reference's value to the shared storage in turn, so the last
/// write survives. References are written in this order:
///
/// 1. references without a numeric `Tag` before tagged ones;
/// 2. tagged references by ascending tag;
/// 3. untagged references by the ascending number in their `_R-<n>` suffix.
///
/// Two tagged references with equal tags have no defined order, and neither
/// does an untagged reference whose ID lacks a number. Those pairs are
/// incomparable, so callers must refuse them when their bytes differ.
/// Witness: M-011F_A-0693-24 P-11, whose always-visible R-12 stores 1 and
/// whose hidden R-126 (visible while P-12 is 0) stores 4; the download
/// stores 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferenceWriteOrder {
    tag: Option<u32>,
    number: Option<u32>,
}

impl ReferenceWriteOrder {
    /// Read the order from a reference's own ID and `Tag`, without any module
    /// instance prefix.
    pub fn of(reference: &ParameterRef) -> ReferenceWriteOrder {
        // An unsigned decimal tag counts; any other text behaves as no tag.
        // TODO: also accept a leading `-0`, which the reference tool's
        // integer parser reads as zero; no corpus product uses one.
        let tag = reference.tag.as_deref().and_then(|tag| tag.trim().parse().ok());
        let number = reference.id.rsplit_once("_R-").and_then(|(_, number)| number.parse().ok());
        ReferenceWriteOrder { tag, number }
    }
}

impl PartialOrd for ReferenceWriteOrder {
    /// `Greater` means written later, so its value survives.
    fn partial_cmp(&self, other: &ReferenceWriteOrder) -> Option<std::cmp::Ordering> {
        use std::cmp::Ordering;
        match (self.tag, other.tag) {
            (Some(left), Some(right)) if left == right => None,
            (Some(left), Some(right)) => Some(left.cmp(&right)),
            (Some(_), None) => Some(Ordering::Greater),
            (None, Some(_)) => Some(Ordering::Less),
            (None, None) => match (self.number, other.number) {
                (Some(left), Some(right)) => Some(left.cmp(&right)),
                _ => None,
            },
        }
    }
}

/// An exact requested selector, including controls hidden from the editor.
/// The consumer decides which value types its procedure language can compare.
#[derive(Debug, Clone, Copy)]
pub struct ProcedureSelector<'a> {
    pub value: &'a ParameterValue,
    pub active: bool,
}

/// One checked product configuration, borrowing the editor so later mutations
/// cannot silently invalidate its settings, objects or resolved geometry.
///
/// The editor cannot change while an evaluation is still in use:
/// ```compile_fail,E0502
/// use zweidraehte_ets_files::Device;
/// use zweidraehte_ets_files::runtime::model::ParameterValue;
/// fn stale_preview(device: &mut Device) {
///     let evaluated = device.evaluate(&[]).expect("valid product");
///     device.set_parameter_value("brightness", ParameterValue::Integer(50));
///     let _ = evaluated.product();
/// }
/// ```
pub struct EvaluatedProduct<'a> {
    device: &'a Device,
    settings: ProductConfiguration,
    objects: Vec<EffectiveComObject>,
    product: ProductData,
    modules: Vec<MaterializedModule>,
}

impl std::fmt::Debug for EvaluatedProduct<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvaluatedProduct")
            .field("product", &self.product.id())
            .field("edited_parameters", &self.settings.parameters.len())
            .field("objects", &self.objects.len())
            .field("modules", &self.modules.len())
            .finish_non_exhaustive()
    }
}

impl<'a> EvaluatedProduct<'a> {
    pub(crate) fn new(
        device: &'a Device,
        selected: &SelectedProduct,
        objects: &[ObjectSetting],
    ) -> Result<Self, ConfigurationError> {
        if let Some(error) = device.derivation_error() {
            return Err(ConfigurationError::Derivation(error.to_owned()));
        }
        // Export omits defaults and inactive union/module branches. Check edits
        // before that filtering so unknown IDs and invalid values cannot vanish
        // into an apparently valid preview. Inactive module instances retain
        // their draft values, but are not members of this evaluated product.
        for (id, value) in device.edited_parameter_values() {
            validate_stored_setting(device, id, value)?;
        }
        let mut settings = configuration_from_device(device);
        settings.objects = objects.to_vec();
        validate_configuration(device, &settings)?;
        let objects = effective_com_objects(device, &settings);

        // Retain the exact allocator results used for geometry. Lowering takes
        // this same roster instead of reconstructing it from editor state.
        let mut modules = device.all_expanded_modules().map(MaterializedModule::from).collect::<Vec<_>>();
        modules.sort_by(|left, right| left.instance_id.cmp(&right.instance_id));
        let product = selected.product().resolve_module_geometry(&modules)?;
        Ok(Self { device, settings, objects, product, modules })
    }

    pub fn device(&self) -> &Device {
        self.device
    }
    pub fn settings(&self) -> &ProductConfiguration {
        &self.settings
    }
    pub fn objects(&self) -> &[EffectiveComObject] {
        &self.objects
    }
    pub fn product(&self) -> &ProductData {
        &self.product
    }

    /// Active module instances and final arguments used to resolve the product's
    /// geometry, sorted by instance ID. Inactive draft instances are omitted.
    pub fn modules(&self) -> &[MaterializedModule] {
        &self.modules
    }

    /// Visit programming inputs in order: memory defaults, visible references
    /// (or base edits without a reference layer), legacy/property values, then
    /// derived replacements: stored calculation results behind hidden blocks
    /// and active assignments. Do not sort or deduplicate by storage ID: distinct
    /// union members and competing references must reach the byte encoder.
    /// Values and root IDs borrow the evaluation where available; this does not
    /// clone editor state.
    pub fn parameter_overlays(&self) -> impl Iterator<Item = ParameterOverlay<'_>> {
        let defaults =
            self.product.parameters().iter().filter(|location| location.seeds_default).filter_map(|location| {
                self.overlay(
                    Cow::Borrowed(&location.id),
                    Cow::Borrowed(self.parameter_value(&location.id)?),
                    ParameterSource::Default,
                    None,
                )
            });

        let mut references = Vec::new();
        let mut seen = HashSet::new();
        if self.device.static_section().parameter_refs.as_ref().is_some_and(|refs| !refs.refs.is_empty()) {
            for reference in self.device.visible_param_refs() {
                let id = Cow::Borrowed(reference.ref_id.as_str());
                seen.insert(id.clone());
                references.push((id, Cow::Borrowed(reference.id.as_str()), Some(ReferenceWriteOrder::of(reference))));
            }
        } else {
            for parameter in &self.settings.parameters {
                let id = Cow::Borrowed(parameter.id.as_str());
                if seen.insert(id.clone()) {
                    references.push((id.clone(), id, None));
                }
            }
        }
        for parameter in self.device.visible_module_parameter_refs() {
            let id: Cow<'_, str> =
                Cow::Owned(format!("{}::{}", parameter.module.instance_id, parameter.reference.ref_id));
            let reference = Cow::Owned(format!("{}::{}", parameter.module.instance_id, parameter.reference.id));
            seen.insert(id.clone());
            references.push((id, reference, Some(ReferenceWriteOrder::of(parameter.reference))));
        }
        for location in self.product.parameters().iter().filter(|location| location.legacy_patch_always) {
            let id = Cow::Borrowed(location.id.as_str());
            if seen.insert(id.clone()) {
                references.push((id.clone(), id, None));
            }
        }
        for location in self.product.property_parameters() {
            let id = Cow::Borrowed(location.id.as_str());
            if seen.insert(id.clone()) {
                references.push((id.clone(), id, None));
            }
        }
        let references = references.into_iter().filter_map(|(id, value_id, order)| {
            let value = self
                .parameter_value(&value_id)
                .map(Cow::Borrowed)
                .or_else(|| effective_default(self.device, &value_id).map(Cow::Owned))?;
            let (source, order) = if id == value_id {
                (ParameterSource::Value, None)
            } else {
                (ParameterSource::Reference(value_id), order)
            };
            self.overlay(id, value, source, order)
        });
        // Active references behind hidden blocks normally hold their
        // defaults, which the memory seed already covers. A calculation can
        // store a different value there; like an assignment, it replaces the
        // default rather than competing with it.
        let calculated = self.device.hidden_active_edits().into_iter().filter_map(|(id, reference)| {
            let value = self.parameter_value(&reference)?;
            self.overlay(Cow::Owned(id), Cow::Borrowed(value), ParameterSource::Derived, None)
        });
        let derived = self.device.derived_parameter_values().into_iter().filter_map(|(id, value)| {
            self.overlay(Cow::Owned(id), Cow::Borrowed(value), ParameterSource::Derived, None)
        });
        defaults.chain(references).chain(calculated).chain(derived)
    }

    /// Resolve only the selector a procedure requests, without exporting every
    /// editor control. Accepts root IDs and `instance_id::local_id` module IDs.
    /// Missing parameters and inactive module instances return `None`; existing
    /// refs outside an active branch retain their value with `active = false`.
    pub fn procedure_selector(&self, id: &str) -> Option<ProcedureSelector<'_>> {
        let value = self.parameter_value(id)?;
        let active = match id.split_once("::") {
            Some((instance, reference)) => self.device.is_module_param_ref_active(instance, reference),
            None if self.device.program().dynamic.is_none() => true,
            None => self.device.is_param_ref_active(id),
        };
        Some(ProcedureSelector { value, active })
    }

    fn parameter_value(&self, id: &str) -> Option<&ParameterValue> {
        if id.contains("::") {
            self.device.get_module_parameter_value_by_composite_id(id)
        } else {
            self.device.get_parameter_value(id)
        }
    }

    fn overlay<'s>(
        &'s self,
        id: Cow<'s, str>,
        value: Cow<'s, ParameterValue>,
        source: ParameterSource<'s>,
        reference_order: Option<ReferenceWriteOrder>,
    ) -> Option<ParameterOverlay<'s>> {
        let size_bits = self
            .product
            .parameters()
            .iter()
            .find(|location| location.id == id)
            .map(|location| location.size_bits)
            .or_else(|| {
                self.product.property_parameters().iter().find(|location| location.id == id).map(|p| p.size_bits)
            })?;
        let parameter_type = self
            .device
            .get_configuration_parameter_info(&id)
            .and_then(|info| self.device.get_parameter_type(&info.type_id))
            .map(|parameter_type| &parameter_type.type_def);
        Some(ParameterOverlay { id, source, value, parameter_type, size_bits, reference_order })
    }

    /// Transfer the resolved product and its module roster without cloning.
    /// Lowering reads the settings and object views before consuming these parts.
    pub fn into_parts(self) -> (ProductData, Vec<MaterializedModule>) {
        (self.product, self.modules)
    }

    /// Transfer only the resolved product, discarding the other evaluated values.
    pub fn into_product(self) -> ProductData {
        self.product
    }
}
