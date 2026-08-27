//! Product-aware parameter and communication-object configuration.
//!
//! Installation formats do not belong in the product parser. This module
//! accepts small format-neutral settings and applies the product semantics
//! which need a live [`Device`]: typed value validation, dynamic visibility,
//! visible `ParameterRef` defaults, and the base → visible-ref → project flag
//! layering. Addresses, memberships, credentials, and persistence stay in
//! the host project layer.

use thiserror::Error;
use zweidraehte_proto::messages::knx::Priority;

use crate::schema::{ComObject, ComObjectPriority, EnableFlag, ParameterTypeDef};

use super::device::Device;
use super::model::ParameterValue;

// ============================================================================
// Format-neutral product settings
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct ProductConfiguration {
    pub parameters: Vec<ParameterSetting>,
    pub objects: Vec<ObjectSetting>,
}

/// One full MTXML parameter ID and its authored value.
#[derive(Debug, Clone, PartialEq)]
pub struct ParameterSetting {
    /// The full MTXML parameter id (`M-0083_A-009B-14-E59D_P-24`) —
    /// the one identifier that is unique per parameter; names are not.
    pub id: String,
    pub value: ParameterValue,
}

/// Project overrides for one visible communication object.
#[derive(Debug, Clone, Copy, Default)]
pub struct ObjectSetting {
    pub com_object: u16,
    pub flags: ObjectFlagOverrides,
}

/// Per-flag overrides; `None` keeps the product's setting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ObjectFlagOverrides {
    pub read: Option<bool>,
    pub write: Option<bool>,
    pub communication: Option<bool>,
    pub transmit: Option<bool>,
    pub update: Option<bool>,
    pub read_on_init: Option<bool>,
    pub priority: Option<Priority>,
}

/// What can go wrong while applying authored product settings.
#[derive(Debug, Error)]
pub enum ConfigurationError {
    #[error("the product defines no parameter `{0}`")]
    UnknownParameter(String),
    #[error("parameter `{0}` is not user-configurable (its access is None or Read)")]
    NotConfigurable(String),
    #[error(
        "parameter `{0}` is not visible under the configured values — \
         another choice (a different mode, or another member of its \
         union) currently owns it"
    )]
    NotVisible(String),
    #[error("parameter `{param}`: {reason}")]
    InvalidValue { param: String, reason: String },
    #[error("the product defines no com object number {0}")]
    UnknownComObject(u16),
    #[error("com object {0} is not visible under the configured values")]
    ComObjectNotVisible(u16),
}

// ============================================================================
// Applying configuration to a device
// ============================================================================

/// Apply authored product settings to a freshly-constructed device.
///
/// Parameter values are set first — all of them, since visibility
/// conditions may depend on other overridden parameters — and only
/// then validated for visibility under the *final* configuration.
/// That visibility check is what protects union members: writing a
/// value for a member whose alternative is active would corrupt the
/// shared bytes.
///
/// On error the device holds a partial configuration; callers use a
/// scratch `Device` and discard it. Flag overrides are validated here
/// but consumed by [`effective_com_objects`].
pub fn apply_configuration(
    device: &mut Device,
    configuration: &ProductConfiguration,
) -> Result<(), ConfigurationError> {
    for param in &configuration.parameters {
        let info = device
            .get_parameter_info(&param.id)
            .ok_or_else(|| ConfigurationError::UnknownParameter(param.id.clone()))?;
        if info.hidden || info.read_only {
            return Err(ConfigurationError::NotConfigurable(param.id.clone()));
        }
        validate_value(device, &param.id, &param.value)?;
        device.set_parameter_value(&param.id, param.value.clone());
    }

    // Visibility and writability under the final configuration. A
    // parameter is user-configurable when some visible ref targets it
    // whose effective access — the ref's override, else the base
    // parameter's (already known to be ReadWrite from the check above)
    // — is neither None (hidden) nor Read (display-only). The
    // visibility half is what protects union members: writing a value
    // for a member whose alternative is active would corrupt the
    // shared bytes.
    for param in &configuration.parameters {
        // Small BCU-era product files may expose the base parameter table
        // directly and have no reference/dynamic layer at all. In that shape
        // the base parameter is the visible configuration surface.
        if !has_parameter_references(device) {
            continue;
        }
        let mut visibly_referenced = false;
        let mut writable = false;
        for r in device.visible_param_refs().filter(|r| r.ref_id == param.id) {
            match r.access.as_deref() {
                Some("None") => {}
                Some("Read") => visibly_referenced = true,
                _ => {
                    visibly_referenced = true;
                    writable = true;
                }
            }
        }
        if !visibly_referenced {
            return Err(ConfigurationError::NotVisible(param.id.clone()));
        }
        if !writable {
            return Err(ConfigurationError::NotConfigurable(param.id.clone()));
        }
    }

    let visible_objects = visible_object_numbers(device);
    for object in &configuration.objects {
        if !visible_objects.contains(&object.com_object) {
            return Err(if object_exists(device, object.com_object) {
                ConfigurationError::ComObjectNotVisible(object.com_object)
            } else {
                ConfigurationError::UnknownComObject(object.com_object)
            });
        }
    }

    Ok(())
}

/// Check a value against the parameter's declared type.
fn validate_value(device: &Device, param_id: &str, value: &ParameterValue) -> Result<(), ConfigurationError> {
    let invalid = |reason: String| ConfigurationError::InvalidValue { param: param_id.to_string(), reason };

    let info = device.get_parameter_info(param_id).expect("caller resolved the parameter already");
    let Some(param_type) = device.get_parameter_type(&info.type_id) else {
        // A parameter without a resolvable type cannot be validated —
        // or encoded into memory later — so reject it here.
        return Err(invalid(format!("its type `{}` is not defined by the product", info.type_id)));
    };

    match (&param_type.type_def, value) {
        (ParameterTypeDef::TypeNumber(n), ParameterValue::Integer(i)) => {
            if *i < n.min_inclusive || *i > n.max_inclusive {
                return Err(invalid(format!(
                    "{i} is outside the allowed range {}..={}",
                    n.min_inclusive, n.max_inclusive
                )));
            }
        }
        (ParameterTypeDef::TypeRestriction(r), ParameterValue::Integer(i)) => {
            if !r.enumerations.iter().any(|e| i64::from(e.value) == *i) {
                let choices: Vec<String> = r.enumerations.iter().map(|e| format!("{} = {}", e.value, e.text)).collect();
                return Err(invalid(format!("{i} is not one of: {}", choices.join(", "))));
            }
        }
        (ParameterTypeDef::TypeFloat(f), ParameterValue::Integer(i)) => {
            let as_float = *i as f64;
            if as_float < f.min_inclusive || as_float > f.max_inclusive {
                return Err(invalid(format!(
                    "{i} is outside the allowed range {}..={}",
                    f.min_inclusive, f.max_inclusive
                )));
            }
        }
        (ParameterTypeDef::TypeFloat(f), ParameterValue::Float(v)) => {
            if *v < f.min_inclusive || *v > f.max_inclusive {
                return Err(invalid(format!(
                    "{v} is outside the allowed range {}..={}",
                    f.min_inclusive, f.max_inclusive
                )));
            }
        }
        (ParameterTypeDef::TypeText(t), ParameterValue::Text(s)) => {
            let capacity = (t.size_in_bit / 8) as usize;
            if s.len() > capacity {
                return Err(invalid(format!("{} bytes of text exceed the field's {capacity}", s.len())));
            }
        }
        (ParameterTypeDef::TypeColor(color), ParameterValue::Text(value)) => {
            if color.space.decode_value(value).is_none() {
                return Err(invalid(format!(
                    "{value:?} is not a #{} value for {}",
                    "HH".repeat(usize::from(color.space.size_bits() / 8)),
                    color.space.name()
                )));
            }
        }
        (ParameterTypeDef::TypeTime(time), ParameterValue::Integer(value)) => {
            if *value < time.min_inclusive || *value > time.max_inclusive {
                return Err(invalid(format!(
                    "{value} {} is outside the allowed range {}..={}",
                    time.unit.value_unit(),
                    time.min_inclusive,
                    time.max_inclusive
                )));
            }

            if !time.accepts_value(*value) {
                return Err(invalid(format!(
                    "{value} cannot be represented by this {}-bit time parameter",
                    time.size_in_bit
                )));
            }
        }
        (ParameterTypeDef::TypeNumber(_) | ParameterTypeDef::TypeRestriction(_), _) => {
            return Err(invalid("this parameter takes an integer value".to_string()));
        }
        (ParameterTypeDef::TypeFloat(_), _) => {
            return Err(invalid("this parameter takes a numeric value".to_string()));
        }
        (ParameterTypeDef::TypeText(_), _) => {
            return Err(invalid("this parameter takes a text value".to_string()));
        }
        (ParameterTypeDef::TypeColor(_), _) => {
            return Err(invalid("this parameter takes a colour value such as #FFFFFF".to_string()));
        }
        (ParameterTypeDef::TypeTime(time), _) => {
            return Err(invalid(format!("this parameter takes an integer value in {}", time.unit.value_unit())));
        }
        (ParameterTypeDef::TypeNone(_) | ParameterTypeDef::TypePicture(_) | ParameterTypeDef::TypeIpAddress(_), _) => {
            return Err(invalid("this parameter type is not configurable through the project".to_string()));
        }
    }
    Ok(())
}

// ============================================================================
// Reading configuration back out of a device
// ============================================================================

/// The effective default of a visible parameter: a visible
/// `ParameterRef` may override the base parameter's `Value`, and for
/// this product family (the MDT programs carry hundreds of such
/// overrides) that override *is* the default ETS shows and writes.
pub fn effective_default(device: &Device, param_id: &str) -> Option<ParameterValue> {
    let ref_override = device
        .visible_param_refs()
        .find(|r| r.ref_id == param_id)
        .and_then(|r| r.value.as_deref())
        .map(|raw| device.parse_value_typed(param_id, raw));
    ref_override.or_else(|| {
        device.get_parameter_info(param_id).map(|info| device.parse_value_typed(param_id, &info.default_value))
    })
}

/// Capture touched parameter values which differ from their effective
/// product/ref default. Object overrides are installation state and cannot be
/// inferred from a [`Device`], so callers retain those separately.
pub fn configuration_from_device(device: &Device) -> ProductConfiguration {
    let mut parameters = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let visible_ids: Vec<&str> = if has_parameter_references(device) {
        device.visible_param_refs().map(|param_ref| param_ref.ref_id.as_str()).collect()
    } else {
        // With no reference table the base parameters are the authored
        // surface. Hidden/read-only entries can never become touched through
        // `apply_configuration`, and untouched internal defaults are omitted.
        device.parameter_infos().filter(|info| !info.hidden && !info.read_only).map(|info| info.id.as_str()).collect()
    };
    for id in visible_ids {
        if !seen.insert(id) || !device.is_parameter_touched(id) {
            continue;
        }
        let Some(current) = device.get_parameter_value(id) else { continue };
        if effective_default(device, id).as_ref() != Some(current) {
            parameters.push(ParameterSetting { id: id.to_string(), value: current.clone() });
        }
    }
    parameters.sort_by(|a, b| a.id.cmp(&b.id));
    ProductConfiguration { parameters, objects: Vec::new() }
}

// ============================================================================
// Effective com objects
// ============================================================================

/// One com object as it would land in the device's group object
/// table: the base `ComObject` definition, overridden by the visible
/// `ComObjectRef`, overridden by the project's flag section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveComObject {
    pub number: u16,
    /// ETS's size spelling (`"1 Bit"`, `"1 Byte"` …), ref-overridable.
    pub object_size: String,
    pub datapoint_type: Option<String>,
    pub priority: Priority,
    pub read: bool,
    pub write: bool,
    pub communication: bool,
    pub transmit: bool,
    pub update: bool,
    pub read_on_init: bool,
    /// Display text (ref override first), for dump/report output.
    pub text: String,
    pub function_text: String,
    pub flag_sources: EffectiveFlagSources,
}

/// One reference from an MTXML communication object's `DatapointType`
/// attribute.
///
/// That attribute is an XML Schema `IDREFS`, so real products commonly
/// encode one effective subtype as a hierarchy such as
/// `DPT-1 DPST-1-1`. Keeping the list interpretation here prevents callers
/// from mistaking the whole whitespace-separated value for one identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductDptReference {
    pub main: u16,
    pub subtype: Option<u16>,
}

/// Parsed MTXML datapoint references in source order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductDptReferences {
    references: Vec<ProductDptReference>,
}

impl ProductDptReferences {
    /// Parse `DPT-n`, `DPST-n-m`, and the canonical project spelling
    /// `n.m`. Every whitespace-separated reference must be valid.
    pub fn parse(value: &str) -> Option<Self> {
        let references = value.split_whitespace().map(parse_product_dpt_reference).collect::<Option<Vec<_>>>()?;
        (!references.is_empty()).then_some(Self { references })
    }

    /// Test a project DPT against the product annotation.
    ///
    /// A subtype reference is more specific than its accompanying main-type
    /// reference. Thus `DPT-1 DPST-1-1` accepts `1.001`, not every DPT-1
    /// subtype. Products that name only `DPT-1` accept any subtype in that
    /// main type.
    pub fn accepts(&self, candidate: ProductDptReference) -> bool {
        let has_subtypes =
            self.references.iter().any(|reference| reference.main == candidate.main && reference.subtype.is_some());
        self.references.iter().any(|reference| {
            reference.main == candidate.main && if has_subtypes { reference.subtype == candidate.subtype } else { true }
        })
    }

    /// Prefer the first explicit subtype, falling back to the first generic
    /// main-type reference. This matches the conventional `DPT DPST` pair
    /// emitted by Manufacturer Tool and gives editors a deterministic default.
    pub fn preferred(&self) -> ProductDptReference {
        self.references.iter().copied().find(|reference| reference.subtype.is_some()).unwrap_or(self.references[0])
    }
}

fn parse_product_dpt_reference(value: &str) -> Option<ProductDptReference> {
    if let Some(value) = value.strip_prefix("DPST-") {
        let (main, subtype) = value.split_once('-')?;
        return Some(ProductDptReference { main: main.parse().ok()?, subtype: Some(subtype.parse().ok()?) });
    }
    if let Some(main) = value.strip_prefix("DPT-") {
        return Some(ProductDptReference { main: main.parse().ok()?, subtype: None });
    }
    let (main, subtype) = value.split_once('.')?;
    Some(ProductDptReference { main: main.parse().ok()?, subtype: Some(subtype.parse().ok()?) })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveValueSource {
    Product,
    VisibleReference,
    Project,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveFlagSources {
    pub priority: EffectiveValueSource,
    pub read: EffectiveValueSource,
    pub write: EffectiveValueSource,
    pub communication: EffectiveValueSource,
    pub transmit: EffectiveValueSource,
    pub update: EffectiveValueSource,
    pub read_on_init: EffectiveValueSource,
}

/// Resolve the com objects visible under the device's current
/// configuration, with ref and project overrides applied, ascending by
/// number.
///
/// When several refs of one object are visible at once the first one
/// wins; the vendor programs use choose/when to keep at most one
/// visible, so a collision is product-data noise rather than a state
/// we can order meaningfully.
pub fn effective_com_objects(device: &Device, configuration: &ProductConfiguration) -> Vec<EffectiveComObject> {
    let enabled = |flag: &EnableFlag| matches!(flag, EnableFlag::Enabled);
    let ref_flag = |over: &Option<EnableFlag>, base: &EnableFlag| enabled(over.as_ref().unwrap_or(base));
    let source = |project: bool, reference: bool| {
        if project {
            EffectiveValueSource::Project
        } else if reference {
            EffectiveValueSource::VisibleReference
        } else {
            EffectiveValueSource::Product
        }
    };

    let mut by_number: std::collections::BTreeMap<u16, EffectiveComObject> = std::collections::BTreeMap::new();
    for object_ref in device.visible_com_object_refs() {
        let Some(base) = device.get_com_object(&object_ref.ref_id) else { continue };
        let flags = configuration
            .objects
            .iter()
            .find(|object| object.com_object == base.number)
            .map(|object| object.flags)
            .unwrap_or_default();

        by_number.entry(base.number).or_insert_with(|| EffectiveComObject {
            number: base.number,
            object_size: object_ref.object_size.clone().unwrap_or_else(|| base.object_size.clone()),
            datapoint_type: object_ref.datapoint_type.clone().or_else(|| base.datapoint_type.clone()),
            priority: flags
                .priority
                .unwrap_or_else(|| schema_priority(object_ref.priority.or(base.priority).unwrap_or_default())),
            read: flags.read.unwrap_or_else(|| ref_flag(&object_ref.read_flag, &base.read_flag)),
            write: flags.write.unwrap_or_else(|| ref_flag(&object_ref.write_flag, &base.write_flag)),
            communication: flags
                .communication
                .unwrap_or_else(|| ref_flag(&object_ref.communication_flag, &base.communication_flag)),
            transmit: flags.transmit.unwrap_or_else(|| ref_flag(&object_ref.transmit_flag, &base.transmit_flag)),
            update: flags.update.unwrap_or_else(|| ref_flag(&object_ref.update_flag, &base.update_flag)),
            read_on_init: flags
                .read_on_init
                .unwrap_or_else(|| ref_flag(&object_ref.read_on_init_flag, &base.read_on_init_flag)),
            text: object_ref.text.clone().unwrap_or_else(|| base.text.clone()),
            function_text: object_ref.function_text.clone().unwrap_or_else(|| base.function_text.clone()),
            flag_sources: EffectiveFlagSources {
                priority: source(flags.priority.is_some(), object_ref.priority.is_some()),
                read: source(flags.read.is_some(), object_ref.read_flag.is_some()),
                write: source(flags.write.is_some(), object_ref.write_flag.is_some()),
                communication: source(flags.communication.is_some(), object_ref.communication_flag.is_some()),
                transmit: source(flags.transmit.is_some(), object_ref.transmit_flag.is_some()),
                update: source(flags.update.is_some(), object_ref.update_flag.is_some()),
                read_on_init: source(flags.read_on_init.is_some(), object_ref.read_on_init_flag.is_some()),
            },
        });
    }

    // A reference table makes visibility explicit. Without one, the product
    // directly exposes its base COT — the compact MTXML shape used by BCU1,
    // BCU2, and conformance products with no dynamic UI.
    if !has_com_object_references(device)
        && let Some(table) = &device.static_section().com_object_table
    {
        for base in &table.objects {
            let flags = configuration
                .objects
                .iter()
                .find(|object| object.com_object == base.number)
                .map(|object| object.flags)
                .unwrap_or_default();
            by_number.insert(base.number, EffectiveComObject {
                number: base.number,
                object_size: base.object_size.clone(),
                datapoint_type: base.datapoint_type.clone(),
                priority: flags.priority.unwrap_or_else(|| schema_priority(base.priority.unwrap_or_default())),
                read: flags.read.unwrap_or_else(|| enabled(&base.read_flag)),
                write: flags.write.unwrap_or_else(|| enabled(&base.write_flag)),
                communication: flags.communication.unwrap_or_else(|| enabled(&base.communication_flag)),
                transmit: flags.transmit.unwrap_or_else(|| enabled(&base.transmit_flag)),
                update: flags.update.unwrap_or_else(|| enabled(&base.update_flag)),
                read_on_init: flags.read_on_init.unwrap_or_else(|| enabled(&base.read_on_init_flag)),
                text: base.text.clone(),
                function_text: base.function_text.clone(),
                flag_sources: EffectiveFlagSources {
                    priority: source(flags.priority.is_some(), false),
                    read: source(flags.read.is_some(), false),
                    write: source(flags.write.is_some(), false),
                    communication: source(flags.communication.is_some(), false),
                    transmit: source(flags.transmit.is_some(), false),
                    update: source(flags.update.is_some(), false),
                    read_on_init: source(flags.read_on_init.is_some(), false),
                },
            });
        }
    }
    by_number.into_values().collect()
}

fn schema_priority(priority: ComObjectPriority) -> Priority {
    match priority {
        ComObjectPriority::Low => Priority::Low,
        ComObjectPriority::High => Priority::High,
        ComObjectPriority::Alert => Priority::Alarm,
    }
}

fn visible_object_numbers(device: &Device) -> std::collections::HashSet<u16> {
    if !has_com_object_references(device) {
        return device
            .static_section()
            .com_object_table
            .as_ref()
            .into_iter()
            .flat_map(|table| table.objects.iter().map(|object| object.number))
            .collect();
    }
    device.visible_com_object_refs().filter_map(|r| device.get_com_object(&r.ref_id)).map(|o| o.number).collect()
}

fn has_parameter_references(device: &Device) -> bool {
    device.static_section().parameter_refs.as_ref().is_some_and(|references| !references.refs.is_empty())
}

fn has_com_object_references(device: &Device) -> bool {
    device.static_section().com_object_refs.as_ref().is_some_and(|references| !references.refs.is_empty())
}

fn object_exists(device: &Device, number: u16) -> bool {
    fn in_table(objects: &[ComObject], number: u16) -> bool {
        objects.iter().any(|o| o.number == number)
    }
    device.static_section().com_object_table.as_ref().is_some_and(|t| in_table(&t.objects, number))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::model::{VisibilityVisitor, walk_dynamic};
    use crate::runtime::parser::parse_application_program;

    /// A program with the shapes the configuration layer must handle: a
    /// selector-driven choose (mode 0 shows one union member and a
    /// plain com-object ref; mode 1 shows the other member, a level
    /// parameter whose *ref* overrides the default, and a com-object
    /// ref that overrides flags), plus an always-visible hidden
    /// parameter, an editable base parameter inside an invisible block,
    /// and two read-only shapes: a union member whose base access is
    /// "Read", and a parameter whose only visible ref overrides access
    /// to "Read". The invisible block also gates a communication object,
    /// since its dynamic logic remains active despite having no parameter UI.
    const FIXTURE: &str = r#"<KNX xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="zweidraehte" ToolVersion="0.1.0" xmlns="http://knx.org/xml/project/20">
  <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
    <ApplicationProgram Id="M-00FA_A-1" ApplicationNumber="1" ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-0705" Name="Fixture" LoadProcedureStyle="ProductProcedure" PeiType="0" DefaultLanguage="de-DE" DynamicTableManagement="false" Linkable="false">
      <Static>
        <Code><AbsoluteSegment Id="M-00FA_A-1_AS-4300" Address="17152" Size="8" MemoryType="EEPROM" /></Code>
        <ParameterTypes>
          <ParameterType Id="M-00FA_A-1_PT-MODE" Name="Mode"><TypeRestriction Base="Value" SizeInBit="8"><Enumeration Text="Off" Value="0" Id="M-00FA_A-1_PT-MODE_EN-0" /><Enumeration Text="On" Value="1" Id="M-00FA_A-1_PT-MODE_EN-1" /></TypeRestriction></ParameterType>
          <ParameterType Id="M-00FA_A-1_PT-N8" Name="N8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="100" /></ParameterType>
          <ParameterType Id="M-00FA_A-1_PT-TXT" Name="T240"><TypeText SizeInBit="240" /></ParameterType>
          <ParameterType Id="M-00FA_A-1_PT-TIME" Name="Duration"><TypeTime SizeInBit="24" Unit="PackedDaysHoursMinutesAndSeconds" minInclusive="0" maxInclusive="86400" UIHint="Duration_hhmmss" /></ParameterType>
        </ParameterTypes>
        <Parameters>
          <Parameter Id="M-00FA_A-1_P-1" Name="Mode" ParameterType="M-00FA_A-1_PT-MODE" Text="Mode" Value="0"><Memory CodeSegment="M-00FA_A-1_AS-4300" Offset="0" BitOffset="0" /></Parameter>
          <Parameter Id="M-00FA_A-1_P-2" Name="Level" ParameterType="M-00FA_A-1_PT-N8" Text="Level" Value="50"><Memory CodeSegment="M-00FA_A-1_AS-4300" Offset="1" BitOffset="0" /></Parameter>
          <Parameter Id="M-00FA_A-1_P-3" Name="Internal" ParameterType="M-00FA_A-1_PT-N8" Text="" Access="None" Value="7"><Memory CodeSegment="M-00FA_A-1_AS-4300" Offset="2" BitOffset="0" /></Parameter>
          <Parameter Id="M-00FA_A-1_P-6" Name="Description" ParameterType="M-00FA_A-1_PT-TXT" Text="Description" Value="" />
          <Parameter Id="M-00FA_A-1_P-8" Name="RefLocked" ParameterType="M-00FA_A-1_PT-N8" Text="Ref locked" Value="4"><Memory CodeSegment="M-00FA_A-1_AS-4300" Offset="4" BitOffset="0" /></Parameter>
          <Parameter Id="M-00FA_A-1_P-9" Name="Duration" ParameterType="M-00FA_A-1_PT-TIME" Text="Duration" Value="60"><Memory CodeSegment="M-00FA_A-1_AS-4300" Offset="5" BitOffset="0" /></Parameter>
          <Parameter Id="M-00FA_A-1_P-10" Name="InternalSelector" ParameterType="M-00FA_A-1_PT-N8" Text="Internal selector" Value="1" />
          <Union SizeInBit="8">
            <Memory CodeSegment="M-00FA_A-1_AS-4300" Offset="3" BitOffset="0" />
            <Parameter Id="M-00FA_A-1_P-4" Name="OffChoice" ParameterType="M-00FA_A-1_PT-N8" Text="Off choice" Value="1" Offset="0" BitOffset="0" />
            <Parameter Id="M-00FA_A-1_P-5" Name="OnChoice" ParameterType="M-00FA_A-1_PT-N8" Text="On choice" Value="2" Offset="0" BitOffset="0" DefaultUnionParameter="true" />
            <Parameter Id="M-00FA_A-1_P-7" Name="ShownChoice" ParameterType="M-00FA_A-1_PT-N8" Text="Shown choice" Access="Read" Value="3" Offset="0" BitOffset="0" />
          </Union>
        </Parameters>
        <ParameterRefs>
          <ParameterRef Id="M-00FA_A-1_P-1_R-1" RefId="M-00FA_A-1_P-1" />
          <ParameterRef Id="M-00FA_A-1_P-2_R-2" RefId="M-00FA_A-1_P-2" Value="60" />
          <ParameterRef Id="M-00FA_A-1_P-2_R-11" RefId="M-00FA_A-1_P-2" Value="70" />
          <ParameterRef Id="M-00FA_A-1_P-3_R-3" RefId="M-00FA_A-1_P-3" />
          <ParameterRef Id="M-00FA_A-1_P-4_R-4" RefId="M-00FA_A-1_P-4" />
          <ParameterRef Id="M-00FA_A-1_P-5_R-5" RefId="M-00FA_A-1_P-5" />
          <ParameterRef Id="M-00FA_A-1_P-6_R-6" RefId="M-00FA_A-1_P-6" />
          <ParameterRef Id="M-00FA_A-1_P-7_R-7" RefId="M-00FA_A-1_P-7" Access="Read" />
          <ParameterRef Id="M-00FA_A-1_P-8_R-8" RefId="M-00FA_A-1_P-8" Access="Read" />
          <ParameterRef Id="M-00FA_A-1_P-9_R-9" RefId="M-00FA_A-1_P-9" />
          <ParameterRef Id="M-00FA_A-1_P-10_R-10" RefId="M-00FA_A-1_P-10" />
        </ParameterRefs>
        <ComObjectTable>
          <ComObject Id="M-00FA_A-1_O-1" Name="Switch" Text="Switch" Number="1" FunctionText="On/Off" ObjectSize="1 Bit" ReadFlag="Disabled" WriteFlag="Enabled" CommunicationFlag="Enabled" TransmitFlag="Disabled" UpdateFlag="Disabled" ReadOnInitFlag="Disabled" />
          <ComObject Id="M-00FA_A-1_O-2" Name="Status" Text="Status" Number="2" FunctionText="On/Off" ObjectSize="1 Bit" ReadFlag="Enabled" WriteFlag="Disabled" CommunicationFlag="Enabled" TransmitFlag="Enabled" UpdateFlag="Disabled" ReadOnInitFlag="Disabled" />
        </ComObjectTable>
        <ComObjectRefs>
          <ComObjectRef Id="M-00FA_A-1_O-1_R-1" RefId="M-00FA_A-1_O-1" />
          <ComObjectRef Id="M-00FA_A-1_O-1_R-2" RefId="M-00FA_A-1_O-1" ReadFlag="Enabled" Priority="High" Text="Switch (on)" />
          <ComObjectRef Id="M-00FA_A-1_O-2_R-3" RefId="M-00FA_A-1_O-2" />
        </ComObjectRefs>
      </Static>
      <Dynamic>
        <Channel Id="M-00FA_A-1_CH-1" Name="Main">
          <ParameterBlock Id="M-00FA_A-1_PB-1" Text="Main">
            <ParameterRefRef RefId="M-00FA_A-1_P-1_R-1" />
            <ParameterRefRef RefId="M-00FA_A-1_P-3_R-3" />
            <ParameterRefRef RefId="M-00FA_A-1_P-6_R-6" />
            <ParameterRefRef RefId="M-00FA_A-1_P-7_R-7" />
            <ParameterRefRef RefId="M-00FA_A-1_P-8_R-8" />
            <ParameterRefRef RefId="M-00FA_A-1_P-9_R-9" />
            <choose ParamRefId="M-00FA_A-1_P-1_R-1">
              <when test="0">
                <ParameterRefRef RefId="M-00FA_A-1_P-4_R-4" />
                <ComObjectRefRef RefId="M-00FA_A-1_O-1_R-1" />
              </when>
              <when test="1">
                <ParameterRefRef RefId="M-00FA_A-1_P-5_R-5" />
                <ParameterRefRef RefId="M-00FA_A-1_P-2_R-2" />
                <ParameterRefRef RefId="M-00FA_A-1_P-2_R-11" />
                <ComObjectRefRef RefId="M-00FA_A-1_O-1_R-2" />
              </when>
            </choose>
          </ParameterBlock>
          <ParameterBlock Id="M-00FA_A-1_PB-2" Text="Internal" Access="None">
            <ParameterRefRef RefId="M-00FA_A-1_P-10_R-10" />
            <choose ParamRefId="M-00FA_A-1_P-10_R-10">
              <when test="1">
                <ComObjectRefRef RefId="M-00FA_A-1_O-2_R-3" />
              </when>
            </choose>
          </ParameterBlock>
        </Channel>
      </Dynamic>
    </ApplicationProgram>
  </ApplicationPrograms></Manufacturer></ManufacturerData>
</KNX>"#;

    fn device() -> Device {
        let knx = parse_application_program(FIXTURE).expect("the fixture parses");
        let program =
            knx.manufacturer_data.manufacturer.application_programs.programs.into_iter().next().expect("one program");
        Device::new(program, None)
    }

    fn base_tables_device() -> Device {
        let knx = parse_application_program(FIXTURE).expect("the fixture parses");
        let mut program =
            knx.manufacturer_data.manufacturer.application_programs.programs.into_iter().next().expect("one program");
        program.static_section.parameter_refs = None;
        program.static_section.com_object_refs = None;
        Device::new(program, None)
    }

    fn param_id(suffix: &str) -> String {
        format!("M-00FA_A-1_P-{suffix}")
    }

    fn setting(id: &str, value: ParameterValue) -> ParameterSetting {
        ParameterSetting { id: param_id(id), value }
    }

    #[test]
    fn applies_values_before_recomputing_visibility() {
        let mut dev = device();
        let configuration = ProductConfiguration {
            parameters: vec![
                setting("1", ParameterValue::Integer(1)),
                // P-5 only becomes visible because P-1 flips first.
                setting("5", ParameterValue::Integer(9)),
            ],
            objects: Vec::new(),
        };
        apply_configuration(&mut dev, &configuration).expect("configuration applies");
        assert_eq!(dev.get_parameter_value(&param_id("5")), Some(&ParameterValue::Integer(9)));
    }

    #[test]
    fn applies_time_values_as_integer_counts_in_the_declared_unit() {
        let mut dev = device();
        let configuration = ProductConfiguration {
            parameters: vec![setting("9", ParameterValue::Integer(3_661))],
            objects: Vec::new(),
        };

        apply_configuration(&mut dev, &configuration).expect("time configuration applies");

        assert_eq!(dev.get_parameter_value(&param_id("9")), Some(&ParameterValue::Integer(3_661)));
    }

    #[test]
    fn invisible_blocks_hide_parameters_but_keep_dynamic_objects_active() {
        let mut dev = device();

        assert!(!dev.is_param_ref_visible("M-00FA_A-1_P-10_R-10"));
        assert!(dev.is_com_object_ref_visible("M-00FA_A-1_O-2_R-3"));

        let mut visitor = VisibilityVisitor::new();
        walk_dynamic(
            dev.dynamic_section().expect("the fixture has a dynamic section"),
            &mut visitor,
            &dev,
            dev.module_defs(),
        );

        assert!(!visitor.is_param_ref_visible("M-00FA_A-1_P-10_R-10"));
        assert!(visitor.is_com_object_ref_visible("M-00FA_A-1_O-2_R-3"));

        let error = apply_configuration(&mut dev, &ProductConfiguration {
            parameters: vec![setting("10", ParameterValue::Integer(0))],
            objects: Vec::new(),
        })
        .expect_err("an invisible block's parameter is rejected");

        assert!(error.to_string().contains("not visible"), "{error}");
    }

    #[test]
    fn rejects_hidden_read_only_bad_and_unknown_settings() {
        for (setting, expected) in [
            (setting("2", ParameterValue::Integer(10)), "not visible"),
            (setting("3", ParameterValue::Integer(1)), "not user-configurable"),
            (setting("1", ParameterValue::Integer(3)), "is not one of"),
            (setting("99", ParameterValue::Integer(0)), "defines no parameter"),
            (setting("7", ParameterValue::Integer(1)), "not user-configurable"),
            (setting("8", ParameterValue::Integer(1)), "not user-configurable"),
            (setting("9", ParameterValue::Integer(86_401)), "outside the allowed range"),
            (setting("9", ParameterValue::Text("01:00:00".to_string())), "takes an integer value in s"),
        ] {
            let mut dev = device();
            let error =
                apply_configuration(&mut dev, &ProductConfiguration { parameters: vec![setting], objects: Vec::new() })
                    .expect_err("invalid setting is rejected");
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn effective_default_and_configuration_export_use_visible_refs() {
        let mut dev = device();
        apply_configuration(&mut dev, &ProductConfiguration {
            parameters: vec![setting("1", ParameterValue::Integer(1))],
            objects: Vec::new(),
        })
        .expect("configuration applies");

        let visible_level_refs = dev
            .visible_param_refs()
            .filter(|parameter_ref| parameter_ref.ref_id == param_id("2"))
            .map(|parameter_ref| parameter_ref.id.as_str())
            .collect::<Vec<_>>();

        assert_eq!(visible_level_refs, ["M-00FA_A-1_P-2_R-2", "M-00FA_A-1_P-2_R-11"]);
        assert_eq!(effective_default(&dev, &param_id("2")), Some(ParameterValue::Integer(60)));

        dev.set_parameter_value(&param_id("2"), ParameterValue::Integer(80));
        dev.set_parameter_value(&param_id("5"), ParameterValue::Integer(2));
        let exported = configuration_from_device(&dev);
        let ids: Vec<_> = exported.parameters.iter().map(|parameter| parameter.id.as_str()).collect();
        assert_eq!(ids, [param_id("1").as_str(), param_id("2").as_str()]);
    }

    #[test]
    fn flag_layers_include_wire_system_priority() {
        let mut dev = device();
        let configuration = ProductConfiguration {
            parameters: vec![setting("1", ParameterValue::Integer(1))],
            objects: vec![ObjectSetting {
                com_object: 1,
                flags: ObjectFlagOverrides {
                    transmit: Some(true),
                    priority: Some(Priority::System),
                    ..Default::default()
                },
            }],
        };
        apply_configuration(&mut dev, &configuration).expect("configuration applies");
        let object = effective_com_objects(&dev, &configuration)
            .into_iter()
            .find(|object| object.number == 1)
            .expect("switch object is visible");
        assert!(object.read, "visible ref enables read");
        assert!(object.transmit, "project enables transmit");
        assert_eq!(object.priority, Priority::System);
        assert_eq!(object.flag_sources.read, EffectiveValueSource::VisibleReference);
        assert_eq!(object.flag_sources.transmit, EffectiveValueSource::Project);
        assert_eq!(object.flag_sources.priority, EffectiveValueSource::Project);
    }

    #[test]
    fn unknown_object_is_rejected() {
        let mut dev = device();
        let result = apply_configuration(&mut dev, &ProductConfiguration {
            parameters: Vec::new(),
            objects: vec![ObjectSetting { com_object: 42, flags: ObjectFlagOverrides::default() }],
        });
        assert!(matches!(result, Err(ConfigurationError::UnknownComObject(42))));
    }

    #[test]
    fn base_tables_are_the_configuration_surface_when_refs_are_absent() {
        let mut dev = base_tables_device();
        let configuration = ProductConfiguration {
            parameters: vec![setting("1", ParameterValue::Integer(1))],
            objects: vec![ObjectSetting {
                com_object: 1,
                flags: ObjectFlagOverrides { transmit: Some(true), ..Default::default() },
            }],
        };

        apply_configuration(&mut dev, &configuration).expect("base-table configuration applies");
        assert_eq!(configuration_from_device(&dev).parameters, configuration.parameters);

        let object = effective_com_objects(&dev, &configuration)
            .into_iter()
            .find(|object| object.number == 1)
            .expect("base switch object is visible");
        assert!(object.transmit);
        assert_eq!(object.flag_sources.transmit, EffectiveValueSource::Project);
        assert_eq!(object.flag_sources.read, EffectiveValueSource::Product);
    }

    #[test]
    fn datapoint_idrefs_use_the_specific_subtype_in_a_hierarchy() {
        let references = ProductDptReferences::parse("DPT-1 DPST-1-1").expect("IDREFS parse");
        assert_eq!(references.preferred(), ProductDptReference { main: 1, subtype: Some(1) });
        assert!(references.accepts(ProductDptReference { main: 1, subtype: Some(1) }));
        assert!(!references.accepts(ProductDptReference { main: 1, subtype: Some(2) }));

        let generic = ProductDptReferences::parse("DPT-1").expect("generic DPT parses");
        assert!(generic.accepts(ProductDptReference { main: 1, subtype: Some(2) }));
        assert!(ProductDptReferences::parse("DPT-1 garbage").is_none());
    }
}
