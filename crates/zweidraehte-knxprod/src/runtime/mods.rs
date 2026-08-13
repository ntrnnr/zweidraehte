//! Declarative single-device configuration ("mods") over a [`Device`].
//!
//! A mods file is the diff between a product's defaults and one
//! installation's configuration: parameter values, group-address
//! links, com-object flag overrides, and the device's individual
//! address. Two producers write it — a dump tool emitting a commented
//! skeleton, and the TUI exporting its edits — and one consumer reads
//! it: the loader, which applies it to a fresh [`Device`] and compiles
//! a download from the result.
//!
//! The types here are plain serde data, deliberately format-agnostic;
//! the tools serialize them as TOML. Everything that needs product
//! knowledge to interpret (value ranges, visibility, ref overrides)
//! happens in [`apply_mods`] / [`effective_com_objects`] against the
//! `Device`, so every consumer validates identically.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::schema::{ComObject, ComObjectPriority, EnableFlag, ParameterTypeDef};

use super::device::Device;
use super::model::{GroupAddress, ParameterValue};

// ============================================================================
// The mods file
// ============================================================================

/// One device's configuration overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceMods {
    pub device: DeviceSection,
    /// Parameter overrides, `[[param]]` in the TOML spelling.
    #[serde(default, rename = "param", skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<ParamOverride>,
    /// Group links and flag overrides, `[[link]]` in the TOML spelling.
    #[serde(default, rename = "link", skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<LinkOverride>,
}

/// The `[device]` header.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceSection {
    /// The individual address this installation assigns, in the usual
    /// `area.line.device` spelling. Kept a string here — parsing it
    /// into an address type is the loader's business, this crate has
    /// no addressing types.
    pub individual_address: String,
    /// The device's APDU capacity for memory writes, when the caller
    /// knows better than the loader's conservative default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_apdu: Option<u16>,
}

/// One parameter set to a non-default value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamOverride {
    /// The full MTXML parameter id (`M-0083_A-009B-14-E59D_P-24`) —
    /// the one identifier that is unique per parameter; names are not.
    pub id: String,
    pub value: ModsValue,
}

/// A parameter value as the mods file spells it. Untagged, so the TOML
/// reads naturally: `value = 3`, `value = 21.5`, `value = "Kitchen"`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ModsValue {
    Int(i64),
    Float(f64),
    Text(String),
}

impl From<&ParameterValue> for ModsValue {
    fn from(value: &ParameterValue) -> Self {
        match value {
            ParameterValue::Integer(i) => Self::Int(*i),
            ParameterValue::Float(f) => Self::Float(*f),
            ParameterValue::Text(t) => Self::Text(t.clone()),
            // Bytes only arise for TypeNone parameters, which are not
            // configurable through mods; hex text keeps the export
            // readable if one ever leaks through.
            ParameterValue::Bytes(b) => Self::Text(b.iter().map(|byte| format!("{byte:02X}")).collect()),
        }
    }
}

impl From<&ModsValue> for ParameterValue {
    fn from(value: &ModsValue) -> Self {
        match value {
            ModsValue::Int(i) => Self::Integer(*i),
            ModsValue::Float(f) => Self::Float(*f),
            ModsValue::Text(t) => Self::Text(t.clone()),
        }
    }
}

/// Group addresses (and optional flag overrides) for one com object.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LinkOverride {
    /// The object's `Number` — the ASAP the association table uses.
    pub com_object: u16,
    /// `main/middle/sub` strings; the first one is the sending
    /// address, the rest listen.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub group_addresses: Vec<String>,
    /// Flag overrides on top of what the product (and the currently
    /// visible `ComObjectRef`) declares.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<FlagOverrides>,
}

/// Per-flag overrides; `None` keeps the product's setting.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct FlagOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub communication: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transmit: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_on_init: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<ComObjectPriority>,
}

/// What can go wrong applying a mods file. Every variant names the
/// offending entry — a mods file is hand-edited, so "which line do I
/// fix" is the whole point of the message.
#[derive(Debug, Error)]
pub enum ModsError {
    #[error("the product defines no parameter `{0}`")]
    UnknownParameter(String),
    #[error("parameter `{0}` is not user-configurable (its access is None)")]
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
    #[error("com object {com_object}: `{address}` is not a valid group address (main/middle/sub)")]
    InvalidGroupAddress { com_object: u16, address: String },
}

// ============================================================================
// Applying mods to a device
// ============================================================================

/// Apply a mods file to a freshly-constructed device.
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
pub fn apply_mods(device: &mut Device, mods: &DeviceMods) -> Result<(), ModsError> {
    for param in &mods.params {
        let info = device.get_parameter_info(&param.id).ok_or_else(|| ModsError::UnknownParameter(param.id.clone()))?;
        if info.hidden {
            return Err(ModsError::NotConfigurable(param.id.clone()));
        }
        validate_value(device, &param.id, &param.value)?;
        device.set_parameter_value(&param.id, ParameterValue::from(&param.value));
    }

    // Visibility under the final configuration. A parameter is visible
    // when some visible ref targets it and that ref is not
    // access-hidden itself.
    for param in &mods.params {
        let visibly_referenced =
            device.visible_param_refs().any(|r| r.ref_id == param.id && r.access.as_deref() != Some("None"));
        if !visibly_referenced {
            return Err(ModsError::NotVisible(param.id.clone()));
        }
    }

    let visible_objects = visible_object_numbers(device);
    for link in &mods.links {
        if !visible_objects.contains(&link.com_object) {
            return Err(if object_exists(device, link.com_object) {
                ModsError::ComObjectNotVisible(link.com_object)
            } else {
                ModsError::UnknownComObject(link.com_object)
            });
        }

        // Re-assigning replaces: a dump/apply round-trip must not
        // accumulate addresses across runs.
        device.clear_group_addresses(link.com_object);
        for address in &link.group_addresses {
            let parsed = GroupAddress::parse(address).ok_or_else(|| ModsError::InvalidGroupAddress {
                com_object: link.com_object,
                address: address.clone(),
            })?;
            device.assign_group_address(link.com_object, parsed);
        }
    }

    Ok(())
}

/// Check a mods value against the parameter's declared type.
fn validate_value(device: &Device, param_id: &str, value: &ModsValue) -> Result<(), ModsError> {
    let invalid = |reason: String| ModsError::InvalidValue { param: param_id.to_string(), reason };

    let info = device.get_parameter_info(param_id).expect("caller resolved the parameter already");
    let Some(param_type) = device.get_parameter_type(&info.type_id) else {
        // A parameter without a resolvable type cannot be validated —
        // or encoded into memory later — so reject it here.
        return Err(invalid(format!("its type `{}` is not defined by the product", info.type_id)));
    };

    match (&param_type.type_def, value) {
        (ParameterTypeDef::TypeNumber(n), ModsValue::Int(i)) => {
            if *i < n.min_inclusive || *i > n.max_inclusive {
                return Err(invalid(format!(
                    "{i} is outside the allowed range {}..={}",
                    n.min_inclusive, n.max_inclusive
                )));
            }
        }
        (ParameterTypeDef::TypeRestriction(r), ModsValue::Int(i)) => {
            if !r.enumerations.iter().any(|e| i64::from(e.value) == *i) {
                let choices: Vec<String> = r.enumerations.iter().map(|e| format!("{} = {}", e.value, e.text)).collect();
                return Err(invalid(format!("{i} is not one of: {}", choices.join(", "))));
            }
        }
        (ParameterTypeDef::TypeFloat(f), ModsValue::Int(i)) => {
            let as_float = *i as f64;
            if as_float < f.min_inclusive || as_float > f.max_inclusive {
                return Err(invalid(format!(
                    "{i} is outside the allowed range {}..={}",
                    f.min_inclusive, f.max_inclusive
                )));
            }
        }
        (ParameterTypeDef::TypeFloat(f), ModsValue::Float(v)) => {
            if *v < f.min_inclusive || *v > f.max_inclusive {
                return Err(invalid(format!(
                    "{v} is outside the allowed range {}..={}",
                    f.min_inclusive, f.max_inclusive
                )));
            }
        }
        (ParameterTypeDef::TypeText(t), ModsValue::Text(s)) => {
            let capacity = (t.size_in_bit / 8) as usize;
            if s.len() > capacity {
                return Err(invalid(format!("{} bytes of text exceed the field's {capacity}", s.len())));
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
        (ParameterTypeDef::TypeNone(_) | ParameterTypeDef::TypePicture(_) | ParameterTypeDef::TypeIpAddress(_), _) => {
            return Err(invalid("this parameter type is not configurable through a mods file".to_string()));
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

/// Export the diff-from-defaults as a mods file.
///
/// Parameters appear when they were explicitly set *and* differ from
/// their effective default; links always appear in full. The
/// `[device]` section is left for the caller — a product file knows
/// nothing about the installation's addressing.
pub fn mods_from_device(device: &Device) -> DeviceMods {
    let mut params = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for param_ref in device.visible_param_refs() {
        let id = &param_ref.ref_id;
        if !seen.insert(id.clone()) || !device.is_parameter_touched(id) {
            continue;
        }
        let Some(current) = device.get_parameter_value(id) else { continue };
        if effective_default(device, id).as_ref() != Some(current) {
            params.push(ParamOverride { id: id.clone(), value: ModsValue::from(current) });
        }
    }
    params.sort_by(|a, b| a.id.cmp(&b.id));

    let mut links: Vec<LinkOverride> = device
        .all_bindings()
        .map(|(com_object, bindings)| {
            // The sending address leads, whatever the storage order.
            let mut addresses: Vec<&_> = bindings.iter().collect();
            addresses.sort_by_key(|b| !b.is_sending);
            LinkOverride {
                com_object,
                group_addresses: addresses.iter().map(|b| b.group_address.to_string()).collect(),
                flags: None,
            }
        })
        .collect();
    links.sort_by_key(|l| l.com_object);

    DeviceMods { device: DeviceSection::default(), params, links }
}

// ============================================================================
// Effective com objects
// ============================================================================

/// One com object as it would land in the device's group object
/// table: the base `ComObject` definition, overridden by the visible
/// `ComObjectRef`, overridden by the mods file's flag section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveComObject {
    pub number: u16,
    /// ETS's size spelling (`"1 Bit"`, `"1 Byte"` …), ref-overridable.
    pub object_size: String,
    pub priority: ComObjectPriority,
    pub read: bool,
    pub write: bool,
    pub communication: bool,
    pub transmit: bool,
    pub update: bool,
    pub read_on_init: bool,
    /// Display text (ref override first), for dump/report output.
    pub text: String,
    pub function_text: String,
}

/// Resolve the com objects visible under the device's current
/// configuration, with ref and mods overrides applied, ascending by
/// number.
///
/// When several refs of one object are visible at once the first one
/// wins; the vendor programs use choose/when to keep at most one
/// visible, so a collision is product-data noise rather than a state
/// we can order meaningfully.
pub fn effective_com_objects(device: &Device, mods: &DeviceMods) -> Vec<EffectiveComObject> {
    let enabled = |flag: &EnableFlag| matches!(flag, EnableFlag::Enabled);
    let ref_flag = |over: &Option<EnableFlag>, base: &EnableFlag| enabled(over.as_ref().unwrap_or(base));

    let mut by_number: std::collections::BTreeMap<u16, EffectiveComObject> = std::collections::BTreeMap::new();
    for object_ref in device.visible_com_object_refs() {
        let Some(base) = device.get_com_object(&object_ref.ref_id) else { continue };
        let flags = mods.links.iter().find(|l| l.com_object == base.number).and_then(|l| l.flags).unwrap_or_default();

        by_number.entry(base.number).or_insert_with(|| EffectiveComObject {
            number: base.number,
            object_size: object_ref.object_size.clone().unwrap_or_else(|| base.object_size.clone()),
            priority: flags.priority.or(object_ref.priority).or(base.priority).unwrap_or_default(),
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
        });
    }
    by_number.into_values().collect()
}

fn visible_object_numbers(device: &Device) -> std::collections::HashSet<u16> {
    device.visible_com_object_refs().filter_map(|r| device.get_com_object(&r.ref_id)).map(|o| o.number).collect()
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
    use crate::runtime::parser::parse_application_program;

    /// A program with the shapes the mods layer must handle: a
    /// selector-driven choose (mode 0 shows one union member and a
    /// plain com-object ref; mode 1 shows the other member, a level
    /// parameter whose *ref* overrides the default, and a com-object
    /// ref that overrides flags), plus an always-visible hidden
    /// parameter.
    const FIXTURE: &str = r#"<KNX xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="zweidraehte" ToolVersion="0.1.0" xmlns="http://knx.org/xml/project/20">
  <ManufacturerData><Manufacturer RefId="M-00FA"><ApplicationPrograms>
    <ApplicationProgram Id="M-00FA_A-1" ApplicationNumber="1" ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-0705" Name="Fixture" LoadProcedureStyle="ProductProcedure" PeiType="0" DefaultLanguage="de-DE" DynamicTableManagement="false" Linkable="false">
      <Static>
        <Code><AbsoluteSegment Id="M-00FA_A-1_AS-4300" Address="17152" Size="8" MemoryType="EEPROM" /></Code>
        <ParameterTypes>
          <ParameterType Id="M-00FA_A-1_PT-MODE" Name="Mode"><TypeRestriction Base="Value" SizeInBit="8"><Enumeration Text="Off" Value="0" Id="M-00FA_A-1_PT-MODE_EN-0" /><Enumeration Text="On" Value="1" Id="M-00FA_A-1_PT-MODE_EN-1" /></TypeRestriction></ParameterType>
          <ParameterType Id="M-00FA_A-1_PT-N8" Name="N8"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="100" /></ParameterType>
          <ParameterType Id="M-00FA_A-1_PT-TXT" Name="T240"><TypeText SizeInBit="240" /></ParameterType>
        </ParameterTypes>
        <Parameters>
          <Parameter Id="M-00FA_A-1_P-1" Name="Mode" ParameterType="M-00FA_A-1_PT-MODE" Text="Mode" Value="0"><Memory CodeSegment="M-00FA_A-1_AS-4300" Offset="0" BitOffset="0" /></Parameter>
          <Parameter Id="M-00FA_A-1_P-2" Name="Level" ParameterType="M-00FA_A-1_PT-N8" Text="Level" Value="50"><Memory CodeSegment="M-00FA_A-1_AS-4300" Offset="1" BitOffset="0" /></Parameter>
          <Parameter Id="M-00FA_A-1_P-3" Name="Internal" ParameterType="M-00FA_A-1_PT-N8" Text="" Access="None" Value="7"><Memory CodeSegment="M-00FA_A-1_AS-4300" Offset="2" BitOffset="0" /></Parameter>
          <Parameter Id="M-00FA_A-1_P-6" Name="Description" ParameterType="M-00FA_A-1_PT-TXT" Text="Description" Value="" />
          <Union SizeInBit="8">
            <Memory CodeSegment="M-00FA_A-1_AS-4300" Offset="3" BitOffset="0" />
            <Parameter Id="M-00FA_A-1_P-4" Name="OffChoice" ParameterType="M-00FA_A-1_PT-N8" Text="Off choice" Value="1" Offset="0" BitOffset="0" />
            <Parameter Id="M-00FA_A-1_P-5" Name="OnChoice" ParameterType="M-00FA_A-1_PT-N8" Text="On choice" Value="2" Offset="0" BitOffset="0" DefaultUnionParameter="true" />
          </Union>
        </Parameters>
        <ParameterRefs>
          <ParameterRef Id="M-00FA_A-1_P-1_R-1" RefId="M-00FA_A-1_P-1" />
          <ParameterRef Id="M-00FA_A-1_P-2_R-2" RefId="M-00FA_A-1_P-2" Value="60" />
          <ParameterRef Id="M-00FA_A-1_P-3_R-3" RefId="M-00FA_A-1_P-3" />
          <ParameterRef Id="M-00FA_A-1_P-4_R-4" RefId="M-00FA_A-1_P-4" />
          <ParameterRef Id="M-00FA_A-1_P-5_R-5" RefId="M-00FA_A-1_P-5" />
          <ParameterRef Id="M-00FA_A-1_P-6_R-6" RefId="M-00FA_A-1_P-6" />
        </ParameterRefs>
        <ComObjectTable>
          <ComObject Id="M-00FA_A-1_O-1" Name="Switch" Text="Switch" Number="1" FunctionText="On/Off" ObjectSize="1 Bit" ReadFlag="Disabled" WriteFlag="Enabled" CommunicationFlag="Enabled" TransmitFlag="Disabled" UpdateFlag="Disabled" ReadOnInitFlag="Disabled" />
        </ComObjectTable>
        <ComObjectRefs>
          <ComObjectRef Id="M-00FA_A-1_O-1_R-1" RefId="M-00FA_A-1_O-1" />
          <ComObjectRef Id="M-00FA_A-1_O-1_R-2" RefId="M-00FA_A-1_O-1" ReadFlag="Enabled" Priority="High" Text="Switch (on)" />
        </ComObjectRefs>
      </Static>
      <Dynamic>
        <Channel Id="M-00FA_A-1_CH-1" Name="Main">
          <ParameterBlock Id="M-00FA_A-1_PB-1" Text="Main">
            <ParameterRefRef RefId="M-00FA_A-1_P-1_R-1" />
            <ParameterRefRef RefId="M-00FA_A-1_P-3_R-3" />
            <ParameterRefRef RefId="M-00FA_A-1_P-6_R-6" />
            <choose ParamRefId="M-00FA_A-1_P-1_R-1">
              <when test="0">
                <ParameterRefRef RefId="M-00FA_A-1_P-4_R-4" />
                <ComObjectRefRef RefId="M-00FA_A-1_O-1_R-1" />
              </when>
              <when test="1">
                <ParameterRefRef RefId="M-00FA_A-1_P-5_R-5" />
                <ParameterRefRef RefId="M-00FA_A-1_P-2_R-2" />
                <ComObjectRefRef RefId="M-00FA_A-1_O-1_R-2" />
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
        Device::new(program, None, None)
    }

    fn param_id(suffix: &str) -> String {
        format!("M-00FA_A-1_P-{suffix}")
    }

    #[test]
    fn applies_values_links_and_recomputed_visibility() {
        let mut dev = device();
        let mods = DeviceMods {
            device: DeviceSection::default(),
            params: vec![
                ParamOverride { id: param_id("1"), value: ModsValue::Int(1) },
                // P-5 only becomes visible *because* P-1 flips to 1 —
                // proving values apply before visibility validates.
                ParamOverride { id: param_id("5"), value: ModsValue::Int(9) },
            ],
            links: vec![LinkOverride {
                com_object: 1,
                group_addresses: vec!["1/2/3".to_string(), "1/2/4".to_string()],
                flags: None,
            }],
        };

        apply_mods(&mut dev, &mods).expect("applies");
        assert_eq!(dev.get_parameter_value(&param_id("5")), Some(&ParameterValue::Integer(9)));
        let bindings = dev.get_bindings(1).expect("bound");
        assert_eq!(bindings.len(), 2);
        assert!(bindings[0].is_sending, "the first listed address sends");
    }

    #[test]
    fn rejects_a_parameter_hidden_by_the_current_configuration() {
        // P-2 sits in the mode-1 branch; the fixture boots in mode 0.
        let mut dev = device();
        let mods = DeviceMods {
            params: vec![ParamOverride { id: param_id("2"), value: ModsValue::Int(10) }],
            ..Default::default()
        };
        assert!(matches!(apply_mods(&mut dev, &mods), Err(ModsError::NotVisible(_))));
    }

    #[test]
    fn rejects_the_inactive_union_member() {
        // Mode 0 shows P-4; setting P-5 would stomp the same byte.
        let mut dev = device();
        let mods = DeviceMods {
            params: vec![ParamOverride { id: param_id("5"), value: ModsValue::Int(9) }],
            ..Default::default()
        };
        assert!(matches!(apply_mods(&mut dev, &mods), Err(ModsError::NotVisible(_))));
    }

    #[test]
    fn rejects_access_none_and_bad_values_and_unknowns() {
        let mut dev = device();
        let hidden = DeviceMods {
            params: vec![ParamOverride { id: param_id("3"), value: ModsValue::Int(1) }],
            ..Default::default()
        };
        assert!(matches!(apply_mods(&mut dev, &hidden), Err(ModsError::NotConfigurable(_))));

        let mut dev = device();
        let out_of_range = DeviceMods {
            params: vec![ParamOverride { id: param_id("1"), value: ModsValue::Int(3) }],
            ..Default::default()
        };
        assert!(matches!(apply_mods(&mut dev, &out_of_range), Err(ModsError::InvalidValue { .. })));

        let mut dev = device();
        let unknown = DeviceMods {
            params: vec![ParamOverride { id: param_id("99"), value: ModsValue::Int(0) }],
            ..Default::default()
        };
        assert!(matches!(apply_mods(&mut dev, &unknown), Err(ModsError::UnknownParameter(_))));

        let mut dev = device();
        let unknown_object = DeviceMods {
            links: vec![LinkOverride { com_object: 42, group_addresses: vec!["1/1/1".to_string()], flags: None }],
            ..Default::default()
        };
        assert!(matches!(apply_mods(&mut dev, &unknown_object), Err(ModsError::UnknownComObject(42))));
    }

    #[test]
    fn effective_default_honors_the_visible_ref_override() {
        let mut dev = device();
        // In mode 1, P-2's visible ref carries Value="60".
        apply_mods(&mut dev, &DeviceMods {
            params: vec![ParamOverride { id: param_id("1"), value: ModsValue::Int(1) }],
            ..Default::default()
        })
        .expect("applies");
        assert_eq!(effective_default(&dev, &param_id("2")), Some(ParameterValue::Integer(60)));
        // P-1 has no ref override: the base default stands.
        assert_eq!(effective_default(&dev, &param_id("1")), Some(ParameterValue::Integer(0)));
    }

    #[test]
    fn export_round_trips_and_diffs_against_effective_defaults() {
        let mut dev = device();
        let mods = DeviceMods {
            device: DeviceSection::default(),
            params: vec![ParamOverride { id: param_id("1"), value: ModsValue::Int(1) }, ParamOverride {
                id: param_id("2"),
                value: ModsValue::Int(80),
            }],
            links: vec![LinkOverride { com_object: 1, group_addresses: vec!["1/2/3".to_string()], flags: None }],
        };
        apply_mods(&mut dev, &mods).expect("applies");

        // Also set P-5 *to its effective default* — the export must
        // drop it again.
        dev.set_parameter_value(&param_id("5"), ParameterValue::Integer(2));

        let exported = mods_from_device(&dev);
        let ids: Vec<&str> = exported.params.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, [param_id("1").as_str(), param_id("2").as_str()]);
        assert_eq!(exported.links.len(), 1);
        assert_eq!(exported.links[0].group_addresses, ["1/2/3"]);
    }

    /// Virtual parameters — memoryless text like a button description
    /// — travel in the same `[[param]]` section: they never patch
    /// device memory (no location, so the resolver skips them), but
    /// they shape labels and must survive export/apply round trips.
    #[test]
    fn virtual_text_parameters_round_trip_through_mods() {
        let mut dev = device();
        let mods = DeviceMods {
            params: vec![ParamOverride { id: param_id("6"), value: ModsValue::Text("Kitchen light".to_string()) }],
            ..Default::default()
        };
        apply_mods(&mut dev, &mods).expect("applies");
        assert_eq!(dev.get_parameter_value(&param_id("6")), Some(&ParameterValue::Text("Kitchen light".to_string())));

        let exported = mods_from_device(&dev);
        assert_eq!(exported.params.len(), 1);
        assert_eq!(exported.params[0].id, param_id("6"));
        assert_eq!(exported.params[0].value, ModsValue::Text("Kitchen light".to_string()));

        // Setting it via the TUI path (set_parameter_value) exports
        // identically, and an empty edit equals the default and drops
        // out again.
        dev.set_parameter_value(&param_id("6"), ParameterValue::Text(String::new()));
        assert!(mods_from_device(&dev).params.is_empty(), "back at the default, nothing to export");
    }

    #[test]
    fn effective_com_objects_layer_ref_and_mods_overrides() {
        // Mode 0: the plain ref — the base object's flags as declared.
        let dev = device();
        let objects = effective_com_objects(&dev, &DeviceMods::default());
        assert_eq!(objects.len(), 1);
        let object = &objects[0];
        assert!(!object.read && object.write && object.communication);
        assert_eq!(object.priority, ComObjectPriority::Low);

        // Mode 1: the ref flips Read on and raises the priority; a
        // mods override then flips Transmit on top.
        let mut dev = device();
        let mods = DeviceMods {
            params: vec![ParamOverride { id: param_id("1"), value: ModsValue::Int(1) }],
            links: vec![LinkOverride {
                com_object: 1,
                group_addresses: Vec::new(),
                flags: Some(FlagOverrides { transmit: Some(true), ..Default::default() }),
            }],
            ..Default::default()
        };
        apply_mods(&mut dev, &mods).expect("applies");
        let objects = effective_com_objects(&dev, &mods);
        let object = &objects[0];
        assert!(object.read, "the mode-1 ref enables Read");
        assert!(object.transmit, "the mods flags enable Transmit");
        assert_eq!(object.priority, ComObjectPriority::High);
        assert_eq!(object.text, "Switch (on)");
    }
}
