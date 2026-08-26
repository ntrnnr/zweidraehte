//! From a configured [`Device`] to the download's product-derived inputs.
//!
//! The knxprod runtime owns everything that needs *product* semantics
//! — visibility, ref overrides, value validation ([`apply_configuration`]
//! does
//! all of that). This module owns the translation into the download
//! engine's vocabulary: encoding typed parameter values into
//! device-memory bytes and packing the effective communication objects into
//! the group-object-table coding. The compile pipeline itself stays untouched — it remains
//! the one, conformance-verified producer of download blobs.
//!
//! [`apply_configuration`]: zweidraehte_ets_files::runtime::configuration::apply_configuration

use zweidraehte_ets_files::runtime::Device;
use zweidraehte_ets_files::runtime::configuration::{
    EffectiveComObject, ProductConfiguration, effective_com_objects, effective_default,
};
use zweidraehte_ets_files::runtime::model::ParameterValue as ModelValue;
use zweidraehte_ets_files::schema::ParameterTypeDef;
use zweidraehte_proto::com_object::{ComObjectFlags, ComObjectType};
use zweidraehte_proto::dpt::KnxFloat16;

use super::configuration::DeviceConfiguration;
use super::project::ParameterValue;
use crate::error::{Error, Result};
use zweidraehte_ets_files::product::{ComObjectDef, ProductData};

/// The download-ready rendering of one configured device.
#[derive(Debug, Clone)]
pub struct ResolvedProject {
    /// Target-independent desired state. New commissioning callers use
    /// this field and resolve key material before lowering it.
    pub configuration: DeviceConfiguration,
    /// Project values and effective objects kept together at the compiler
    /// boundary. They cannot be paired with a different product mutation.
    pub lowered: super::configuration::LoweredDeviceConfiguration,
}

/// Render a configured device into the download engine's inputs.
///
/// Call after [`apply_configuration`] succeeded on `device` — this function
/// re-derives nothing that validation already established.
///
/// Parameter values first seed every ordinary stored parameter's base value
/// (and the designated default member of each union). Visible references,
/// explicit edits and `LegacyPatchAlways` parameters are then layered over
/// that base. Every property-backed parameter is included as well because,
/// unlike a seeded memory segment, its load-control data block has no other
/// source. This mirrors ETS even when segment `Data` omits defaults or a
/// `ParameterRef` value differs from the base parameter value.
///
/// [`apply_configuration`]: zweidraehte_ets_files::runtime::configuration::apply_configuration
pub fn resolve_product_configuration(
    device: &Device,
    settings: &ProductConfiguration,
    mut configuration: DeviceConfiguration,
    product: &ProductData,
) -> Result<ResolvedProject> {
    // Segment `Data` is not required to contain parameter defaults. ETS
    // initializes every ordinary stored parameter from its base `Value`, and
    // initializes shared union storage from the member explicitly designated
    // as `DefaultUnionParameter`. Active references below then override this
    // base image. Some BCU2 products depend on this ordering even though
    // System B products commonly duplicate the defaults in `Data`.
    for location in product.parameters().iter().filter(|location| location.seeds_default) {
        let Some(value) = device.get_parameter_value(&location.id) else { continue };
        let type_def = device
            .get_parameter_info(&location.id)
            .and_then(|info| device.get_parameter_type(&info.type_id))
            .map(|parameter_type| &parameter_type.type_def);
        let bytes = encode_value(value, type_def, location.size_bits)
            .map_err(|reason| Error::ProductData(format!("parameter {}: {reason}", location.id)))?;
        configuration.parameters.push(ParameterValue { id: location.id.clone(), value: bytes });
    }

    // The parameters to write: every visible one, deduplicated (the
    // same ref can appear on several pages), plus the LegacyPatchAlways
    // stragglers that need writing regardless of visibility.
    let mut ids: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    if device.static_section().parameter_refs.as_ref().is_some_and(|references| !references.refs.is_empty()) {
        for param_ref in device.visible_param_refs() {
            if seen.insert(param_ref.ref_id.clone()) {
                ids.push(param_ref.ref_id.clone());
            }
        }
    } else {
        // With no reference layer, only explicitly touched base parameters
        // need patching; untouched defaults are already in segment data.
        for parameter in &settings.parameters {
            if seen.insert(parameter.id.clone()) {
                ids.push(parameter.id.clone());
            }
        }
    }
    for location in product.parameters() {
        if location.legacy_patch_always && seen.insert(location.id.clone()) {
            ids.push(location.id.clone());
        }
    }
    for location in product.property_parameters() {
        if seen.insert(location.id.clone()) {
            ids.push(location.id.clone());
        }
    }

    for id in ids {
        // A visible parameter without a storage location is UI-only (a
        // picture or heading), so it contributes no download bytes.
        let size_bits =
            product.parameters().iter().find(|location| location.id == id).map(|location| location.size_bits).or_else(
                || {
                    product
                        .property_parameters()
                        .iter()
                        .find(|location| location.id == id)
                        .map(|location| location.size_bits)
                },
            );
        let Some(size_bits) = size_bits else { continue };

        // The value ETS would write: the user's choice when there is
        // one, the effective default (ref override before base
        // default) otherwise.
        let value = if device.is_parameter_touched(&id) {
            device.get_parameter_value(&id).cloned()
        } else {
            effective_default(device, &id)
        };
        let Some(value) = value else { continue };

        let type_def = device
            .get_parameter_info(&id)
            .and_then(|info| device.get_parameter_type(&info.type_id))
            .map(|t| &t.type_def);
        let bytes = encode_value(&value, type_def, size_bits)
            .map_err(|reason| Error::ProductData(format!("parameter {id}: {reason}")))?;
        configuration.parameters.push(ParameterValue { id, value: bytes });
    }

    let com_objects = effective_com_objects(device, settings)
        .iter()
        .map(|object| {
            let object_type = ComObjectType::from_ets_size_string(&object.object_size).ok_or_else(|| {
                Error::ProductData(format!(
                    "object {} has an unrecognized size {:?}",
                    object.number, object.object_size
                ))
            })?;
            Ok(ComObjectDef { number: object.number, object_type, flags: pack_effective_flags(object) })
        })
        .collect::<Result<Vec<_>>>()?;

    configuration.objects = com_objects.clone();
    let lowered = configuration.lower_product_structure()?;
    Ok(ResolvedProject { configuration, lowered })
}

/// Encode one typed value into device-memory bytes.
///
/// Big-endian throughout — that is how ETS stores multi-byte
/// parameters, and [`patch_one_parameter`](super::project) interprets
/// bit-packed values the same way.
fn encode_value(
    value: &ModelValue,
    type_def: Option<&ParameterTypeDef>,
    size_bits: u16,
) -> core::result::Result<Vec<u8>, String> {
    match value {
        ModelValue::Integer(i) => {
            if let Some(ParameterTypeDef::TypeTime(time)) = type_def {
                if size_bits != u16::from(time.size_in_bit) {
                    return Err(format!(
                        "the storage location is {size_bits} bits but the time type declares {} bits",
                        time.size_in_bit
                    ));
                }

                return time.encode_value(*i).ok_or_else(|| {
                    format!("{i} {} is outside the time type's range or storage width", time.unit.value_unit())
                });
            }

            if size_bits == 0 {
                return Err("an integer value needs a type-declared width to be encoded".to_string());
            }
            if size_bits > 64 {
                return Err(format!("{size_bits}-bit integers are not supported"));
            }
            // Two's-complement masking covers signedInt and
            // unsignedInt alike; range validation already happened in
            // `apply_configuration`.
            let mask = if size_bits == 64 { u64::MAX } else { (1u64 << size_bits) - 1 };
            let raw = (*i as u64) & mask;
            let width = usize::from(size_bits.div_ceil(8));
            Ok(raw.to_be_bytes()[8 - width..].to_vec())
        }
        ModelValue::Float(f) => match type_def {
            Some(ParameterTypeDef::TypeFloat(t)) if t.encoding.starts_with("DPT 9") => {
                Ok(KnxFloat16::from_f32(*f as f32).to_bytes().to_vec())
            }
            Some(ParameterTypeDef::TypeFloat(t)) if t.encoding.starts_with("DPT 14") => {
                Ok((*f as f32).to_be_bytes().to_vec())
            }
            Some(ParameterTypeDef::TypeFloat(t)) => Err(format!("float encoding {:?} is not supported", t.encoding)),
            _ => Err("a float value on a non-float parameter type".to_string()),
        },
        ModelValue::Text(s) if let Some(ParameterTypeDef::TypeColor(color)) = type_def => {
            color.space.decode_value(s).ok_or_else(|| format!("{s:?} is not a valid {} colour", color.space.name()))
        }
        ModelValue::Text(s) => {
            // A text field owns its full width; shorter strings are
            // zero-padded so stale bytes cannot survive behind them.
            let width = usize::from(size_bits.div_ceil(8)).max(s.len());
            let mut bytes = vec![0u8; width];
            bytes[..s.len()].copy_from_slice(s.as_bytes());
            Ok(bytes)
        }
        ModelValue::Bytes(b) => Ok(b.clone()),
    }
}

/// Pack the effective flags into the group object table's coding
/// octet, mirroring the product extractor's packing of base objects.
fn pack_effective_flags(object: &EffectiveComObject) -> ComObjectFlags {
    let mut byte = 0u8;
    for (enabled, mask) in [
        (object.update, ComObjectFlags::UE_FLAG_MASK),
        (object.transmit, ComObjectFlags::TE_FLAG_MASK),
        (object.read_on_init, ComObjectFlags::ROI_FLAG_MASK),
        (object.write, ComObjectFlags::WE_FLAG_MASK),
        (object.read, ComObjectFlags::RE_FLAG_MASK),
        (object.communication, ComObjectFlags::CE_FLAG_MASK),
    ] {
        if enabled {
            byte |= mask;
        }
    }
    byte |= u8::from(object.priority);
    ComObjectFlags::from_byte(byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_base_defaults_seed_the_download_even_when_not_visible() {
        let xml = zweidraehte_ets_files::product::fixtures::SYSTEM7_MTXML
            .replace(
                "        <Parameters>",
                r#"        <ParameterTypes>
          <ParameterType Id="M-00FA_A-0306-02-0000_PT-1" Name="Mode"><TypeNumber SizeInBit="8" Type="unsignedInt" minInclusive="0" maxInclusive="255" /></ParameterType>
        </ParameterTypes>
        <Parameters>"#,
            )
            .replace(r#"Text="Mode" Value="0""#, r#"Text="Mode" Value="7""#);
        let knx = zweidraehte_ets_files::runtime::parser::parse_application_program(&xml).expect("fixture parses");
        let program = knx.manufacturer_data.manufacturer.application_programs.programs[0].clone();
        let product = ProductData::from_program(&program).expect("product extracts");
        let mut device = Device::new(program, None);
        let settings = ProductConfiguration::default();
        zweidraehte_ets_files::runtime::configuration::apply_configuration(&mut device, &settings)
            .expect("default configuration applies");
        let configuration = DeviceConfiguration {
            identity: super::super::configuration::DeviceIdentity {
                desired_address: zweidraehte_proto::address::IndividualAddress::new(1, 1, 1),
                serial_number: None,
            },
            data_secure_enabled: false,
            parameters: Vec::new(),
            object_memberships: Vec::new(),
            objects: Vec::new(),
            net_security: std::collections::BTreeMap::new(),
            max_apdu: None,
        };

        let resolved =
            resolve_product_configuration(&device, &settings, configuration, &product).expect("configuration resolves");
        assert_eq!(resolved.configuration.parameters.len(), 1);
        assert_eq!(resolved.configuration.parameters[0].value, [7]);
    }

    #[test]
    fn integers_encode_big_endian_and_masked() {
        assert_eq!(encode_value(&ModelValue::Integer(0x1234), None, 16).expect("encodes"), [0x12, 0x34]);
        // Negative values wrap into the field's two's complement.
        assert_eq!(encode_value(&ModelValue::Integer(-1), None, 8).expect("encodes"), [0xFF]);
        // Sub-byte fields occupy one byte for the bit patcher.
        assert_eq!(encode_value(&ModelValue::Integer(5), None, 4).expect("encodes"), [0x05]);
        assert!(encode_value(&ModelValue::Integer(1), None, 0).is_err(), "no width, no encoding");
    }

    #[test]
    fn colours_encode_as_channel_octets_not_text() {
        let color = ParameterTypeDef::TypeColor(zweidraehte_ets_files::schema::TypeColor {
            space: zweidraehte_ets_files::schema::ColorSpace::Rgb,
        });
        assert_eq!(encode_value(&ModelValue::Text("#12ABEF".into()), Some(&color), 24).expect("colour encodes"), [
            0x12, 0xAB, 0xEF
        ]);
        assert!(encode_value(&ModelValue::Text("red".into()), Some(&color), 24).is_err());
    }

    #[test]
    fn time_values_use_the_declared_integer_basis_and_width() {
        let time = ParameterTypeDef::TypeTime(zweidraehte_ets_files::schema::TypeTime {
            size_in_bit: 24,
            unit: zweidraehte_ets_files::schema::TimeUnit::PackedDaysHoursMinutesAndSeconds,
            min_inclusive: 0,
            max_inclusive: 691_199,
            ui_hint: Some("Duration_hhmmss".to_string()),
        });

        assert_eq!(encode_value(&ModelValue::Integer(86_400), Some(&time), 24).expect("time encodes"), [
            0x01, 0x51, 0x80
        ]);
        assert!(encode_value(&ModelValue::Integer(691_200), Some(&time), 24).is_err());
        assert!(encode_value(&ModelValue::Integer(60), Some(&time), 16).is_err());
    }

    #[test]
    fn text_pads_to_its_field_width() {
        assert_eq!(encode_value(&ModelValue::Text("AB".to_string()), None, 32).expect("encodes"), [
            0x41, 0x42, 0x00, 0x00
        ]);
    }

    #[test]
    fn dpt9_floats_use_the_knx_float_coding() {
        let t = ParameterTypeDef::TypeFloat(zweidraehte_ets_files::schema::TypeFloat {
            encoding: "DPT 9".to_string(),
            min_inclusive: -100.0,
            max_inclusive: 100.0,
        });
        let bytes = encode_value(&ModelValue::Float(21.0), Some(&t), 0).expect("encodes");
        assert_eq!(KnxFloat16::from_bytes([bytes[0], bytes[1]]).to_f32(), 21.0);
    }

    #[test]
    fn dpt14_floats_use_ieee_754_network_order() {
        let t = ParameterTypeDef::TypeFloat(zweidraehte_ets_files::schema::TypeFloat {
            encoding: "DPT 14".to_string(),
            min_inclusive: -1.0e12,
            max_inclusive: 1.0e12,
        });
        assert_eq!(encode_value(&ModelValue::Float(21.5), Some(&t), 0).expect("encodes"), 21.5f32.to_be_bytes());
    }
}
