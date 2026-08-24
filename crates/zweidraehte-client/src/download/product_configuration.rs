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
//! [`apply_configuration`]: zweidraehte_knxprod::runtime::configuration::apply_configuration

use zweidraehte_knxprod::runtime::Device;
use zweidraehte_knxprod::runtime::configuration::{
    EffectiveComObject, ProductConfiguration, effective_com_objects, effective_default,
};
use zweidraehte_knxprod::runtime::model::ParameterValue as ModelValue;
use zweidraehte_knxprod::schema::ParameterTypeDef;
use zweidraehte_proto::com_object::{ComObjectFlags, ComObjectType};
use zweidraehte_proto::dpt::KnxFloat16;

use super::configuration::DeviceConfiguration;
use super::product::{ComObjectDef, ProductData};
use super::project::{ParameterValue, ProjectConfig};
use crate::error::{Error, Result};

/// The download-ready rendering of one configured device.
#[derive(Debug, Clone)]
pub struct ResolvedProject {
    /// Target-independent desired state. New commissioning callers use
    /// this field and resolve key material before lowering it.
    pub configuration: DeviceConfiguration,
    /// What [`compile`](super::compile) consumes as the project layer.
    pub project: ProjectConfig,
    /// The effective com objects (base definition ⊕ visible ref ⊕
    /// project flag overrides). The caller substitutes these for
    /// [`ProductData::com_objects`] before compiling, so the group
    /// object table reflects the *configuration*, not just the
    /// product's base declarations.
    /// ([`ProductData::com_object_numbers`] deliberately keeps the
    /// full declared roster through this substitution — dynamic table
    /// management sizes association slots off it.)
    pub com_objects: Vec<ComObjectDef>,
}

/// Render a configured device into the download engine's inputs.
///
/// Call after [`apply_configuration`] succeeded on `device` — this function
/// re-derives nothing that validation already established.
///
/// Parameter values are emitted for **every visible parameter** that
/// has a memory location, not only the overridden ones, plus every
/// `LegacyPatchAlways` parameter. That is what ETS effectively writes,
/// and it makes `ParameterRef` `Value` overrides (which this product
/// family uses by the hundreds) land in the image even when the user
/// changed nothing: an untouched parameter's effective default *is*
/// the visible ref's value, which need not equal the segment's seeded
/// default bytes.
///
/// [`apply_configuration`]: zweidraehte_knxprod::runtime::configuration::apply_configuration
pub fn resolve_product_configuration(
    device: &Device,
    settings: &ProductConfiguration,
    mut configuration: DeviceConfiguration,
    product: &ProductData,
) -> Result<ResolvedProject> {
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
    for location in &product.parameters {
        if location.legacy_patch_always && seen.insert(location.id.clone()) {
            ids.push(location.id.clone());
        }
    }

    for id in ids {
        // A visible parameter without a memory location is UI-only
        // (a picture, a heading) — nothing to write.
        let Some(location) = product.parameters.iter().find(|l| l.id == id) else { continue };

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
        let bytes = encode_value(&value, type_def, location.size_bits)
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
    let project = configuration.lower(None)?.project;
    Ok(ResolvedProject { configuration, project, com_objects })
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
    fn integers_encode_big_endian_and_masked() {
        assert_eq!(encode_value(&ModelValue::Integer(0x1234), None, 16).expect("encodes"), [0x12, 0x34]);
        // Negative values wrap into the field's two's complement.
        assert_eq!(encode_value(&ModelValue::Integer(-1), None, 8).expect("encodes"), [0xFF]);
        // Sub-byte fields occupy one byte for the bit patcher.
        assert_eq!(encode_value(&ModelValue::Integer(5), None, 4).expect("encodes"), [0x05]);
        assert!(encode_value(&ModelValue::Integer(1), None, 0).is_err(), "no width, no encoding");
    }

    #[test]
    fn text_pads_to_its_field_width() {
        assert_eq!(encode_value(&ModelValue::Text("AB".to_string()), None, 32).expect("encodes"), [
            0x41, 0x42, 0x00, 0x00
        ]);
    }

    #[test]
    fn dpt9_floats_use_the_knx_float_coding() {
        let t = ParameterTypeDef::TypeFloat(zweidraehte_knxprod::schema::TypeFloat {
            encoding: "DPT 9".to_string(),
            min_inclusive: -100.0,
            max_inclusive: 100.0,
        });
        let bytes = encode_value(&ModelValue::Float(21.0), Some(&t), 0).expect("encodes");
        assert_eq!(KnxFloat16::from_bytes([bytes[0], bytes[1]]).to_f32(), 21.0);
    }
}
